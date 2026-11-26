;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Concurrent GC mutator/collector safepoint handshake protocol (Doligez-Leroy / SATB).
;;; Typed structural AST + auto-derived countermodel via (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export SafepointHandshakeModel SkipHandshakeCountermodel)

(.def (SafepointHandshakeModel @ ThreatModel.)
  identity: 'engineering.gc.safepoint-handshake
  family: 'engineering.gc.safepoint-handshake
  quint-module: "gc_safepoint_handshake"
  quint-file: "SafepointHandshake.qnt"
  domain-dir: "engineering/gc/safepoint-handshake"
  quint-imports: '()
  rules: '((gc-hs-safe GC-HS-SAFE quint)
           (gc-hs-skip GC-HS-SKIP quint))
  dependencies: '((GC-HS-SAFE source) (GC-HS-SAFE profile) (GC-HS-SAFE method)
                  (GC-HS-SKIP source) (GC-HS-SKIP profile) (GC-HS-SKIP method))
  invariant: "During concurrent Mark phase, every mutator has enabled its write barrier and no unbarriered store occurs."
  parameters: '()
  ;; Phases: 0=Idle, 1=SyncMark, 2=Mark, 3=Sweep.
  state: '((phase "int" "0")
           (m1Barrier "bool" "false")
           (m2Barrier "bool" "false")
           (unbarrieredWrite "bool" "false"))
  guards: '((mutator-safepoint-ack (and (. h m1Barrier) (. h m2Barrier))))
  transitions:
  '((requestSyncMark
     (action requestSyncMark ()
       (if (= (. h phase) 0) (set-h (phase 1)) (keep-h))))
    (m1AckSafepoint
     (action m1AckSafepoint ()
       (if (and (= (. h phase) 1) (not (. h m1Barrier)))
         (set-h (m1Barrier #t))
         (keep-h))))
    (m2AckSafepoint
     (action m2AckSafepoint ()
       (if (and (= (. h phase) 1) (not (. h m2Barrier)))
         (set-h (m2Barrier #t))
         (keep-h))))
    (enterMark
     (action enterMark ()
       (if (and (= (. h phase) 1)
                (guard mutator-safepoint-ack (and (. h m1Barrier) (. h m2Barrier))))
         (set-h (phase 2))
         (keep-h))))
    (m1Mutate
     (action m1Mutate ()
       (set-h (unbarrieredWrite (or (. h unbarrieredWrite) (and (= (. h phase) 2) (not (. h m1Barrier))))))))
    (m2Mutate
     (action m2Mutate ()
       (set-h (unbarrieredWrite (or (. h unbarrieredWrite) (and (= (. h phase) 2) (not (. h m2Barrier))))))))
    (enterSweep
     (action enterSweep ()
       (if (= (. h phase) 2) (set-h (phase 3)) (keep-h))))
    (finishCycle
     (action finishCycle ()
       (if (= (. h phase) 3)
         (set-h (phase 0) (m1Barrier #f) (m2Barrier #f))
         (keep-h))))
    (step
     (action step ()
       (any requestSyncMark m1AckSafepoint m2AckSafepoint enterMark m1Mutate m2Mutate enterSweep finishCycle))))
  safety:
  '(and (not (. h unbarrieredWrite))
        (or (!= (. h phase) 2) (and (. h m1Barrier) (. h m2Barrier))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (fullHandshakeCycleTest
     (run fullHandshakeCycleTest
       (then init requestSyncMark m1AckSafepoint m2AckSafepoint enterMark m1Mutate m2Mutate enterSweep finishCycle checkSafe)))
    (partialAckBlocksMarkTest
     (run partialAckBlocksMarkTest
       (then init requestSyncMark m1AckSafepoint enterMark
             (all (assert (= (. h phase) 1)) (assert safety) (keep-h)))))
    (skipHandshakeCountermodelTest
     (run skipHandshakeCountermodelTest
       (then init requestSyncMark m1AckSafepoint enterMarkNoHandshake m2Mutate checkUnsafe))))
  countermodels: (list SkipHandshakeCountermodel)
  limits: "Finite 2-mutator safepoint handshake abstraction; does not model OS thread preemption, page-fault polling, or stack scanning.")

;; Weakened descendant: collector enters Mark without waiting for all mutators to acknowledge barrier activation.
(.def (SkipHandshakeCountermodel @ SafepointHandshakeModel)
  identity: 'engineering.gc.safepoint-handshake.skip-handshake
  dropped-guard: 'mutator-safepoint-ack
  step-action: "stepSkipHandshake"
  derive-from-transition: 'enterMark
  derive-action-name: 'enterMarkNoHandshake
  expected-itf-predicate: "h.phase == 2 and (not(h.m1Barrier) or not(h.m2Barrier))")
