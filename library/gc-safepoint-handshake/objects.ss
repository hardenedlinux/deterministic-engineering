;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Concurrent GC mutator/collector safepoint handshake protocol (Doligez-Leroy / SATB).
;;; Collector cannot enter Mark until every mutator enables its write barrier at a safepoint.
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
  guards: '((mutator-safepoint-ack "h.m1Barrier and h.m2Barrier"))
  transitions:
  '((requestSyncMark "action requestSyncMark = if (h.phase == 0)\n    h' = h.with(\"phase\", 1)\n    else h' = h")
    (m1AckSafepoint "action m1AckSafepoint = if (h.phase == 1 and not(h.m1Barrier))\n    h' = h.with(\"m1Barrier\", true)\n    else h' = h")
    (m2AckSafepoint "action m2AckSafepoint = if (h.phase == 1 and not(h.m2Barrier))\n    h' = h.with(\"m2Barrier\", true)\n    else h' = h")
    (enterMark "action enterMark = if (h.phase == 1 and h.m1Barrier and h.m2Barrier)\n    h' = h.with(\"phase\", 2)\n    else h' = h")
    (m1Mutate "action m1Mutate = h' = h.with(\"unbarrieredWrite\", h.unbarrieredWrite or (h.phase == 2 and not(h.m1Barrier)))")
    (m2Mutate "action m2Mutate = h' = h.with(\"unbarrieredWrite\", h.unbarrieredWrite or (h.phase == 2 and not(h.m2Barrier)))")
    (enterSweep "action enterSweep = if (h.phase == 2)\n    h' = h.with(\"phase\", 3)\n    else h' = h")
    (finishCycle "action finishCycle = if (h.phase == 3)\n    h' = h.with(\"phase\", 0).with(\"m1Barrier\", false).with(\"m2Barrier\", false)\n    else h' = h")
    (step "action step = any { requestSyncMark, m1AckSafepoint, m2AckSafepoint, enterMark, m1Mutate, m2Mutate, enterSweep, finishCycle }"))
  safety: "not(h.unbarrieredWrite) and (h.phase != 2 or (h.m1Barrier and h.m2Barrier))"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (fullHandshakeCycleTest "run fullHandshakeCycleTest = init.then(requestSyncMark).then(m1AckSafepoint).then(m2AckSafepoint).then(enterMark).then(m1Mutate).then(m2Mutate).then(enterSweep).then(finishCycle).then(checkSafe)")
    (partialAckBlocksMarkTest "run partialAckBlocksMarkTest = init.then(requestSyncMark).then(m1AckSafepoint).then(enterMark).then(all { assert(h.phase == 1), assert(safety), h' = h })")
    (skipHandshakeCountermodelTest "run skipHandshakeCountermodelTest = init.then(requestSyncMark).then(m1AckSafepoint).then(enterMarkNoHandshake).then(m2Mutate).then(checkUnsafe)"))
  countermodels: (list SkipHandshakeCountermodel)
  limits: "Finite 2-mutator safepoint handshake abstraction; does not model OS thread preemption, page-fault polling, or stack scanning.")

;; Weakened descendant: collector enters Mark without waiting for all mutators to acknowledge barrier activation.
(.def (SkipHandshakeCountermodel @ SafepointHandshakeModel)
  identity: 'engineering.gc.safepoint-handshake.skip-handshake
  dropped-guard: 'mutator-safepoint-ack
  step-action: "stepSkipHandshake"
  counter-action: "action enterMarkNoHandshake = if (h.phase == 1)\n    h' = h.with(\"phase\", 2)\n    else h' = h\n  action stepSkipHandshake = any { step, enterMarkNoHandshake }"
  expected-itf-predicate: "h.phase == 2 and (not(h.m1Barrier) or not(h.m2Barrier))")
