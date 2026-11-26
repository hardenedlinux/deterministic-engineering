;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Concurrent tri-color GC marking model with Dijkstra insertion write barrier.
;;; Emergent tri-color & live-sweep safety (zero synthetic unsafe flag);
;;; countermodel auto-derived via 3-arg (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export TricolorWriteBarrierModel NoWriteBarrierCountermodel)

(.def (TricolorWriteBarrierModel @ ThreatModel.)
  identity: 'engineering.gc.tricolor-write-barrier
  family: 'engineering.gc.tricolor-write-barrier
  quint-module: "gc_tricolor_barrier"
  quint-file: "TricolorWriteBarrier.qnt"
  domain-dir: "engineering/gc/tricolor-write-barrier"
  quint-imports: '()
  rules: '((gc-tricolor-strong GC-TRICOLOR-STRONG quint)
           (gc-tricolor-no-barrier GC-NO-BARRIER quint))
  dependencies: '((GC-TRICOLOR-STRONG source) (GC-TRICOLOR-STRONG profile) (GC-TRICOLOR-STRONG method)
                  (GC-NO-BARRIER source) (GC-NO-BARRIER profile) (GC-NO-BARRIER method))
  invariant: "Strong tri-color invariant holds during marking (no Black->White edge) and sweep never reclaims a reachable live object."
  parameters: '()
  ;; Colors: 0=White, 1=Grey, 2=Black. Phases: 0=Marking, 1=Sweeping, 2=Done.
  ;; Root A is already Black; B is Grey with B->C; C is White (reachable via A->B->C).
  state: '((phase "int" "0")
           (colorA "int" "2")
           (colorB "int" "1")
           (colorC "int" "0")
           (aToB "bool" "true")
           (bToC "bool" "true")
           (aToC "bool" "false")
           (sweptC "bool" "false"))
  guards: '((dijkstra-write-barrier (if (= (. h colorC) 0) 1 (. h colorC))))
  transitions:
  '((liveC
     (val liveC (or (. h aToC) (and (. h aToB) (. h bToC)))))
    (mutateWithBarrier
     (action mutateWithBarrier ()
       (if (and (= (. h phase) 0) (. h bToC) (not (. h aToC)))
         (set-h (aToC #t)
                (bToC #f)
                (colorC (guard dijkstra-write-barrier
                               (if (= (. h colorC) 0) 1 (. h colorC))
                               (. h colorC))))
         (keep-h))))
    (scanB
     (action scanB ()
       (if (and (= (. h phase) 0) (= (. h colorB) 1))
         (set-h (colorB 2)
                (colorC (if (and (. h bToC) (= (. h colorC) 0)) 1 (. h colorC))))
         (keep-h))))
    (scanC
     (action scanC ()
       (if (and (= (. h phase) 0) (= (. h colorC) 1))
         (set-h (colorC 2))
         (keep-h))))
    (finishMark
     (action finishMark ()
       (if (and (= (. h phase) 0) (!= (. h colorB) 1) (!= (. h colorC) 1))
         (set-h (phase 1))
         (keep-h))))
    (sweep
     (action sweep ()
       (if (= (. h phase) 1)
         (set-h (phase 2) (sweptC (= (. h colorC) 0)))
         (keep-h))))
    (step
     (action step () (any mutateWithBarrier scanB scanC finishMark sweep))))
  safety:
  '(and (not (and (. h sweptC) liveC))
        (or (!= (. h phase) 0)
            (not (and (= (. h colorA) 2) (. h aToC) (= (. h colorC) 0)))))
  traces:
  '((checkSafeDone
     (action checkSafeDone ()
       (all (assert (= (. h phase) 2)) (assert (not (. h sweptC))) (assert safety) (keep-h))))
    (checkUnsafeSwept
     (action checkUnsafeSwept ()
       (all (assert (. h sweptC)) (assert (not safety)) (keep-h))))
    (collectorScansBeforeMutateTest
     (run collectorScansBeforeMutateTest
       (then init scanB scanC finishMark sweep checkSafeDone)))
    (barrierPreservesLiveCTest
     (run barrierPreservesLiveCTest
       (then init mutateWithBarrier scanB scanC finishMark sweep checkSafeDone)))
    (missingBarrierSweepsLiveCTest
     (run missingBarrierSweepsLiveCTest
       (then init mutateNoBarrier scanB finishMark sweep checkUnsafeSwept))))
  countermodels: (list NoWriteBarrierCountermodel)
  limits: "Finite 3-object tri-color marking abstraction; does not model hardware weak memory ordering, compaction, or allocator fragmentation.")

;; Weakened descendant: mutator installs Black(A)->White(C) and drops B->C without shading C Grey.
(.def (NoWriteBarrierCountermodel @ TricolorWriteBarrierModel)
  identity: 'engineering.gc.tricolor-write-barrier.no-write-barrier
  dropped-guard: 'dijkstra-write-barrier
  step-action: "stepNoWriteBarrier"
  derive-from-transition: 'mutateWithBarrier
  derive-action-name: 'mutateNoBarrier
  expected-itf-predicate: "h.colorA == 2 and h.aToC == true and h.colorC == 0")
