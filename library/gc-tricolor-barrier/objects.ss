;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Concurrent tri-color GC marking model with Dijkstra insertion write barrier
;;; and weakened countermodel omitting the write barrier (sweeping live object C).
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
           (sweptC "bool" "false")
           (unsafe "bool" "false"))
  guards: '((dijkstra-write-barrier "colorC shaded Grey on Black->White pointer store"))
  transitions:
  '((liveC "val liveC = h.aToC or (h.aToB and h.bToC)")
    (mutateWithBarrier "action mutateWithBarrier = if (h.phase == 0 and h.bToC and not(h.aToC))\n    h' = h.with(\"aToC\", true).with(\"bToC\", false).with(\"colorC\", if (h.colorC == 0) 1 else h.colorC)\n    else h' = h")
    (scanB "action scanB = if (h.phase == 0 and h.colorB == 1)\n    h' = h.with(\"colorB\", 2).with(\"colorC\", if (h.bToC and h.colorC == 0) 1 else h.colorC)\n    else h' = h")
    (scanC "action scanC = if (h.phase == 0 and h.colorC == 1)\n    h' = h.with(\"colorC\", 2)\n    else h' = h")
    (finishMark "action finishMark = if (h.phase == 0 and h.colorB != 1 and h.colorC != 1)\n    h' = h.with(\"phase\", 1)\n    else h' = h")
    (sweep "action sweep = if (h.phase == 1)\n    h' = h.with(\"phase\", 2).with(\"sweptC\", h.colorC == 0).with(\"unsafe\", h.unsafe or (h.colorC == 0 and liveC))\n    else h' = h")
    (step "action step = any { mutateWithBarrier, scanB, scanC, finishMark, sweep }"))
  safety: "not(h.unsafe) and not(h.sweptC and liveC) and (h.phase != 0 or not(h.colorA == 2 and h.aToC and h.colorC == 0))"
  traces:
  '((checkSafeDone "action checkSafeDone = all { assert(h.phase == 2), assert(not(h.sweptC)), assert(safety), h' = h }")
    (checkUnsafeSwept "action checkUnsafeSwept = all { assert(h.sweptC), assert(h.unsafe), assert(not(safety)), h' = h }")
    (collectorScansBeforeMutateTest "run collectorScansBeforeMutateTest = init.then(scanB).then(scanC).then(finishMark).then(sweep).then(checkSafeDone)")
    (barrierPreservesLiveCTest "run barrierPreservesLiveCTest = init.then(mutateWithBarrier).then(scanB).then(scanC).then(finishMark).then(sweep).then(checkSafeDone)")
    (missingBarrierSweepsLiveCTest "run missingBarrierSweepsLiveCTest = init.then(mutateNoBarrier).then(scanB).then(finishMark).then(sweep).then(checkUnsafeSwept)"))
  countermodels: (list NoWriteBarrierCountermodel)
  limits: "Finite 3-object tri-color marking abstraction; does not model hardware weak memory ordering, compaction, or allocator fragmentation.")

;; Weakened descendant: mutator installs Black(A)->White(C) and drops B->C without shading C Grey.
(.def (NoWriteBarrierCountermodel @ TricolorWriteBarrierModel)
  identity: 'engineering.gc.tricolor-write-barrier.no-write-barrier
  dropped-guard: 'dijkstra-write-barrier
  step-action: "stepNoWriteBarrier"
  counter-action: "action mutateNoBarrier = if (h.phase == 0 and h.bToC and not(h.aToC))\n    h' = h.with(\"aToC\", true).with(\"bToC\", false)\n    else h' = h\n  action stepNoWriteBarrier = any { step, mutateNoBarrier }"
  expected-itf-predicate: "h.colorA == 2 and h.aToC == true and h.colorC == 0")
