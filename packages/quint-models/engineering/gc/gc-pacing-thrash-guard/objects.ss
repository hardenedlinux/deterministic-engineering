;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; GC pacing soft-memory-limit headroom & GC CPU thrash-limiter model.
;;; Co-located Yuanxu unit: single source of truth alongside GcPacingThrashGuard.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export GcPacingThrashGuardModel
        ZeroHeadroomThrashCountermodel
        UnboundedGcCpuSpiralCountermodel)

(.def (GcPacingThrashGuardModel @ ThreatModel.)
  identity: 'engineering.gc.gc-pacing-thrash-guard
  family: 'engineering.gc.gc-pacing-thrash-guard
  title: "GC Pacing Soft-Memory-Limit Headroom & CPU Thrash Guard"
  subdomain: 'quint.engineering.gc
  papers:
  '(("D. Cotroneo, S. Orlando, S. Russo (IEEE SRDS 2007)"
     "Characterizing Aging Phenomena of the Java Virtual Machine — GC overhead amplification under live-set growth.")
    ("M. Knyszek (Go Runtime Design, Go 1.19+)"
     "GOMEMLIMIT Soft Memory Limit & GC CPU Limiter — preventing GC thrashing death spirals near memory ceiling.")
    ("N. Bronson, A. Aghayev, A. Charapko, T. Zhu (ACM HotOS 2021)"
     "Metastable Failures in Distributed Systems — GC pause feedback loops locking services in degraded states."))
  quint-module: "gc_pacing_thrash"
  quint-file: "GcPacingThrashGuard.qnt"
  domain-dir: "engineering/gc/gc-pacing-thrash-guard"
  quint-imports: '()
  rules:
  '((gc-thrash-headroom GC-THRASH-HEAD quint)
    (gc-thrash-cpu GC-THRASH-CPU quint))
  dependencies:
  '((GC-THRASH-HEAD source)
    (GC-THRASH-HEAD profile)
    (GC-THRASH-HEAD method)
    (GC-THRASH-CPU source)
    (GC-THRASH-CPU profile)
    (GC-THRASH-CPU method))
  invariant: "Admission headroom shedding keeps live heap strictly below soft memory limit and GC CPU pacing bounds consecutive collection cycles per mutator window."
  parameters: '()
  state:
  '((liveHeap "int" "0")
    (gcCyclesInWindow "int" "0")
    (shedRequests "int" "0")
    (completedWork "int" "0"))
  guards:
  '((gc-headroom-admission (< (. h liveHeap) 3))
    (gc-cpu-thrash-cap (< (. h gcCyclesInWindow) 1)))
  transitions:
  '((admitAlloc
      (action admitAlloc ()
        (if (and (< (. h liveHeap) 4)
                 (< (. h shedRequests) 3)
                 (< (. h completedWork) 4)
                 (guard gc-headroom-admission (< (. h liveHeap) 3)))
          (set-h (liveHeap (+ (. h liveHeap) 1)))
          (if (and (< (. h shedRequests) 3) (< (. h completedWork) 4))
            (set-h (shedRequests (+ (. h shedRequests) 1)))
            (keep-h)))))
    (runGcCycle
      (action runGcCycle ()
        (if (and (> (. h liveHeap) 0)
                 (< (. h gcCyclesInWindow) 2)
                 (guard gc-cpu-thrash-cap (< (. h gcCyclesInWindow) 1)))
          (set-h (liveHeap (- (. h liveHeap) 1))
                 (gcCyclesInWindow (+ (. h gcCyclesInWindow) 1)))
          (keep-h))))
    (finishMutatorWindow
      (action finishMutatorWindow ()
        (if (and (> (. h gcCyclesInWindow) 0) (< (. h completedWork) 4))
          (set-h (gcCyclesInWindow 0)
                 (completedWork (+ (. h completedWork) 1)))
          (keep-h))))
    (step
      (action step ()
        (any admitAlloc runGcCycle finishMutatorWindow))))
  safety:
  '(and (<= (. h liveHeap) 3)
        (<= (. h gcCyclesInWindow) 1))
  traces:
  '((checkHealthyPacing
      (action checkHealthyPacing ()
        (all (assert (<= (. h liveHeap) 3))
             (assert (<= (. h gcCyclesInWindow) 1))
             (assert (> (. h completedWork) 0))
             (assert safety)
             (keep-h))))
    (checkThrashViolation
      (action checkThrashViolation ()
        (all (assert (or (> (. h liveHeap) 3) (> (. h gcCyclesInWindow) 1)))
             (assert (not safety))
             (keep-h))))
    (steadyPacingWindowTest
      (run steadyPacingWindowTest
        (then init admitAlloc admitAlloc admitAlloc admitAlloc runGcCycle finishMutatorWindow checkHealthyPacing)))
    (zeroHeadroomRefutedTest
      (run zeroHeadroomRefutedTest
        (then init admitAlloc admitAlloc admitAlloc admitAllocUnchecked checkThrashViolation)))
    (gcCpuSpiralRefutedTest
      (run gcCpuSpiralRefutedTest
        (then init admitAlloc admitAlloc runGcCycle runGcCycleUnchecked checkThrashViolation))))
  countermodels: (list ZeroHeadroomThrashCountermodel UnboundedGcCpuSpiralCountermodel)
  limits: "Finite heap-headroom and GC-window abstraction (softMemLimit=4, safe live ceiling=3, max GC cycles per mutator window=1); models logical pacing/thrashing bounds, not object-graph pointer density or physical stop-the-world pause latency.")

(.def (ZeroHeadroomThrashCountermodel @ GcPacingThrashGuardModel)
  identity: 'engineering.gc.gc-pacing-thrash-guard.zero-headroom-thrash
  dropped-guard: 'gc-headroom-admission
  step-action: "stepZeroHeadroomThrash"
  derive-from-transition: 'admitAlloc
  derive-action-name: 'admitAllocUnchecked
  expected-itf-predicate: "h.liveHeap > 3")

(.def (UnboundedGcCpuSpiralCountermodel @ GcPacingThrashGuardModel)
  identity: 'engineering.gc.gc-pacing-thrash-guard.unbounded-gc-cpu-spiral
  dropped-guard: 'gc-cpu-thrash-cap
  step-action: "stepUnboundedGcCpuSpiral"
  derive-from-transition: 'runGcCycle
  derive-action-name: 'runGcCycleUnchecked
  expected-itf-predicate: "h.gcCyclesInWindow > 1")
