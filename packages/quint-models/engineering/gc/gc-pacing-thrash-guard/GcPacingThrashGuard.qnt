// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.gc.gc-pacing-thrash-guard
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel gc-headroom-admission step=stepZeroHeadroomThrash max-steps=6 itf="h.liveHeap > 3"
// @countermodel gc-cpu-thrash-cap step=stepUnboundedGcCpuSpiral max-steps=6 itf="h.gcCyclesInWindow > 1"
// Limits: Finite heap-headroom and GC-window abstraction (softMemLimit=4, safe live ceiling=3, max GC cycles per mutator window=1); models logical pacing/thrashing bounds, not object-graph pointer density or physical stop-the-world pause latency.
module gc_pacing_thrash {
  type State = { liveHeap: int, gcCyclesInWindow: int, shedRequests: int, completedWork: int }
  var h: State
  action init = h' = { liveHeap: 0, gcCyclesInWindow: 0, shedRequests: 0, completedWork: 0 }
  action admitAlloc = if ((h.liveHeap < 4 and h.shedRequests < 3 and h.completedWork < 4 and h.liveHeap < 3)) h' = h.with("liveHeap", (h.liveHeap + 1)) else if ((h.shedRequests < 3 and h.completedWork < 4)) h' = h.with("shedRequests", (h.shedRequests + 1)) else h' = h
  action runGcCycle = if ((h.liveHeap > 0 and h.gcCyclesInWindow < 2 and h.gcCyclesInWindow < 1)) h' = h.with("liveHeap", (h.liveHeap - 1)).with("gcCyclesInWindow", (h.gcCyclesInWindow + 1)) else h' = h
  action finishMutatorWindow = if ((h.gcCyclesInWindow > 0 and h.completedWork < 4)) h' = h.with("gcCyclesInWindow", 0).with("completedWork", (h.completedWork + 1)) else h' = h
  action step = any { admitAlloc, runGcCycle, finishMutatorWindow }
  val safety = (h.liveHeap <= 3 and h.gcCyclesInWindow <= 1)
  // Countermodel engineering.gc.gc-pacing-thrash-guard.zero-headroom-thrash (dropped guard: gc-headroom-admission)
  action admitAllocUnchecked = if ((h.liveHeap < 4 and h.shedRequests < 3 and h.completedWork < 4 and true)) h' = h.with("liveHeap", (h.liveHeap + 1)) else if ((h.shedRequests < 3 and h.completedWork < 4)) h' = h.with("shedRequests", (h.shedRequests + 1)) else h' = h
  action stepZeroHeadroomThrash = any { step, admitAllocUnchecked }
  // Countermodel engineering.gc.gc-pacing-thrash-guard.unbounded-gc-cpu-spiral (dropped guard: gc-cpu-thrash-cap)
  action runGcCycleUnchecked = if ((h.liveHeap > 0 and h.gcCyclesInWindow < 2 and true)) h' = h.with("liveHeap", (h.liveHeap - 1)).with("gcCyclesInWindow", (h.gcCyclesInWindow + 1)) else h' = h
  action stepUnboundedGcCpuSpiral = any { step, runGcCycleUnchecked }
  action checkHealthyPacing = all { assert(h.liveHeap <= 3), assert(h.gcCyclesInWindow <= 1), assert(h.completedWork > 0), assert(safety), h' = h }
  action checkThrashViolation = all { assert((h.liveHeap > 3 or h.gcCyclesInWindow > 1)), assert(not(safety)), h' = h }
  run steadyPacingWindowTest = init.then(admitAlloc).then(admitAlloc).then(admitAlloc).then(admitAlloc).then(runGcCycle).then(finishMutatorWindow).then(checkHealthyPacing)
  run zeroHeadroomRefutedTest = init.then(admitAlloc).then(admitAlloc).then(admitAlloc).then(admitAllocUnchecked).then(checkThrashViolation)
  run gcCpuSpiralRefutedTest = init.then(admitAlloc).then(admitAlloc).then(runGcCycle).then(runGcCycleUnchecked).then(checkThrashViolation)
}
