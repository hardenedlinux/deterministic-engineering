// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.gc.tricolor-write-barrier
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel dijkstra-write-barrier step=stepNoWriteBarrier max-steps=6 itf="h.colorA == 2 and h.aToC == true and h.colorC == 0"
// Limits: Finite 3-object tri-color marking abstraction; does not model hardware weak memory ordering, compaction, or allocator fragmentation.
module gc_tricolor_barrier {
  type State = { phase: int, colorA: int, colorB: int, colorC: int, aToB: bool, bToC: bool, aToC: bool, sweptC: bool }
  var h: State
  action init = h' = { phase: 0, colorA: 2, colorB: 1, colorC: 0, aToB: true, bToC: true, aToC: false, sweptC: false }
  val liveC = (h.aToC or (h.aToB and h.bToC))
  action mutateWithBarrier = if ((h.phase == 0 and h.bToC and not(h.aToC))) h' = h.with("aToC", true).with("bToC", false).with("colorC", if (h.colorC == 0) 1 else h.colorC) else h' = h
  action scanB = if ((h.phase == 0 and h.colorB == 1)) h' = h.with("colorB", 2).with("colorC", if ((h.bToC and h.colorC == 0)) 1 else h.colorC) else h' = h
  action scanC = if ((h.phase == 0 and h.colorC == 1)) h' = h.with("colorC", 2) else h' = h
  action finishMark = if ((h.phase == 0 and h.colorB != 1 and h.colorC != 1)) h' = h.with("phase", 1) else h' = h
  action sweep = if (h.phase == 1) h' = h.with("phase", 2).with("sweptC", h.colorC == 0) else h' = h
  action step = any { mutateWithBarrier, scanB, scanC, finishMark, sweep }
  val safety = (not((h.sweptC and liveC)) and (h.phase != 0 or not((h.colorA == 2 and h.aToC and h.colorC == 0))))
  // Countermodel engineering.gc.tricolor-write-barrier.no-write-barrier (dropped guard: dijkstra-write-barrier)
  action mutateNoBarrier = if ((h.phase == 0 and h.bToC and not(h.aToC))) h' = h.with("aToC", true).with("bToC", false).with("colorC", h.colorC) else h' = h
  action stepNoWriteBarrier = any { step, mutateNoBarrier }
  action checkSafeDone = all { assert(h.phase == 2), assert(not(h.sweptC)), assert(safety), h' = h }
  action checkUnsafeSwept = all { assert(h.sweptC), assert(not(safety)), h' = h }
  run collectorScansBeforeMutateTest = init.then(scanB).then(scanC).then(finishMark).then(sweep).then(checkSafeDone)
  run barrierPreservesLiveCTest = init.then(mutateWithBarrier).then(scanB).then(scanC).then(finishMark).then(sweep).then(checkSafeDone)
  run missingBarrierSweepsLiveCTest = init.then(mutateNoBarrier).then(scanB).then(finishMark).then(sweep).then(checkUnsafeSwept)
}
