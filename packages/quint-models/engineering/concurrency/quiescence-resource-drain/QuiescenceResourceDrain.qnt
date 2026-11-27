// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.quiescence-resource-drain
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel error-path-release step=stepErrorPathLeak max-steps=6 itf="h.heldHandles > h.activeWork"
// @countermodel cancel-drain-release step=stepCancelDrainLeak max-steps=6 itf="h.heldHandles > h.activeWork"
// Limits: Finite 2-slot, 4-cycle resource lifecycle abstraction; models logical handle/task conservation across normal, error, and cancel paths, not OS kernel FD tables or allocator fragmentation.
module concurrency_quiescence_drain {
  type State = { activeWork: int, heldHandles: int, pendingError: bool, pendingCancel: bool, cyclesCompleted: int }
  var h: State
  action init = h' = { activeWork: 0, heldHandles: 0, pendingError: false, pendingCancel: false, cyclesCompleted: 0 }
  action acquireWork = if ((h.activeWork < 2 and h.heldHandles < 2 and h.cyclesCompleted < 4)) h' = h.with("activeWork", (h.activeWork + 1)).with("heldHandles", (h.heldHandles + 1)) else h' = h
  action completeNormal = if ((h.activeWork > 0 and not(h.pendingError) and not(h.pendingCancel))) h' = h.with("activeWork", (h.activeWork - 1)).with("heldHandles", (h.heldHandles - 1)).with("cyclesCompleted", (h.cyclesCompleted + 1)) else h' = h
  action injectError = if ((h.activeWork > 0 and not(h.pendingError) and not(h.pendingCancel))) h' = h.with("pendingError", true) else h' = h
  action finishWithError = if ((h.activeWork > 0 and h.pendingError)) h' = h.with("activeWork", (h.activeWork - 1)).with("pendingError", false).with("heldHandles", (h.heldHandles - 1)).with("cyclesCompleted", (h.cyclesCompleted + 1)) else h' = h
  action injectCancel = if ((h.activeWork > 0 and not(h.pendingCancel) and not(h.pendingError))) h' = h.with("pendingCancel", true) else h' = h
  action finishWithCancel = if ((h.activeWork > 0 and h.pendingCancel)) h' = h.with("activeWork", (h.activeWork - 1)).with("pendingCancel", false).with("heldHandles", (h.heldHandles - 1)).with("cyclesCompleted", (h.cyclesCompleted + 1)) else h' = h
  action step = any { acquireWork, completeNormal, injectError, finishWithError, injectCancel, finishWithCancel }
  val safety = (h.heldHandles == h.activeWork and h.heldHandles <= 2 and (h.activeWork > 0 or h.heldHandles == 0))
  // Countermodel engineering.concurrency.quiescence-resource-drain.error-path-leak (dropped guard: error-path-release)
  action finishWithErrorLeaky = if ((h.activeWork > 0 and h.pendingError)) h' = h.with("activeWork", (h.activeWork - 1)).with("pendingError", false).with("heldHandles", h.heldHandles).with("cyclesCompleted", (h.cyclesCompleted + 1)) else h' = h
  action stepErrorPathLeak = any { step, finishWithErrorLeaky }
  // Countermodel engineering.concurrency.quiescence-resource-drain.cancel-drain-leak (dropped guard: cancel-drain-release)
  action finishWithCancelLeaky = if ((h.activeWork > 0 and h.pendingCancel)) h' = h.with("activeWork", (h.activeWork - 1)).with("pendingCancel", false).with("heldHandles", h.heldHandles).with("cyclesCompleted", (h.cyclesCompleted + 1)) else h' = h
  action stepCancelDrainLeak = any { step, finishWithCancelLeaky }
  action checkQuiescent = all { assert(h.activeWork == 0), assert(h.heldHandles == 0), assert(safety), h' = h }
  action checkLeaked = all { assert(h.heldHandles > h.activeWork), assert(not(safety)), h' = h }
  run cleanCyclicDrainTest = init.then(acquireWork).then(completeNormal).then(acquireWork).then(injectError).then(finishWithError).then(acquireWork).then(injectCancel).then(finishWithCancel).then(checkQuiescent)
  run errorLeakRefutedTest = init.then(acquireWork).then(injectError).then(finishWithErrorLeaky).then(checkLeaked)
  run cancelLeakRefutedTest = init.then(acquireWork).then(injectCancel).then(finishWithCancelLeaky).then(checkLeaked)
}
