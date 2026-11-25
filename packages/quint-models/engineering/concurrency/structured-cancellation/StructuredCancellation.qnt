// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module engineering.concurrency.structured-cancellation. Do not edit by hand.
// Limits: Finite 2-child structured concurrency abstraction; does not model OS thread scheduling, panic unwinding, or non-cooperative blocking I/O.
module concurrency_structured_cancel {
  type State = { cancelRequested: bool, parentExited: bool, c1State: int, c2State: int, orphanEffect: bool }
  var h: State
  action init = h' = { cancelRequested: false, parentExited: false, c1State: 0, c2State: 0, orphanEffect: false }
  val childrenQuiescent = h.c1State != 1 and h.c1State != 2 and h.c2State != 1 and h.c2State != 2
  action spawnC1 = if (not(h.parentExited) and not(h.cancelRequested) and h.c1State == 0)
    h' = h.with("c1State", 1)
    else h' = h
  action spawnC2 = if (not(h.parentExited) and not(h.cancelRequested) and h.c2State == 0)
    h' = h.with("c2State", 1)
    else h' = h
  action requestCancel = if (not(h.parentExited) and not(h.cancelRequested))
    h' = h.with("cancelRequested", true)
    else h' = h
  action c1Drain = if (h.c1State == 1 and h.cancelRequested)
    h' = h.with("c1State", 2)
    else h' = h
  action c2Drain = if (h.c2State == 1 and h.cancelRequested)
    h' = h.with("c2State", 2)
    else h' = h
  action c1Complete = if (h.c1State == 1 or h.c1State == 2)
    h' = h.with("c1State", 3).with("orphanEffect", h.orphanEffect or h.parentExited)
    else h' = h
  action c2Complete = if (h.c2State == 1 or h.c2State == 2)
    h' = h.with("c2State", 3).with("orphanEffect", h.orphanEffect or h.parentExited)
    else h' = h
  action parentExit = if (not(h.parentExited) and h.cancelRequested and childrenQuiescent)
    h' = h.with("parentExited", true)
    else h' = h
  action step = any { spawnC1, spawnC2, requestCancel, c1Drain, c2Drain, c1Complete, c2Complete, parentExit }
  val safety = not(h.orphanEffect) and (not(h.parentExited) or childrenQuiescent)
  // Countermodel engineering.concurrency.structured-cancellation.fire-and-forget-exit (dropped guard: child-quiescence-barrier)
  action parentExitUnchecked = if (not(h.parentExited) and h.cancelRequested)
    h' = h.with("parentExited", true)
    else h' = h
  action stepFireAndForgetExit = any { step, parentExitUnchecked }
  action checkSafeExit = all { assert(h.parentExited), assert(safety), h' = h }
  action checkOrphan = all { assert(h.orphanEffect), assert(not(safety)), h' = h }
  run gracefulDrainExitTest = init.then(spawnC1).then(requestCancel).then(c1Drain).then(c1Complete).then(parentExit).then(checkSafeExit)
  run activeChildBlocksExitTest = init.then(spawnC1).then(requestCancel).then(parentExit).then(all { assert(not(h.parentExited)), assert(safety), h' = h })
  run fireAndForgetOrphanTest = init.then(spawnC1).then(requestCancel).then(parentExitUnchecked).then(c1Complete).then(checkOrphan)
}
