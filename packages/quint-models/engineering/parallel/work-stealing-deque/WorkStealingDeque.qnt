// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.parallel.work-stealing-deque
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel last-item-cas step=stepNoLastItemCas max-steps=6 itf="h.doubleTaken == true and h.ownerPopped + h.thiefStolen > h.pushed"
// Limits: Finite 1-owner/1-thief Chase-Lev deque abstraction; does not model circular array resizing or ARMv8/TSO weak memory fences.
module parallel_work_stealing {
  type State = { top: int, bottom: int, pushed: int, ownerPopped: int, thiefStolen: int, doubleTaken: bool }
  var h: State
  action init = h' = { top: 0, bottom: 0, pushed: 0, ownerPopped: 0, thiefStolen: 0, doubleTaken: false }
  val dequeLen = h.bottom - h.top
  action ownerPush = if (h.pushed < 3)
    h' = h.with("bottom", h.bottom + 1).with("pushed", h.pushed + 1)
    else h' = h
  action ownerPop = if (h.bottom > h.top)
    h' = h.with("bottom", h.bottom - 1).with("ownerPopped", h.ownerPopped + 1)
    else h' = h
  action thiefSteal = if (h.top < h.bottom)
    h' = h.with("top", h.top + 1).with("thiefStolen", h.thiefStolen + 1)
    else h' = h
  action step = any { ownerPush, ownerPop, thiefSteal }
  val safety = not(h.doubleTaken) and h.ownerPopped + h.thiefStolen <= h.pushed and h.top <= h.bottom
  // Countermodel engineering.parallel.work-stealing-deque.missing-last-item-cas (dropped guard: last-item-cas)
  action raceLastItemNoCas = if (h.bottom - h.top == 1)
    h' = h.with("top", h.top + 1).with("bottom", h.bottom - 1).with("ownerPopped", h.ownerPopped + 1).with("thiefStolen", h.thiefStolen + 1).with("doubleTaken", true)
    else h' = h
  action stepNoLastItemCas = any { step, raceLastItemNoCas }
  action checkSafe = all { assert(safety), h' = h }
  action checkDouble = all { assert(h.doubleTaken), assert(not(safety)), h' = h }
  run pushPopTest = init.then(ownerPush).then(ownerPop).then(all { assert(h.ownerPopped == 1), assert(safety), h' = h })
  run pushStealTest = init.then(ownerPush).then(thiefSteal).then(ownerPop).then(all { assert(h.thiefStolen == 1), assert(h.ownerPopped == 0), assert(safety), h' = h })
  run missingCasDoubleTakeTest = init.then(ownerPush).then(raceLastItemNoCas).then(checkDouble)
}
