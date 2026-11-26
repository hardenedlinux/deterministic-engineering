// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.parallel.work-stealing-deque
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel last-item-cas step=stepNoLastItemCas max-steps=6 itf="h.ownerPopped + h.thiefStolen > h.pushed"
// Limits: Finite 1-owner/1-thief Chase-Lev deque abstraction; does not model circular array resizing or ARMv8/TSO weak memory fences.
module parallel_work_stealing {
  type State = { top: int, bottom: int, pushed: int, ownerPopped: int, thiefStolen: int, thiefReadTop: int }
  var h: State
  action init = h' = { top: 0, bottom: 0, pushed: 0, ownerPopped: 0, thiefStolen: 0, thiefReadTop: -1 }
  val dequeLen = (h.bottom - h.top)
  action ownerPush = if (h.pushed < 3) h' = h.with("bottom", (h.bottom + 1)).with("pushed", (h.pushed + 1)) else h' = h
  action ownerPop = if (h.bottom > h.top) h' = h.with("bottom", (h.bottom - 1)).with("ownerPopped", (h.ownerPopped + 1)) else h' = h
  action thiefStart = if ((h.thiefReadTop < 0 and h.top < h.bottom)) h' = h.with("thiefReadTop", h.top) else h' = h
  action thiefCommitSteal = if (h.thiefReadTop >= 0) if ((h.top == h.thiefReadTop and h.top < h.bottom)) h' = h.with("top", (h.top + 1)).with("thiefStolen", (h.thiefStolen + 1)).with("thiefReadTop", (0 - 1)) else h' = h.with("thiefReadTop", (0 - 1)) else h' = h
  action step = any { ownerPush, ownerPop, thiefStart, thiefCommitSteal }
  val safety = ((h.ownerPopped + h.thiefStolen) <= h.pushed and h.top <= h.bottom)
  // Countermodel engineering.parallel.work-stealing-deque.missing-last-item-cas (dropped guard: last-item-cas)
  action thiefCommitNoCas = if (h.thiefReadTop >= 0) if (true) h' = h.with("top", (h.top + 1)).with("thiefStolen", (h.thiefStolen + 1)).with("thiefReadTop", (0 - 1)) else h' = h.with("thiefReadTop", (0 - 1)) else h' = h
  action stepNoLastItemCas = any { step, thiefCommitNoCas }
  action checkSafe = all { assert(safety), h' = h }
  action checkDouble = all { assert((h.ownerPopped + h.thiefStolen) > h.pushed), assert(not(safety)), h' = h }
  run pushPopTest = init.then(ownerPush).then(ownerPop).then(all { assert(h.ownerPopped == 1), assert(safety), h' = h })
  run pushStealTest = init.then(ownerPush).then(thiefStart).then(thiefCommitSteal).then(ownerPop).then(all { assert(h.thiefStolen == 1), assert(h.ownerPopped == 0), assert(safety), h' = h })
  run lastItemCasArbitrationTest = init.then(ownerPush).then(thiefStart).then(ownerPop).then(thiefCommitSteal).then(all { assert(h.ownerPopped == 1), assert(h.thiefStolen == 0), assert(safety), h' = h })
  run missingCasDoubleTakeTest = init.then(ownerPush).then(thiefStart).then(ownerPop).then(thiefCommitNoCas).then(checkDouble)
}
