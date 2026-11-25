// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module engineering.parallel.epoch-reclamation. Do not edit by hand.
// Limits: Finite 2-worker single-object EBR abstraction; does not model hardware memory fences (Acquire/Release/SeqCst) or allocator reuse.
module parallel_epoch_reclamation {
  type State = { globalEpoch: int, w1Pinned: bool, w1Epoch: int, w2Pinned: bool, w2Epoch: int, retired: bool, retiredEpoch: int, freed: bool, useAfterFree: bool }
  var h: State
  action init = h' = { globalEpoch: 1, w1Pinned: false, w1Epoch: 0, w2Pinned: false, w2Epoch: 0, retired: false, retiredEpoch: 0, freed: false, useAfterFree: false }
  val quiescent = not(h.w1Pinned and h.w1Epoch <= h.retiredEpoch) and not(h.w2Pinned and h.w2Epoch <= h.retiredEpoch)
  action w1Pin = if (not(h.w1Pinned))
    h' = h.with("w1Pinned", true).with("w1Epoch", h.globalEpoch)
    else h' = h
  action w1Read = if (h.w1Pinned)
    h' = h.with("useAfterFree", h.useAfterFree or (h.freed and h.w1Epoch <= h.retiredEpoch))
    else h' = h
  action w1Unpin = if (h.w1Pinned)
    h' = h.with("w1Pinned", false)
    else h' = h
  action w2Pin = if (not(h.w2Pinned))
    h' = h.with("w2Pinned", true).with("w2Epoch", h.globalEpoch)
    else h' = h
  action w2Read = if (h.w2Pinned)
    h' = h.with("useAfterFree", h.useAfterFree or (h.freed and h.w2Epoch <= h.retiredEpoch))
    else h' = h
  action w2Unpin = if (h.w2Pinned)
    h' = h.with("w2Pinned", false)
    else h' = h
  action retireObject = if (not(h.retired))
    h' = h.with("retired", true).with("retiredEpoch", h.globalEpoch)
    else h' = h
  action advanceEpoch = if (h.globalEpoch < 3)
    h' = h.with("globalEpoch", h.globalEpoch + 1)
    else h' = h
  action reclaim = if (h.retired and not(h.freed) and h.globalEpoch > h.retiredEpoch and quiescent)
    h' = h.with("freed", true)
    else h' = h
  action step = any { w1Pin, w1Read, w1Unpin, w2Pin, w2Read, w2Unpin, retireObject, advanceEpoch, reclaim }
  val safety = not(h.useAfterFree) and (not(h.freed) or quiescent)
  // Countermodel engineering.parallel.epoch-reclamation.premature-reclaim (dropped guard: grace-period-quiescence)
  action reclaimPremature = if (h.retired and not(h.freed) and h.globalEpoch > h.retiredEpoch)
    h' = h.with("freed", true)
    else h' = h
  action stepPrematureReclaim = any { step, reclaimPremature }
  action checkSafeFreed = all { assert(h.freed), assert(safety), h' = h }
  action checkNotFreed = all { assert(not(h.freed)), assert(safety), h' = h }
  action checkUaf = all { assert(h.useAfterFree), assert(not(safety)), h' = h }
  run safeReclaimAfterUnpinTest = init.then(w1Pin).then(retireObject).then(advanceEpoch).then(w1Read).then(w1Unpin).then(reclaim).then(checkSafeFreed)
  run pinnedWorkerBlocksReclaimTest = init.then(w1Pin).then(retireObject).then(advanceEpoch).then(reclaim).then(checkNotFreed)
  run prematureReclaimUafTest = init.then(w1Pin).then(retireObject).then(advanceEpoch).then(reclaimPremature).then(w1Read).then(checkUaf)
}
