// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.fenced-coalescing-mailbox
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel coalesce-single-slot step=stepMailboxFlood max-steps=6 itf="h.pendingSlots > 1"
// @countermodel epoch-fence-commit step=stepStaleOverwrite max-steps=6 itf="h.appliedEpoch < h.maxAppliedEpoch"
// Limits: Finite 4-epoch single-slot coalescing mailbox abstraction; does not model OS timer jitter, multi-lane priority preemption, or payload serialization sizes.
module concurrency_fenced_mailbox {
  type State = { activeEpoch: int, pendingSlots: int, inflight: int, jobEpoch: int, appliedEpoch: int, maxAppliedEpoch: int }
  var h: State
  action init = h' = { activeEpoch: 0, pendingSlots: 0, inflight: 0, jobEpoch: 0, appliedEpoch: 0, maxAppliedEpoch: 0 }
  action triggerRequest = if (h.activeEpoch < 4) h' = h.with("activeEpoch", (h.activeEpoch + 1)).with("pendingSlots", if (h.pendingSlots < 1) (h.pendingSlots + 1) else 1) else h' = h
  action dispatchWorker = if ((h.pendingSlots > 0 and h.inflight < 2)) h' = h.with("pendingSlots", (h.pendingSlots - 1)).with("inflight", (h.inflight + 1)).with("jobEpoch", h.activeEpoch) else h' = h
  action applyDirectEpoch = if ((h.activeEpoch > h.maxAppliedEpoch and h.activeEpoch <= 4)) h' = h.with("appliedEpoch", h.activeEpoch).with("maxAppliedEpoch", h.activeEpoch) else h' = h
  action completeWorker = if (h.inflight > 0) if (h.jobEpoch >= h.activeEpoch) h' = h.with("inflight", (h.inflight - 1)).with("appliedEpoch", h.jobEpoch).with("maxAppliedEpoch", if (h.jobEpoch > h.maxAppliedEpoch) h.jobEpoch else h.maxAppliedEpoch) else h' = h.with("inflight", (h.inflight - 1)) else h' = h
  action step = any { triggerRequest, dispatchWorker, applyDirectEpoch, completeWorker }
  val safety = (h.pendingSlots <= 1 and h.inflight <= 2 and h.appliedEpoch == h.maxAppliedEpoch and h.maxAppliedEpoch <= h.activeEpoch)
  // Countermodel engineering.concurrency.fenced-coalescing-mailbox.mailbox-flood (dropped guard: coalesce-single-slot)
  action triggerRequestFlood = if (h.activeEpoch < 4) h' = h.with("activeEpoch", (h.activeEpoch + 1)).with("pendingSlots", (h.pendingSlots + 1)) else h' = h
  action stepMailboxFlood = any { step, triggerRequestFlood }
  // Countermodel engineering.concurrency.fenced-coalescing-mailbox.stale-overwrite (dropped guard: epoch-fence-commit)
  action completeWorkerUnfenced = if (h.inflight > 0) if (true) h' = h.with("inflight", (h.inflight - 1)).with("appliedEpoch", h.jobEpoch).with("maxAppliedEpoch", if (h.jobEpoch > h.maxAppliedEpoch) h.jobEpoch else h.maxAppliedEpoch) else h' = h.with("inflight", (h.inflight - 1)) else h' = h
  action stepStaleOverwrite = any { step, completeWorkerUnfenced }
  run coalescedStaleDropTest = init.then(triggerRequest).then(dispatchWorker).then(triggerRequest).then(applyDirectEpoch).then(completeWorker).then(all { assert(h.appliedEpoch == 2), assert(h.inflight == 0), assert(safety), h' = h })
  run mailboxFloodViolatesSafetyTest = init.then(triggerRequestFlood).then(triggerRequestFlood).then(all { assert(h.pendingSlots > 1), assert(not(safety)), h' = h })
  run staleOverwriteViolatesSafetyTest = init.then(triggerRequest).then(dispatchWorker).then(triggerRequest).then(applyDirectEpoch).then(completeWorkerUnfenced).then(all { assert(h.appliedEpoch < h.maxAppliedEpoch), assert(not(safety)), h' = h })
}
