// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.priority-isolated-bounded-mailbox
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel isolate-priority-ingress step=stepSharedChannelPriorityInversion max-steps=6 itf="h.hiStarved == true"
// @countermodel bound-ingress-capacity step=stepUnboundedQueueGrowth max-steps=6 itf="h.loQueue > 2"
// @countermodel compact-cancelled-zombies step=stepZombieSlotLeak max-steps=6 itf="h.zombieLo > 0"
// Limits: Finite 2-slot per-tier priority mailbox and 1-slot watch channel abstraction; verifies priority isolation under overload, bounded shedding, cancelled-job compaction, and monotonic watch progress, not OS thread scheduling.
module concurrency_priority_isolated_bounded_mailbox {
  type State = { hiQueue: int, loQueue: int, zombieLo: int, hiBurst: int, hiStarved: bool, progressSlots: int, producedWater: int, observedWater: int, shedLoCount: int }
  var h: State
  action init = h' = { hiQueue: 0, loQueue: 0, zombieLo: 0, hiBurst: 0, hiStarved: false, progressSlots: 0, producedWater: 0, observedWater: 0, shedLoCount: 0 }
  action submitHi = if (h.hiQueue < 2) if ((false and h.loQueue >= 2)) h' = h.with("hiStarved", true) else h' = h.with("hiQueue", (h.hiQueue + 1)) else h' = h
  action submitLo = if (h.loQueue < 2) h' = h.with("loQueue", (h.loQueue + 1)) else if (not(true)) h' = h.with("loQueue", (h.loQueue + 1)) else h' = h.with("shedLoCount", (h.shedLoCount + 1))
  action cancelLo = if (h.loQueue > 0) if (true) h' = h.with("loQueue", (h.loQueue - 1)) else h' = h.with("zombieLo", (h.zombieLo + 1)) else h' = h
  action drainOne = if ((h.loQueue > 0 and (h.hiQueue == 0 or h.hiBurst >= 2))) h' = h.with("loQueue", (h.loQueue - 1)).with("hiBurst", 0) else if (h.hiQueue > 0) h' = h.with("hiQueue", (h.hiQueue - 1)).with("hiBurst", (h.hiBurst + 1)) else h' = h
  action publishProgress = if (h.producedWater < 3) h' = h.with("producedWater", (h.producedWater + 1)).with("progressSlots", 1) else h' = h
  action pollProgress = if (h.progressSlots > 0) h' = h.with("observedWater", h.producedWater).with("progressSlots", 0) else h' = h
  action step = any { submitHi, submitLo, cancelLo, drainOne, publishProgress, pollProgress }
  val safety = (h.hiQueue <= 2 and h.loQueue <= 2 and not(h.hiStarved) and h.zombieLo == 0 and h.progressSlots <= 1 and h.observedWater <= h.producedWater)
  // Countermodel engineering.concurrency.priority-isolated-bounded-mailbox.shared-channel-priority-inversion (dropped guard: isolate-priority-ingress)
  action submitHiSharedChannel = if (h.hiQueue < 2) if ((true and h.loQueue >= 2)) h' = h.with("hiStarved", true) else h' = h.with("hiQueue", (h.hiQueue + 1)) else h' = h
  action stepSharedChannelPriorityInversion = any { step, submitHiSharedChannel }
  // Countermodel engineering.concurrency.priority-isolated-bounded-mailbox.unbounded-queue-growth (dropped guard: bound-ingress-capacity)
  action submitLoUnbounded = if (h.loQueue < 2) h' = h.with("loQueue", (h.loQueue + 1)) else if (not(false)) h' = h.with("loQueue", (h.loQueue + 1)) else h' = h.with("shedLoCount", (h.shedLoCount + 1))
  action stepUnboundedQueueGrowth = any { step, submitLoUnbounded }
  // Countermodel engineering.concurrency.priority-isolated-bounded-mailbox.zombie-slot-leak (dropped guard: compact-cancelled-zombies)
  action cancelLoUncompacted = if (h.loQueue > 0) if (false) h' = h.with("loQueue", (h.loQueue - 1)) else h' = h.with("zombieLo", (h.zombieLo + 1)) else h' = h
  action stepZombieSlotLeak = any { step, cancelLoUncompacted }
  action checkMailboxSafe = all { assert(h.shedLoCount > 0), assert(h.hiQueue == 0), assert(h.zombieLo == 0), assert(h.progressSlots == 0), assert(h.observedWater == h.producedWater), assert(safety), h' = h }
  action checkMailboxViolated = all { assert((h.hiStarved or h.loQueue > 2 or h.zombieLo > 0)), assert(not(safety)), h' = h }
  run priorityIsolationAndWatchTest = init.then(submitLo).then(submitLo).then(submitLo).then(submitHi).then(publishProgress).then(publishProgress).then(pollProgress).then(drainOne).then(drainOne).then(drainOne).then(checkMailboxSafe)
  run sharedChannelPriorityInversionRefutedTest = init.then(submitLo).then(submitLo).then(submitHiSharedChannel).then(checkMailboxViolated)
  run unboundedQueueGrowthRefutedTest = init.then(submitLo).then(submitLo).then(submitLoUnbounded).then(checkMailboxViolated)
  run zombieSlotLeakRefutedTest = init.then(submitLo).then(cancelLoUncompacted).then(checkMailboxViolated)
}
