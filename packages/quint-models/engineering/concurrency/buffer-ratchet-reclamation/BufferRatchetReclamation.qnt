// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.buffer-ratchet-reclamation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel pool-max-retain-cap step=stepSpikePoolPoison max-steps=6 itf="h.pooledBytes > 1"
// @countermodel pool-slot-cap step=stepPoolSlotOverflow max-steps=6 itf="h.pooledSlots > 1"
// Limits: Finite buffer-pool abstraction (normal=1 unit, spike=4 units, pool slot ceiling=1, retain ceiling=1); models logical pool watermark retention, not OS allocator page fragmentation or GC compaction pauses.
module concurrency_buffer_ratchet {
  type State = { activeSmall: int, activeSpike: int, pooledSlots: int, pooledBytes: int }
  var h: State
  action init = h' = { activeSmall: 0, activeSpike: 0, pooledSlots: 0, pooledBytes: 0 }
  action acquireSmallFresh = if (h.activeSmall < 2) h' = h.with("activeSmall", (h.activeSmall + 1)) else h' = h
  action acquireSmallFromPool = if ((h.activeSmall < 2 and h.pooledSlots > 0)) h' = h.with("activeSmall", (h.activeSmall + 1)).with("pooledSlots", (h.pooledSlots - 1)).with("pooledBytes", (h.pooledBytes - 1)) else h' = h
  action releaseSmall = if ((h.activeSmall > 0 and h.pooledSlots < 1)) h' = h.with("activeSmall", (h.activeSmall - 1)).with("pooledSlots", (h.pooledSlots + 1)).with("pooledBytes", (h.pooledBytes + 1)) else if (h.activeSmall > 0) h' = h.with("activeSmall", (h.activeSmall - 1)) else h' = h
  action acquireSpike = if (h.activeSpike == 0) h' = h.with("activeSpike", 1) else h' = h
  action releaseSpike = if ((h.activeSpike > 0 and 4 <= 1)) h' = h.with("activeSpike", (h.activeSpike - 1)).with("pooledSlots", (h.pooledSlots + 1)).with("pooledBytes", (h.pooledBytes + 4)) else if (h.activeSpike > 0) h' = h.with("activeSpike", (h.activeSpike - 1)) else h' = h
  action step = any { acquireSmallFresh, acquireSmallFromPool, releaseSmall, acquireSpike, releaseSpike }
  val safety = (h.pooledSlots <= 1 and h.pooledBytes <= 1 and h.pooledBytes == h.pooledSlots and ((h.activeSmall + h.activeSpike) > 0 or h.pooledBytes <= 1))
  // Countermodel engineering.concurrency.buffer-ratchet-reclamation.spike-pool-poison (dropped guard: pool-max-retain-cap)
  action releaseSpikeUnbounded = if ((h.activeSpike > 0 and true)) h' = h.with("activeSpike", (h.activeSpike - 1)).with("pooledSlots", (h.pooledSlots + 1)).with("pooledBytes", (h.pooledBytes + 4)) else if (h.activeSpike > 0) h' = h.with("activeSpike", (h.activeSpike - 1)) else h' = h
  action stepSpikePoolPoison = any { step, releaseSpikeUnbounded }
  // Countermodel engineering.concurrency.buffer-ratchet-reclamation.pool-slot-overflow (dropped guard: pool-slot-cap)
  action releaseSmallUnbounded = if ((h.activeSmall > 0 and true)) h' = h.with("activeSmall", (h.activeSmall - 1)).with("pooledSlots", (h.pooledSlots + 1)).with("pooledBytes", (h.pooledBytes + 1)) else if (h.activeSmall > 0) h' = h.with("activeSmall", (h.activeSmall - 1)) else h' = h
  action stepPoolSlotOverflow = any { step, releaseSmallUnbounded }
  action checkBoundedQuiescent = all { assert(h.activeSmall == 0), assert(h.activeSpike == 0), assert(h.pooledBytes <= 1), assert(safety), h' = h }
  action checkRatchetViolation = all { assert(h.pooledBytes > 1), assert(not(safety)), h' = h }
  run spikeDiscardedCleanlyTest = init.then(acquireSmallFresh).then(releaseSmall).then(acquireSmallFromPool).then(releaseSmall).then(acquireSpike).then(releaseSpike).then(checkBoundedQuiescent)
  run spikePoisonRefutedTest = init.then(acquireSpike).then(releaseSpikeUnbounded).then(checkRatchetViolation)
  run slotOverflowRefutedTest = init.then(acquireSmallFresh).then(releaseSmall).then(acquireSmallFresh).then(releaseSmallUnbounded).then(checkRatchetViolation)
}
