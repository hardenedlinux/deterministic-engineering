// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.bounded-projection-eviction
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel bounded-entry-cap step=stepUnboundedGrowth max-steps=6 itf="h.entries > 2"
// @countermodel cascade-delete-sidemap step=stepOrphanSideMap max-steps=6 itf="h.orphanedSideMap > 0"
// Limits: Finite 2-slot projection/session table abstraction; models bounded retention, idle eviction reclaimability, and cascade side-map deletion, not physical LRU hash-table internals or disk WAL compaction.
module concurrency_bounded_projection_eviction {
  type State = { entries: int, activeCount: int, orphanedSideMap: int, evictions: int }
  var h: State
  action init = h' = { entries: 0, activeCount: 0, orphanedSideMap: 0, evictions: 0 }
  action admitEntry = if ((h.entries < 3 and h.entries < 2)) h' = h.with("entries", (h.entries + 1)).with("activeCount", (h.activeCount + 1)) else h' = h
  action deactivateEntry = if (h.activeCount > 0) h' = h.with("activeCount", (h.activeCount - 1)) else h' = h
  action evictIdleEntry = if (h.entries > h.activeCount) h' = h.with("entries", (h.entries - 1)).with("evictions", (h.evictions + 1)).with("orphanedSideMap", 0) else h' = h
  action admitWithIdleEviction = if ((h.entries == 2 and h.activeCount < h.entries)) h' = h.with("activeCount", (h.activeCount + 1)).with("evictions", (h.evictions + 1)) else h' = h
  action step = any { admitEntry, deactivateEntry, evictIdleEntry, admitWithIdleEviction }
  val safety = (h.entries <= 2 and h.activeCount <= h.entries and h.orphanedSideMap == 0)
  // Countermodel engineering.concurrency.bounded-projection-eviction.unbounded-growth (dropped guard: bounded-entry-cap)
  action admitEntryUnbounded = if ((h.entries < 3 and true)) h' = h.with("entries", (h.entries + 1)).with("activeCount", (h.activeCount + 1)) else h' = h
  action stepUnboundedGrowth = any { step, admitEntryUnbounded }
  // Countermodel engineering.concurrency.bounded-projection-eviction.orphan-sidemap (dropped guard: cascade-delete-sidemap)
  action evictIdleEntryOrphan = if (h.entries > h.activeCount) h' = h.with("entries", (h.entries - 1)).with("evictions", (h.evictions + 1)).with("orphanedSideMap", (h.orphanedSideMap + 1)) else h' = h
  action stepOrphanSideMap = any { step, evictIdleEntryOrphan }
  action checkBoundedReclaimed = all { assert(h.entries <= 2), assert(h.evictions > 0), assert(h.orphanedSideMap == 0), assert(safety), h' = h }
  action checkEvictionViolation = all { assert((h.entries > 2 or h.orphanedSideMap > 0)), assert(not(safety)), h' = h }
  run evictionReclaimsFullTableTest = init.then(admitEntry).then(admitEntry).then(deactivateEntry).then(admitWithIdleEviction).then(deactivateEntry).then(evictIdleEntry).then(checkBoundedReclaimed)
  run unboundedGrowthRefutedTest = init.then(admitEntry).then(admitEntry).then(admitEntryUnbounded).then(checkEvictionViolation)
  run orphanSideMapRefutedTest = init.then(admitEntry).then(deactivateEntry).then(evictIdleEntryOrphan).then(checkEvictionViolation)
}
