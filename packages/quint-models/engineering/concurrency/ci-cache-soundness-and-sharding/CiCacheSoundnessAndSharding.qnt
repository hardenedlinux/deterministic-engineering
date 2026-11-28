// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.ci-cache-soundness-and-sharding
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel bind-engine-and-source-digest step=stepUnderSpecifiedKey max-steps=6 itf="h.falseHitCount > 0"
// @countermodel disjoint-shard-namespaces step=stepCrossShardWriteConflict max-steps=6 itf="h.writeConflictCount > 0"
// @countermodel active-set-gc-on-save step=stepUnboundedCacheRatchet max-steps=6 itf="h.retainedEntries > h.maxCacheEntries"
// Limits: Finite 3-epoch source/engine and 4-entry cache quota abstraction; verifies hermetic ActionKey invalidation, disjoint parallel shard namespaces, and active-set GC quota bounding, not network CDN transport latency or compression ratios.
module concurrency_ci_cache_soundness_and_sharding {
  type State = { engineEpoch: int, sourceEpoch: int, cachedEngineEpoch: int, cachedSourceEpoch: int, shardNamespacesDisjoint: bool, maxCacheEntries: int, retainedEntries: int, falseHitCount: int, writeConflictCount: int, cacheHits: int, rebuilds: int }
  var h: State
  action init = h' = { engineEpoch: 1, sourceEpoch: 1, cachedEngineEpoch: 0, cachedSourceEpoch: 0, shardNamespacesDisjoint: true, maxCacheEntries: 4, retainedEntries: 0, falseHitCount: 0, writeConflictCount: 0, cacheHits: 0, rebuilds: 0 }
  action bumpSource = if (h.sourceEpoch < 3) h' = h.with("sourceEpoch", (h.sourceEpoch + 1)) else h' = h
  action bumpEngine = if (h.engineEpoch < 3) h' = h.with("engineEpoch", (h.engineEpoch + 1)) else h' = h
  action lookupOrRebuild = if (true) if ((h.cachedEngineEpoch == h.engineEpoch and h.cachedSourceEpoch == h.sourceEpoch)) h' = h.with("cacheHits", (h.cacheHits + 1)) else h' = h.with("cachedEngineEpoch", h.engineEpoch).with("cachedSourceEpoch", h.sourceEpoch).with("rebuilds", (h.rebuilds + 1)).with("retainedEntries", if (h.retainedEntries < h.maxCacheEntries) (h.retainedEntries + 1) else h.maxCacheEntries) else if ((h.cachedSourceEpoch == h.sourceEpoch and not(h.cachedEngineEpoch == h.engineEpoch))) h' = h.with("falseHitCount", (h.falseHitCount + 1)).with("cacheHits", (h.cacheHits + 1)) else h' = h.with("cachedEngineEpoch", h.engineEpoch).with("cachedSourceEpoch", h.sourceEpoch).with("rebuilds", (h.rebuilds + 1))
  action saveShardParallel = if (true) h' = h.with("shardNamespacesDisjoint", true).with("retainedEntries", if (h.retainedEntries < h.maxCacheEntries) (h.retainedEntries + 1) else h.maxCacheEntries) else h' = h.with("shardNamespacesDisjoint", false).with("writeConflictCount", (h.writeConflictCount + 1))
  action compactAndSaveCache = if (true) h' = h.with("retainedEntries", if (h.retainedEntries > 2) 2 else h.retainedEntries) else h' = h.with("retainedEntries", (h.maxCacheEntries + 3))
  action step = any { bumpSource, bumpEngine, lookupOrRebuild, saveShardParallel, compactAndSaveCache }
  val safety = (h.falseHitCount == 0 and h.writeConflictCount == 0 and h.shardNamespacesDisjoint and h.retainedEntries <= h.maxCacheEntries and h.retainedEntries >= 0)
  // Countermodel engineering.concurrency.ci-cache-soundness-and-sharding.under-specified-key (dropped guard: bind-engine-and-source-digest)
  action lookupCacheUnderSpecified = if (false) if ((h.cachedEngineEpoch == h.engineEpoch and h.cachedSourceEpoch == h.sourceEpoch)) h' = h.with("cacheHits", (h.cacheHits + 1)) else h' = h.with("cachedEngineEpoch", h.engineEpoch).with("cachedSourceEpoch", h.sourceEpoch).with("rebuilds", (h.rebuilds + 1)).with("retainedEntries", if (h.retainedEntries < h.maxCacheEntries) (h.retainedEntries + 1) else h.maxCacheEntries) else if ((h.cachedSourceEpoch == h.sourceEpoch and not(h.cachedEngineEpoch == h.engineEpoch))) h' = h.with("falseHitCount", (h.falseHitCount + 1)).with("cacheHits", (h.cacheHits + 1)) else h' = h.with("cachedEngineEpoch", h.engineEpoch).with("cachedSourceEpoch", h.sourceEpoch).with("rebuilds", (h.rebuilds + 1))
  action stepUnderSpecifiedKey = any { step, lookupCacheUnderSpecified }
  // Countermodel engineering.concurrency.ci-cache-soundness-and-sharding.cross-shard-write-conflict (dropped guard: disjoint-shard-namespaces)
  action saveShardSharedKeyCollision = if (false) h' = h.with("shardNamespacesDisjoint", true).with("retainedEntries", if (h.retainedEntries < h.maxCacheEntries) (h.retainedEntries + 1) else h.maxCacheEntries) else h' = h.with("shardNamespacesDisjoint", false).with("writeConflictCount", (h.writeConflictCount + 1))
  action stepCrossShardWriteConflict = any { step, saveShardSharedKeyCollision }
  // Countermodel engineering.concurrency.ci-cache-soundness-and-sharding.unbounded-cache-ratchet (dropped guard: active-set-gc-on-save)
  action saveCacheWithoutGc = if (false) h' = h.with("retainedEntries", if (h.retainedEntries > 2) 2 else h.retainedEntries) else h' = h.with("retainedEntries", (h.maxCacheEntries + 3))
  action stepUnboundedCacheRatchet = any { step, saveCacheWithoutGc }
  action checkCiCacheSafe = all { assert(h.cacheHits > 0), assert(h.rebuilds > 0), assert(h.falseHitCount == 0), assert(h.writeConflictCount == 0), assert(h.shardNamespacesDisjoint), assert(h.retainedEntries <= h.maxCacheEntries), assert(safety), h' = h }
  action checkCiCacheViolated = all { assert((h.falseHitCount > 0 or h.writeConflictCount > 0 or not(h.shardNamespacesDisjoint) or h.retainedEntries > h.maxCacheEntries)), assert(not(safety)), h' = h }
  run ciCacheSoundnessSafeTest = init.then(lookupOrRebuild).then(lookupOrRebuild).then(bumpEngine).then(lookupOrRebuild).then(bumpSource).then(lookupOrRebuild).then(saveShardParallel).then(compactAndSaveCache).then(checkCiCacheSafe)
  run underSpecifiedKeyRefutedTest = init.then(lookupOrRebuild).then(bumpEngine).then(lookupCacheUnderSpecified).then(checkCiCacheViolated)
  run crossShardConflictRefutedTest = init.then(saveShardSharedKeyCollision).then(checkCiCacheViolated)
  run unboundedCacheRatchetRefutedTest = init.then(saveCacheWithoutGc).then(checkCiCacheViolated)
}
