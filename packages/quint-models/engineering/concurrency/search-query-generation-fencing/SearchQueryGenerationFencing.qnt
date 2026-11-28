// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.search-query-generation-fencing
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel monotonic-gen-fence step=stepGenerationInversion max-steps=6 itf="h.generationInversion == true"
// @countermodel anchor-selection-id step=stepSelectionIdentityJump max-steps=6 itf="not(h.selectedAnchored)"
// @countermodel epoch-response-fence step=stepStaleBatchOverwrite max-steps=6 itf="h.staleApplied == true"
// Limits: Finite 3-generation, 2-candidate interactive search abstraction; verifies monotonic cancellation, stale batch/DSL rejection, selection identity anchoring, and mark pruning, not ranking relevance scoring.
module concurrency_search_query_generation_fencing {
  type State = { activeGen: int, displayedGen: int, visibleCount: int, markedCount: int, staleDrops: int, selectedAnchored: bool, generationInversion: bool, staleApplied: bool }
  var h: State
  action init = h' = { activeGen: 1, displayedGen: 0, visibleCount: 0, markedCount: 0, staleDrops: 0, selectedAnchored: true, generationInversion: false, staleApplied: false }
  action beginQuery = if (h.activeGen < 3) h' = h.with("activeGen", (h.activeGen + 1)).with("visibleCount", 0).with("markedCount", 0).with("selectedAnchored", true) else h' = h
  action dispatchDelayedOlderQuery = if ((h.activeGen > 1 and h.staleDrops < 3)) h' = h.with("staleDrops", (h.staleDrops + 1)).with("generationInversion", false) else h' = h
  action applyFreshBatch = if (h.visibleCount < 2) h' = h.with("displayedGen", h.activeGen).with("visibleCount", (h.visibleCount + 1)).with("selectedAnchored", if (h.visibleCount > 0) true else true) else h' = h
  action applyStaleBatch = if ((h.activeGen > 1 and h.staleDrops < 3)) h' = h.with("staleDrops", (h.staleDrops + 1)).with("staleApplied", false) else h' = h
  action toggleMark = if ((h.visibleCount > 0 and h.markedCount < h.visibleCount)) h' = h.with("markedCount", (h.markedCount + 1)) else h' = h
  action filterSource = if (h.visibleCount > 0) h' = h.with("visibleCount", (h.visibleCount - 1)).with("markedCount", if (h.markedCount > (h.visibleCount - 1)) (h.visibleCount - 1) else h.markedCount) else h' = h
  action step = any { beginQuery, dispatchDelayedOlderQuery, applyFreshBatch, applyStaleBatch, toggleMark, filterSource }
  val safety = (h.displayedGen <= h.activeGen and h.markedCount <= h.visibleCount and h.selectedAnchored and not(h.generationInversion) and not(h.staleApplied))
  // Countermodel engineering.concurrency.search-query-generation-fencing.generation-inversion (dropped guard: monotonic-gen-fence)
  action dispatchDelayedOlderQueryInverted = if ((h.activeGen > 1 and h.staleDrops < 3)) h' = h.with("staleDrops", (h.staleDrops + 1)).with("generationInversion", true) else h' = h
  action stepGenerationInversion = any { step, dispatchDelayedOlderQueryInverted }
  // Countermodel engineering.concurrency.search-query-generation-fencing.selection-jump (dropped guard: anchor-selection-id)
  action applyFreshBatchUnanchored = if (h.visibleCount < 2) h' = h.with("displayedGen", h.activeGen).with("visibleCount", (h.visibleCount + 1)).with("selectedAnchored", if (h.visibleCount > 0) false else true) else h' = h
  action stepSelectionIdentityJump = any { step, applyFreshBatchUnanchored }
  // Countermodel engineering.concurrency.search-query-generation-fencing.stale-overwrite (dropped guard: epoch-response-fence)
  action applyStaleBatchOverwrite = if ((h.activeGen > 1 and h.staleDrops < 3)) h' = h.with("staleDrops", (h.staleDrops + 1)).with("staleApplied", true) else h' = h
  action stepStaleBatchOverwrite = any { step, applyStaleBatchOverwrite }
  action checkFencedSearchSafe = all { assert(h.displayedGen <= h.activeGen), assert(h.markedCount <= h.visibleCount), assert(h.selectedAnchored), assert(h.staleDrops > 0), assert(safety), h' = h }
  action checkSearchFenceViolation = all { assert((h.generationInversion or not(h.selectedAnchored) or h.staleApplied)), assert(not(safety)), h' = h }
  run fencedSearchLifecycleTest = init.then(applyFreshBatch).then(toggleMark).then(applyFreshBatch).then(beginQuery).then(dispatchDelayedOlderQuery).then(applyStaleBatch).then(applyFreshBatch).then(filterSource).then(checkFencedSearchSafe)
  run generationInversionRefutedTest = init.then(beginQuery).then(dispatchDelayedOlderQueryInverted).then(checkSearchFenceViolation)
  run selectionJumpRefutedTest = init.then(applyFreshBatch).then(applyFreshBatchUnanchored).then(checkSearchFenceViolation)
  run staleBatchRefutedTest = init.then(beginQuery).then(applyStaleBatchOverwrite).then(checkSearchFenceViolation)
}
