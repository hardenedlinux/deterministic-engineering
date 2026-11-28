// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.search-index-snapshot-isolation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel serialize-cold-open step=stepSplitBrainColdOpen max-steps=6 itf="h.splitBrainOpens > 0"
// @countermodel verify-workspace-root step=stepCrossWorkspaceContamination max-steps=6 itf="h.crossWorkspaceHits > 0"
// @countermodel reelect-on-leader-cancel step=stepSingleFlightCascadeFailure max-steps=6 itf="h.cascadeFailures > 0"
// Limits: Finite two-workspace, single-leader/follower snapshot isolation abstraction; verifies cold-open serialization, workspace root isolation, follower re-election under leader cancellation, and bounded reader-pinned segment compaction, not OS filesystem rename durability or Tantivy inverted-index compression internals.
module concurrency_search_index_snapshot_isolation {
  type State = { cachedRoot: int, activeIndexesForRoot: int, snapshotGen: int, activeReaders: int, pinnedSegments: int, leaderActive: bool, waitingFollowers: int, splitBrainOpens: int, crossWorkspaceHits: int, cascadeFailures: int }
  var h: State
  action init = h' = { cachedRoot: 0, activeIndexesForRoot: 0, snapshotGen: 1, activeReaders: 0, pinnedSegments: 1, leaderActive: false, waitingFollowers: 0, splitBrainOpens: 0, crossWorkspaceHits: 0, cascadeFailures: 0 }
  action coldOpenRoot1 = if (h.cachedRoot == 0) if (true) h' = h.with("cachedRoot", 1).with("activeIndexesForRoot", 1).with("pinnedSegments", 1) else h' = h.with("cachedRoot", 1).with("activeIndexesForRoot", (h.activeIndexesForRoot + 2)).with("splitBrainOpens", (h.splitBrainOpens + 1)) else h' = h
  action queryRoot2 = if (h.cachedRoot == 1) if (true) h' = h.with("cachedRoot", 2).with("activeIndexesForRoot", 1).with("snapshotGen", (h.snapshotGen + 1)) else h' = h.with("crossWorkspaceHits", (h.crossWorkspaceHits + 1)) else h' = h
  action startSingleFlightQuery = if ((h.cachedRoot > 0 and not(h.leaderActive))) h' = h.with("leaderActive", true).with("waitingFollowers", 1).with("activeReaders", (h.activeReaders + 1)).with("pinnedSegments", (h.activeReaders + 1)) else h' = h
  action cancelLeaderReelect = if ((h.leaderActive and h.waitingFollowers > 0)) if (true) h' = h.with("leaderActive", true).with("waitingFollowers", (h.waitingFollowers - 1)) else h' = h.with("leaderActive", false).with("waitingFollowers", 0).with("cascadeFailures", (h.cascadeFailures + 1)) else h' = h
  action finishQueryReleaseReader = if (h.leaderActive) h' = h.with("leaderActive", false).with("waitingFollowers", 0).with("activeReaders", if (h.activeReaders > 0) (h.activeReaders - 1) else 0).with("pinnedSegments", if (h.activeReaders > 0) h.activeReaders else 1) else h' = h
  action publishAndCompactSnapshot = if (h.cachedRoot > 0) h' = h.with("snapshotGen", (h.snapshotGen + 1)).with("pinnedSegments", (h.activeReaders + 1)) else h' = h
  action step = any { coldOpenRoot1, queryRoot2, startSingleFlightQuery, cancelLeaderReelect, finishQueryReleaseReader, publishAndCompactSnapshot }
  val safety = (h.activeIndexesForRoot <= 1 and h.splitBrainOpens == 0 and h.crossWorkspaceHits == 0 and h.cascadeFailures == 0 and h.pinnedSegments <= (h.activeReaders + 1) and h.snapshotGen >= 1)
  // Countermodel engineering.concurrency.search-index-snapshot-isolation.split-brain-cold-open (dropped guard: serialize-cold-open)
  action coldOpenRoot1SplitBrain = if (h.cachedRoot == 0) if (false) h' = h.with("cachedRoot", 1).with("activeIndexesForRoot", 1).with("pinnedSegments", 1) else h' = h.with("cachedRoot", 1).with("activeIndexesForRoot", (h.activeIndexesForRoot + 2)).with("splitBrainOpens", (h.splitBrainOpens + 1)) else h' = h
  action stepSplitBrainColdOpen = any { step, coldOpenRoot1SplitBrain }
  // Countermodel engineering.concurrency.search-index-snapshot-isolation.cross-workspace-contamination (dropped guard: verify-workspace-root)
  action queryRoot2Contaminated = if (h.cachedRoot == 1) if (false) h' = h.with("cachedRoot", 2).with("activeIndexesForRoot", 1).with("snapshotGen", (h.snapshotGen + 1)) else h' = h.with("crossWorkspaceHits", (h.crossWorkspaceHits + 1)) else h' = h
  action stepCrossWorkspaceContamination = any { step, queryRoot2Contaminated }
  // Countermodel engineering.concurrency.search-index-snapshot-isolation.single-flight-cascade-failure (dropped guard: reelect-on-leader-cancel)
  action cancelLeaderCascade = if ((h.leaderActive and h.waitingFollowers > 0)) if (false) h' = h.with("leaderActive", true).with("waitingFollowers", (h.waitingFollowers - 1)) else h' = h.with("leaderActive", false).with("waitingFollowers", 0).with("cascadeFailures", (h.cascadeFailures + 1)) else h' = h
  action stepSingleFlightCascadeFailure = any { step, cancelLeaderCascade }
  action checkSnapshotSafe = all { assert(h.cachedRoot == 2), assert(h.activeIndexesForRoot == 1), assert(h.splitBrainOpens == 0), assert(h.crossWorkspaceHits == 0), assert(h.cascadeFailures == 0), assert(h.pinnedSegments <= (h.activeReaders + 1)), assert(safety), h' = h }
  action checkSnapshotViolated = all { assert((h.splitBrainOpens > 0 or h.crossWorkspaceHits > 0 or h.cascadeFailures > 0 or h.activeIndexesForRoot > 1)), assert(not(safety)), h' = h }
  run snapshotIsolationSafeTest = init.then(coldOpenRoot1).then(startSingleFlightQuery).then(cancelLeaderReelect).then(finishQueryReleaseReader).then(publishAndCompactSnapshot).then(queryRoot2).then(checkSnapshotSafe)
  run splitBrainColdOpenRefutedTest = init.then(coldOpenRoot1SplitBrain).then(checkSnapshotViolated)
  run crossWorkspaceContaminationRefutedTest = init.then(coldOpenRoot1).then(queryRoot2Contaminated).then(checkSnapshotViolated)
  run singleFlightCascadeRefutedTest = init.then(coldOpenRoot1).then(startSingleFlightQuery).then(cancelLeaderCascade).then(checkSnapshotViolated)
}
