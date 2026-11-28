// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.durable-ai-context-ssi
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel forbid-semantic-write-skew-merge step=stepWriteSkew max-steps=6 itf="h.writeSkewMerges > 0"
// @countermodel forbid-stale-fencing-commit step=stepStaleFence max-steps=6 itf="h.fencedCommits > 0"
// @countermodel require-sanitized-reviewer-projection step=stepUnsanitizedReview max-steps=6 itf="h.injectedReviews > 0"
// Limits: Finite two-agent SSI rw-antidependency, two-epoch lease fencing, and reviewer context sanitization abstraction; does not model arbitrary multi-hop transitive dependency graphs or covert steganography inside valid code diffs.
module durable_ai_context_ssi {
  type State = { durableEvidenceIntact: bool, rawChatCompacted: bool, readWriteSkew: bool, activeEpoch: int, workerEpoch: int, proseSanitized: bool, writeSkewMerges: int, fencedCommits: int, injectedReviews: int }
  var h: State
  action init = h' = { durableEvidenceIntact: true, rawChatCompacted: false, readWriteSkew: false, activeEpoch: 1, workerEpoch: 1, proseSanitized: true, writeSkewMerges: 0, fencedCommits: 0, injectedReviews: 0 }
  action compactRawChatHistory = if (not(h.rawChatCompacted)) h' = h.with("rawChatCompacted", true) else h' = h
  action introduceRwAntidependency = if (not(h.readWriteSkew)) h' = h.with("readWriteSkew", true) else h' = h
  action revalidateStaleReader = if (h.readWriteSkew) h' = h.with("readWriteSkew", false) else h' = h
  action advanceLeaseEpochOnTimeout = if (h.activeEpoch == 1) h' = h.with("activeEpoch", 2) else h' = h
  action refreshWorkerEpoch = if (h.workerEpoch < h.activeEpoch) h' = h.with("workerEpoch", h.activeEpoch) else h' = h
  action injectCoderProseDraft = if (h.proseSanitized) h' = h.with("proseSanitized", false) else h' = h
  action projectSanitizedReviewerView = if (not(h.proseSanitized)) h' = h.with("proseSanitized", true) else h' = h
  action mergeDisjointAgentBranches = if (not(h.readWriteSkew)) h' = h.with("writeSkewMerges", if (h.readWriteSkew) (h.writeSkewMerges + 1) else h.writeSkewMerges) else h' = h
  action commitWorkerBranch = if (h.workerEpoch == h.activeEpoch) h' = h.with("fencedCommits", if (h.workerEpoch == h.activeEpoch) h.fencedCommits else (h.fencedCommits + 1)) else h' = h
  action runReviewerEvaluation = if (h.proseSanitized) h' = h.with("injectedReviews", if (h.proseSanitized) h.injectedReviews else (h.injectedReviews + 1)) else h' = h
  action step = any { compactRawChatHistory, introduceRwAntidependency, revalidateStaleReader, advanceLeaseEpochOnTimeout, refreshWorkerEpoch, injectCoderProseDraft, projectSanitizedReviewerView, mergeDisjointAgentBranches, commitWorkerBranch, runReviewerEvaluation }
  val safety = (h.durableEvidenceIntact and h.writeSkewMerges == 0 and h.fencedCommits == 0 and h.injectedReviews == 0)
  // Countermodel engineering.defense.durable-ai-context-ssi.write-skew (dropped guard: forbid-semantic-write-skew-merge)
  action mergeBlindWriteSkew = if (true) h' = h.with("writeSkewMerges", if (h.readWriteSkew) (h.writeSkewMerges + 1) else h.writeSkewMerges) else h' = h
  action stepWriteSkew = any { step, mergeBlindWriteSkew }
  // Countermodel engineering.defense.durable-ai-context-ssi.stale-fence (dropped guard: forbid-stale-fencing-commit)
  action commitStaleWorkerEpoch = if (true) h' = h.with("fencedCommits", if (h.workerEpoch == h.activeEpoch) h.fencedCommits else (h.fencedCommits + 1)) else h' = h
  action stepStaleFence = any { step, commitStaleWorkerEpoch }
  // Countermodel engineering.defense.durable-ai-context-ssi.unsanitized-review (dropped guard: require-sanitized-reviewer-projection)
  action reviewUnsanitizedContext = if (true) h' = h.with("injectedReviews", if (h.proseSanitized) h.injectedReviews else (h.injectedReviews + 1)) else h' = h
  action stepUnsanitizedReview = any { step, reviewUnsanitizedContext }
  run compactionSsiFenceAndSanitizedViewSafeTest = init.then(compactRawChatHistory).then(introduceRwAntidependency).then(revalidateStaleReader).then(mergeDisjointAgentBranches).then(advanceLeaseEpochOnTimeout).then(refreshWorkerEpoch).then(commitWorkerBranch).then(injectCoderProseDraft).then(projectSanitizedReviewerView).then(runReviewerEvaluation).then(all { assert(safety), assert(h.rawChatCompacted), assert(h.durableEvidenceIntact), assert(h.workerEpoch == 2), h' = h })
  run writeSkewMergeViolatesSafetyTest = init.then(introduceRwAntidependency).then(mergeBlindWriteSkew).then(all { assert(not(safety)), assert(h.writeSkewMerges > 0), h' = h })
  run staleFenceCommitViolatesSafetyTest = init.then(advanceLeaseEpochOnTimeout).then(commitStaleWorkerEpoch).then(all { assert(not(safety)), assert(h.fencedCommits > 0), h' = h })
  run unsanitizedInjectionViolatesSafetyTest = init.then(injectCoderProseDraft).then(reviewUnsanitizedContext).then(all { assert(not(safety)), assert(h.injectedReviews > 0), h' = h })
}
