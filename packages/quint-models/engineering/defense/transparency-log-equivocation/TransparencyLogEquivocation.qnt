// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.transparency-log-equivocation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-inclusion-proof step=stepUnverifiedInclusion max-steps=6 itf="h.unverifiedEntryAccepts > 0"
// @countermodel require-append-only-consistency step=stepHistoryRewrite max-steps=6 itf="h.historyRewriteAccepts > 0"
// @countermodel forbid-split-view-equivocation step=stepSplitView max-steps=6 itf="h.equivocationAccepts > 0"
// Limits: Finite two-STH inclusion, consistency, and witness-gossip equivocation abstraction; does not model network eclipse attacks that completely isolate all external witnesses from gossiping with one another.
module transparency_log_equivocation {
  type State = { sth1Published: bool, sth2Published: bool, inclusionProofValid: bool, consistencyProofValid: bool, equivocationDetected: bool, unverifiedEntryAccepts: int, historyRewriteAccepts: int, equivocationAccepts: int, verifiedAudits: int }
  var h: State
  action init = h' = { sth1Published: false, sth2Published: false, inclusionProofValid: false, consistencyProofValid: false, equivocationDetected: false, unverifiedEntryAccepts: 0, historyRewriteAccepts: 0, equivocationAccepts: 0, verifiedAudits: 0 }
  action publishInitialSth = if (not(h.sth1Published)) h' = h.with("sth1Published", true) else h' = h
  action verifyEntryInclusion = if ((h.sth1Published and not(h.inclusionProofValid))) h' = h.with("inclusionProofValid", true) else h' = h
  action appendConsistentSth2 = if ((h.sth1Published and not(h.sth2Published))) h' = h.with("sth2Published", true).with("consistencyProofValid", true) else h' = h
  action attemptHistoryRewrite = if ((h.sth1Published and not(h.sth2Published))) h' = h.with("sth2Published", true).with("consistencyProofValid", false) else h' = h
  action emitSplitViewSth = if ((h.sth1Published and not(h.equivocationDetected))) h' = h.with("equivocationDetected", true) else h' = h
  action acceptAuditSnapshot = if ((h.sth2Published and h.inclusionProofValid and h.consistencyProofValid and not(h.equivocationDetected))) h' = h.with("verifiedAudits", (h.verifiedAudits + 1)).with("unverifiedEntryAccepts", if (h.inclusionProofValid) h.unverifiedEntryAccepts else (h.unverifiedEntryAccepts + 1)).with("historyRewriteAccepts", if (h.consistencyProofValid) h.historyRewriteAccepts else (h.historyRewriteAccepts + 1)).with("equivocationAccepts", if (not(h.equivocationDetected)) h.equivocationAccepts else (h.equivocationAccepts + 1)) else h' = h
  action step = any { publishInitialSth, verifyEntryInclusion, appendConsistentSth2, attemptHistoryRewrite, emitSplitViewSth, acceptAuditSnapshot }
  val safety = (h.unverifiedEntryAccepts == 0 and h.historyRewriteAccepts == 0 and h.equivocationAccepts == 0)
  // Countermodel engineering.defense.transparency-log-equivocation.unverified-inclusion (dropped guard: require-inclusion-proof)
  action acceptUnverifiedInclusion = if ((h.sth2Published and true and h.consistencyProofValid and not(h.equivocationDetected))) h' = h.with("verifiedAudits", (h.verifiedAudits + 1)).with("unverifiedEntryAccepts", if (h.inclusionProofValid) h.unverifiedEntryAccepts else (h.unverifiedEntryAccepts + 1)).with("historyRewriteAccepts", if (h.consistencyProofValid) h.historyRewriteAccepts else (h.historyRewriteAccepts + 1)).with("equivocationAccepts", if (not(h.equivocationDetected)) h.equivocationAccepts else (h.equivocationAccepts + 1)) else h' = h
  action stepUnverifiedInclusion = any { step, acceptUnverifiedInclusion }
  // Countermodel engineering.defense.transparency-log-equivocation.history-rewrite (dropped guard: require-append-only-consistency)
  action acceptRewrittenHistory = if ((h.sth2Published and h.inclusionProofValid and true and not(h.equivocationDetected))) h' = h.with("verifiedAudits", (h.verifiedAudits + 1)).with("unverifiedEntryAccepts", if (h.inclusionProofValid) h.unverifiedEntryAccepts else (h.unverifiedEntryAccepts + 1)).with("historyRewriteAccepts", if (h.consistencyProofValid) h.historyRewriteAccepts else (h.historyRewriteAccepts + 1)).with("equivocationAccepts", if (not(h.equivocationDetected)) h.equivocationAccepts else (h.equivocationAccepts + 1)) else h' = h
  action stepHistoryRewrite = any { step, acceptRewrittenHistory }
  // Countermodel engineering.defense.transparency-log-equivocation.split-view (dropped guard: forbid-split-view-equivocation)
  action acceptSplitView = if ((h.sth2Published and h.inclusionProofValid and h.consistencyProofValid and true)) h' = h.with("verifiedAudits", (h.verifiedAudits + 1)).with("unverifiedEntryAccepts", if (h.inclusionProofValid) h.unverifiedEntryAccepts else (h.unverifiedEntryAccepts + 1)).with("historyRewriteAccepts", if (h.consistencyProofValid) h.historyRewriteAccepts else (h.historyRewriteAccepts + 1)).with("equivocationAccepts", if (not(h.equivocationDetected)) h.equivocationAccepts else (h.equivocationAccepts + 1)) else h' = h
  action stepSplitView = any { step, acceptSplitView }
  run verifiedAppendOnlyAuditSafeTest = init.then(publishInitialSth).then(verifyEntryInclusion).then(appendConsistentSth2).then(acceptAuditSnapshot).then(all { assert(safety), assert(h.verifiedAudits == 1), h' = h })
  run unverifiedInclusionViolatesSafetyTest = init.then(publishInitialSth).then(appendConsistentSth2).then(acceptUnverifiedInclusion).then(all { assert(not(safety)), assert(h.unverifiedEntryAccepts > 0), h' = h })
  run historyRewriteViolatesSafetyTest = init.then(publishInitialSth).then(verifyEntryInclusion).then(attemptHistoryRewrite).then(acceptRewrittenHistory).then(all { assert(not(safety)), assert(h.historyRewriteAccepts > 0), h' = h })
  run splitViewViolatesSafetyTest = init.then(publishInitialSth).then(verifyEntryInclusion).then(appendConsistentSth2).then(emitSplitViewSth).then(acceptSplitView).then(all { assert(not(safety)), assert(h.equivocationAccepts > 0), h' = h })
}
