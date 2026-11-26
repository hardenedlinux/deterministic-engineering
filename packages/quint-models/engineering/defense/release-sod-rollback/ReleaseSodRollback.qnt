// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.release-sod-rollback
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel enforce-separation-of-duties step=stepSelfApproval max-steps=6 itf="h.sodViolations > 0"
// @countermodel require-pinned-rollback-cut step=stepUnpinnedPromotion max-steps=6 itf="h.unpinnedPromotions > 0"
// @countermodel forbid-revoked-or-breached-promotion step=stepFreezeBypass max-steps=6 itf="h.revokedOrBreachedPromotions > 0"
// Limits: Finite single-release SoD, canary SLO, and pre-release Merkle rollback abstraction; does not model multi-region traffic shifting, non-reversible database schema drops, or external DNS propagation lag.
module release_sod_rollback {
  type State = { authorId: int, approverId: int, independentAuditPassed: bool, preReleaseCutPinned: bool, authorityRevoked: bool, canarySloBreached: bool, promotedToProd: bool, rolledBack: bool, forensicHistoryIntact: bool, sodViolations: int, unpinnedPromotions: int, revokedOrBreachedPromotions: int }
  var h: State
  action init = h' = { authorId: 1, approverId: 0, independentAuditPassed: false, preReleaseCutPinned: false, authorityRevoked: false, canarySloBreached: false, promotedToProd: false, rolledBack: false, forensicHistoryIntact: true, sodViolations: 0, unpinnedPromotions: 0, revokedOrBreachedPromotions: 0 }
  action authorSelfApproveAttempt = if ((h.approverId == 0 and not(h.promotedToProd))) h' = h.with("approverId", h.authorId) else h' = h
  action independentApprove = if ((h.approverId != 2 and not(h.promotedToProd))) h' = h.with("approverId", 2) else h' = h
  action passReleaseAudit = if (not(h.independentAuditPassed)) h' = h.with("independentAuditPassed", true) else h' = h
  action pinPreReleaseCut = if (not(h.preReleaseCutPinned)) h' = h.with("preReleaseCutPinned", true) else h' = h
  action triggerEmergencyFreeze = if (not(h.authorityRevoked)) h' = h.with("authorityRevoked", true) else h' = h
  action detectCanaryBreach = if (not(h.canarySloBreached)) h' = h.with("canarySloBreached", true) else h' = h
  action promoteToProduction = if ((not(h.promotedToProd) and (h.approverId != 0 and h.approverId != h.authorId) and h.preReleaseCutPinned and (h.independentAuditPassed and not(h.authorityRevoked) and not(h.canarySloBreached)))) h' = h.with("promotedToProd", true).with("sodViolations", if ((h.approverId != 0 and h.approverId != h.authorId)) h.sodViolations else (h.sodViolations + 1)).with("unpinnedPromotions", if (h.preReleaseCutPinned) h.unpinnedPromotions else (h.unpinnedPromotions + 1)).with("revokedOrBreachedPromotions", if ((h.independentAuditPassed and not(h.authorityRevoked) and not(h.canarySloBreached))) h.revokedOrBreachedPromotions else (h.revokedOrBreachedPromotions + 1)) else h' = h
  action rollbackToPinnedCut = if ((h.promotedToProd and h.preReleaseCutPinned and not(h.rolledBack))) h' = h.with("promotedToProd", false).with("rolledBack", true) else h' = h
  action step = any { authorSelfApproveAttempt, independentApprove, passReleaseAudit, pinPreReleaseCut, triggerEmergencyFreeze, detectCanaryBreach, promoteToProduction, rollbackToPinnedCut }
  val safety = (h.forensicHistoryIntact and h.sodViolations == 0 and h.unpinnedPromotions == 0 and h.revokedOrBreachedPromotions == 0)
  // Countermodel engineering.defense.release-sod-rollback.self-approval (dropped guard: enforce-separation-of-duties)
  action promoteSelfApproved = if ((not(h.promotedToProd) and true and h.preReleaseCutPinned and (h.independentAuditPassed and not(h.authorityRevoked) and not(h.canarySloBreached)))) h' = h.with("promotedToProd", true).with("sodViolations", if ((h.approverId != 0 and h.approverId != h.authorId)) h.sodViolations else (h.sodViolations + 1)).with("unpinnedPromotions", if (h.preReleaseCutPinned) h.unpinnedPromotions else (h.unpinnedPromotions + 1)).with("revokedOrBreachedPromotions", if ((h.independentAuditPassed and not(h.authorityRevoked) and not(h.canarySloBreached))) h.revokedOrBreachedPromotions else (h.revokedOrBreachedPromotions + 1)) else h' = h
  action stepSelfApproval = any { step, promoteSelfApproved }
  // Countermodel engineering.defense.release-sod-rollback.unpinned-promotion (dropped guard: require-pinned-rollback-cut)
  action promoteWithoutCut = if ((not(h.promotedToProd) and (h.approverId != 0 and h.approverId != h.authorId) and true and (h.independentAuditPassed and not(h.authorityRevoked) and not(h.canarySloBreached)))) h' = h.with("promotedToProd", true).with("sodViolations", if ((h.approverId != 0 and h.approverId != h.authorId)) h.sodViolations else (h.sodViolations + 1)).with("unpinnedPromotions", if (h.preReleaseCutPinned) h.unpinnedPromotions else (h.unpinnedPromotions + 1)).with("revokedOrBreachedPromotions", if ((h.independentAuditPassed and not(h.authorityRevoked) and not(h.canarySloBreached))) h.revokedOrBreachedPromotions else (h.revokedOrBreachedPromotions + 1)) else h' = h
  action stepUnpinnedPromotion = any { step, promoteWithoutCut }
  // Countermodel engineering.defense.release-sod-rollback.freeze-bypass (dropped guard: forbid-revoked-or-breached-promotion)
  action promoteIgnoreFreeze = if ((not(h.promotedToProd) and (h.approverId != 0 and h.approverId != h.authorId) and h.preReleaseCutPinned and true)) h' = h.with("promotedToProd", true).with("sodViolations", if ((h.approverId != 0 and h.approverId != h.authorId)) h.sodViolations else (h.sodViolations + 1)).with("unpinnedPromotions", if (h.preReleaseCutPinned) h.unpinnedPromotions else (h.unpinnedPromotions + 1)).with("revokedOrBreachedPromotions", if ((h.independentAuditPassed and not(h.authorityRevoked) and not(h.canarySloBreached))) h.revokedOrBreachedPromotions else (h.revokedOrBreachedPromotions + 1)) else h' = h
  action stepFreezeBypass = any { step, promoteIgnoreFreeze }
  run governedPromotionAndDurableRollbackSafeTest = init.then(passReleaseAudit).then(pinPreReleaseCut).then(independentApprove).then(promoteToProduction).then(detectCanaryBreach).then(rollbackToPinnedCut).then(all { assert(safety), assert(h.rolledBack), assert(not(h.promotedToProd)), assert(h.forensicHistoryIntact), h' = h })
  run selfApprovalViolatesSodTest = init.then(passReleaseAudit).then(pinPreReleaseCut).then(authorSelfApproveAttempt).then(promoteSelfApproved).then(all { assert(not(safety)), assert(h.sodViolations > 0), h' = h })
  run unpinnedPromotionViolatesSafetyTest = init.then(passReleaseAudit).then(independentApprove).then(promoteWithoutCut).then(all { assert(not(safety)), assert(h.unpinnedPromotions > 0), h' = h })
  run freezeBypassViolatesSafetyTest = init.then(pinPreReleaseCut).then(independentApprove).then(triggerEmergencyFreeze).then(promoteIgnoreFreeze).then(all { assert(not(safety)), assert(h.revokedOrBreachedPromotions > 0), h' = h })
}
