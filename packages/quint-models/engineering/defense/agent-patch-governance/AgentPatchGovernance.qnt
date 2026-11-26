// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.agent-patch-governance
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-independent-audit step=stepSelfCertified max-steps=6 itf="h.decision == 1 and not(h.independentAuditPassed)"
// @countermodel forbid-unwitnessed-obligation-deletion step=stepDeletedObligation max-steps=6 itf="h.decision == 1 and h.obligationDeleted and not(h.replacementAdmitted)"
// @countermodel forbid-floor-weakening-on-retry step=stepFloorWeakening max-steps=6 itf="h.decision == 1 and h.floorWeakened"
// Limits: Finite single-patch governance loop with bounded retry budget (max 2 retries); does not model multi-PR merge conflicts, compromised CI runners, or adversarial oracle poisoning.
module agent_patch_governance {
  type State = { patchProposed: bool, agentClaimsFixed: bool, independentAuditPassed: bool, obligationDeleted: bool, replacementAdmitted: bool, floorWeakened: bool, repairAttempts: int, decision: int }
  var h: State
  action init = h' = { patchProposed: false, agentClaimsFixed: false, independentAuditPassed: false, obligationDeleted: false, replacementAdmitted: false, floorWeakened: false, repairAttempts: 0, decision: 0 }
  action proposePatch = if (not(h.patchProposed)) h' = h.with("patchProposed", true) else h' = h
  action agentClaimFixed = if ((h.patchProposed and not(h.agentClaimsFixed))) h' = h.with("agentClaimsFixed", true) else h' = h
  action passIndependentAudit = if ((h.patchProposed and h.decision == 0 and not(h.independentAuditPassed) and not(h.floorWeakened))) h' = h.with("independentAuditPassed", true) else h' = h
  action deleteObligationInDiff = if ((h.patchProposed and h.decision == 0 and not(h.obligationDeleted))) h' = h.with("obligationDeleted", true) else h' = h
  action admitReplacementWitness = if ((h.obligationDeleted and h.decision == 0 and not(h.replacementAdmitted))) h' = h.with("replacementAdmitted", true) else h' = h
  action attemptFloorWeakening = if ((h.patchProposed and h.decision == 0 and not(h.floorWeakened))) h' = h.with("floorWeakened", true) else h' = h
  action refuseAndRetry = if ((h.patchProposed and h.decision == 0 and h.repairAttempts < 2 and (not(h.independentAuditPassed) or h.floorWeakened or (h.obligationDeleted and not(h.replacementAdmitted))))) h' = h.with("repairAttempts", (h.repairAttempts + 1)).with("floorWeakened", false) else h' = h
  action escalateBudgetExhausted = if ((h.patchProposed and h.decision == 0 and h.repairAttempts == 2)) h' = h.with("decision", 3) else h' = h
  action admitPatch = if ((h.patchProposed and h.decision == 0 and h.independentAuditPassed and (not(h.obligationDeleted) or h.replacementAdmitted) and not(h.floorWeakened))) h' = h.with("decision", 1) else h' = h
  action step = any { proposePatch, agentClaimFixed, passIndependentAudit, deleteObligationInDiff, admitReplacementWitness, attemptFloorWeakening, refuseAndRetry, escalateBudgetExhausted, admitPatch }
  val safety = (h.repairAttempts <= 2 and (h.decision != 1 or (h.independentAuditPassed and not(h.floorWeakened) and (not(h.obligationDeleted) or h.replacementAdmitted))))
  // Countermodel engineering.defense.agent-patch-governance.self-certified (dropped guard: require-independent-audit)
  action admitPatchSelfCertified = if ((h.patchProposed and h.decision == 0 and true and (not(h.obligationDeleted) or h.replacementAdmitted) and not(h.floorWeakened))) h' = h.with("decision", 1) else h' = h
  action stepSelfCertified = any { step, admitPatchSelfCertified }
  // Countermodel engineering.defense.agent-patch-governance.deleted-obligation (dropped guard: forbid-unwitnessed-obligation-deletion)
  action admitPatchDeletedObligation = if ((h.patchProposed and h.decision == 0 and h.independentAuditPassed and true and not(h.floorWeakened))) h' = h.with("decision", 1) else h' = h
  action stepDeletedObligation = any { step, admitPatchDeletedObligation }
  // Countermodel engineering.defense.agent-patch-governance.floor-weakening (dropped guard: forbid-floor-weakening-on-retry)
  action admitPatchWeakenedFloor = if ((h.patchProposed and h.decision == 0 and h.independentAuditPassed and (not(h.obligationDeleted) or h.replacementAdmitted) and true)) h' = h.with("decision", 1) else h' = h
  action stepFloorWeakening = any { step, admitPatchWeakenedFloor }
  run verifiedPatchAdmittedSafeTest = init.then(proposePatch).then(agentClaimFixed).then(passIndependentAudit).then(admitPatch).then(all { assert(safety), assert(h.decision == 1), h' = h })
  run budgetExhaustionEscalatesHumanSafeTest = init.then(proposePatch).then(agentClaimFixed).then(attemptFloorWeakening).then(refuseAndRetry).then(refuseAndRetry).then(escalateBudgetExhausted).then(all { assert(safety), assert(h.decision == 3), assert(h.repairAttempts == 2), h' = h })
  run selfCertifiedViolatesSafetyTest = init.then(proposePatch).then(agentClaimFixed).then(admitPatchSelfCertified).then(all { assert(not(safety)), assert(h.decision == 1), assert(not(h.independentAuditPassed)), h' = h })
  run deletedObligationViolatesSafetyTest = init.then(proposePatch).then(passIndependentAudit).then(deleteObligationInDiff).then(admitPatchDeletedObligation).then(all { assert(not(safety)), assert(h.decision == 1), assert(h.obligationDeleted), assert(not(h.replacementAdmitted)), h' = h })
  run floorWeakeningViolatesSafetyTest = init.then(proposePatch).then(passIndependentAudit).then(attemptFloorWeakening).then(admitPatchWeakenedFloor).then(all { assert(not(safety)), assert(h.decision == 1), assert(h.floorWeakened), h' = h })
}
