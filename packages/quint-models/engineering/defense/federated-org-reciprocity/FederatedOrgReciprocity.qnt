// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.federated-org-reciprocity
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-treaty-ratified step=stepUnratifiedTreaty max-steps=6 itf="h.unratifiedTreatyViolations > 0"
// @countermodel require-bilateral-countersigs step=stepUnilateralSign max-steps=6 itf="h.unilateralSignViolations > 0"
// @countermodel require-no-dispute-freeze step=stepDisputeFreeze max-steps=6 itf="h.disputeFreezeViolations > 0"
// Limits: Bounded bilateral reciprocity and dispute-freeze state machine; arbitrary member org registries, self-reciprocity anti-spoofing, and treaty epoch expiration are proved unboundedly in FederatedOrgReciprocity.lean.
module federated_org_reciprocity {
  type State = { treatyRatified: bool, originOrgSigned: bool, targetOrgSigned: bool, disputeFreezeActive: bool, admittedFedOps: int, unratifiedTreatyViolations: int, unilateralSignViolations: int, disputeFreezeViolations: int }
  var h: State
  action init = h' = { treatyRatified: false, originOrgSigned: false, targetOrgSigned: false, disputeFreezeActive: false, admittedFedOps: 0, unratifiedTreatyViolations: 0, unilateralSignViolations: 0, disputeFreezeViolations: 0 }
  action ratifyBilateralTreaty = if (not(h.treatyRatified)) h' = h.with("treatyRatified", true) else h' = h
  action originOrgSign = if (not(h.originOrgSigned)) h' = h.with("originOrgSigned", true) else h' = h
  action targetOrgSign = if (not(h.targetOrgSigned)) h' = h.with("targetOrgSigned", true) else h' = h
  action raiseDisputeFreeze = if (not(h.disputeFreezeActive)) h' = h.with("disputeFreezeActive", true) else h' = h
  action resolveDisputeFreeze = if (h.disputeFreezeActive) h' = h.with("disputeFreezeActive", false) else h' = h
  action admitFederatedOp = if ((h.admittedFedOps < 2 and h.treatyRatified and (h.originOrgSigned and h.targetOrgSigned) and not(h.disputeFreezeActive))) h' = h.with("admittedFedOps", (h.admittedFedOps + 1)).with("unratifiedTreatyViolations", if (h.treatyRatified) h.unratifiedTreatyViolations else (h.unratifiedTreatyViolations + 1)).with("unilateralSignViolations", if ((h.originOrgSigned and h.targetOrgSigned)) h.unilateralSignViolations else (h.unilateralSignViolations + 1)).with("disputeFreezeViolations", if (not(h.disputeFreezeActive)) h.disputeFreezeViolations else (h.disputeFreezeViolations + 1)) else h' = h
  action step = any { ratifyBilateralTreaty, originOrgSign, targetOrgSign, raiseDisputeFreeze, resolveDisputeFreeze, admitFederatedOp }
  val safety = (h.unratifiedTreatyViolations == 0 and h.unilateralSignViolations == 0 and h.disputeFreezeViolations == 0)
  // Countermodel engineering.defense.federated-org-reciprocity.unratified-treaty (dropped guard: require-treaty-ratified)
  action admitOpUnratified = if ((h.admittedFedOps < 2 and true and (h.originOrgSigned and h.targetOrgSigned) and not(h.disputeFreezeActive))) h' = h.with("admittedFedOps", (h.admittedFedOps + 1)).with("unratifiedTreatyViolations", if (h.treatyRatified) h.unratifiedTreatyViolations else (h.unratifiedTreatyViolations + 1)).with("unilateralSignViolations", if ((h.originOrgSigned and h.targetOrgSigned)) h.unilateralSignViolations else (h.unilateralSignViolations + 1)).with("disputeFreezeViolations", if (not(h.disputeFreezeActive)) h.disputeFreezeViolations else (h.disputeFreezeViolations + 1)) else h' = h
  action stepUnratifiedTreaty = any { step, admitOpUnratified }
  // Countermodel engineering.defense.federated-org-reciprocity.unilateral-sign (dropped guard: require-bilateral-countersigs)
  action admitOpUnilateral = if ((h.admittedFedOps < 2 and h.treatyRatified and true and not(h.disputeFreezeActive))) h' = h.with("admittedFedOps", (h.admittedFedOps + 1)).with("unratifiedTreatyViolations", if (h.treatyRatified) h.unratifiedTreatyViolations else (h.unratifiedTreatyViolations + 1)).with("unilateralSignViolations", if ((h.originOrgSigned and h.targetOrgSigned)) h.unilateralSignViolations else (h.unilateralSignViolations + 1)).with("disputeFreezeViolations", if (not(h.disputeFreezeActive)) h.disputeFreezeViolations else (h.disputeFreezeViolations + 1)) else h' = h
  action stepUnilateralSign = any { step, admitOpUnilateral }
  // Countermodel engineering.defense.federated-org-reciprocity.dispute-freeze (dropped guard: require-no-dispute-freeze)
  action admitOpFrozen = if ((h.admittedFedOps < 2 and h.treatyRatified and (h.originOrgSigned and h.targetOrgSigned) and true)) h' = h.with("admittedFedOps", (h.admittedFedOps + 1)).with("unratifiedTreatyViolations", if (h.treatyRatified) h.unratifiedTreatyViolations else (h.unratifiedTreatyViolations + 1)).with("unilateralSignViolations", if ((h.originOrgSigned and h.targetOrgSigned)) h.unilateralSignViolations else (h.unilateralSignViolations + 1)).with("disputeFreezeViolations", if (not(h.disputeFreezeActive)) h.disputeFreezeViolations else (h.disputeFreezeViolations + 1)) else h' = h
  action stepDisputeFreeze = any { step, admitOpFrozen }
  run cleanFederatedOpTest = init.then(ratifyBilateralTreaty).then(originOrgSign).then(targetOrgSign).then(admitFederatedOp).then(all { assert(safety), assert(h.admittedFedOps == 1), h' = h })
  run unratifiedTreatyViolatesSafetyTest = init.then(originOrgSign).then(targetOrgSign).then(admitOpUnratified).then(all { assert(not(safety)), assert(h.unratifiedTreatyViolations > 0), h' = h })
  run unilateralSignViolatesSafetyTest = init.then(ratifyBilateralTreaty).then(originOrgSign).then(admitOpUnilateral).then(all { assert(not(safety)), assert(h.unilateralSignViolations > 0), h' = h })
  run disputeFreezeViolatesSafetyTest = init.then(ratifyBilateralTreaty).then(originOrgSign).then(targetOrgSign).then(raiseDisputeFreeze).then(admitOpFrozen).then(all { assert(not(safety)), assert(h.disputeFreezeViolations > 0), h' = h })
}
