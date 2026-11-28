// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.policy-admission-sufficiency
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel enforce-policy-direct-record step=stepBypassDirectRecord max-steps=6 itf="h.verdictQualified == true and h.policyRequiresDirectRecord == true and h.directRecordPresent == false"
// @countermodel require-admitted-method-mapping step=stepUnadmittedMethod max-steps=6 itf="h.verdictQualified == true and h.methodAdmissionStatus != 1"
// @countermodel preserve-authentic-method-on-refusal step=stepPurgeMethodOnRefusal max-steps=6 itf="h.methodPreserved == false"
// Limits: Finite single-verdict policy-admission and sufficiency abstraction (methodAdmissionStatus: 0=unknown, 1=admitted, 2=forbidden); does not model multi-tenant delegation chains or cryptographic receipt verification.
module policy_admission_sufficiency {
  type State = { historySufficient: bool, policyRequiresDirectRecord: bool, directRecordPresent: bool, methodAdmissionStatus: int, verdictQualified: bool, methodPreserved: bool }
  var h: State
  action init = h' = { historySufficient: false, policyRequiresDirectRecord: false, directRecordPresent: false, methodAdmissionStatus: 0, verdictQualified: false, methodPreserved: true }
  action supplySufficientHistory = if (not(h.historySufficient)) h' = h.with("historySufficient", true) else h' = h
  action requireDirectRecordPolicy = if ((not(h.policyRequiresDirectRecord) and not(h.verdictQualified))) h' = h.with("policyRequiresDirectRecord", true) else h' = h
  action supplyDirectRecord = if (not(h.directRecordPresent)) h' = h.with("directRecordPresent", true) else h' = h
  action admitMethodMapping = if (h.methodAdmissionStatus == 0) h' = h.with("methodAdmissionStatus", 1) else h' = h
  action forbidMethodMapping = if (h.methodAdmissionStatus == 0) h' = h.with("methodAdmissionStatus", 2) else h' = h
  action refuseUnadmittedBinding = if (h.methodAdmissionStatus == 2) h' = h.with("methodPreserved", h.methodPreserved) else h' = h
  action qualifyVerdict = if ((h.historySufficient and (not(h.policyRequiresDirectRecord) or h.directRecordPresent) and h.methodAdmissionStatus == 1)) h' = h.with("verdictQualified", true) else h' = h
  action step = any { supplySufficientHistory, requireDirectRecordPolicy, supplyDirectRecord, admitMethodMapping, forbidMethodMapping, refuseUnadmittedBinding, qualifyVerdict }
  val safety = (h.methodPreserved and (not(h.verdictQualified) or h.historySufficient) and (not(h.verdictQualified) or not(h.policyRequiresDirectRecord) or h.directRecordPresent) and (not(h.verdictQualified) or h.methodAdmissionStatus == 1))
  // Countermodel engineering.defense.policy-admission-sufficiency.bypass-direct-record (dropped guard: enforce-policy-direct-record)
  action qualifyWithoutDirectRecord = if ((h.historySufficient and true and h.methodAdmissionStatus == 1)) h' = h.with("verdictQualified", true) else h' = h
  action stepBypassDirectRecord = any { step, qualifyWithoutDirectRecord }
  // Countermodel engineering.defense.policy-admission-sufficiency.unadmitted-method (dropped guard: require-admitted-method-mapping)
  action qualifyWithoutAdmittedMethod = if ((h.historySufficient and (not(h.policyRequiresDirectRecord) or h.directRecordPresent) and true)) h' = h.with("verdictQualified", true) else h' = h
  action stepUnadmittedMethod = any { step, qualifyWithoutAdmittedMethod }
  // Countermodel engineering.defense.policy-admission-sufficiency.purge-method-on-refusal (dropped guard: preserve-authentic-method-on-refusal)
  action refuseAndPurgeMethod = if (h.methodAdmissionStatus == 2) h' = h.with("methodPreserved", false) else h' = h
  action stepPurgeMethodOnRefusal = any { step, refuseAndPurgeMethod }
  run sufficientHistoryWithoutDirectPolicyTest = init.then(supplySufficientHistory).then(admitMethodMapping).then(qualifyVerdict).then(all { assert(safety), assert(h.verdictQualified), assert(not(h.directRecordPresent)), h' = h })
  run strictPolicyNeedsDirectRecordTest = init.then(supplySufficientHistory).then(requireDirectRecordPolicy).then(admitMethodMapping).then(qualifyVerdict).then(all { assert(safety), assert(not(h.verdictQualified)), h' = h }).then(supplyDirectRecord).then(qualifyVerdict).then(all { assert(safety), assert(h.verdictQualified), h' = h })
  run bypassDirectRecordCountermodelTest = init.then(supplySufficientHistory).then(requireDirectRecordPolicy).then(admitMethodMapping).then(qualifyWithoutDirectRecord).then(all { assert(not(safety)), assert(h.verdictQualified), assert(h.policyRequiresDirectRecord), assert(not(h.directRecordPresent)), h' = h })
  run unadmittedMethodCountermodelTest = init.then(supplySufficientHistory).then(qualifyWithoutAdmittedMethod).then(all { assert(not(safety)), assert(h.verdictQualified), assert(h.methodAdmissionStatus != 1), h' = h })
  run purgeMethodOnRefusalCountermodelTest = init.then(forbidMethodMapping).then(refuseAndPurgeMethod).then(all { assert(not(safety)), assert(not(h.methodPreserved)), h' = h })
}
