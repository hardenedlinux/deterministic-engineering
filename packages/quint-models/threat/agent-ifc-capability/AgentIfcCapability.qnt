// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.agent-ifc-capability
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel control-data-segregation step=stepPromptInjectionHijack max-steps=6 itf="h.toolInvoked == true and h.toolControlledByTainted == true"
// @countermodel capability-ifc-egress step=stepConfidentialExfiltration max-steps=6 itf="h.toolInvoked == true and h.sinkObservedSecret == true and not(h.sinkObservedDeclassified)"
// Limits: Finite lattice-label IFC abstraction (CaMeL/FIDES); does not model semantic prompt classification, covert timing channels, or LLM token probabilities.
module agent_ifc_capability {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { planIntegrityHigh: bool, dataTainted: bool, taintedPlanReady: bool, dataConfidential: bool, declassified: bool, toolInvoked: bool, toolControlledByTainted: bool, sinkObservedSecret: bool, sinkObservedDeclassified: bool }
  var h: State
  action init = h' = { planIntegrityHigh: true, dataTainted: false, taintedPlanReady: false, dataConfidential: false, declassified: false, toolInvoked: false, toolControlledByTainted: false, sinkObservedSecret: false, sinkObservedDeclassified: false }
  action ingestUntrustedData = h' = h.with("dataTainted", true).with("taintedPlanReady", true)
  action readConfidentialSecret = h' = h.with("dataConfidential", true).with("declassified", false)
  action approveDeclassification = if ((h.planIntegrityHigh and h.dataConfidential)) h' = h.with("declassified", true) else h' = h
  action invokeTrustedTool = if ((h.planIntegrityHigh and (not(h.dataConfidential) or h.declassified))) h' = h.with("toolInvoked", true).with("toolControlledByTainted", false).with("sinkObservedSecret", h.dataConfidential).with("sinkObservedDeclassified", h.declassified) else h' = h
  action step = any { ingestUntrustedData, readConfidentialSecret, approveDeclassification, invokeTrustedTool }
  val safety = (not(h.toolInvoked) or (not(h.toolControlledByTainted) and (not(h.sinkObservedSecret) or h.sinkObservedDeclassified)))
  // Countermodel threat.agent-ifc-capability.prompt-injection-control-hijack (dropped guard: control-data-segregation)
  action invokeToolFromTaintedData = if ((h.planIntegrityHigh and (not(h.dataConfidential) or h.declassified))) h' = h.with("toolInvoked", true).with("toolControlledByTainted", h.taintedPlanReady).with("sinkObservedSecret", h.dataConfidential).with("sinkObservedDeclassified", h.declassified) else h' = h
  action stepPromptInjectionHijack = any { step, invokeToolFromTaintedData }
  // Countermodel threat.agent-ifc-capability.confidential-exfiltration (dropped guard: capability-ifc-egress)
  action invokeToolNoIfcEgress = if ((h.planIntegrityHigh and true)) h' = h.with("toolInvoked", true).with("toolControlledByTainted", false).with("sinkObservedSecret", h.dataConfidential).with("sinkObservedDeclassified", h.declassified) else h' = h
  action stepConfidentialExfiltration = any { step, invokeToolNoIfcEgress }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run quarantinedUntrustedDataSafeTest = init.then(ingestUntrustedData).then(invokeTrustedTool).then(all { assert(h.toolInvoked), assert(not(h.toolControlledByTainted)), assert(safety), h' = h })
  run confidentialBlockedWithoutDeclassTest = init.then(readConfidentialSecret).then(invokeTrustedTool).then(all { assert(not(h.toolInvoked)), assert(safety), h' = h })
  run declassifiedEgressAllowedTest = init.then(readConfidentialSecret).then(approveDeclassification).then(invokeTrustedTool).then(all { assert(h.toolInvoked), assert(safety), h' = h })
  run promptInjectionHijackCountermodelTest = init.then(ingestUntrustedData).then(invokeToolFromTaintedData).then(checkUnsafe)
  run confidentialExfiltrationCountermodelTest = init.then(readConfidentialSecret).then(invokeToolNoIfcEgress).then(checkUnsafe)
}
