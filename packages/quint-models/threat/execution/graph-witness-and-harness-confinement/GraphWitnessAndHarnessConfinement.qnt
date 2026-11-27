// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.graph-witness-and-harness-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-sealed-witness-or-epoch-serde-forgery step=stepWitnessForgery max-steps=6 itf="h.witnessForgeryBreaches > 0"
// @countermodel forbid-policy-decision-routing-or-dup-edge-bypass step=stepRoutingPolicyBypass max-steps=6 itf="h.routingPolicyBreaches > 0"
// @countermodel forbid-harness-cedar-capability-spoof-or-case-bypass step=stepCedarCapabilitySpoof max-steps=6 itf="h.cedarSpoofBreaches > 0"
// @countermodel forbid-artifact-symlink-escape-or-config-env-exfil step=stepArtifactOrConfigEscape max-steps=6 itf="h.artifactConfigBreaches > 0"
// Limits: Finite bounded AgentGraph witness/routing & live-harness governance/artifact confinement state machine (fencingEpoch <= 12, contextCut <= 12, stepCount <= 12); models custom validated Deserialize parity on AdmittedGovernedContext, AdmittedMarlinDispatch & FencingEpoch with Detached-settlement/overflow reconciliation guards, PolicyDecision evidence + duplicate-edge rejection in AgentGraph planning/projection, destructive-tool precedence & case-insensitive Cedar gate admission in CompiledHarnessGovernanceGate, symlink-safe atomic intent-case artifact materialization, and bounded non-symlink Weaver TOML route loading with timeout & credential_env allowlist hygiene, without modeling OS kernel VFS races or remote LLM wire transport.
module execution_graph_witness_and_harness_confinement {
  type State = { fencingEpoch: int, contextCut: int, witnessSerdeEnforced: bool, routingPolicyEnforced: bool, cedarGateHardened: bool, artifactAndConfigConfined: bool, witnessForgeryBreaches: int, routingPolicyBreaches: int, cedarSpoofBreaches: int, artifactConfigBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { fencingEpoch: 1, contextCut: 1, witnessSerdeEnforced: true, routingPolicyEnforced: true, cedarGateHardened: true, artifactAndConfigConfined: true, witnessForgeryBreaches: 0, routingPolicyBreaches: 0, cedarSpoofBreaches: 0, artifactConfigBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action admitVerifiedGraphWitness = if ((h.stepCount < 12 and h.witnessSerdeEnforced and h.fencingEpoch < 12)) h' = h.with("fencingEpoch", (h.fencingEpoch + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action planPolicyScopedGraphRoute = if ((h.stepCount < 12 and h.routingPolicyEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action evaluateCedarHarnessToolGate = if ((h.stepCount < 12 and h.cedarGateHardened)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action materializeConfinedArtifactBundle = if ((h.stepCount < 12 and h.artifactAndConfigConfined)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action loadBoundedWeaverTomlRoute = if ((h.stepCount < 12 and h.artifactAndConfigConfined)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action advanceGovernedContextCut = if ((h.stepCount < 12 and h.witnessSerdeEnforced and h.contextCut < 12)) h' = h.with("contextCut", (h.contextCut + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { admitVerifiedGraphWitness, planPolicyScopedGraphRoute, evaluateCedarHarnessToolGate, materializeConfinedArtifactBundle, loadBoundedWeaverTomlRoute, advanceGovernedContextCut }
  val safety = (h.witnessForgeryBreaches == 0 and h.routingPolicyBreaches == 0 and h.cedarSpoofBreaches == 0 and h.artifactConfigBreaches == 0 and h.witnessSerdeEnforced and h.routingPolicyEnforced and h.cedarGateHardened and h.artifactAndConfigConfined and h.fencingEpoch >= 1 and h.fencingEpoch <= 12 and h.contextCut >= 1 and h.contextCut <= 12 and h.stepCount <= 12)
  // Countermodel threat.execution.graph-witness-and-harness-confinement.witness-serde-forgery (dropped guard: forbid-sealed-witness-or-epoch-serde-forgery)
  action exploitWitnessForgery = if ((h.stepCount < 12)) h' = h.with("witnessSerdeEnforced", false).with("witnessForgeryBreaches", (h.witnessForgeryBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepWitnessForgery = any { step, exploitWitnessForgery }
  // Countermodel threat.execution.graph-witness-and-harness-confinement.routing-policy-bypass (dropped guard: forbid-policy-decision-routing-or-dup-edge-bypass)
  action exploitRoutingPolicyBypass = if ((h.stepCount < 12)) h' = h.with("routingPolicyEnforced", false).with("routingPolicyBreaches", (h.routingPolicyBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepRoutingPolicyBypass = any { step, exploitRoutingPolicyBypass }
  // Countermodel threat.execution.graph-witness-and-harness-confinement.cedar-capability-spoof (dropped guard: forbid-harness-cedar-capability-spoof-or-case-bypass)
  action exploitCedarCapabilitySpoof = if ((h.stepCount < 12)) h' = h.with("cedarGateHardened", false).with("cedarSpoofBreaches", (h.cedarSpoofBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepCedarCapabilitySpoof = any { step, exploitCedarCapabilitySpoof }
  // Countermodel threat.execution.graph-witness-and-harness-confinement.artifact-or-config-escape (dropped guard: forbid-artifact-symlink-escape-or-config-env-exfil)
  action exploitArtifactOrConfigEscape = if ((h.stepCount < 12)) h' = h.with("artifactAndConfigConfined", false).with("artifactConfigBreaches", (h.artifactConfigBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepArtifactOrConfigEscape = any { step, exploitArtifactOrConfigEscape }
  action checkSm35Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm35Violated = all { assert((h.witnessForgeryBreaches > 0 or h.routingPolicyBreaches > 0 or h.cedarSpoofBreaches > 0 or h.artifactConfigBreaches > 0)), assert(not(safety)), h' = h }
  run cleanGraphAndHarnessSafeTest = init.then(admitVerifiedGraphWitness).then(planPolicyScopedGraphRoute).then(evaluateCedarHarnessToolGate).then(materializeConfinedArtifactBundle).then(loadBoundedWeaverTomlRoute).then(advanceGovernedContextCut).then(checkSm35Safe)
  run witnessForgeryRefutedTest = init.then(exploitWitnessForgery).then(checkSm35Violated)
  run routingPolicyBypassRefutedTest = init.then(exploitRoutingPolicyBypass).then(checkSm35Violated)
  run cedarCapabilitySpoofRefutedTest = init.then(exploitCedarCapabilitySpoof).then(checkSm35Violated)
  run artifactOrConfigEscapeRefutedTest = init.then(exploitArtifactOrConfigEscape).then(checkSm35Violated)
}
