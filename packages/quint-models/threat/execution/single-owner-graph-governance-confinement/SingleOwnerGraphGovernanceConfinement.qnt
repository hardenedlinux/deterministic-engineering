// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.single-owner-graph-governance-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel wire-prod-executor-governance-gate step=stepDisconnectedGovernanceBypass max-steps=6 itf="h.disconnectedGovBypasses > 0"
// @countermodel retire-shadow-legacy-engine step=stepShadowLegacySplitBrain max-steps=6 itf="h.shadowLegacyExecutions > 0"
// @countermodel fail-closed-tripped-breaker step=stepTrippedBreakerFallthrough max-steps=6 itf="h.trippedBreakerBypasses > 0"
// @countermodel bind-fencing-and-governance-epoch step=stepStaleEpochDualDispatch max-steps=6 itf="h.staleEpochDualDispatches > 0"
// Limits: Finite single-owner GraphEngine execution convergence and production-reachable governance admission abstraction (ADV-L4 hostile attack tier); proves every production atomic effect and TaskActor dispatch traverses the active GovernanceAdmissionGate/ExecutionCircuitBreaker with zero legacy-loop shadow execution, not arbitrary OS kernel bypasses.
module execution_single_owner_graph_governance_confinement {
  type State = { governedAdmitted: int, hostileBlocked: int, disconnectedGovBypasses: int, shadowLegacyExecutions: int, trippedBreakerBypasses: int, staleEpochDualDispatches: int }
  var h: State
  action init = h' = { governedAdmitted: 0, hostileBlocked: 0, disconnectedGovBypasses: 0, shadowLegacyExecutions: 0, trippedBreakerBypasses: 0, staleEpochDualDispatches: 0 }
  action dispatchGovernedGraphEffect = h' = h.with("governedAdmitted", (h.governedAdmitted + 1))
  action dispatchGovernedTaskActor = h' = h.with("governedAdmitted", (h.governedAdmitted + 1))
  action blockTrippedBreakerEffect = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockCedarOrAscentForbid = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action rejectLegacyShadowDispatch = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action rejectStaleFencingEpoch = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action step = any { dispatchGovernedGraphEffect, dispatchGovernedTaskActor, blockTrippedBreakerEffect, blockCedarOrAscentForbid, rejectLegacyShadowDispatch, rejectStaleFencingEpoch }
  val safety = (h.disconnectedGovBypasses == 0 and h.shadowLegacyExecutions == 0 and h.trippedBreakerBypasses == 0 and h.staleEpochDualDispatches == 0)
  // Countermodel threat.execution.single-owner-graph-governance-confinement.disconnected-governance-bypass (dropped guard: wire-prod-executor-governance-gate)
  action executeUngatedProdGraphEffect = h' = h.with("disconnectedGovBypasses", (h.disconnectedGovBypasses + 1))
  action stepDisconnectedGovernanceBypass = any { step, executeUngatedProdGraphEffect }
  // Countermodel threat.execution.single-owner-graph-governance-confinement.shadow-legacy-split-brain (dropped guard: retire-shadow-legacy-engine)
  action executeUnretiredLegacyLoopEffect = h' = h.with("shadowLegacyExecutions", (h.shadowLegacyExecutions + 1))
  action stepShadowLegacySplitBrain = any { step, executeUnretiredLegacyLoopEffect }
  // Countermodel threat.execution.single-owner-graph-governance-confinement.tripped-breaker-fallthrough (dropped guard: fail-closed-tripped-breaker)
  action fallthroughTrippedEstopBreaker = h' = h.with("trippedBreakerBypasses", (h.trippedBreakerBypasses + 1))
  action stepTrippedBreakerFallthrough = any { step, fallthroughTrippedEstopBreaker }
  // Countermodel threat.execution.single-owner-graph-governance-confinement.stale-epoch-dual-dispatch (dropped guard: bind-fencing-and-governance-epoch)
  action dispatchStaleEpochAfterRevocation = h' = h.with("staleEpochDualDispatches", (h.staleEpochDualDispatches + 1))
  action stepStaleEpochDualDispatch = any { step, dispatchStaleEpochAfterRevocation }
  action checkSingleOwnerGovSafe = all { assert(h.governedAdmitted > 0), assert(h.hostileBlocked > 0), assert(h.disconnectedGovBypasses == 0), assert(h.shadowLegacyExecutions == 0), assert(h.trippedBreakerBypasses == 0), assert(h.staleEpochDualDispatches == 0), assert(safety), h' = h }
  action checkSingleOwnerGovViolated = all { assert((h.disconnectedGovBypasses > 0 or h.shadowLegacyExecutions > 0 or h.trippedBreakerBypasses > 0 or h.staleEpochDualDispatches > 0)), assert(not(safety)), h' = h }
  run singleOwnerGovSafeTest = init.then(dispatchGovernedGraphEffect).then(dispatchGovernedTaskActor).then(blockTrippedBreakerEffect).then(blockCedarOrAscentForbid).then(rejectLegacyShadowDispatch).then(rejectStaleFencingEpoch).then(checkSingleOwnerGovSafe)
  run disconnectedGovernanceBypassRefutedTest = init.then(executeUngatedProdGraphEffect).then(checkSingleOwnerGovViolated)
  run shadowLegacySplitBrainRefutedTest = init.then(executeUnretiredLegacyLoopEffect).then(checkSingleOwnerGovViolated)
  run trippedBreakerFallthroughRefutedTest = init.then(fallthroughTrippedEstopBreaker).then(checkSingleOwnerGovViolated)
  run staleEpochDualDispatchRefutedTest = init.then(dispatchStaleEpochAfterRevocation).then(checkSingleOwnerGovViolated)
}
