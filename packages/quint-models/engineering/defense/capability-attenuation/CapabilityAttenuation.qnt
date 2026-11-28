// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.capability-attenuation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel enforce-monotonic-attenuation step=stepScopeEscalation max-steps=6 itf="h.escalationViolations > 0"
// @countermodel forbid-revoked-ancestor-subtree step=stepRevokedSubtree max-steps=6 itf="h.revokedSubtreeExecutions > 0"
// @countermodel require-valid-mac-and-depth step=stepForgedOrDepth max-steps=6 itf="h.forgedOrDepthViolations > 0"
// Limits: Finite two-hop monotonic scope attenuation, chain MAC integrity, hop-depth bound, and M3 cascading revocation abstraction; does not model side-channel exfiltration by an authorized delegate or out-of-band network collusion.
module capability_attenuation {
  type State = { rootScope: int, parentScope: int, childScope: int, delegationDepth: int, maxDepth: int, parentDelegatable: bool, chainMacValid: bool, ancestorRevoked: bool, escalationViolations: int, revokedSubtreeExecutions: int, forgedOrDepthViolations: int, validExecutions: int }
  var h: State
  action init = h' = { rootScope: 3, parentScope: 0, childScope: 0, delegationDepth: 0, maxDepth: 2, parentDelegatable: true, chainMacValid: false, ancestorRevoked: false, escalationViolations: 0, revokedSubtreeExecutions: 0, forgedOrDepthViolations: 0, validExecutions: 0 }
  action mintParentDelegation = if (h.parentScope == 0) h' = h.with("parentScope", 2).with("delegationDepth", 1).with("chainMacValid", true) else h' = h
  action attenuateChildSafe = if ((h.parentScope > 0 and h.childScope == 0)) h' = h.with("childScope", 1).with("delegationDepth", 2).with("chainMacValid", true) else h' = h
  action attemptScopeEscalation = if ((h.parentScope > 0 and h.childScope == 0)) h' = h.with("childScope", 3).with("delegationDepth", 2).with("chainMacValid", true) else h' = h
  action attemptTamperMacOrDepth = if ((h.parentScope > 0 and h.chainMacValid)) h' = h.with("chainMacValid", false).with("delegationDepth", 3) else h' = h
  action freezeParentDelegation = if (h.parentDelegatable) h' = h.with("parentDelegatable", false) else h' = h
  action revokeAncestorInM3 = if (not(h.ancestorRevoked)) h' = h.with("ancestorRevoked", true) else h' = h
  action executeDelegatedAction = if (((h.childScope > 0 and h.childScope <= h.parentScope and h.parentScope <= h.rootScope) and not(h.ancestorRevoked) and (h.chainMacValid and h.parentDelegatable and h.delegationDepth <= h.maxDepth))) h' = h.with("validExecutions", (h.validExecutions + 1)).with("escalationViolations", if ((h.childScope > 0 and h.childScope <= h.parentScope and h.parentScope <= h.rootScope)) h.escalationViolations else (h.escalationViolations + 1)).with("revokedSubtreeExecutions", if (not(h.ancestorRevoked)) h.revokedSubtreeExecutions else (h.revokedSubtreeExecutions + 1)).with("forgedOrDepthViolations", if ((h.chainMacValid and h.parentDelegatable and h.delegationDepth <= h.maxDepth)) h.forgedOrDepthViolations else (h.forgedOrDepthViolations + 1)) else h' = h
  action step = any { mintParentDelegation, attenuateChildSafe, attemptScopeEscalation, attemptTamperMacOrDepth, freezeParentDelegation, revokeAncestorInM3, executeDelegatedAction }
  val safety = (h.escalationViolations == 0 and h.revokedSubtreeExecutions == 0 and h.forgedOrDepthViolations == 0)
  // Countermodel engineering.defense.capability-attenuation.scope-escalation (dropped guard: enforce-monotonic-attenuation)
  action executeEscalated = if ((true and not(h.ancestorRevoked) and (h.chainMacValid and h.parentDelegatable and h.delegationDepth <= h.maxDepth))) h' = h.with("validExecutions", (h.validExecutions + 1)).with("escalationViolations", if ((h.childScope > 0 and h.childScope <= h.parentScope and h.parentScope <= h.rootScope)) h.escalationViolations else (h.escalationViolations + 1)).with("revokedSubtreeExecutions", if (not(h.ancestorRevoked)) h.revokedSubtreeExecutions else (h.revokedSubtreeExecutions + 1)).with("forgedOrDepthViolations", if ((h.chainMacValid and h.parentDelegatable and h.delegationDepth <= h.maxDepth)) h.forgedOrDepthViolations else (h.forgedOrDepthViolations + 1)) else h' = h
  action stepScopeEscalation = any { step, executeEscalated }
  // Countermodel engineering.defense.capability-attenuation.revoked-subtree (dropped guard: forbid-revoked-ancestor-subtree)
  action executeRevokedSubtree = if (((h.childScope > 0 and h.childScope <= h.parentScope and h.parentScope <= h.rootScope) and true and (h.chainMacValid and h.parentDelegatable and h.delegationDepth <= h.maxDepth))) h' = h.with("validExecutions", (h.validExecutions + 1)).with("escalationViolations", if ((h.childScope > 0 and h.childScope <= h.parentScope and h.parentScope <= h.rootScope)) h.escalationViolations else (h.escalationViolations + 1)).with("revokedSubtreeExecutions", if (not(h.ancestorRevoked)) h.revokedSubtreeExecutions else (h.revokedSubtreeExecutions + 1)).with("forgedOrDepthViolations", if ((h.chainMacValid and h.parentDelegatable and h.delegationDepth <= h.maxDepth)) h.forgedOrDepthViolations else (h.forgedOrDepthViolations + 1)) else h' = h
  action stepRevokedSubtree = any { step, executeRevokedSubtree }
  // Countermodel engineering.defense.capability-attenuation.forged-or-depth (dropped guard: require-valid-mac-and-depth)
  action executeForgedOrOverDepth = if (((h.childScope > 0 and h.childScope <= h.parentScope and h.parentScope <= h.rootScope) and not(h.ancestorRevoked) and true)) h' = h.with("validExecutions", (h.validExecutions + 1)).with("escalationViolations", if ((h.childScope > 0 and h.childScope <= h.parentScope and h.parentScope <= h.rootScope)) h.escalationViolations else (h.escalationViolations + 1)).with("revokedSubtreeExecutions", if (not(h.ancestorRevoked)) h.revokedSubtreeExecutions else (h.revokedSubtreeExecutions + 1)).with("forgedOrDepthViolations", if ((h.chainMacValid and h.parentDelegatable and h.delegationDepth <= h.maxDepth)) h.forgedOrDepthViolations else (h.forgedOrDepthViolations + 1)) else h' = h
  action stepForgedOrDepth = any { step, executeForgedOrOverDepth }
  run monotonicAttenuationAndSafeExecutionTest = init.then(mintParentDelegation).then(attenuateChildSafe).then(executeDelegatedAction).then(all { assert(safety), assert(h.validExecutions == 1), assert(h.childScope <= h.parentScope), h' = h })
  run scopeEscalationViolatesSafetyTest = init.then(mintParentDelegation).then(attemptScopeEscalation).then(executeEscalated).then(all { assert(not(safety)), assert(h.escalationViolations > 0), h' = h })
  run revokedSubtreeViolatesSafetyTest = init.then(mintParentDelegation).then(attenuateChildSafe).then(revokeAncestorInM3).then(executeRevokedSubtree).then(all { assert(not(safety)), assert(h.revokedSubtreeExecutions > 0), h' = h })
  run forgedOrOverDepthViolatesSafetyTest = init.then(mintParentDelegation).then(attenuateChildSafe).then(attemptTamperMacOrDepth).then(executeForgedOrOverDepth).then(all { assert(not(safety)), assert(h.forgedOrDepthViolations > 0), h' = h })
}
