// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.identity.delegated-agent-authz
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel obo-scope-attenuation step=stepScopeAmplification max-steps=6 itf="h.scopeAmplified == true"
// @countermodel obo-actor-provenance step=stepActorImpersonation max-steps=6 itf="h.impersonatedHuman == true"
// @countermodel obo-revocation-currency step=stepZombieDelegation max-steps=6 itf="h.zombieDelegatedUse == true"
// @countermodel step-up-verified-floor step=stepStepUpBypass max-steps=6 itf="h.unverifiedPrivileged == true"
// Limits: Finite RFC 8693 OBO delegation and RFC 9470 step-up abstraction; does not model JWT signature verification, multi-hop nested act arrays beyond depth 1, or IdP MFA phishing resistance.
module delegated_agent_authz {
  import authority_currentness.* from "../../zero-trust/authority-currentness/AuthorityCurrentness"
  type State = { humanAuthEpoch: int, humanSignedIn: bool, humanScopeLevel: int, emailVerified: bool, stepUpFresh: bool, delegatedActive: bool, delegatedEpoch: int, delegatedScopeLevel: int, humanGatesApproved: int, executedScopeLevel: int, scopeAmplified: bool, impersonatedHuman: bool, zombieDelegatedUse: bool, unverifiedPrivileged: bool }
  var h: State
  action init = h' = { humanAuthEpoch: 1, humanSignedIn: true, humanScopeLevel: 2, emailVerified: true, stepUpFresh: false, delegatedActive: false, delegatedEpoch: 0, delegatedScopeLevel: 0, humanGatesApproved: 0, executedScopeLevel: 0, scopeAmplified: false, impersonatedHuman: false, zombieDelegatedUse: false, unverifiedPrivileged: false }
  action performStepUp = if ((h.humanSignedIn and h.emailVerified and not(h.stepUpFresh))) h' = h.with("stepUpFresh", true) else h' = h
  action revokeHumanSession = if ((h.humanSignedIn and h.humanAuthEpoch < 3)) h' = h.with("humanSignedIn", false).with("stepUpFresh", false).with("humanAuthEpoch", (h.humanAuthEpoch + 1)) else h' = h
  action reauthenticateHumanAs(verified: bool): bool = if ((not(h.humanSignedIn) and h.humanAuthEpoch < 3)) h' = h.with("humanSignedIn", true).with("emailVerified", verified).with("stepUpFresh", false).with("humanAuthEpoch", (h.humanAuthEpoch + 1)) else h' = h
  action reauthenticateHuman = { nondet verified = Set(true, false).oneOf()
    reauthenticateHumanAs(verified) }
  action delegateToAgentAs(reqScope: int): bool = if ((h.humanSignedIn and not(h.delegatedActive) and reqScope <= h.humanScopeLevel)) h' = h.with("delegatedActive", true).with("delegatedEpoch", h.humanAuthEpoch).with("delegatedScopeLevel", reqScope).with("scopeAmplified", (h.scopeAmplified or reqScope > h.humanScopeLevel)) else h' = h
  action delegateToAgent = { nondet reqScope = Set(1, 2, 3).oneOf()
    delegateToAgentAs(reqScope) }
  action executeDelegated = if ((h.delegatedActive and (h.humanSignedIn and epochCurrent(h.humanAuthEpoch, h.delegatedEpoch)))) h' = h.with("delegatedActive", false).with("executedScopeLevel", h.delegatedScopeLevel).with("zombieDelegatedUse", (h.zombieDelegatedUse or not(h.humanSignedIn) or h.humanAuthEpoch != h.delegatedEpoch)) else h' = h
  action approveHumanOnlyGateAs(isAgent: bool): bool = if ((h.humanSignedIn and h.humanGatesApproved < 3 and (not(isAgent) or h.delegatedActive) and not(isAgent))) h' = h.with("humanGatesApproved", (h.humanGatesApproved + 1)).with("impersonatedHuman", (h.impersonatedHuman or isAgent)) else h' = h
  action approveHumanOnlyGate = { nondet isAgent = Set(false, true).oneOf()
    approveHumanOnlyGateAs(isAgent) }
  action executePrivilegedHuman = if ((h.humanSignedIn and h.emailVerified and h.stepUpFresh)) h' = h.with("stepUpFresh", false).with("unverifiedPrivileged", (h.unverifiedPrivileged or not(h.humanSignedIn) or not(h.emailVerified) or not(h.stepUpFresh))) else h' = h
  action step = any { performStepUp, revokeHumanSession, reauthenticateHuman, delegateToAgent, executeDelegated, approveHumanOnlyGate, executePrivilegedHuman }
  val safety = (not(h.scopeAmplified) and not(h.impersonatedHuman) and not(h.zombieDelegatedUse) and not(h.unverifiedPrivileged))
  // Countermodel threat.identity.delegated-agent-authz.scope-amplification (dropped guard: obo-scope-attenuation)
  action delegateToAgentNoAtten(reqScope: int): bool = if ((h.humanSignedIn and not(h.delegatedActive) and true)) h' = h.with("delegatedActive", true).with("delegatedEpoch", h.humanAuthEpoch).with("delegatedScopeLevel", reqScope).with("scopeAmplified", (h.scopeAmplified or reqScope > h.humanScopeLevel)) else h' = h
  action stepScopeAmplification = any { step, { nondet reqScope = Set(1, 2, 3).oneOf()
    delegateToAgentNoAtten(reqScope) } }
  // Countermodel threat.identity.delegated-agent-authz.actor-impersonation (dropped guard: obo-actor-provenance)
  action approveGateNoProvenance(isAgent: bool): bool = if ((h.humanSignedIn and h.humanGatesApproved < 3 and (not(isAgent) or h.delegatedActive) and true)) h' = h.with("humanGatesApproved", (h.humanGatesApproved + 1)).with("impersonatedHuman", (h.impersonatedHuman or isAgent)) else h' = h
  action stepActorImpersonation = any { step, { nondet isAgent = Set(false, true).oneOf()
    approveGateNoProvenance(isAgent) } }
  // Countermodel threat.identity.delegated-agent-authz.zombie-revoked-delegation (dropped guard: obo-revocation-currency)
  action executeDelegatedNoRevoke = if ((h.delegatedActive and true)) h' = h.with("delegatedActive", false).with("executedScopeLevel", h.delegatedScopeLevel).with("zombieDelegatedUse", (h.zombieDelegatedUse or not(h.humanSignedIn) or h.humanAuthEpoch != h.delegatedEpoch)) else h' = h
  action stepZombieDelegation = any { step, executeDelegatedNoRevoke }
  // Countermodel threat.identity.delegated-agent-authz.step-up-bypass (dropped guard: step-up-verified-floor)
  action executePrivilegedNoStepUp = if (true) h' = h.with("stepUpFresh", false).with("unverifiedPrivileged", (h.unverifiedPrivileged or not(h.humanSignedIn) or not(h.emailVerified) or not(h.stepUpFresh))) else h' = h
  action stepStepUpBypass = any { step, executePrivilegedNoStepUp }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run attenuatedDelegationAndStepUpSafeTest = init.then(delegateToAgentAs(1)).then(executeDelegated).then(performStepUp).then(executePrivilegedHuman).then(approveHumanOnlyGateAs(false)).then(all { assert(h.executedScopeLevel == 1), assert(h.humanGatesApproved == 1), assert(safety), h' = h })
  run revocationBlocksDelegatedAgentTest = init.then(delegateToAgentAs(2)).then(revokeHumanSession).then(executeDelegated).then(all { assert(h.executedScopeLevel == 0), assert(safety), h' = h })
  run scopeAmplificationCountermodelTest = init.then(delegateToAgentNoAtten(3)).then(checkUnsafe)
  run actorImpersonationCountermodelTest = init.then(delegateToAgentAs(1)).then(approveGateNoProvenance(true)).then(checkUnsafe)
  run zombieDelegatedCountermodelTest = init.then(delegateToAgentAs(2)).then(revokeHumanSession).then(executeDelegatedNoRevoke).then(checkUnsafe)
  run stepUpBypassCountermodelTest = init.then(executePrivilegedNoStepUp).then(checkUnsafe)
}
