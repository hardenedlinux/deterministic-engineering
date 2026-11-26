// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.zero-trust.shared-context-governance
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel private-scope-isolation step=stepPrivateContextLeak max-steps=6 itf="h.privateLeak == true"
// @countermodel owner-only-scope-promotion step=stepUnauthorizedPromotion max-steps=6 itf="h.unauthorizedPromote == true"
// @countermodel share-membership-current step=stepRevokedMemberRead max-steps=6 itf="h.revokedReadLeak == true"
// @countermodel multi-party-taint-gate step=stepMultiPartyTaintHijack max-steps=6 itf="h.taintedToolHijack == true"
// Limits: Finite two-principal scope-promotion, ACL-epoch revocation, and multi-party taint abstraction; does not model vector-embedding semantic leakage, encrypted group key agreement, or side-channel cache timing.
module shared_context_governance {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { entryScope: int, entryConfidential: bool, entryDeclassified: bool, peerInChannel: bool, aclEpoch: int, peerHandleIssued: bool, peerHandleEpoch: int, channelTainted: bool, peerReads: int, agentToolCalls: int, privateLeak: bool, unauthorizedPromote: bool, revokedReadLeak: bool, taintedToolHijack: bool }
  var h: State
  action init = h' = { entryScope: 0, entryConfidential: true, entryDeclassified: false, peerInChannel: true, aclEpoch: 1, peerHandleIssued: false, peerHandleEpoch: 0, channelTainted: false, peerReads: 0, agentToolCalls: 0, privateLeak: false, unauthorizedPromote: false, revokedReadLeak: false, taintedToolHijack: false }
  action promoteScopeAs(actorIsOwner: bool, explicitDeclassify: bool): bool = if ((h.entryScope == 0 and (actorIsOwner and (not(h.entryConfidential) or explicitDeclassify)))) h' = h.with("entryScope", 1).with("entryDeclassified", (h.entryDeclassified or explicitDeclassify)).with("unauthorizedPromote", (h.unauthorizedPromote or not(actorIsOwner) or (h.entryConfidential and not(explicitDeclassify)))) else h' = h
  action promoteScope = { nondet actorIsOwner = Set(false, true).oneOf()
    nondet explicitDeclassify = Set(false, true).oneOf()
    promoteScopeAs(actorIsOwner, explicitDeclassify) }
  action mintPeerHandle = if ((h.peerInChannel and not(h.peerHandleIssued))) h' = h.with("peerHandleIssued", true).with("peerHandleEpoch", h.aclEpoch) else h' = h
  action peerReadContext = if ((h.peerHandleIssued and h.peerReads < 3 and h.entryScope >= 1 and (h.peerInChannel and epochCurrent(h.aclEpoch, h.peerHandleEpoch)))) h' = h.with("peerReads", (h.peerReads + 1)).with("privateLeak", (h.privateLeak or h.entryScope == 0)).with("revokedReadLeak", (h.revokedReadLeak or not(h.peerInChannel) or h.aclEpoch != h.peerHandleEpoch)) else h' = h
  action revokePeerAccess = if ((h.peerInChannel and h.aclEpoch < 4)) h' = h.with("peerInChannel", false).with("aclEpoch", (h.aclEpoch + 1)) else h' = h
  action rejoinPeer = if ((not(h.peerInChannel) and h.aclEpoch < 4)) h' = h.with("peerInChannel", true).with("peerHandleIssued", false).with("peerHandleEpoch", 0) else h' = h
  action poisonSharedContext = h' = h.with("channelTainted", true)
  action agentExecToolAs(humanGateApproved: bool): bool = if ((h.agentToolCalls < 3 and (not(h.channelTainted) or humanGateApproved))) h' = h.with("agentToolCalls", (h.agentToolCalls + 1)).with("taintedToolHijack", (h.taintedToolHijack or (h.channelTainted and not(humanGateApproved)))) else h' = h
  action agentExecTool = { nondet humanGateApproved = Set(false, true).oneOf()
    agentExecToolAs(humanGateApproved) }
  action step = any { promoteScope, mintPeerHandle, peerReadContext, revokePeerAccess, rejoinPeer, poisonSharedContext, agentExecTool }
  val safety = (not(h.privateLeak) and not(h.unauthorizedPromote) and not(h.revokedReadLeak) and not(h.taintedToolHijack))
  // Countermodel threat.zero-trust.shared-context-governance.private-context-leak (dropped guard: private-scope-isolation)
  action peerReadNoScopeCheck = if ((h.peerHandleIssued and h.peerReads < 3 and true and (h.peerInChannel and epochCurrent(h.aclEpoch, h.peerHandleEpoch)))) h' = h.with("peerReads", (h.peerReads + 1)).with("privateLeak", (h.privateLeak or h.entryScope == 0)).with("revokedReadLeak", (h.revokedReadLeak or not(h.peerInChannel) or h.aclEpoch != h.peerHandleEpoch)) else h' = h
  action stepPrivateContextLeak = any { step, peerReadNoScopeCheck }
  // Countermodel threat.zero-trust.shared-context-governance.unauthorized-promotion (dropped guard: owner-only-scope-promotion)
  action promoteScopeUnchecked(actorIsOwner: bool, explicitDeclassify: bool): bool = if ((h.entryScope == 0 and true)) h' = h.with("entryScope", 1).with("entryDeclassified", (h.entryDeclassified or explicitDeclassify)).with("unauthorizedPromote", (h.unauthorizedPromote or not(actorIsOwner) or (h.entryConfidential and not(explicitDeclassify)))) else h' = h
  action stepUnauthorizedPromotion = any { step, { nondet actorIsOwner = Set(false, true).oneOf()
    nondet explicitDeclassify = Set(false, true).oneOf()
    promoteScopeUnchecked(actorIsOwner, explicitDeclassify) } }
  // Countermodel threat.zero-trust.shared-context-governance.revoked-member-read (dropped guard: share-membership-current)
  action peerReadNoAclCheck = if ((h.peerHandleIssued and h.peerReads < 3 and h.entryScope >= 1 and true)) h' = h.with("peerReads", (h.peerReads + 1)).with("privateLeak", (h.privateLeak or h.entryScope == 0)).with("revokedReadLeak", (h.revokedReadLeak or not(h.peerInChannel) or h.aclEpoch != h.peerHandleEpoch)) else h' = h
  action stepRevokedMemberRead = any { step, peerReadNoAclCheck }
  // Countermodel threat.zero-trust.shared-context-governance.multi-party-taint-hijack (dropped guard: multi-party-taint-gate)
  action agentExecToolNoTaintGate(humanGateApproved: bool): bool = if ((h.agentToolCalls < 3 and true)) h' = h.with("agentToolCalls", (h.agentToolCalls + 1)).with("taintedToolHijack", (h.taintedToolHijack or (h.channelTainted and not(humanGateApproved)))) else h' = h
  action stepMultiPartyTaintHijack = any { step, { nondet humanGateApproved = Set(false, true).oneOf()
    agentExecToolNoTaintGate(humanGateApproved) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validOwnerPromoteAndPeerReadTest = init.then(promoteScopeAs(true, true)).then(mintPeerHandle).then(peerReadContext).then(all { assert(h.entryScope == 1), assert(h.peerReads == 1), assert(safety), h' = h })
  run privateAndRevokedReadsBlockedTest = init.then(mintPeerHandle).then(peerReadContext).then(promoteScopeAs(false, true)).then(promoteScopeAs(true, true)).then(revokePeerAccess).then(peerReadContext).then(all { assert(h.peerReads == 0), assert(not(h.privateLeak)), assert(not(h.unauthorizedPromote)), assert(not(h.revokedReadLeak)), assert(safety), h' = h })
  run taintedSharedContextRequiresGateTest = init.then(poisonSharedContext).then(agentExecToolAs(false)).then(agentExecToolAs(true)).then(all { assert(h.agentToolCalls == 1), assert(not(h.taintedToolHijack)), assert(safety), h' = h })
  run privateLeakCountermodelTest = init.then(mintPeerHandle).then(peerReadNoScopeCheck).then(checkUnsafe)
  run unauthorizedPromoteCountermodelTest = init.then(promoteScopeUnchecked(false, false)).then(checkUnsafe)
  run revokedReadCountermodelTest = init.then(promoteScopeAs(true, true)).then(mintPeerHandle).then(revokePeerAccess).then(peerReadNoAclCheck).then(checkUnsafe)
  run multiPartyTaintCountermodelTest = init.then(poisonSharedContext).then(agentExecToolNoTaintGate(false)).then(checkUnsafe)
}
