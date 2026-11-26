// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.protocol.chatroom-ingress-governance
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel ingress-origin-provenance step=stepForgedExternalIngress max-steps=6 itf="h.forgedGateReceipt == true"
// @countermodel channel-thread-affinity step=stepCrossChannelInject max-steps=6 itf="h.crossChannelInjected == true"
// @countermodel gate-oneshot-pending step=stepGateReplayOrAgentApprove max-steps=6 itf="h.gateReplayed == true"
// @countermodel matter-gate-lock step=stepAgentSelfUnblock max-steps=6 itf="h.agentSelfUnblocked == true"
// @countermodel tainted-tool-human-gate step=stepTaintedToolBypass max-steps=6 itf="h.taintedToolBypass == true"
// Limits: Finite multi-role agent chatroom ingress, channel affinity, and one-shot human gate governance abstraction; does not model cryptographic webhook HMAC algorithms, semantic LLM prompt classification, or federated transport encryption.
module chatroom_ingress_governance {
  type State = { gateId: int, gateStatus: int, matterBlockedByGate: bool, taintedExternalMsg: bool, toolExecuted: bool, forgedGateReceipt: bool, crossChannelInjected: bool, gateReplayed: bool, agentSelfUnblocked: bool, taintedToolBypass: bool }
  var h: State
  action init = h' = { gateId: 0, gateStatus: 0, matterBlockedByGate: false, taintedExternalMsg: false, toolExecuted: false, forgedGateReceipt: false, crossChannelInjected: false, gateReplayed: false, agentSelfUnblocked: false, taintedToolBypass: false }
  action ingestExternalAs(originVerified: bool, claimsGate: bool, targetCh: int, rootCh: int): bool = if (((originVerified and not(claimsGate)) and targetCh == rootCh)) h' = h.with("taintedExternalMsg", true).with("forgedGateReceipt", (h.forgedGateReceipt or not(originVerified) or claimsGate)).with("crossChannelInjected", (h.crossChannelInjected or targetCh != rootCh)) else h' = h
  action ingestExternal = { nondet originVerified = Set(true, false).oneOf()
    nondet claimsGate = Set(false, true).oneOf()
    nondet targetCh = Set(1, 2).oneOf()
    nondet rootCh = Set(1, 2).oneOf()
    ingestExternalAs(originVerified, claimsGate, targetCh, rootCh) }
  action agentRequestGate = if ((h.gateStatus != 1 and h.gateId < 3)) h' = h.with("gateId", (h.gateId + 1)).with("gateStatus", 1).with("matterBlockedByGate", true) else h' = h
  action resolveGateAs(isAgent: bool, approve: bool): bool = if ((h.gateId > 0 and (h.gateStatus == 1 and not(isAgent)))) h' = h.with("gateReplayed", (h.gateReplayed or h.gateStatus != 1 or isAgent)).with("gateStatus", if (approve) 2 else 3).with("matterBlockedByGate", if (approve) false else h.matterBlockedByGate) else h' = h
  action resolveGate = { nondet isAgent = Set(false, true).oneOf()
    nondet approve = Set(true, false).oneOf()
    resolveGateAs(isAgent, approve) }
  action unblockMatterAs(isAgent: bool): bool = if ((h.matterBlockedByGate and (not(h.matterBlockedByGate) or not(isAgent)))) h' = h.with("matterBlockedByGate", false).with("agentSelfUnblocked", (h.agentSelfUnblocked or isAgent)) else h' = h
  action unblockMatter = { nondet isAgent = Set(false, true).oneOf()
    unblockMatterAs(isAgent) }
  action agentInvokeTool = if ((not(h.taintedExternalMsg) or h.gateStatus == 2)) h' = h.with("toolExecuted", true).with("taintedToolBypass", (h.taintedToolBypass or (h.taintedExternalMsg and h.gateStatus != 2))) else h' = h
  action step = any { ingestExternal, agentRequestGate, resolveGate, unblockMatter, agentInvokeTool }
  val safety = (not(h.forgedGateReceipt) and not(h.crossChannelInjected) and not(h.gateReplayed) and not(h.agentSelfUnblocked) and not(h.taintedToolBypass))
  // Countermodel threat.protocol.chatroom-ingress-governance.forged-external-ingress (dropped guard: ingress-origin-provenance)
  action ingestExternalNoOrigin(originVerified: bool, claimsGate: bool, targetCh: int, rootCh: int): bool = if ((true and targetCh == rootCh)) h' = h.with("taintedExternalMsg", true).with("forgedGateReceipt", (h.forgedGateReceipt or not(originVerified) or claimsGate)).with("crossChannelInjected", (h.crossChannelInjected or targetCh != rootCh)) else h' = h
  action stepForgedExternalIngress = any { step, { nondet originVerified = Set(true, false).oneOf()
    nondet claimsGate = Set(false, true).oneOf()
    nondet targetCh = Set(1, 2).oneOf()
    nondet rootCh = Set(1, 2).oneOf()
    ingestExternalNoOrigin(originVerified, claimsGate, targetCh, rootCh) } }
  // Countermodel threat.protocol.chatroom-ingress-governance.cross-channel-inject (dropped guard: channel-thread-affinity)
  action ingestExternalNoChannelCheck(originVerified: bool, claimsGate: bool, targetCh: int, rootCh: int): bool = if (((originVerified and not(claimsGate)) and true)) h' = h.with("taintedExternalMsg", true).with("forgedGateReceipt", (h.forgedGateReceipt or not(originVerified) or claimsGate)).with("crossChannelInjected", (h.crossChannelInjected or targetCh != rootCh)) else h' = h
  action stepCrossChannelInject = any { step, { nondet originVerified = Set(true, false).oneOf()
    nondet claimsGate = Set(false, true).oneOf()
    nondet targetCh = Set(1, 2).oneOf()
    nondet rootCh = Set(1, 2).oneOf()
    ingestExternalNoChannelCheck(originVerified, claimsGate, targetCh, rootCh) } }
  // Countermodel threat.protocol.chatroom-ingress-governance.gate-replay-or-agent-approve (dropped guard: gate-oneshot-pending)
  action resolveGateNoOneShot(isAgent: bool, approve: bool): bool = if ((h.gateId > 0 and true)) h' = h.with("gateReplayed", (h.gateReplayed or h.gateStatus != 1 or isAgent)).with("gateStatus", if (approve) 2 else 3).with("matterBlockedByGate", if (approve) false else h.matterBlockedByGate) else h' = h
  action stepGateReplayOrAgentApprove = any { step, { nondet isAgent = Set(false, true).oneOf()
    nondet approve = Set(true, false).oneOf()
    resolveGateNoOneShot(isAgent, approve) } }
  // Countermodel threat.protocol.chatroom-ingress-governance.agent-self-unblock-matter (dropped guard: matter-gate-lock)
  action unblockMatterNoGateLock(isAgent: bool): bool = if ((h.matterBlockedByGate and true)) h' = h.with("matterBlockedByGate", false).with("agentSelfUnblocked", (h.agentSelfUnblocked or isAgent)) else h' = h
  action stepAgentSelfUnblock = any { step, { nondet isAgent = Set(false, true).oneOf()
    unblockMatterNoGateLock(isAgent) } }
  // Countermodel threat.protocol.chatroom-ingress-governance.tainted-tool-bypass (dropped guard: tainted-tool-human-gate)
  action agentInvokeToolNoTaintGate = if (true) h' = h.with("toolExecuted", true).with("taintedToolBypass", (h.taintedToolBypass or (h.taintedExternalMsg and h.gateStatus != 2))) else h' = h
  action stepTaintedToolBypass = any { step, agentInvokeToolNoTaintGate }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run verifiedExternalThenHumanGateAllowsToolTest = init.then(ingestExternalAs(true, false, 1, 1)).then(agentInvokeTool).then(agentRequestGate).then(resolveGateAs(true, true)).then(unblockMatterAs(true)).then(resolveGateAs(false, true)).then(agentInvokeTool).then(all { assert(h.toolExecuted), assert(not(h.matterBlockedByGate)), assert(h.gateStatus == 2), assert(safety), h' = h })
  run rejectedGateBlocksReplayAndUnblockTest = init.then(ingestExternalAs(true, false, 1, 1)).then(agentRequestGate).then(resolveGateAs(false, false)).then(resolveGateAs(false, true)).then(unblockMatterAs(true)).then(agentInvokeTool).then(all { assert(h.gateStatus == 3), assert(h.matterBlockedByGate), assert(not(h.toolExecuted)), assert(safety), h' = h })
  run forgedExternalIngressCountermodelTest = init.then(ingestExternalNoOrigin(false, true, 1, 1)).then(checkUnsafe)
  run crossChannelInjectCountermodelTest = init.then(ingestExternalNoChannelCheck(true, false, 1, 2)).then(checkUnsafe)
  run gateReplayCountermodelTest = init.then(agentRequestGate).then(resolveGateAs(false, false)).then(resolveGateNoOneShot(false, true)).then(checkUnsafe)
  run agentSelfUnblockCountermodelTest = init.then(agentRequestGate).then(unblockMatterNoGateLock(true)).then(checkUnsafe)
  run taintedToolBypassCountermodelTest = init.then(ingestExternalAs(true, false, 1, 1)).then(agentInvokeToolNoTaintGate).then(checkUnsafe)
}
