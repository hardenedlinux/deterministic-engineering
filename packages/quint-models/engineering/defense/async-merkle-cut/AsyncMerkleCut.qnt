// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.async-merkle-cut
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-channel-drained-for-cut step=stepDropChannel max-steps=6 itf="h.droppedChannelCuts > 0"
// @countermodel forbid-lww-conflict-merge step=stepLwwMerge max-steps=6 itf="h.lwwConflictsErased > 0"
// @countermodel require-current-policy-digest step=stepStalePolicy max-steps=6 itf="h.stalePolicyAdmits > 0"
// Limits: Finite two-branch asynchronous cut and two-version hot policy co-evolution abstraction; does not model unbounded multi-party vector clocks, Byzantine message forgery, or arbitrary three-way AST merge semantics.
module async_merkle_cut {
  type State = { fastCommits: int, slowBlocked: bool, inFlightMsg: bool, channelDrained: bool, branchConflict: bool, activePolicyVer: int, verdictPolicyVer: int, cutConsistent: bool, droppedChannelCuts: int, lwwConflictsErased: int, stalePolicyAdmits: int }
  var h: State
  action init = h' = { fastCommits: 0, slowBlocked: false, inFlightMsg: false, channelDrained: true, branchConflict: false, activePolicyVer: 1, verdictPolicyVer: 1, cutConsistent: true, droppedChannelCuts: 0, lwwConflictsErased: 0, stalePolicyAdmits: 0 }
  action blockSlowAgent = if (not(h.slowBlocked)) h' = h.with("slowBlocked", true) else h' = h
  action fastAgentLocalCommit = if (h.fastCommits < 3) h' = h.with("fastCommits", (h.fastCommits + 1)) else h' = h
  action sendCrossAgentHandoff = if (not(h.inFlightMsg)) h' = h.with("inFlightMsg", true).with("channelDrained", false) else h' = h
  action captureChannelMessage = if ((h.inFlightMsg and not(h.channelDrained))) h' = h.with("inFlightMsg", false).with("channelDrained", true) else h' = h
  action introduceBranchConflict = if (not(h.branchConflict)) h' = h.with("branchConflict", true) else h' = h
  action resolveConflictExplicitly = if (h.branchConflict) h' = h.with("branchConflict", false) else h' = h
  action hotUpgradePolicy = if (h.activePolicyVer == 1) h' = h.with("activePolicyVer", 2) else h' = h
  action revalidateUnderActivePolicy = if (h.verdictPolicyVer < h.activePolicyVer) h' = h.with("verdictPolicyVer", h.activePolicyVer) else h' = h
  action sealAsyncCut = if (h.channelDrained) h' = h.with("droppedChannelCuts", if (h.channelDrained) h.droppedChannelCuts else (h.droppedChannelCuts + 1)) else h' = h
  action mergeBranches = if (not(h.branchConflict)) h' = h.with("lwwConflictsErased", if (h.branchConflict) (h.lwwConflictsErased + 1) else h.lwwConflictsErased) else h' = h
  action admitSuspendedVerdict = if (h.verdictPolicyVer == h.activePolicyVer) h' = h.with("stalePolicyAdmits", if (h.verdictPolicyVer == h.activePolicyVer) h.stalePolicyAdmits else (h.stalePolicyAdmits + 1)) else h' = h
  action step = any { blockSlowAgent, fastAgentLocalCommit, sendCrossAgentHandoff, captureChannelMessage, introduceBranchConflict, resolveConflictExplicitly, hotUpgradePolicy, revalidateUnderActivePolicy, sealAsyncCut, mergeBranches, admitSuspendedVerdict }
  val safety = (h.cutConsistent and h.droppedChannelCuts == 0 and h.lwwConflictsErased == 0 and h.stalePolicyAdmits == 0)
  // Countermodel engineering.defense.async-merkle-cut.dropped-channel (dropped guard: require-channel-drained-for-cut)
  action sealAsyncCutDropChannel = if (true) h' = h.with("droppedChannelCuts", if (h.channelDrained) h.droppedChannelCuts else (h.droppedChannelCuts + 1)) else h' = h
  action stepDropChannel = any { step, sealAsyncCutDropChannel }
  // Countermodel engineering.defense.async-merkle-cut.lww-conflict (dropped guard: forbid-lww-conflict-merge)
  action mergeBranchesLww = if (true) h' = h.with("lwwConflictsErased", if (h.branchConflict) (h.lwwConflictsErased + 1) else h.lwwConflictsErased) else h' = h
  action stepLwwMerge = any { step, mergeBranchesLww }
  // Countermodel engineering.defense.async-merkle-cut.stale-policy (dropped guard: require-current-policy-digest)
  action admitStalePolicyVerdict = if (true) h' = h.with("stalePolicyAdmits", if (h.verdictPolicyVer == h.activePolicyVer) h.stalePolicyAdmits else (h.stalePolicyAdmits + 1)) else h' = h
  action stepStalePolicy = any { step, admitStalePolicyVerdict }
  run stragglerFreeCommitAndSafeCutTest = init.then(blockSlowAgent).then(fastAgentLocalCommit).then(fastAgentLocalCommit).then(sendCrossAgentHandoff).then(captureChannelMessage).then(sealAsyncCut).then(hotUpgradePolicy).then(revalidateUnderActivePolicy).then(admitSuspendedVerdict).then(all { assert(safety), assert(h.slowBlocked), assert(h.fastCommits == 2), assert(h.verdictPolicyVer == 2), h' = h })
  run droppedChannelCutViolatesSafetyTest = init.then(sendCrossAgentHandoff).then(sealAsyncCutDropChannel).then(all { assert(not(safety)), assert(h.droppedChannelCuts > 0), h' = h })
  run silentLwwConflictViolatesSafetyTest = init.then(introduceBranchConflict).then(mergeBranchesLww).then(all { assert(not(safety)), assert(h.lwwConflictsErased > 0), h' = h })
  run stalePolicyAdmitViolatesSafetyTest = init.then(hotUpgradePolicy).then(admitStalePolicyVerdict).then(all { assert(not(safety)), assert(h.stalePolicyAdmits > 0), h' = h })
}
