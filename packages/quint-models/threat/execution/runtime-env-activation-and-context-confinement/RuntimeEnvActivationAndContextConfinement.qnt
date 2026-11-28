// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.runtime-env-activation-and-context-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-direnv-loader-hijack-or-denylist-bypass step=stepDirenvLoaderHijack max-steps=6 itf="h.direnvHijackBreaches > 0"
// @countermodel forbid-envrc-or-org-store-symlink-escape step=stepPathSymlinkEscape max-steps=6 itf="h.symlinkEscapeBreaches > 0"
// @countermodel forbid-org-snapshot-or-channel-epoch-rollback step=stepGovernanceRollback max-steps=6 itf="h.rollbackBreaches > 0"
// @countermodel forbid-two-zone-prefix-tamper-or-cross-task-proxy step=stepPrefixOrTaskBypass max-steps=6 itf="h.prefixOrTaskBreaches > 0"
// Limits: Finite bounded runtime environment activation, Org store confinement & governed context bridge state machine (activeLeases <= 4, orgGen <= 12, channelEpoch <= 12, stepCount <= 12); models direnv export loader-hijack/denylist/size filtering + bounded subprocess stdout/timeout, explicit .envrc/sub-agent home/Org store symlink confinement, monotonic OrgGovernanceLedger snapshot generation + atomic commit rebasing + non-resetting SharedContextGovernanceLedger channel epoch/taint, and recomputed Two-Zone KV-Prefix frozen_prefix digest + cursor/proposal task_id binding, without modeling OS kernel VFS race internals or cryptographic hash preimage resistance.
module execution_runtime_env_activation_and_context_confinement {
  type State = { orgGen: int, channelEpoch: int, activeLeases: int, direnvFilterEnforced: bool, symlinkConfinementEnforced: bool, monotonicRollbackGuardEnforced: bool, twoZoneDigestVerified: bool, direnvHijackBreaches: int, symlinkEscapeBreaches: int, rollbackBreaches: int, prefixOrTaskBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { orgGen: 1, channelEpoch: 1, activeLeases: 0, direnvFilterEnforced: true, symlinkConfinementEnforced: true, monotonicRollbackGuardEnforced: true, twoZoneDigestVerified: true, direnvHijackBreaches: 0, symlinkEscapeBreaches: 0, rollbackBreaches: 0, prefixOrTaskBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action applySanitizedDirenvExport = if ((h.stepCount < 12 and h.direnvFilterEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action verifyConfinedEnvrcAndOrgPath = if ((h.stepCount < 12 and h.symlinkConfinementEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action acquireOrgRegionLease = if ((h.stepCount < 12 and h.monotonicRollbackGuardEnforced and h.activeLeases < 4)) h' = h.with("activeLeases", (h.activeLeases + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action commitOrgSubtreeMonotonically = if ((h.stepCount < 12 and h.monotonicRollbackGuardEnforced and h.activeLeases > 0 and h.orgGen < 12)) h' = h.with("activeLeases", (h.activeLeases - 1)).with("orgGen", (h.orgGen + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action advanceSharedChannelEpoch = if ((h.stepCount < 12 and h.monotonicRollbackGuardEnforced and h.channelEpoch < 12)) h' = h.with("channelEpoch", (h.channelEpoch + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action assembleVerifiedTwoZonePrompt = if ((h.stepCount < 12 and h.twoZoneDigestVerified)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { applySanitizedDirenvExport, verifyConfinedEnvrcAndOrgPath, acquireOrgRegionLease, commitOrgSubtreeMonotonically, advanceSharedChannelEpoch, assembleVerifiedTwoZonePrompt }
  val safety = (h.direnvHijackBreaches == 0 and h.symlinkEscapeBreaches == 0 and h.rollbackBreaches == 0 and h.prefixOrTaskBreaches == 0 and h.direnvFilterEnforced and h.symlinkConfinementEnforced and h.monotonicRollbackGuardEnforced and h.twoZoneDigestVerified and h.orgGen >= 1 and h.orgGen <= 12 and h.channelEpoch >= 1 and h.channelEpoch <= 12 and h.activeLeases >= 0 and h.activeLeases <= 4 and h.stepCount <= 12)
  // Countermodel threat.execution.runtime-env-activation-and-context-confinement.direnv-loader-hijack (dropped guard: forbid-direnv-loader-hijack-or-denylist-bypass)
  action exploitDirenvLoaderHijack = if ((h.stepCount < 12)) h' = h.with("direnvFilterEnforced", false).with("direnvHijackBreaches", (h.direnvHijackBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepDirenvLoaderHijack = any { step, exploitDirenvLoaderHijack }
  // Countermodel threat.execution.runtime-env-activation-and-context-confinement.path-symlink-escape (dropped guard: forbid-envrc-or-org-store-symlink-escape)
  action exploitPathSymlinkEscape = if ((h.stepCount < 12)) h' = h.with("symlinkConfinementEnforced", false).with("symlinkEscapeBreaches", (h.symlinkEscapeBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepPathSymlinkEscape = any { step, exploitPathSymlinkEscape }
  // Countermodel threat.execution.runtime-env-activation-and-context-confinement.governance-rollback (dropped guard: forbid-org-snapshot-or-channel-epoch-rollback)
  action exploitGovernanceRollback = if ((h.stepCount < 12)) h' = h.with("monotonicRollbackGuardEnforced", false).with("rollbackBreaches", (h.rollbackBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepGovernanceRollback = any { step, exploitGovernanceRollback }
  // Countermodel threat.execution.runtime-env-activation-and-context-confinement.prefix-or-task-bypass (dropped guard: forbid-two-zone-prefix-tamper-or-cross-task-proxy)
  action exploitPrefixOrTaskBypass = if ((h.stepCount < 12)) h' = h.with("twoZoneDigestVerified", false).with("prefixOrTaskBreaches", (h.prefixOrTaskBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepPrefixOrTaskBypass = any { step, exploitPrefixOrTaskBypass }
  action checkSm34Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm34Violated = all { assert((h.direnvHijackBreaches > 0 or h.symlinkEscapeBreaches > 0 or h.rollbackBreaches > 0 or h.prefixOrTaskBreaches > 0)), assert(not(safety)), h' = h }
  run cleanEnvAndContextSafeTest = init.then(applySanitizedDirenvExport).then(verifyConfinedEnvrcAndOrgPath).then(acquireOrgRegionLease).then(commitOrgSubtreeMonotonically).then(advanceSharedChannelEpoch).then(assembleVerifiedTwoZonePrompt).then(checkSm34Safe)
  run direnvLoaderHijackRefutedTest = init.then(exploitDirenvLoaderHijack).then(checkSm34Violated)
  run pathSymlinkEscapeRefutedTest = init.then(exploitPathSymlinkEscape).then(checkSm34Violated)
  run governanceRollbackRefutedTest = init.then(exploitGovernanceRollback).then(checkSm34Violated)
  run prefixOrTaskBypassRefutedTest = init.then(exploitPrefixOrTaskBypass).then(checkSm34Violated)
}
