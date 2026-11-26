// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.durable-agent-persistence
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-precommit-stable step=stepUnstableCommit max-steps=6 itf="h.unsafeUnstableCommits > 0"
// @countermodel require-resume-reattestation step=stepZombieResume max-steps=6 itf="h.unsafeZombieEffects > 0"
// @countermodel forbid-blind-crash-replay-intent step=stepBlindCrashReplay max-steps=6 itf="h.duplicateCrashEffects > 0"
// Limits: Finite single-root orthogonal persistence and crash-resume governance abstraction; does not model Byzantine storage corruption, multi-region consensus latency, or hardware NVRAM tearing.
module durable_agent_persistence {
  type State = { rootVersion: int, merkleHistoryIntact: bool, preCommitStable: bool, agentCrashed: bool, authorityRevoked: bool, resumeReattested: bool, inFlightIntent: bool, unsafeUnstableCommits: int, unsafeZombieEffects: int, duplicateCrashEffects: int }
  var h: State
  action init = h' = { rootVersion: 0, merkleHistoryIntact: true, preCommitStable: false, agentCrashed: false, authorityRevoked: false, resumeReattested: false, inFlightIntent: false, unsafeUnstableCommits: 0, unsafeZombieEffects: 0, duplicateCrashEffects: 0 }
  action settlePreCommitHook = if ((not(h.agentCrashed) and not(h.preCommitStable))) h' = h.with("preCommitStable", true) else h' = h
  action commitMerkleRoot = if ((not(h.agentCrashed) and h.rootVersion < 3 and h.preCommitStable)) h' = h.with("rootVersion", (h.rootVersion + 1)).with("preCommitStable", false).with("unsafeUnstableCommits", if (h.preCommitStable) h.unsafeUnstableCommits else (h.unsafeUnstableCommits + 1)) else h' = h
  action recordInFlightIntent = if ((not(h.agentCrashed) and not(h.inFlightIntent))) h' = h.with("inFlightIntent", true) else h' = h
  action crashOrSuspendAgent = if (not(h.agentCrashed)) h' = h.with("agentCrashed", true).with("preCommitStable", false).with("resumeReattested", false) else h' = h
  action revokeLiveAuthority = if (not(h.authorityRevoked)) h' = h.with("authorityRevoked", true).with("resumeReattested", false) else h' = h
  action resumeFromMerkleRoot = if (h.agentCrashed) h' = h.with("agentCrashed", false).with("resumeReattested", false) else h' = h
  action reattestLiveAuthority = if ((not(h.agentCrashed) and not(h.authorityRevoked) and not(h.resumeReattested))) h' = h.with("resumeReattested", true) else h' = h
  action reconcilePendingIntent = if ((not(h.agentCrashed) and h.inFlightIntent)) h' = h.with("inFlightIntent", false) else h' = h
  action dispatchResumedEffect = if ((not(h.agentCrashed) and (h.resumeReattested and not(h.authorityRevoked)) and not(h.inFlightIntent))) h' = h.with("inFlightIntent", true).with("unsafeZombieEffects", if ((h.resumeReattested and not(h.authorityRevoked))) h.unsafeZombieEffects else (h.unsafeZombieEffects + 1)).with("duplicateCrashEffects", if (h.inFlightIntent) (h.duplicateCrashEffects + 1) else h.duplicateCrashEffects) else h' = h
  action step = any { settlePreCommitHook, commitMerkleRoot, recordInFlightIntent, crashOrSuspendAgent, revokeLiveAuthority, resumeFromMerkleRoot, reattestLiveAuthority, reconcilePendingIntent, dispatchResumedEffect }
  val safety = (h.merkleHistoryIntact and h.unsafeUnstableCommits == 0 and h.unsafeZombieEffects == 0 and h.duplicateCrashEffects == 0)
  // Countermodel engineering.defense.durable-agent-persistence.unstable-commit (dropped guard: require-precommit-stable)
  action commitMerkleRootUnstable = if ((not(h.agentCrashed) and h.rootVersion < 3 and true)) h' = h.with("rootVersion", (h.rootVersion + 1)).with("preCommitStable", false).with("unsafeUnstableCommits", if (h.preCommitStable) h.unsafeUnstableCommits else (h.unsafeUnstableCommits + 1)) else h' = h
  action stepUnstableCommit = any { step, commitMerkleRootUnstable }
  // Countermodel engineering.defense.durable-agent-persistence.zombie-resume (dropped guard: require-resume-reattestation)
  action dispatchZombieEffect = if ((not(h.agentCrashed) and true and not(h.inFlightIntent))) h' = h.with("inFlightIntent", true).with("unsafeZombieEffects", if ((h.resumeReattested and not(h.authorityRevoked))) h.unsafeZombieEffects else (h.unsafeZombieEffects + 1)).with("duplicateCrashEffects", if (h.inFlightIntent) (h.duplicateCrashEffects + 1) else h.duplicateCrashEffects) else h' = h
  action stepZombieResume = any { step, dispatchZombieEffect }
  // Countermodel engineering.defense.durable-agent-persistence.crash-replay-duplicate (dropped guard: forbid-blind-crash-replay-intent)
  action dispatchBlindCrashReplay = if ((not(h.agentCrashed) and (h.resumeReattested and not(h.authorityRevoked)) and true)) h' = h.with("inFlightIntent", true).with("unsafeZombieEffects", if ((h.resumeReattested and not(h.authorityRevoked))) h.unsafeZombieEffects else (h.unsafeZombieEffects + 1)).with("duplicateCrashEffects", if (h.inFlightIntent) (h.duplicateCrashEffects + 1) else h.duplicateCrashEffects) else h' = h
  action stepBlindCrashReplay = any { step, dispatchBlindCrashReplay }
  run stableCommitAndSafeResumeTest = init.then(settlePreCommitHook).then(commitMerkleRoot).then(recordInFlightIntent).then(crashOrSuspendAgent).then(resumeFromMerkleRoot).then(reconcilePendingIntent).then(reattestLiveAuthority).then(dispatchResumedEffect).then(all { assert(safety), assert(h.rootVersion == 1), assert(h.merkleHistoryIntact), h' = h })
  run unstableCommitViolatesSafetyTest = init.then(commitMerkleRootUnstable).then(all { assert(not(safety)), assert(h.unsafeUnstableCommits > 0), h' = h })
  run zombieResumeViolatesSafetyTest = init.then(crashOrSuspendAgent).then(revokeLiveAuthority).then(resumeFromMerkleRoot).then(dispatchZombieEffect).then(all { assert(not(safety)), assert(h.unsafeZombieEffects > 0), h' = h })
  run crashReplayDuplicateViolatesSafetyTest = init.then(recordInFlightIntent).then(crashOrSuspendAgent).then(resumeFromMerkleRoot).then(reattestLiveAuthority).then(dispatchBlindCrashReplay).then(all { assert(not(safety)), assert(h.duplicateCrashEffects > 0), h' = h })
}
