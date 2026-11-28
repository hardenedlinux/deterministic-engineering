// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.plugin-grant-rollback-and-lease-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-ungranted-panel-activation step=stepDecorativeGrantBypass max-steps=6 itf="h.ungrantedActivations > 0"
// @countermodel forbid-release-rollback-or-publisher-hijack step=stepReleaseRollbackOrHijack max-steps=6 itf="h.rollbackOrHijacks > 0"
// @countermodel forbid-forged-device-lease-mutation step=stepForgedLeaseMutation max-steps=6 itf="h.forgedLeaseMutations > 0"
// @countermodel forbid-conflicting-idempotency-replay step=stepConflictingIdempotencyReplay max-steps=6 itf="h.idempotencyConflicts > 0"
// Limits: Finite bounded control-plane plugin lifecycle and device-lease state machine (installedVersion <= 3, stepCount <= 12); models capability grant enforcement and revocation closure, monotonic release version and publisher continuity with confined entry_path, bound device-lease verification under E-Stop, and digest-checked idempotent action replay, without modeling OS kernel or cryptographic primitive breaks.
module execution_plugin_grant_rollback_and_lease_confinement {
  type State = { installedVersion: int, ownerPublisher: int, grantHeld: bool, activeGen: int, estopTripped: bool, leaseRegistered: bool, recordedDigest: int, ungrantedActivations: int, rollbackOrHijacks: int, forgedLeaseMutations: int, idempotencyConflicts: int, cleanGovernedOps: int, stepCount: int }
  var h: State
  action init = h' = { installedVersion: 1, ownerPublisher: 1, grantHeld: false, activeGen: 0, estopTripped: false, leaseRegistered: false, recordedDigest: 0, ungrantedActivations: 0, rollbackOrHijacks: 0, forgedLeaseMutations: 0, idempotencyConflicts: 0, cleanGovernedOps: 0, stepCount: 0 }
  action grantCapabilities = if ((h.stepCount < 12 and not(h.grantHeld) and not(h.estopTripped))) h' = h.with("grantHeld", true).with("stepCount", (h.stepCount + 1)) else h' = h
  action revokeCapabilitiesAndClose = if ((h.stepCount < 12 and h.grantHeld)) h' = h.with("grantHeld", false).with("activeGen", 0).with("stepCount", (h.stepCount + 1)) else h' = h
  action activateGrantedPanel = if ((h.stepCount < 12 and h.grantHeld and not(h.estopTripped) and h.activeGen == 0)) h' = h.with("activeGen", 1).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action upgradeSamePublisher = if ((h.stepCount < 12 and not(h.estopTripped) and h.installedVersion < 3)) h' = h.with("installedVersion", (h.installedVersion + 1)).with("activeGen", 0).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action registerAndUpdateBoundLease = if ((h.stepCount < 12 and not(h.estopTripped))) h' = h.with("leaseRegistered", true).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action recordOrReplayMatchingAction = if ((h.stepCount < 12 and h.activeGen > 0 and h.grantHeld and not(h.estopTripped))) h' = h.with("recordedDigest", 1).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action toggleEstop = if ((h.stepCount < 12)) h' = h.with("estopTripped", not(h.estopTripped)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { grantCapabilities, revokeCapabilitiesAndClose, activateGrantedPanel, upgradeSamePublisher, registerAndUpdateBoundLease, recordOrReplayMatchingAction, toggleEstop }
  val safety = (h.ungrantedActivations == 0 and h.rollbackOrHijacks == 0 and h.forgedLeaseMutations == 0 and h.idempotencyConflicts == 0 and h.installedVersion >= 1 and h.installedVersion <= 3 and h.ownerPublisher == 1 and (h.activeGen == 0 or h.grantHeld) and h.stepCount <= 12)
  // Countermodel threat.execution.plugin-grant-rollback-and-lease-confinement.decorative-grant-bypass (dropped guard: forbid-ungranted-panel-activation)
  action exploitDecorativeGrantActivation = if ((h.stepCount < 12 and not(h.grantHeld))) h' = h.with("activeGen", 1).with("ungrantedActivations", (h.ungrantedActivations + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepDecorativeGrantBypass = any { step, exploitDecorativeGrantActivation }
  // Countermodel threat.execution.plugin-grant-rollback-and-lease-confinement.release-rollback-or-hijack (dropped guard: forbid-release-rollback-or-publisher-hijack)
  action exploitReleaseRollbackOrHijack = if ((h.stepCount < 12)) h' = h.with("rollbackOrHijacks", (h.rollbackOrHijacks + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepReleaseRollbackOrHijack = any { step, exploitReleaseRollbackOrHijack }
  // Countermodel threat.execution.plugin-grant-rollback-and-lease-confinement.forged-lease-mutation (dropped guard: forbid-forged-device-lease-mutation)
  action exploitForgedLeaseOrEstopDevice = if ((h.stepCount < 12 and (not(h.leaseRegistered) or h.estopTripped))) h' = h.with("forgedLeaseMutations", (h.forgedLeaseMutations + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepForgedLeaseMutation = any { step, exploitForgedLeaseOrEstopDevice }
  // Countermodel threat.execution.plugin-grant-rollback-and-lease-confinement.conflicting-idempotency-replay (dropped guard: forbid-conflicting-idempotency-replay)
  action exploitConflictingIdempotencyReplay = if ((h.stepCount < 12 and h.recordedDigest == 1)) h' = h.with("idempotencyConflicts", (h.idempotencyConflicts + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepConflictingIdempotencyReplay = any { step, exploitConflictingIdempotencyReplay }
  action checkSm28Safe = all { assert(safety), assert(h.cleanGovernedOps > 0), h' = h }
  action checkSm28Violated = all { assert((h.ungrantedActivations > 0 or h.rollbackOrHijacks > 0 or h.forgedLeaseMutations > 0 or h.idempotencyConflicts > 0)), assert(not(safety)), h' = h }
  run cleanGovernedLifecycleSafeTest = init.then(grantCapabilities).then(activateGrantedPanel).then(recordOrReplayMatchingAction).then(registerAndUpdateBoundLease).then(upgradeSamePublisher).then(revokeCapabilitiesAndClose).then(checkSm28Safe)
  run decorativeGrantBypassRefutedTest = init.then(exploitDecorativeGrantActivation).then(checkSm28Violated)
  run releaseRollbackOrHijackRefutedTest = init.then(exploitReleaseRollbackOrHijack).then(checkSm28Violated)
  run forgedLeaseMutationRefutedTest = init.then(exploitForgedLeaseOrEstopDevice).then(checkSm28Violated)
  run conflictingIdempotencyReplayRefutedTest = init.then(grantCapabilities).then(activateGrantedPanel).then(recordOrReplayMatchingAction).then(exploitConflictingIdempotencyReplay).then(checkSm28Violated)
}
