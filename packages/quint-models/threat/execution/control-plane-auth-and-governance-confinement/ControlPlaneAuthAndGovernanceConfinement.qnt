// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.control-plane-auth-and-governance-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel enforce-canonical-ct-auth-entrypoint step=stepShadowEntrypointAuthBypass max-steps=6 itf="h.shadowAuthBypasses > 0"
// @countermodel enforce-control-plane-rpc-estop step=stepControlPlaneEstopBypass max-steps=6 itf="h.controlPlaneEstopBypasses > 0"
// @countermodel scrub-and-bound-release-gate-shell step=stepUnscrubbedReleaseShellLeak max-steps=6 itf="h.releaseShellSecretLeaks > 0"
// @countermodel reject-empty-bearer-credential step=stepEmptyBearerPrefixBypass max-steps=6 itf="h.emptyBearerBypasses > 0"
// Limits: Finite control-plane entrypoint auth, mutating RPC E-Stop governance confinement, empty-Bearer credential rejection, and release-gate shell secret scrubbing abstraction (ADV-L4 hostile attack tier); proves every production binary entrypoint and mutating RPC enforces canonical constant-time non-empty Bearer auth and fail-closed E-Stop mediation, not arbitrary OS kernel bypasses.
module execution_control_plane_auth_and_governance_confinement {
  type State = { admittedCleanOps: int, hostileBlocked: int, shadowAuthBypasses: int, controlPlaneEstopBypasses: int, releaseShellSecretLeaks: int, emptyBearerBypasses: int }
  var h: State
  action init = h' = { admittedCleanOps: 0, hostileBlocked: 0, shadowAuthBypasses: 0, controlPlaneEstopBypasses: 0, releaseShellSecretLeaks: 0, emptyBearerBypasses: 0 }
  action admitAuthenticatedGovernedRpc = h' = h.with("admittedCleanOps", (h.admittedCleanOps + 1))
  action runScrubbedBoundedReleaseGate = h' = h.with("admittedCleanOps", (h.admittedCleanOps + 1))
  action blockShadowDefaultOrTimingAuth = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockMutatingRpcDuringEstop = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockUnscrubbedLoginReleaseShell = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockEmptyBearerCredential = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action step = any { admitAuthenticatedGovernedRpc, runScrubbedBoundedReleaseGate, blockShadowDefaultOrTimingAuth, blockMutatingRpcDuringEstop, blockUnscrubbedLoginReleaseShell, blockEmptyBearerCredential }
  val safety = (h.shadowAuthBypasses == 0 and h.controlPlaneEstopBypasses == 0 and h.releaseShellSecretLeaks == 0 and h.emptyBearerBypasses == 0)
  // Countermodel threat.execution.control-plane-auth-and-governance-confinement.shadow-entrypoint-auth-bypass (dropped guard: enforce-canonical-ct-auth-entrypoint)
  action exploitShadowAuthEntrypoint = h' = h.with("shadowAuthBypasses", (h.shadowAuthBypasses + 1))
  action stepShadowEntrypointAuthBypass = any { step, exploitShadowAuthEntrypoint }
  // Countermodel threat.execution.control-plane-auth-and-governance-confinement.control-plane-estop-bypass (dropped guard: enforce-control-plane-rpc-estop)
  action exploitUngatedControlPlaneRpc = h' = h.with("controlPlaneEstopBypasses", (h.controlPlaneEstopBypasses + 1))
  action stepControlPlaneEstopBypass = any { step, exploitUngatedControlPlaneRpc }
  // Countermodel threat.execution.control-plane-auth-and-governance-confinement.unscrubbed-release-shell-leak (dropped guard: scrub-and-bound-release-gate-shell)
  action exploitUnscrubbedReleaseShell = h' = h.with("releaseShellSecretLeaks", (h.releaseShellSecretLeaks + 1))
  action stepUnscrubbedReleaseShellLeak = any { step, exploitUnscrubbedReleaseShell }
  // Countermodel threat.execution.control-plane-auth-and-governance-confinement.empty-bearer-prefix-bypass (dropped guard: reject-empty-bearer-credential)
  action exploitEmptyBearerPrefix = h' = h.with("emptyBearerBypasses", (h.emptyBearerBypasses + 1))
  action stepEmptyBearerPrefixBypass = any { step, exploitEmptyBearerPrefix }
  action checkControlPlaneGovSafe = all { assert(h.admittedCleanOps > 0), assert(h.hostileBlocked > 0), assert(h.shadowAuthBypasses == 0), assert(h.controlPlaneEstopBypasses == 0), assert(h.releaseShellSecretLeaks == 0), assert(h.emptyBearerBypasses == 0), assert(safety), h' = h }
  action checkControlPlaneGovViolated = all { assert((h.shadowAuthBypasses > 0 or h.controlPlaneEstopBypasses > 0 or h.releaseShellSecretLeaks > 0 or h.emptyBearerBypasses > 0)), assert(not(safety)), h' = h }
  run controlPlaneGovSafeTest = init.then(admitAuthenticatedGovernedRpc).then(runScrubbedBoundedReleaseGate).then(blockShadowDefaultOrTimingAuth).then(blockMutatingRpcDuringEstop).then(blockUnscrubbedLoginReleaseShell).then(blockEmptyBearerCredential).then(checkControlPlaneGovSafe)
  run shadowEntrypointAuthBypassRefutedTest = init.then(exploitShadowAuthEntrypoint).then(checkControlPlaneGovViolated)
  run controlPlaneEstopBypassRefutedTest = init.then(exploitUngatedControlPlaneRpc).then(checkControlPlaneGovViolated)
  run unscrubbedReleaseShellLeakRefutedTest = init.then(exploitUnscrubbedReleaseShell).then(checkControlPlaneGovViolated)
  run emptyBearerPrefixBypassRefutedTest = init.then(exploitEmptyBearerPrefix).then(checkControlPlaneGovViolated)
}
