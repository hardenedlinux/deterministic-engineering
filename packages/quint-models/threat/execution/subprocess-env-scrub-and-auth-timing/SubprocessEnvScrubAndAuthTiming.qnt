// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.subprocess-env-scrub-and-auth-timing
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel scrub-sandbox-env-allowlist step=stepSandboxEnvInheritLeak max-steps=6 itf="h.sandboxSecretLeaks > 0"
// @countermodel scrub-plugin-build-env-allowlist step=stepPluginBuildEnvLeak max-steps=6 itf="h.pluginSecretLeaks > 0"
// @countermodel constant-time-bearer-verify step=stepTimingOracleAuth max-steps=6 itf="h.authTimingOracles > 0"
// @countermodel reject-blank-auth-and-stdin-inherit step=stepBlankAuthOrStdinLeak max-steps=6 itf="h.blankAuthBypasses > 0"
// Limits: Finite subprocess environment allowlist, plugin build sandbox, and constant-time bearer auth state abstraction (ADV-L4 hostile attack tier); verifies zero ambient secret inheritance into sandbox/plugin subprocesses, constant-time bearer verification, and fail-closed blank-token refusal, not hardware microarchitectural cache-line side channels.
module execution_subprocess_env_scrub_and_auth_timing {
  type State = { cleanAdmitted: int, hostileBlocked: int, sandboxSecretLeaks: int, pluginSecretLeaks: int, authTimingOracles: int, blankAuthBypasses: int }
  var h: State
  action init = h' = { cleanAdmitted: 0, hostileBlocked: 0, sandboxSecretLeaks: 0, pluginSecretLeaks: 0, authTimingOracles: 0, blankAuthBypasses: 0 }
  action spawnScrubbedSandboxTool = h' = h.with("cleanAdmitted", (h.cleanAdmitted + 1))
  action spawnScrubbedPluginBuild = h' = h.with("cleanAdmitted", (h.cleanAdmitted + 1))
  action verifyConstantTimeBearer = h' = h.with("cleanAdmitted", (h.cleanAdmitted + 1))
  action blockSecretEnvInheritance = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockInvalidOrBlankBearer = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockUntrustedStdinInherit = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action step = any { spawnScrubbedSandboxTool, spawnScrubbedPluginBuild, verifyConstantTimeBearer, blockSecretEnvInheritance, blockInvalidOrBlankBearer, blockUntrustedStdinInherit }
  val safety = (h.sandboxSecretLeaks == 0 and h.pluginSecretLeaks == 0 and h.authTimingOracles == 0 and h.blankAuthBypasses == 0)
  // Countermodel threat.execution.subprocess-env-scrub-and-auth-timing.sandbox-env-inherit-leak (dropped guard: scrub-sandbox-env-allowlist)
  action leakAmbientSecretToSandbox = h' = h.with("sandboxSecretLeaks", (h.sandboxSecretLeaks + 1))
  action stepSandboxEnvInheritLeak = any { step, leakAmbientSecretToSandbox }
  // Countermodel threat.execution.subprocess-env-scrub-and-auth-timing.plugin-build-env-leak (dropped guard: scrub-plugin-build-env-allowlist)
  action leakAmbientSecretToPluginBuild = h' = h.with("pluginSecretLeaks", (h.pluginSecretLeaks + 1))
  action stepPluginBuildEnvLeak = any { step, leakAmbientSecretToPluginBuild }
  // Countermodel threat.execution.subprocess-env-scrub-and-auth-timing.timing-oracle-auth (dropped guard: constant-time-bearer-verify)
  action compareBearerShortCircuit = h' = h.with("authTimingOracles", (h.authTimingOracles + 1))
  action stepTimingOracleAuth = any { step, compareBearerShortCircuit }
  // Countermodel threat.execution.subprocess-env-scrub-and-auth-timing.blank-auth-or-stdin-leak (dropped guard: reject-blank-auth-and-stdin-inherit)
  action admitBlankExpectedBearer = h' = h.with("blankAuthBypasses", (h.blankAuthBypasses + 1))
  action stepBlankAuthOrStdinLeak = any { step, admitBlankExpectedBearer }
  action checkEnvScrubAuthSafe = all { assert(h.cleanAdmitted > 0), assert(h.hostileBlocked > 0), assert(h.sandboxSecretLeaks == 0), assert(h.pluginSecretLeaks == 0), assert(h.authTimingOracles == 0), assert(h.blankAuthBypasses == 0), assert(safety), h' = h }
  action checkEnvScrubAuthViolated = all { assert((h.sandboxSecretLeaks > 0 or h.pluginSecretLeaks > 0 or h.authTimingOracles > 0 or h.blankAuthBypasses > 0)), assert(not(safety)), h' = h }
  run envScrubAuthSafeTest = init.then(spawnScrubbedSandboxTool).then(spawnScrubbedPluginBuild).then(verifyConstantTimeBearer).then(blockSecretEnvInheritance).then(blockInvalidOrBlankBearer).then(blockUntrustedStdinInherit).then(checkEnvScrubAuthSafe)
  run sandboxEnvLeakRefutedTest = init.then(leakAmbientSecretToSandbox).then(checkEnvScrubAuthViolated)
  run pluginBuildEnvLeakRefutedTest = init.then(leakAmbientSecretToPluginBuild).then(checkEnvScrubAuthViolated)
  run timingOracleAuthRefutedTest = init.then(compareBearerShortCircuit).then(checkEnvScrubAuthViolated)
  run blankAuthBypassRefutedTest = init.then(admitBlankExpectedBearer).then(checkEnvScrubAuthViolated)
}
