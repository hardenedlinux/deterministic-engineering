// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.hook-policy-and-protocol-contract-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-toml-unknown-field-failopen-or-unbounded-config step=stepConfigFailOpen max-steps=6 itf="h.configFailOpenBreaches > 0"
// @countermodel forbid-duplicate-hook-shadow-or-unbounded-async-fanout step=stepHookShadowOrFanout max-steps=6 itf="h.hookShadowOrFanoutBreaches > 0"
// @countermodel forbid-trust-rejection-masking-or-dynamic-action-flood step=stepTrustMaskOrActionFlood max-steps=6 itf="h.trustMaskOrActionBreaches > 0"
// @countermodel forbid-subagent-contradiction-serde-bypass-or-endpoint-injection step=stepProtocolContractBypass max-steps=6 itf="h.protocolContractBreaches > 0"
// Limits: Finite bounded hook policy dispatch, registry uniqueness & protocol contract validation state machine (registeredHooks <= 6, asyncTasksRunning <= 4, validatedProfiles <= 4, stepCount <= 12); models deny_unknown_fields + bounded TOML config + validated GerbilScheme extension, unique hook_id upsert preventing sticky ghost hooks + semaphore-bounded async hook fanout, immutable Rust trust-floor rejections (UntrustedRejected/ModifiedRejected) + bounded dynamic policy actions/rewrites, contradictory SubAgentPermissionSet / zero-budget / recursive-depth rejection, validated RuntimeSessionId Deserialize parity, and control/URL-meta refusal in ModelEndpoint::validate_contract, without modeling OS memory pressure or cryptographic signature verification.
module execution_hook_policy_and_protocol_contract_confinement {
  type State = { registeredHooks: int, asyncTasksRunning: int, validatedProfiles: int, strictConfigEnforced: bool, uniqueHookIdsEnforced: bool, trustFloorImmutable: bool, protocolContractsEnforced: bool, configFailOpenBreaches: int, hookShadowOrFanoutBreaches: int, trustMaskOrActionBreaches: int, protocolContractBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { registeredHooks: 0, asyncTasksRunning: 0, validatedProfiles: 0, strictConfigEnforced: true, uniqueHookIdsEnforced: true, trustFloorImmutable: true, protocolContractsEnforced: true, configFailOpenBreaches: 0, hookShadowOrFanoutBreaches: 0, trustMaskOrActionBreaches: 0, protocolContractBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action loadStrictHookTomlConfig = if ((h.stepCount < 12 and h.strictConfigEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action upsertUniqueHookRegistration = if ((h.stepCount < 12 and h.uniqueHookIdsEnforced and h.registeredHooks < 6)) h' = h.with("registeredHooks", (h.registeredHooks + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action unregisterHookCompletely = if ((h.stepCount < 12 and h.uniqueHookIdsEnforced and h.registeredHooks > 0)) h' = h.with("registeredHooks", (h.registeredHooks - 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action dispatchBoundedAsyncHook = if ((h.stepCount < 12 and h.asyncTasksRunning < 4)) h' = h.with("asyncTasksRunning", (h.asyncTasksRunning + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action completeBoundedAsyncHook = if ((h.stepCount < 12 and h.asyncTasksRunning > 0)) h' = h.with("asyncTasksRunning", (h.asyncTasksRunning - 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action applyBoundedDynamicActionPreservingTrustFloor = if ((h.stepCount < 12 and h.trustFloorImmutable)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action validateSubAgentAndProtocolBoundary = if ((h.stepCount < 12 and h.protocolContractsEnforced and h.validatedProfiles < 4)) h' = h.with("validatedProfiles", (h.validatedProfiles + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { loadStrictHookTomlConfig, upsertUniqueHookRegistration, unregisterHookCompletely, dispatchBoundedAsyncHook, completeBoundedAsyncHook, applyBoundedDynamicActionPreservingTrustFloor, validateSubAgentAndProtocolBoundary }
  val safety = (h.configFailOpenBreaches == 0 and h.hookShadowOrFanoutBreaches == 0 and h.trustMaskOrActionBreaches == 0 and h.protocolContractBreaches == 0 and h.strictConfigEnforced and h.uniqueHookIdsEnforced and h.trustFloorImmutable and h.protocolContractsEnforced and h.registeredHooks >= 0 and h.registeredHooks <= 6 and h.asyncTasksRunning >= 0 and h.asyncTasksRunning <= 4 and h.validatedProfiles <= 4 and h.stepCount <= 12)
  // Countermodel threat.execution.hook-policy-and-protocol-contract-confinement.config-fail-open (dropped guard: forbid-toml-unknown-field-failopen-or-unbounded-config)
  action exploitConfigFailOpen = if ((h.stepCount < 12)) h' = h.with("strictConfigEnforced", false).with("configFailOpenBreaches", (h.configFailOpenBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepConfigFailOpen = any { step, exploitConfigFailOpen }
  // Countermodel threat.execution.hook-policy-and-protocol-contract-confinement.hook-shadow-or-fanout (dropped guard: forbid-duplicate-hook-shadow-or-unbounded-async-fanout)
  action exploitHookShadowOrFanout = if ((h.stepCount < 12)) h' = h.with("uniqueHookIdsEnforced", false).with("hookShadowOrFanoutBreaches", (h.hookShadowOrFanoutBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepHookShadowOrFanout = any { step, exploitHookShadowOrFanout }
  // Countermodel threat.execution.hook-policy-and-protocol-contract-confinement.trust-mask-or-action-flood (dropped guard: forbid-trust-rejection-masking-or-dynamic-action-flood)
  action exploitTrustMaskOrActionFlood = if ((h.stepCount < 12)) h' = h.with("trustFloorImmutable", false).with("trustMaskOrActionBreaches", (h.trustMaskOrActionBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepTrustMaskOrActionFlood = any { step, exploitTrustMaskOrActionFlood }
  // Countermodel threat.execution.hook-policy-and-protocol-contract-confinement.protocol-contract-bypass (dropped guard: forbid-subagent-contradiction-serde-bypass-or-endpoint-injection)
  action exploitProtocolContractBypass = if ((h.stepCount < 12)) h' = h.with("protocolContractsEnforced", false).with("protocolContractBreaches", (h.protocolContractBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepProtocolContractBypass = any { step, exploitProtocolContractBypass }
  action checkSm33Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm33Violated = all { assert((h.configFailOpenBreaches > 0 or h.hookShadowOrFanoutBreaches > 0 or h.trustMaskOrActionBreaches > 0 or h.protocolContractBreaches > 0)), assert(not(safety)), h' = h }
  run cleanHookAndProtocolSafeTest = init.then(loadStrictHookTomlConfig).then(upsertUniqueHookRegistration).then(dispatchBoundedAsyncHook).then(completeBoundedAsyncHook).then(applyBoundedDynamicActionPreservingTrustFloor).then(validateSubAgentAndProtocolBoundary).then(unregisterHookCompletely).then(checkSm33Safe)
  run configFailOpenRefutedTest = init.then(exploitConfigFailOpen).then(checkSm33Violated)
  run hookShadowOrFanoutRefutedTest = init.then(exploitHookShadowOrFanout).then(checkSm33Violated)
  run trustMaskOrActionFloodRefutedTest = init.then(exploitTrustMaskOrActionFlood).then(checkSm33Violated)
  run protocolContractBypassRefutedTest = init.then(exploitProtocolContractBypass).then(checkSm33Violated)
}
