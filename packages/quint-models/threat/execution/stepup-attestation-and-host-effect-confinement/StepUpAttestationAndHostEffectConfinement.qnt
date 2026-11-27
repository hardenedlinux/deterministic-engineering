// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.stepup-attestation-and-host-effect-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-stepup-spoof-or-weak-acr-rearm step=stepStepUpSpoofRearm max-steps=6 itf="h.spoofedRearms > 0"
// @countermodel forbid-estop-llm-or-reserved-cas-overwrite step=stepEstopEffectOrCasOverwrite max-steps=6 itf="h.effectOrCasBreaches > 0"
// @countermodel forbid-watcher-suicide-on-broadcast-lag step=stepWatcherLagSuicide max-steps=6 itf="h.watcherSuicides > 0"
// @countermodel forbid-fact-store-deser-bomb-or-persist-desync step=stepFactBombOrPersistDesync max-steps=6 itf="h.factBombOrDesyncs > 0"
// Limits: Finite bounded Scheme governance host controller & atomic-effect worker state machine (factCount <= 3, stepCount <= 12); models strict RFC 9470 Step-Up MFA ACR allowlist and agent-prefix/duplicate-param rejection, E-Stop mediation on LlmComplete plus reserved governance CAS key confinement on CasPut, broadcast-lag survival in gate/UI watchers, and fact-store capacity parity with fail-closed CAS persist handling, without modeling cryptographic SHA-256 breaks or OS process takeover.
module execution_stepup_attestation_and_host_effect_confinement {
  type State = { estopTripped: bool, watchersAlive: bool, factCount: int, reservedCasIntact: bool, spoofedRearms: int, effectOrCasBreaches: int, watcherSuicides: int, factBombOrDesyncs: int, cleanGovernedOps: int, stepCount: int }
  var h: State
  action init = h' = { estopTripped: false, watchersAlive: true, factCount: 0, reservedCasIntact: true, spoofedRearms: 0, effectOrCasBreaches: 0, watcherSuicides: 0, factBombOrDesyncs: 0, cleanGovernedOps: 0, stepCount: 0 }
  action tripEstop = if ((h.stepCount < 12 and not(h.estopTripped))) h' = h.with("estopTripped", true).with("stepCount", (h.stepCount + 1)) else h' = h
  action verifiedMfaHumanRearmAndPersist = if ((h.stepCount < 12 and h.estopTripped and h.watchersAlive)) h' = h.with("estopTripped", false).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action executeArmedLlmAndUserCas = if ((h.stepCount < 12 and not(h.estopTripped) and h.reservedCasIntact)) h' = h.with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action surviveBroadcastLag = if ((h.stepCount < 12 and h.watchersAlive)) h' = h.with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action mutateFactWithinCap = if ((h.stepCount < 12 and h.factCount < 3)) h' = h.with("factCount", (h.factCount + 1)).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action rejectFactAtCap = if ((h.stepCount < 12 and h.factCount == 3)) h' = h.with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action failClosedRearmOnCasError = if ((h.stepCount < 12 and h.estopTripped)) h' = h.with("estopTripped", true).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { tripEstop, verifiedMfaHumanRearmAndPersist, executeArmedLlmAndUserCas, surviveBroadcastLag, mutateFactWithinCap, rejectFactAtCap, failClosedRearmOnCasError }
  val safety = (h.spoofedRearms == 0 and h.effectOrCasBreaches == 0 and h.watcherSuicides == 0 and h.factBombOrDesyncs == 0 and h.watchersAlive and h.reservedCasIntact and h.factCount >= 0 and h.factCount <= 3 and h.stepCount <= 12)
  // Countermodel threat.execution.stepup-attestation-and-host-effect-confinement.stepup-spoof-rearm (dropped guard: forbid-stepup-spoof-or-weak-acr-rearm)
  action exploitStepUpSpoofOrWeakAcr = if ((h.stepCount < 12 and h.estopTripped)) h' = h.with("estopTripped", false).with("spoofedRearms", (h.spoofedRearms + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepStepUpSpoofRearm = any { step, exploitStepUpSpoofOrWeakAcr }
  // Countermodel threat.execution.stepup-attestation-and-host-effect-confinement.estop-effect-or-cas-overwrite (dropped guard: forbid-estop-llm-or-reserved-cas-overwrite)
  action exploitEstopLlmOrReservedCas = if ((h.stepCount < 12 and (h.estopTripped or h.reservedCasIntact))) h' = h.with("reservedCasIntact", false).with("effectOrCasBreaches", (h.effectOrCasBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepEstopEffectOrCasOverwrite = any { step, exploitEstopLlmOrReservedCas }
  // Countermodel threat.execution.stepup-attestation-and-host-effect-confinement.watcher-lag-suicide (dropped guard: forbid-watcher-suicide-on-broadcast-lag)
  action exploitWatcherLagSuicide = if ((h.stepCount < 12 and h.watchersAlive)) h' = h.with("watchersAlive", false).with("watcherSuicides", (h.watcherSuicides + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepWatcherLagSuicide = any { step, exploitWatcherLagSuicide }
  // Countermodel threat.execution.stepup-attestation-and-host-effect-confinement.fact-bomb-or-persist-desync (dropped guard: forbid-fact-store-deser-bomb-or-persist-desync)
  action exploitFactOverflowOrSilentPersistDrop = if ((h.stepCount < 12 and h.factCount == 3)) h' = h.with("factCount", 4).with("factBombOrDesyncs", (h.factBombOrDesyncs + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepFactBombOrPersistDesync = any { step, exploitFactOverflowOrSilentPersistDrop }
  action checkSm30Safe = all { assert(safety), assert(h.cleanGovernedOps > 0), h' = h }
  action checkSm30Violated = all { assert((h.spoofedRearms > 0 or h.effectOrCasBreaches > 0 or h.watcherSuicides > 0 or h.factBombOrDesyncs > 0)), assert(not(safety)), h' = h }
  run cleanHostGovernanceSafeTest = init.then(executeArmedLlmAndUserCas).then(surviveBroadcastLag).then(mutateFactWithinCap).then(mutateFactWithinCap).then(mutateFactWithinCap).then(rejectFactAtCap).then(tripEstop).then(failClosedRearmOnCasError).then(verifiedMfaHumanRearmAndPersist).then(checkSm30Safe)
  run stepUpSpoofRearmRefutedTest = init.then(tripEstop).then(exploitStepUpSpoofOrWeakAcr).then(checkSm30Violated)
  run estopEffectOrCasOverwriteRefutedTest = init.then(tripEstop).then(exploitEstopLlmOrReservedCas).then(checkSm30Violated)
  run watcherLagSuicideRefutedTest = init.then(exploitWatcherLagSuicide).then(checkSm30Violated)
  run factBombOrPersistDesyncRefutedTest = init.then(mutateFactWithinCap).then(mutateFactWithinCap).then(mutateFactWithinCap).then(exploitFactOverflowOrSilentPersistDrop).then(checkSm30Violated)
}
