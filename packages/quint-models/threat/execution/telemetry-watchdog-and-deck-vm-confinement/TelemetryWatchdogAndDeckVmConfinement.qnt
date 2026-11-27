// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.telemetry-watchdog-and-deck-vm-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-cleartext-remote-otlp-endpoint step=stepCleartextOtlpExfil max-steps=6 itf="h.otlpExfilBreaches > 0"
// @countermodel forbid-unscrubbed-host-observer-env-leak step=stepObserverEnvLeak max-steps=6 itf="h.observerEnvBreaches > 0"
// @countermodel forbid-watchdog-future-timestamp-blinding step=stepWatchdogBlinding max-steps=6 itf="h.watchdogBlindBreaches > 0"
// @countermodel forbid-deck-vm-unbounded-controls-or-timer-pinning step=stepDeckVmExhaustion max-steps=6 itf="h.deckVmExhaustionBreaches > 0"
// Limits: Finite bounded telemetry/watchdog and Deck single-VM confinement state machine (activeModules <= 12, activeTimers <= 12, stepCount <= 12); models loopback-only HTTP / remote HTTPS OTLP endpoint and label confinement, env_clear()-scrubbed non-symlink host observer sidecar spawning, monotonic-bounded watchdog heartbeat timestamps preventing u64::MAX blinding plus non-zero PID/timeout guards, and bounded Deck single-VM active module/timer capacities and finite timer delay ceilings, without modeling OS kernel kqueue internals or live network packet loss.
module execution_telemetry_watchdog_and_deck_vm_confinement {
  type State = { activeModules: int, activeTimers: int, otlpTlsEnforced: bool, observerEnvScrubbed: bool, watchdogClockBounded: bool, deckVmBoundsEnforced: bool, otlpExfilBreaches: int, observerEnvBreaches: int, watchdogBlindBreaches: int, deckVmExhaustionBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { activeModules: 1, activeTimers: 0, otlpTlsEnforced: true, observerEnvScrubbed: true, watchdogClockBounded: true, deckVmBoundsEnforced: true, otlpExfilBreaches: 0, observerEnvBreaches: 0, watchdogBlindBreaches: 0, deckVmExhaustionBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action exportTlsBoundedOtlpTrace = if ((h.stepCount < 12 and h.otlpTlsEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action spawnScrubbedHostObserver = if ((h.stepCount < 12 and h.observerEnvScrubbed)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action sampleValidatedWatchdogPulse = if ((h.stepCount < 12 and h.watchdogClockBounded)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action activateBoundedDeckModule = if ((h.stepCount < 12 and h.deckVmBoundsEnforced and h.activeModules < 12)) h' = h.with("activeModules", (h.activeModules + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action armBoundedDeckTimer = if ((h.stepCount < 12 and h.deckVmBoundsEnforced and h.activeTimers < 12)) h' = h.with("activeTimers", (h.activeTimers + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action retireBoundedDeckTimer = if ((h.stepCount < 12 and h.deckVmBoundsEnforced and h.activeTimers > 0)) h' = h.with("activeTimers", (h.activeTimers - 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { exportTlsBoundedOtlpTrace, spawnScrubbedHostObserver, sampleValidatedWatchdogPulse, activateBoundedDeckModule, armBoundedDeckTimer, retireBoundedDeckTimer }
  val safety = (h.otlpExfilBreaches == 0 and h.observerEnvBreaches == 0 and h.watchdogBlindBreaches == 0 and h.deckVmExhaustionBreaches == 0 and h.otlpTlsEnforced and h.observerEnvScrubbed and h.watchdogClockBounded and h.deckVmBoundsEnforced and h.activeModules >= 1 and h.activeModules <= 12 and h.activeTimers >= 0 and h.activeTimers <= 12 and h.stepCount <= 12)
  // Countermodel threat.execution.telemetry-watchdog-and-deck-vm-confinement.cleartext-remote-otlp (dropped guard: forbid-cleartext-remote-otlp-endpoint)
  action exploitCleartextOtlpExfil = if ((h.stepCount < 12)) h' = h.with("otlpTlsEnforced", false).with("otlpExfilBreaches", (h.otlpExfilBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepCleartextOtlpExfil = any { step, exploitCleartextOtlpExfil }
  // Countermodel threat.execution.telemetry-watchdog-and-deck-vm-confinement.unscrubbed-observer-env (dropped guard: forbid-unscrubbed-host-observer-env-leak)
  action exploitObserverEnvLeak = if ((h.stepCount < 12)) h' = h.with("observerEnvScrubbed", false).with("observerEnvBreaches", (h.observerEnvBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepObserverEnvLeak = any { step, exploitObserverEnvLeak }
  // Countermodel threat.execution.telemetry-watchdog-and-deck-vm-confinement.watchdog-future-timestamp-blinding (dropped guard: forbid-watchdog-future-timestamp-blinding)
  action exploitWatchdogBlinding = if ((h.stepCount < 12)) h' = h.with("watchdogClockBounded", false).with("watchdogBlindBreaches", (h.watchdogBlindBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepWatchdogBlinding = any { step, exploitWatchdogBlinding }
  // Countermodel threat.execution.telemetry-watchdog-and-deck-vm-confinement.deck-vm-state-exhaustion (dropped guard: forbid-deck-vm-unbounded-controls-or-timer-pinning)
  action exploitDeckVmExhaustion = if ((h.stepCount < 12)) h' = h.with("deckVmBoundsEnforced", false).with("deckVmExhaustionBreaches", (h.deckVmExhaustionBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepDeckVmExhaustion = any { step, exploitDeckVmExhaustion }
  action checkSm36Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm36Violated = all { assert((h.otlpExfilBreaches > 0 or h.observerEnvBreaches > 0 or h.watchdogBlindBreaches > 0 or h.deckVmExhaustionBreaches > 0)), assert(not(safety)), h' = h }
  run cleanTelemetryDeckVmSafeTest = init.then(exportTlsBoundedOtlpTrace).then(spawnScrubbedHostObserver).then(sampleValidatedWatchdogPulse).then(activateBoundedDeckModule).then(armBoundedDeckTimer).then(retireBoundedDeckTimer).then(checkSm36Safe)
  run cleartextOtlpRefutedTest = init.then(exploitCleartextOtlpExfil).then(checkSm36Violated)
  run observerEnvLeakRefutedTest = init.then(exploitObserverEnvLeak).then(checkSm36Violated)
  run watchdogBlindingRefutedTest = init.then(exploitWatchdogBlinding).then(checkSm36Violated)
  run deckVmExhaustionRefutedTest = init.then(exploitDeckVmExhaustion).then(checkSm36Violated)
}
