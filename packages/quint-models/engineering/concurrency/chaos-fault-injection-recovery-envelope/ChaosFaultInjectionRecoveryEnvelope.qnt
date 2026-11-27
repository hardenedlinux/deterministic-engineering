// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.chaos-fault-injection-recovery-envelope
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel shed-load-on-open-circuit step=stepOpenCircuitCascade max-steps=6 itf="h.cascadeViolations > 0"
// @countermodel typed-refusal-under-fault step=stepSilentFallbackCorruption max-steps=6 itf="h.silentCorruptions > 0"
// @countermodel half-open-probe-recovery step=stepStickyRecoveryWedge max-steps=6 itf="h.stickyWedged > 0"
// Limits: Finite 2-fault trip threshold and 2-slot active load chaos abstraction; verifies open-circuit load shedding, typed degraded refusal, and deterministic recovery probing, not wall-clock exponential backoff jitter.
module concurrency_chaos_fault_injection_recovery_envelope {
  type State = { faultActive: bool, circuitState: int, activeLoad: int, consecutiveFaults: int, recoveredCount: int, refusedDegraded: int, cascadeViolations: int, silentCorruptions: int, stickyWedged: int }
  var h: State
  action init = h' = { faultActive: false, circuitState: 0, activeLoad: 0, consecutiveFaults: 0, recoveredCount: 0, refusedDegraded: 0, cascadeViolations: 0, silentCorruptions: 0, stickyWedged: 0 }
  action injectFault = if (not(h.faultActive)) h' = h.with("faultActive", true) else h' = h
  action clearFault = if (h.faultActive) h' = h.with("faultActive", false) else h' = h
  action handleRequest = if (h.circuitState == 1) if (true) h' = h.with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("activeLoad", (h.activeLoad + 1)).with("cascadeViolations", (h.cascadeViolations + 1)) else if (h.faultActive) if (true) if ((h.consecutiveFaults + 1) >= 2) h' = h.with("consecutiveFaults", (h.consecutiveFaults + 1)).with("circuitState", 1).with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("consecutiveFaults", (h.consecutiveFaults + 1)).with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("silentCorruptions", (h.silentCorruptions + 1)) else if (h.activeLoad < 2) h' = h.with("activeLoad", (h.activeLoad + 1)) else h' = h
  action finishRequest = if (h.activeLoad > 0) h' = h.with("activeLoad", (h.activeLoad - 1)) else h' = h
  action probeRecovery = if ((h.circuitState == 1 and not(h.faultActive))) if (true) h' = h.with("circuitState", 0).with("consecutiveFaults", 0).with("recoveredCount", (h.recoveredCount + 1)) else h' = h.with("stickyWedged", (h.stickyWedged + 1)) else h' = h
  action step = any { injectFault, clearFault, handleRequest, finishRequest, probeRecovery }
  val safety = (h.activeLoad <= 2 and h.cascadeViolations == 0 and h.silentCorruptions == 0 and h.stickyWedged == 0)
  // Countermodel engineering.concurrency.chaos-fault-injection-recovery-envelope.open-circuit-cascade (dropped guard: shed-load-on-open-circuit)
  action handleRequestCascade = if (h.circuitState == 1) if (false) h' = h.with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("activeLoad", (h.activeLoad + 1)).with("cascadeViolations", (h.cascadeViolations + 1)) else if (h.faultActive) if (true) if ((h.consecutiveFaults + 1) >= 2) h' = h.with("consecutiveFaults", (h.consecutiveFaults + 1)).with("circuitState", 1).with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("consecutiveFaults", (h.consecutiveFaults + 1)).with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("silentCorruptions", (h.silentCorruptions + 1)) else if (h.activeLoad < 2) h' = h.with("activeLoad", (h.activeLoad + 1)) else h' = h
  action stepOpenCircuitCascade = any { step, handleRequestCascade }
  // Countermodel engineering.concurrency.chaos-fault-injection-recovery-envelope.silent-fallback-corruption (dropped guard: typed-refusal-under-fault)
  action handleRequestSilent = if (h.circuitState == 1) if (true) h' = h.with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("activeLoad", (h.activeLoad + 1)).with("cascadeViolations", (h.cascadeViolations + 1)) else if (h.faultActive) if (false) if ((h.consecutiveFaults + 1) >= 2) h' = h.with("consecutiveFaults", (h.consecutiveFaults + 1)).with("circuitState", 1).with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("consecutiveFaults", (h.consecutiveFaults + 1)).with("refusedDegraded", (h.refusedDegraded + 1)) else h' = h.with("silentCorruptions", (h.silentCorruptions + 1)) else if (h.activeLoad < 2) h' = h.with("activeLoad", (h.activeLoad + 1)) else h' = h
  action stepSilentFallbackCorruption = any { step, handleRequestSilent }
  // Countermodel engineering.concurrency.chaos-fault-injection-recovery-envelope.sticky-recovery-wedge (dropped guard: half-open-probe-recovery)
  action probeRecoveryWedged = if ((h.circuitState == 1 and not(h.faultActive))) if (false) h' = h.with("circuitState", 0).with("consecutiveFaults", 0).with("recoveredCount", (h.recoveredCount + 1)) else h' = h.with("stickyWedged", (h.stickyWedged + 1)) else h' = h
  action stepStickyRecoveryWedge = any { step, probeRecoveryWedged }
  action checkChaosSafe = all { assert(h.refusedDegraded > 0), assert(h.recoveredCount > 0), assert(h.circuitState == 0), assert(h.activeLoad == 0), assert(safety), h' = h }
  action checkChaosViolated = all { assert((h.cascadeViolations > 0 or h.silentCorruptions > 0 or h.stickyWedged > 0)), assert(not(safety)), h' = h }
  run chaosRecoverySafeTest = init.then(handleRequest).then(finishRequest).then(injectFault).then(handleRequest).then(handleRequest).then(handleRequest).then(clearFault).then(probeRecovery).then(checkChaosSafe)
  run openCircuitCascadeRefutedTest = init.then(injectFault).then(handleRequest).then(handleRequest).then(handleRequestCascade).then(checkChaosViolated)
  run silentFallbackRefutedTest = init.then(injectFault).then(handleRequestSilent).then(checkChaosViolated)
  run stickyWedgeRefutedTest = init.then(injectFault).then(handleRequest).then(handleRequest).then(clearFault).then(probeRecoveryWedged).then(checkChaosViolated)
}
