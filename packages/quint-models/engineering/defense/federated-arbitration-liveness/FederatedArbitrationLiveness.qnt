// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.federated-arbitration-liveness
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-retry-budget step=stepUnboundedRetry max-steps=6 itf="h.unboundedRetryViolations > 0"
// @countermodel require-no-deadlock step=stepDeadlockRetry max-steps=6 itf="h.deadlockRetryViolations > 0"
// @countermodel require-non-terminal step=stepTerminalReentry max-steps=6 itf="h.terminalReentryViolations > 0"
// Limits: Two-attempt bounded retry abstraction; arbitrary maxAttempts and absorbing terminal phases are proved unboundedly in FederatedArbitrationLiveness.lean.
module federated_arbitration_liveness {
  type State = { attempts: int, deadlockDetected: bool, terminated: bool, escalated: bool, admitted: bool, unboundedRetryViolations: int, deadlockRetryViolations: int, terminalReentryViolations: int }
  var h: State
  action init = h' = { attempts: 0, deadlockDetected: false, terminated: false, escalated: false, admitted: false, unboundedRetryViolations: 0, deadlockRetryViolations: 0, terminalReentryViolations: 0 }
  action detectDeadlockCycle = if ((not(h.terminated) and not(h.deadlockDetected))) h' = h.with("deadlockDetected", true) else h' = h
  action attemptAutoRetry = if ((h.attempts < 3 and h.attempts < 2 and not(h.deadlockDetected) and not(h.terminated))) h' = h.with("attempts", (h.attempts + 1)).with("unboundedRetryViolations", if (h.attempts < 2) h.unboundedRetryViolations else (h.unboundedRetryViolations + 1)).with("deadlockRetryViolations", if (not(h.deadlockDetected)) h.deadlockRetryViolations else (h.deadlockRetryViolations + 1)).with("terminalReentryViolations", if (not(h.terminated)) h.terminalReentryViolations else (h.terminalReentryViolations + 1)) else h' = h
  action escalateOrAbort = if ((not(h.terminated) and (h.deadlockDetected or h.attempts >= 2))) h' = h.with("terminated", true).with("escalated", true) else h' = h
  action admitClean = if ((not(h.terminated) and not(h.deadlockDetected) and h.attempts < 2)) h' = h.with("terminated", true).with("admitted", true) else h' = h
  action step = any { detectDeadlockCycle, attemptAutoRetry, escalateOrAbort, admitClean }
  val safety = (h.unboundedRetryViolations == 0 and h.deadlockRetryViolations == 0 and h.terminalReentryViolations == 0 and not((h.escalated and h.admitted)))
  // Countermodel engineering.defense.federated-arbitration-liveness.unbounded-retry (dropped guard: require-retry-budget)
  action attemptUnboundedRetry = if ((h.attempts < 3 and true and not(h.deadlockDetected) and not(h.terminated))) h' = h.with("attempts", (h.attempts + 1)).with("unboundedRetryViolations", if (h.attempts < 2) h.unboundedRetryViolations else (h.unboundedRetryViolations + 1)).with("deadlockRetryViolations", if (not(h.deadlockDetected)) h.deadlockRetryViolations else (h.deadlockRetryViolations + 1)).with("terminalReentryViolations", if (not(h.terminated)) h.terminalReentryViolations else (h.terminalReentryViolations + 1)) else h' = h
  action stepUnboundedRetry = any { step, attemptUnboundedRetry }
  // Countermodel engineering.defense.federated-arbitration-liveness.deadlock-retry (dropped guard: require-no-deadlock)
  action attemptDeadlockRetry = if ((h.attempts < 3 and h.attempts < 2 and true and not(h.terminated))) h' = h.with("attempts", (h.attempts + 1)).with("unboundedRetryViolations", if (h.attempts < 2) h.unboundedRetryViolations else (h.unboundedRetryViolations + 1)).with("deadlockRetryViolations", if (not(h.deadlockDetected)) h.deadlockRetryViolations else (h.deadlockRetryViolations + 1)).with("terminalReentryViolations", if (not(h.terminated)) h.terminalReentryViolations else (h.terminalReentryViolations + 1)) else h' = h
  action stepDeadlockRetry = any { step, attemptDeadlockRetry }
  // Countermodel engineering.defense.federated-arbitration-liveness.terminal-reentry (dropped guard: require-non-terminal)
  action attemptTerminalReentry = if ((h.attempts < 3 and h.attempts < 2 and not(h.deadlockDetected) and true)) h' = h.with("attempts", (h.attempts + 1)).with("unboundedRetryViolations", if (h.attempts < 2) h.unboundedRetryViolations else (h.unboundedRetryViolations + 1)).with("deadlockRetryViolations", if (not(h.deadlockDetected)) h.deadlockRetryViolations else (h.deadlockRetryViolations + 1)).with("terminalReentryViolations", if (not(h.terminated)) h.terminalReentryViolations else (h.terminalReentryViolations + 1)) else h' = h
  action stepTerminalReentry = any { step, attemptTerminalReentry }
  run boundedEscalationTest = init.then(attemptAutoRetry).then(attemptAutoRetry).then(escalateOrAbort).then(attemptAutoRetry).then(all { assert(safety), assert(h.escalated), assert(not(h.admitted)), h' = h })
  run unboundedRetryViolatesSafetyTest = init.then(attemptAutoRetry).then(attemptAutoRetry).then(attemptUnboundedRetry).then(all { assert(not(safety)), assert(h.unboundedRetryViolations > 0), h' = h })
  run deadlockRetryViolatesSafetyTest = init.then(detectDeadlockCycle).then(attemptDeadlockRetry).then(all { assert(not(safety)), assert(h.deadlockRetryViolations > 0), h' = h })
  run terminalReentryViolatesSafetyTest = init.then(admitClean).then(attemptTerminalReentry).then(all { assert(not(safety)), assert(h.terminalReentryViolations > 0), h' = h })
}
