// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.process-signal-ledger-and-fanout-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-protected-pid-or-pgid-kill step=stepProtectedPidKill max-steps=6 itf="h.signalScopeBreaches > 0"
// @countermodel forbid-unfingerprinted-pid-reuse-reap step=stepPidReuseReap max-steps=6 itf="h.pidReuseBreaches > 0"
// @countermodel forbid-symlink-or-unbounded-process-ledger step=stepLedgerEscapeOrOom max-steps=6 itf="h.ledgerIntegrityBreaches > 0"
// @countermodel forbid-unbounded-fanout-or-undrained-abort step=stepFanoutExhaustion max-steps=6 itf="h.fanoutConfinementBreaches > 0"
// Limits: Finite bounded runtime process-signal, orphan reconciliation, process-ledger, and sub-agent fanout confinement state machine (activeFanout <= 12, ledgerEntries <= 12, stepCount <= 12); models fail-closed POSIX PID/PGID signal guards (> 1 and != host PID/PGID preventing kill(0)/kill(-1)/self-kill), mandatory OS start-time fingerprinting for orphan reconciliation and reaping, symlink-free O_NOFOLLOW byte- and entry-bounded schema-checked process ledger persistence, and hard-capped sub-agent fanout parallelism with abort-drain quiescence, without modeling kernel PID table exhaustion or scheduler preemption timing.
module execution_process_signal_ledger_and_fanout_confinement {
  type State = { activeFanout: int, ledgerEntries: int, signalTargetGuarded: bool, startFingerprintRequired: bool, ledgerConfinementEnforced: bool, fanoutBoundsAndDrainEnforced: bool, signalScopeBreaches: int, pidReuseBreaches: int, ledgerIntegrityBreaches: int, fanoutConfinementBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { activeFanout: 0, ledgerEntries: 0, signalTargetGuarded: true, startFingerprintRequired: true, ledgerConfinementEnforced: true, fanoutBoundsAndDrainEnforced: true, signalScopeBreaches: 0, pidReuseBreaches: 0, ledgerIntegrityBreaches: 0, fanoutConfinementBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action signalValidatedProcessGroup = if ((h.stepCount < 12 and h.signalTargetGuarded)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action reconcileFingerprintedOrphan = if ((h.stepCount < 12 and h.startFingerprintRequired)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action persistBoundedSymlinkSafeLedger = if ((h.stepCount < 12 and h.ledgerConfinementEnforced and h.ledgerEntries < 12)) h' = h.with("ledgerEntries", (h.ledgerEntries + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action admitBoundedFanoutWorker = if ((h.stepCount < 12 and h.fanoutBoundsAndDrainEnforced and h.activeFanout < 12)) h' = h.with("activeFanout", (h.activeFanout + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action completeFanoutWorker = if ((h.stepCount < 12 and h.fanoutBoundsAndDrainEnforced and h.activeFanout > 0)) h' = h.with("activeFanout", (h.activeFanout - 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action drainAbortedFanoutWorkers = if ((h.stepCount < 12 and h.fanoutBoundsAndDrainEnforced and h.activeFanout > 0)) h' = h.with("activeFanout", 0).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { signalValidatedProcessGroup, reconcileFingerprintedOrphan, persistBoundedSymlinkSafeLedger, admitBoundedFanoutWorker, completeFanoutWorker, drainAbortedFanoutWorkers }
  val safety = (h.signalScopeBreaches == 0 and h.pidReuseBreaches == 0 and h.ledgerIntegrityBreaches == 0 and h.fanoutConfinementBreaches == 0 and h.signalTargetGuarded and h.startFingerprintRequired and h.ledgerConfinementEnforced and h.fanoutBoundsAndDrainEnforced and h.activeFanout >= 0 and h.activeFanout <= 12 and h.ledgerEntries >= 0 and h.ledgerEntries <= 12 and h.stepCount <= 12)
  // Countermodel threat.execution.process-signal-ledger-and-fanout-confinement.protected-pid-kill (dropped guard: forbid-protected-pid-or-pgid-kill)
  action exploitProtectedPidKill = if ((h.stepCount < 12)) h' = h.with("signalTargetGuarded", false).with("signalScopeBreaches", (h.signalScopeBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepProtectedPidKill = any { step, exploitProtectedPidKill }
  // Countermodel threat.execution.process-signal-ledger-and-fanout-confinement.pid-reuse-reap (dropped guard: forbid-unfingerprinted-pid-reuse-reap)
  action exploitPidReuseReap = if ((h.stepCount < 12)) h' = h.with("startFingerprintRequired", false).with("pidReuseBreaches", (h.pidReuseBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepPidReuseReap = any { step, exploitPidReuseReap }
  // Countermodel threat.execution.process-signal-ledger-and-fanout-confinement.ledger-escape-or-oom (dropped guard: forbid-symlink-or-unbounded-process-ledger)
  action exploitLedgerEscapeOrOom = if ((h.stepCount < 12)) h' = h.with("ledgerConfinementEnforced", false).with("ledgerIntegrityBreaches", (h.ledgerIntegrityBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepLedgerEscapeOrOom = any { step, exploitLedgerEscapeOrOom }
  // Countermodel threat.execution.process-signal-ledger-and-fanout-confinement.fanout-exhaustion (dropped guard: forbid-unbounded-fanout-or-undrained-abort)
  action exploitFanoutExhaustion = if ((h.stepCount < 12)) h' = h.with("fanoutBoundsAndDrainEnforced", false).with("fanoutConfinementBreaches", (h.fanoutConfinementBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepFanoutExhaustion = any { step, exploitFanoutExhaustion }
  action checkSm37Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm37Violated = all { assert((h.signalScopeBreaches > 0 or h.pidReuseBreaches > 0 or h.ledgerIntegrityBreaches > 0 or h.fanoutConfinementBreaches > 0)), assert(not(safety)), h' = h }
  run cleanProcessSignalLedgerFanoutSafeTest = init.then(signalValidatedProcessGroup).then(reconcileFingerprintedOrphan).then(persistBoundedSymlinkSafeLedger).then(admitBoundedFanoutWorker).then(completeFanoutWorker).then(admitBoundedFanoutWorker).then(drainAbortedFanoutWorkers).then(checkSm37Safe)
  run protectedPidKillRefutedTest = init.then(exploitProtectedPidKill).then(checkSm37Violated)
  run pidReuseReapRefutedTest = init.then(exploitPidReuseReap).then(checkSm37Violated)
  run ledgerEscapeOrOomRefutedTest = init.then(exploitLedgerEscapeOrOom).then(checkSm37Violated)
  run fanoutExhaustionRefutedTest = init.then(exploitFanoutExhaustion).then(checkSm37Violated)
}
