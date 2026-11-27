;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM37 (ADV-L4): Process-Group Signal Confinement, Anti-PID-Reuse Orphan
;;; Reaping, Symlink-Safe Bounded Process Ledger & Bounded Fanout Drain.
;;; Formalizes four real ADV-L4 boundary defects discovered in
;;; marlin-agent-runtime:
;;;  1. process/shutdown.rs (signal_unix_target, is_process_group_alive,
;;;     wait_for_process_group_exit) and cleanup.rs accepted pid/pgid <= 1 or
;;;     matching the current host PID/PGID, turning pgid=0 into POSIX kill(0)
;;;     (host process-group suicide) and pgid=1 into POSIX kill(-1) (killing
;;;     every user-owned process on the machine), while managed_reaper waited on
;;;     ctx.pid rather than target_pgid.
;;;  2. process/reconcile.rs matches_recorded_start_time returned true when
;;;     os_start_time_secs was None and never rejected protected/self PIDs or
;;;     PGIDs during probe_persisted_process and reap_survived_entry.
;;;  3. process/ledger.rs FileProcessLedgerStore followed symlinks on ledger,
;;;     lock, and parent paths, performed unbounded read_to_string without a
;;;     file-size cap, skipped schema_version validation, and left active and
;;;     in-memory ledger entries unbounded.
;;;  4. tokio_runtime/fanout.rs allowed unbounded sub-agent fanout parallelism
;;;     (None or huge bounded values), returned from cancel_remaining_work after
;;;     abort_all() without awaiting drained task exits, and lost panicked input
;;;     index attribution via join_next() instead of join_next_with_id().
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ProcessSignalLedgerAndFanoutConfinementModel)

(.def (ProcessSignalLedgerAndFanoutConfinementModel @ ThreatModel.)
  identity: 'threat.execution.process-signal-ledger-and-fanout-confinement
  family: 'threat.execution.process-signal-ledger-and-fanout-confinement
  title: "Process Signal, Ledger & Fanout Confinement (SM37)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM37 ADV-L4 POSIX signal target confinement forbidding pid/pgid <= 1 and host self-PID/PGID kill(0)/kill(-1) hazards, fail-closed OS start-time fingerprinting for post-restart orphan reconciliation and reaping, O_NOFOLLOW symlink-safe byte- and entry-bounded schema-checked process ledger persistence, and hard-capped sub-agent fanout parallelism with abort-drain quiescence and exact panic index attribution.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-runtime admitted pid/pgid 0 and 1 in libc::kill(-pgid_i32, sig) (kill(0)/kill(-1)), failed open on missing os_start_time_secs during orphan reconciliation, followed symlinks and performed unbounded schema-unchecked reads in FileProcessLedgerStore, and permitted unbounded fanout parallelism with undrained abort_all() returns in WorkingCopySubAgentFanoutRunner."))
  quint-module: "execution_process_signal_ledger_and_fanout_confinement"
  quint-file: "ProcessSignalLedgerAndFanoutConfinement.qnt"
  domain-dir: "threat/execution/process-signal-ledger-and-fanout-confinement"
  rules:
  '((process-signal-ledger-fanout-safe DE-SM37-SAFE quint)
    (process-signal-ledger-fanout-countermodel DE-SM37-COUNTER quint))
  dependencies:
  '((DE-SM37-SAFE source)
    (DE-SM37-SAFE profile)
    (DE-SM37-SAFE method)
    (DE-SM37-COUNTER source)
    (DE-SM37-COUNTER profile)
    (DE-SM37-COUNTER method))
  invariant: "POSIX signal targets reject pid/pgid <= 1 and host self-PID/PGID (signalScopeBreaches == 0 and signalTargetGuarded), orphan reconciliation and reaping fail closed without verified OS start-time fingerprints (pidReuseBreaches == 0 and startFingerprintRequired), process ledger I/O enforces symlink-free O_NOFOLLOW byte/schema/capacity confinement (ledgerIntegrityBreaches == 0 and ledgerConfinementEnforced and ledgerEntries <= 12), and sub-agent fanout enforces hard parallelism ceilings plus full abort-drain quiescence (fanoutConfinementBreaches == 0 and fanoutBoundsAndDrainEnforced and activeFanout >= 0 and activeFanout <= 12)."
  limits: "Finite bounded runtime process-signal, orphan reconciliation, process-ledger, and sub-agent fanout confinement state machine (activeFanout <= 12, ledgerEntries <= 12, stepCount <= 12); models fail-closed POSIX PID/PGID signal guards (> 1 and != host PID/PGID preventing kill(0)/kill(-1)/self-kill), mandatory OS start-time fingerprinting for orphan reconciliation and reaping, symlink-free O_NOFOLLOW byte- and entry-bounded schema-checked process ledger persistence, and hard-capped sub-agent fanout parallelism with abort-drain quiescence, without modeling kernel PID table exhaustion or scheduler preemption timing.")
