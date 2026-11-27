;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM32 (ADV-L4): GitOps Subprocess Environment Neutralization, Hook/Fsmonitor
;;; Lockdown, Argument-Injection & Snapshot Confinement, Bounded Execution &
;;; Parallel Worker Panic Isolation.
;;; Formalizes five real ADV-L4 vulnerabilities discovered in marlin-agent-gitops:
;;;  1. GIT_REPOSITORY_OVERRIDES stripped only 10 variables and omitted
;;;     GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, GIT_EXEC_PATH, GIT_TEMPLATE_DIR,
;;;     GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, GIT_ASKPASS, and GIT_PAGER, while
;;;     read.rs and working_copy/driver.rs never set GIT_CONFIG_NOSYSTEM=1 or
;;;     GIT_CONFIG_GLOBAL=/dev/null, enabling arbitrary command execution and
;;;     remote URL rewrites via inherited environment variables.
;;;  2. ProcessWorkingCopyCommandRunner::run and command_projection.rs omitted
;;;     core.fsmonitor=false on all Git and Worktrunk working-copy mutations
;;;     (and omitted core.hooksPath=/dev/null on git worktree list/remove),
;;;     letting hostile repository .git/config [core] fsmonitor execute shell
;;;     commands during worktree creation, switch, or removal.
;;;  3. WorkingCopyCommandProjection accepted unvalidated dash-prefixed
;;;     WorkingCopyBranchName, WorkingCopyBaseRef, and WorkingCopyId values
;;;     (e.g. "--execute=...", "-f", "--orphan") enabling CLI option injection,
;;;     and WorkingCopyRetentionPolicy::plan_sweep joined unsanitized
;;;     working_copy.id into snapshot_root enabling ../../ and absolute path
;;;     traversal escapes outside the snapshot directory.
;;;  4. WorkingCopyProviderExecutableProbeCommand, verify_pull_request_repository,
;;;     and ProcessWorkingCopyCommandRunner::run called unbounded .output().await
;;;     without execution timeout, stdout/stderr byte caps, stdin(Stdio::null()),
;;;     or kill_on_drop(true), risking OOM, hangs, and orphan git/wt/gh children.
;;;  5. WorkingCopyIsolationDriver::isolate_parallel called .expect() on
;;;     JoinSet::join_next(), crashing the coordinator if any worker panicked,
;;;     and resolve_working_copy accepted root "/" or ".." Worktrunk JSON paths.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export GitopsSubprocessConfinementAndArgInjectionModel)

(.def (GitopsSubprocessConfinementAndArgInjectionModel @ ThreatModel.)
  identity: 'threat.execution.gitops-subprocess-confinement-and-arg-injection
  family: 'threat.execution.gitops-subprocess-confinement-and-arg-injection
  title: "GitOps Subprocess Environment Neutralization, Fsmonitor Lockdown, Arg-Injection & Panic Isolation (SM32)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM32 ADV-L4 complete GIT_* override stripping and GIT_CONFIG_NOSYSTEM=1 / GIT_CONFIG_GLOBAL=/dev/null neutralization, dual-layer core.hooksPath=/dev/null and core.fsmonitor=false enforcement across Git and Worktrunk subprocesses, non-flag/non-control validation of WorkingCopyBranchName/WorkingCopyBaseRef/WorkingCopyId and confined retention snapshot paths, concurrent bounded stdout/stderr capture with timeout and kill_on_drop(true), and JoinSet panic-isolated fanout receipts.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-gitops omitted GIT_CONFIG_GLOBAL/GIT_EXEC_PATH/GIT_SSH_COMMAND from GIT_REPOSITORY_OVERRIDES, omitted core.fsmonitor=false on working-copy provider execution, projected unvalidated dash-prefixed branch/base_ref/id arguments and unsanitized retention snapshot paths, ran unbounded .output().await without timeout or kill_on_drop in working_copy/driver.rs, and crashed isolate_parallel via .expect() on worker panics."))
  quint-module: "execution_gitops_subprocess_confinement_and_arg_injection"
  quint-file: "GitopsSubprocessConfinementAndArgInjection.qnt"
  domain-dir: "threat/execution/gitops-subprocess-confinement-and-arg-injection"
  rules:
  '((gitops-subprocess-confinement-safe DE-SM32-SAFE quint)
    (gitops-subprocess-confinement-countermodel DE-SM32-COUNTER quint))
  dependencies:
  '((DE-SM32-SAFE source)
    (DE-SM32-SAFE profile)
    (DE-SM32-SAFE method)
    (DE-SM32-COUNTER source)
    (DE-SM32-COUNTER profile)
    (DE-SM32-COUNTER method))
  invariant: "No GitOps read or working-copy provider subprocess inherits GIT_CONFIG_GLOBAL/SYSTEM/EXEC_PATH/SSH_COMMAND overrides (envHijackBreaches == 0 and envConfinementEnforced), every Git and Worktrunk invocation enforces core.hooksPath=/dev/null and core.fsmonitor=false (fsmonitorHookBreaches == 0 and fsmonitorHooksDisabled), projected branch/base_ref/id tokens reject leading '-' and control chars while retention snapshots stay strictly confined inside snapshot_root and Worktrunk receipts reject '/' or '..' (argOrSnapshotBreaches == 0 and argAndSnapshotValidated), and provider commands run bounded with timeout/kill_on_drop while isolate_parallel isolates worker panics into rejected receipts (subprocessOrPanicBreaches == 0 and boundedSubprocessEnforced)."
  limits: "Finite bounded GitOps subprocess confinement, projection argument-injection & parallel fanout isolation state machine (parallelTasksCompleted <= 6, parallelPanicsIsolated <= 4, stepCount <= 12); models complete GIT_* environment neutralization (GIT_CONFIG_GLOBAL/SYSTEM/EXEC_PATH/SSH_COMMAND/EXTERNAL_DIFF + GIT_CONFIG_NOSYSTEM=1), dual-layer core.hooksPath=/dev/null & core.fsmonitor=false enforcement on Git and Worktrunk subprocesses, non-flag/non-control validation on branch/base_ref/id and snapshot_root path confinement, concurrent bounded stdout/stderr capture with timeout and kill_on_drop, and JoinSet panic isolation without modeling OS kernel ptrace or binary tampering inside trusted PATH.")
