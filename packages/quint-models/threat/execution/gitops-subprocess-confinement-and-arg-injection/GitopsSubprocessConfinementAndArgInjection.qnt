// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.gitops-subprocess-confinement-and-arg-injection
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-git-env-config-or-exec-path-hijack step=stepGitEnvHijack max-steps=6 itf="h.envHijackBreaches > 0"
// @countermodel forbid-repo-fsmonitor-or-hook-execution step=stepFsmonitorOrHookBypass max-steps=6 itf="h.fsmonitorHookBreaches > 0"
// @countermodel forbid-option-injection-or-snapshot-path-escape step=stepArgOrSnapshotBypass max-steps=6 itf="h.argOrSnapshotBreaches > 0"
// @countermodel forbid-unbounded-subprocess-or-parallel-worker-panic-crash step=stepSubprocessOrPanicBypass max-steps=6 itf="h.subprocessOrPanicBreaches > 0"
// Limits: Finite bounded GitOps subprocess confinement, projection argument-injection & parallel fanout isolation state machine (parallelTasksCompleted <= 6, parallelPanicsIsolated <= 4, stepCount <= 12); models complete GIT_* environment neutralization (GIT_CONFIG_GLOBAL/SYSTEM/EXEC_PATH/SSH_COMMAND/EXTERNAL_DIFF + GIT_CONFIG_NOSYSTEM=1), dual-layer core.hooksPath=/dev/null & core.fsmonitor=false enforcement on Git and Worktrunk subprocesses, non-flag/non-control validation on branch/base_ref/id and snapshot_root path confinement, concurrent bounded stdout/stderr capture with timeout and kill_on_drop, and JoinSet panic isolation without modeling OS kernel ptrace or binary tampering inside trusted PATH.
module execution_gitops_subprocess_confinement_and_arg_injection {
  type State = { confinedCommandsRun: int, validatedProjections: int, parallelTasksCompleted: int, parallelPanicsIsolated: int, envConfinementEnforced: bool, fsmonitorHooksDisabled: bool, argAndSnapshotValidated: bool, boundedSubprocessEnforced: bool, envHijackBreaches: int, fsmonitorHookBreaches: int, argOrSnapshotBreaches: int, subprocessOrPanicBreaches: int, stepCount: int }
  var h: State
  action init = h' = { confinedCommandsRun: 0, validatedProjections: 0, parallelTasksCompleted: 0, parallelPanicsIsolated: 0, envConfinementEnforced: true, fsmonitorHooksDisabled: true, argAndSnapshotValidated: true, boundedSubprocessEnforced: true, envHijackBreaches: 0, fsmonitorHookBreaches: 0, argOrSnapshotBreaches: 0, subprocessOrPanicBreaches: 0, stepCount: 0 }
  action runConfinedGitRead = if ((h.stepCount < 12 and h.envConfinementEnforced and h.fsmonitorHooksDisabled)) h' = h.with("confinedCommandsRun", (h.confinedCommandsRun + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action projectValidatedWorkingCopy = if ((h.stepCount < 12 and h.argAndSnapshotValidated)) h' = h.with("validatedProjections", (h.validatedProjections + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action runBoundedProviderCommand = if ((h.stepCount < 12 and h.envConfinementEnforced and h.fsmonitorHooksDisabled and h.boundedSubprocessEnforced)) h' = h.with("confinedCommandsRun", (h.confinedCommandsRun + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action planConfinedRetentionSnapshot = if ((h.stepCount < 12 and h.argAndSnapshotValidated)) h' = h.with("validatedProjections", (h.validatedProjections + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action completeParallelIsolationTask = if ((h.stepCount < 12 and h.parallelTasksCompleted < 6)) h' = h.with("parallelTasksCompleted", (h.parallelTasksCompleted + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action isolatePanickedParallelWorker = if ((h.stepCount < 12 and h.parallelPanicsIsolated < 4)) h' = h.with("parallelPanicsIsolated", (h.parallelPanicsIsolated + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action validateWorktrunkReceiptPath = if ((h.stepCount < 12 and h.argAndSnapshotValidated)) h' = h.with("validatedProjections", (h.validatedProjections + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { runConfinedGitRead, projectValidatedWorkingCopy, runBoundedProviderCommand, planConfinedRetentionSnapshot, completeParallelIsolationTask, isolatePanickedParallelWorker, validateWorktrunkReceiptPath }
  val safety = (h.envHijackBreaches == 0 and h.fsmonitorHookBreaches == 0 and h.argOrSnapshotBreaches == 0 and h.subprocessOrPanicBreaches == 0 and h.envConfinementEnforced and h.fsmonitorHooksDisabled and h.argAndSnapshotValidated and h.boundedSubprocessEnforced and h.parallelTasksCompleted <= 6 and h.parallelPanicsIsolated <= 4 and h.stepCount <= 12)
  // Countermodel threat.execution.gitops-subprocess-confinement-and-arg-injection.git-env-hijack (dropped guard: forbid-git-env-config-or-exec-path-hijack)
  action exploitGitEnvHijack = if ((h.stepCount < 12)) h' = h.with("envConfinementEnforced", false).with("envHijackBreaches", (h.envHijackBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepGitEnvHijack = any { step, exploitGitEnvHijack }
  // Countermodel threat.execution.gitops-subprocess-confinement-and-arg-injection.fsmonitor-or-hook-bypass (dropped guard: forbid-repo-fsmonitor-or-hook-execution)
  action exploitFsmonitorOrHookBypass = if ((h.stepCount < 12)) h' = h.with("fsmonitorHooksDisabled", false).with("fsmonitorHookBreaches", (h.fsmonitorHookBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepFsmonitorOrHookBypass = any { step, exploitFsmonitorOrHookBypass }
  // Countermodel threat.execution.gitops-subprocess-confinement-and-arg-injection.arg-or-snapshot-bypass (dropped guard: forbid-option-injection-or-snapshot-path-escape)
  action exploitArgOrSnapshotBypass = if ((h.stepCount < 12)) h' = h.with("argAndSnapshotValidated", false).with("argOrSnapshotBreaches", (h.argOrSnapshotBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepArgOrSnapshotBypass = any { step, exploitArgOrSnapshotBypass }
  // Countermodel threat.execution.gitops-subprocess-confinement-and-arg-injection.subprocess-or-panic-bypass (dropped guard: forbid-unbounded-subprocess-or-parallel-worker-panic-crash)
  action exploitSubprocessOrPanicBypass = if ((h.stepCount < 12)) h' = h.with("boundedSubprocessEnforced", false).with("subprocessOrPanicBreaches", (h.subprocessOrPanicBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepSubprocessOrPanicBypass = any { step, exploitSubprocessOrPanicBypass }
  action checkSm32Safe = all { assert(safety), assert((h.confinedCommandsRun > 0 or h.validatedProjections > 0)), h' = h }
  action checkSm32Violated = all { assert((h.envHijackBreaches > 0 or h.fsmonitorHookBreaches > 0 or h.argOrSnapshotBreaches > 0 or h.subprocessOrPanicBreaches > 0)), assert(not(safety)), h' = h }
  run cleanGitopsConfinementSafeTest = init.then(runConfinedGitRead).then(projectValidatedWorkingCopy).then(runBoundedProviderCommand).then(planConfinedRetentionSnapshot).then(completeParallelIsolationTask).then(isolatePanickedParallelWorker).then(validateWorktrunkReceiptPath).then(checkSm32Safe)
  run envHijackRefutedTest = init.then(exploitGitEnvHijack).then(checkSm32Violated)
  run fsmonitorOrHookBypassRefutedTest = init.then(exploitFsmonitorOrHookBypass).then(checkSm32Violated)
  run argOrSnapshotBypassRefutedTest = init.then(exploitArgOrSnapshotBypass).then(checkSm32Violated)
  run subprocessOrPanicBypassRefutedTest = init.then(exploitSubprocessOrPanicBypass).then(checkSm32Violated)
}
