/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM32: Adversarial (`ADV-L4`) GitOps Subprocess Confinement, Fsmonitor Lockdown, Argument-Injection & Panic Isolation

Standalone objectified `LeanPoo` module (50th Lean module, zero edits to
`Core/Stability.lean`) formalizing five real `ADV-L4` GitOps execution
vulnerabilities discovered in `marlin-agent-gitops`:

1. **Complete Git Environment Neutralization**: `GIT_REPOSITORY_OVERRIDES`
   omitted `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_EXEC_PATH`,
   `GIT_TEMPLATE_DIR`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, and `GIT_ASKPASS`,
   while `read.rs` and `working_copy/driver.rs` never set `GIT_CONFIG_NOSYSTEM=1`
   or `GIT_CONFIG_GLOBAL=/dev/null`, enabling arbitrary command execution and
   remote URL rewrites via inherited environment variables.
2. **Dual-Layer Hook & Fsmonitor Lockdown**: `ProcessWorkingCopyCommandRunner::run`
   and `command_projection.rs` omitted `core.fsmonitor=false` on Git and Worktrunk
   working-copy operations (and omitted `core.hooksPath=/dev/null` on `worktree
   list`/`remove`), letting hostile repository `.git/config [core] fsmonitor`
   execute arbitrary shell commands.
3. **Option-Injection & Retention Snapshot Path Confinement**: `WorkingCopyBranchName`,
   `WorkingCopyBaseRef`, and `WorkingCopyId` admitted dash-prefixed CLI options
   (`--execute=...`, `--orphan`, `-f`) and control characters in command projection,
   while `WorkingCopyRetentionPolicy::plan_sweep` joined unsanitized `working_copy.id`
   into `snapshot_root` allowing `../../` and absolute path traversal escapes.
4. **Bounded Resilient Subprocess Capture**: `WorkingCopyProviderExecutableProbeCommand`,
   `verify_pull_request_repository`, and `ProcessWorkingCopyCommandRunner::run`
   called unbounded `.output().await` without timeout, stdout/stderr byte caps,
   `stdin(Stdio::null())`, or `kill_on_drop(true)`.
5. **Parallel Worker Panic Isolation & Receipt Path Validation**:
   `WorkingCopyIsolationDriver::isolate_parallel` crashed the coordinator via
   `.expect()` on `JoinSet::join_next()` worker panics, and `resolve_working_copy`
   accepted root `"/"` or `".."` traversal segments in Worktrunk JSON receipts.
-/

namespace DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Git subprocess environment neutralization admission predicate. -/
def gitSubprocessEnvConfined
    (stripsGlobalSystemConfigAndExecPath : Bool)
    (setsNoSystemAndNullGlobalConfig : Bool)
    (disablesInteractivePrompts : Bool) : Bool :=
  stripsGlobalSystemConfigAndExecPath &&
  setsNoSystemAndNullGlobalConfig &&
  disablesInteractivePrompts

/-- Dual-layer Git hook and fsmonitor neutralization across Git & Worktrunk providers. -/
def gitHooksAndFsmonitorLocked
    (disablesHooksPath : Bool)
    (disablesFsmonitor : Bool)
    (propagatesConfigParamsToSubprocesses : Bool) : Bool :=
  disablesHooksPath && disablesFsmonitor && propagatesConfigParamsToSubprocesses

/-- Command-projection argument & retention snapshot path admission predicate. -/
def projectedArgAndSnapshotSafe
    (nonEmptyNoControl : Bool)
    (noLeadingDashOption : Bool)
    (noPathTraversalOrRootEscape : Bool) : Bool :=
  nonEmptyNoControl && noLeadingDashOption && noPathTraversalOrRootEscape

/-- Bounded provider subprocess capture policy (stdout/stderr caps, timeout, kill_on_drop, null stdin). -/
def boundedProviderCaptureSafe
    (stdoutBytes stderrBytes maxBytes : Nat)
    (withinTimeout : Bool)
    (killOnDropAndNullStdin : Bool) : Bool :=
  (stdoutBytes ≤ maxBytes) && (stderrBytes ≤ maxBytes) && withinTimeout && killOnDropAndNullStdin

/-- Parallel fanout receipt accounting outcome when worker tasks may succeed, reject, or panic. -/
structure ParallelFanoutAccounting where
  applied : Nat
  rejectedNormal : Nat
  rejectedPanicked : Nat
  deriving DecidableEq, Repr

def ParallelFanoutAccounting.totalReceipts (a : ParallelFanoutAccounting) : Nat :=
  a.applied + (a.rejectedNormal + a.rejectedPanicked)

/-- Security posture of a Marlin GitOps subprocess & working-copy boundary. -/
structure GitopsConfinementConfig where
  enforcesCompleteGitEnvNeutralization : Bool
  enforcesDualLayerHooksAndFsmonitorLockdown : Bool
  enforcesArgInjectionAndSnapshotConfinement : Bool
  enforcesBoundedSubprocessCaptureAndKillOnDrop : Bool
  enforcesParallelPanicIsolationAndReceiptPathCheck : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a GitOps configuration satisfies strict SM32 confinement. -/
def strictSm32Admitted (c : GitopsConfinementConfig) : Bool :=
  c.enforcesCompleteGitEnvNeutralization &&
  c.enforcesDualLayerHooksAndFsmonitorLockdown &&
  c.enforcesArgInjectionAndSnapshotConfinement &&
  c.enforcesBoundedSubprocessCaptureAndKillOnDrop &&
  c.enforcesParallelPanicIsolationAndReceiptPathCheck &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM32 hostile exploit classes remain reachable. -/
def anySm32ExploitReachable (c : GitopsConfinementConfig) : Bool :=
  !c.enforcesCompleteGitEnvNeutralization ||
  !c.enforcesDualLayerHooksAndFsmonitorLockdown ||
  !c.enforcesArgInjectionAndSnapshotConfinement ||
  !c.enforcesBoundedSubprocessCaptureAndKillOnDrop ||
  !c.enforcesParallelPanicIsolationAndReceiptPathCheck

/-- Canonical hardened SM32 Marlin GitOps posture. -/
def hardenedSm32Config : GitopsConfinementConfig :=
  { enforcesCompleteGitEnvNeutralization := true
    enforcesDualLayerHooksAndFsmonitorLockdown := true
    enforcesArgInjectionAndSnapshotConfinement := true
    enforcesBoundedSubprocessCaptureAndKillOnDrop := true
    enforcesParallelPanicIsolationAndReceiptPathCheck := true
    pressureTier := .l4HostileAttack }

def defectiveGitEnvConfig : GitopsConfinementConfig :=
  { hardenedSm32Config with enforcesCompleteGitEnvNeutralization := false }

def defectiveFsmonitorHooksConfig : GitopsConfinementConfig :=
  { hardenedSm32Config with enforcesDualLayerHooksAndFsmonitorLockdown := false }

def defectiveArgSnapshotConfig : GitopsConfinementConfig :=
  { hardenedSm32Config with enforcesArgInjectionAndSnapshotConfinement := false }

def defectiveUnboundedOutputConfig : GitopsConfinementConfig :=
  { hardenedSm32Config with enforcesBoundedSubprocessCaptureAndKillOnDrop := false }

def defectivePanicCrashConfig : GitopsConfinementConfig :=
  { hardenedSm32Config with enforcesParallelPanicIsolationAndReceiptPathCheck := false }

def defectiveGentleTierConfig : GitopsConfinementConfig :=
  { hardenedSm32Config with pressureTier := .l1Gentle }

/-- Theorem 1: Omitting GIT_CONFIG_GLOBAL/EXEC_PATH stripping, NOSYSTEM/null global config, or prompt disable fails Git environment confinement. -/
theorem sm32_git_env_confinement_requires_all_guards (a b c : Bool) :
    gitSubprocessEnvConfined false b c = false ∧
    gitSubprocessEnvConfined a false c = false ∧
    gitSubprocessEnvConfined a b false = false ∧
    gitSubprocessEnvConfined true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 2: Omitting core.hooksPath=/dev/null, core.fsmonitor=false, or GIT_CONFIG_PARAMETERS propagation fails hook/fsmonitor lockdown. -/
theorem sm32_hooks_and_fsmonitor_lockdown_complete (a b c : Bool) :
    gitHooksAndFsmonitorLocked false b c = false ∧
    gitHooksAndFsmonitorLocked a false c = false ∧
    gitHooksAndFsmonitorLocked a b false = false ∧
    gitHooksAndFsmonitorLocked true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 3: Dash-prefixed options, control chars/empty values, and path-traversal/root escapes are all unconditionally refused. -/
theorem sm32_arg_injection_and_snapshot_escape_refused (a b c : Bool) :
    projectedArgAndSnapshotSafe false b c = false ∧
    projectedArgAndSnapshotSafe a false c = false ∧
    projectedArgAndSnapshotSafe a b false = false ∧
    projectedArgAndSnapshotSafe true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 4: Exceeding stdout or stderr byte caps, timing out, or lacking kill_on_drop/null stdin fails bounded subprocess capture. -/
theorem sm32_bounded_capture_refuses_overflow_timeout_or_orphan
    (stdoutBytes stderrBytes maxBytes : Nat) (withinTimeout killOnDrop : Bool) :
    (maxBytes < stdoutBytes →
      boundedProviderCaptureSafe stdoutBytes stderrBytes maxBytes withinTimeout killOnDrop = false) ∧
    (maxBytes < stderrBytes →
      boundedProviderCaptureSafe stdoutBytes stderrBytes maxBytes withinTimeout killOnDrop = false) ∧
    boundedProviderCaptureSafe stdoutBytes stderrBytes maxBytes false killOnDrop = false ∧
    boundedProviderCaptureSafe stdoutBytes stderrBytes maxBytes withinTimeout false = false := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro hgt
    have hnotle : ¬ (stdoutBytes ≤ maxBytes) := Nat.not_le_of_gt hgt
    simp [boundedProviderCaptureSafe, hnotle]
  · intro hgt
    have hnotle : ¬ (stderrBytes ≤ maxBytes) := Nat.not_le_of_gt hgt
    simp [boundedProviderCaptureSafe, hnotle]
  · simp [boundedProviderCaptureSafe]
  · simp [boundedProviderCaptureSafe]

/-- Theorem 5: Converting each panicked parallel worker into a rejected receipt preserves total request conservation without coordinator crashes. -/
theorem sm32_parallel_panic_isolation_conserves_receipts (a : ParallelFanoutAccounting) :
    ParallelFanoutAccounting.totalReceipts { a with rejectedPanicked := a.rejectedPanicked + 1 } =
    a.totalReceipts + 1 := by
  simp [ParallelFanoutAccounting.totalReceipts, Nat.add_assoc]

/-- Theorem 6: Strict SM32 admission eliminates all 5 GitOps exploit classes. -/
theorem sm32_strict_admission_eliminates_all_exploits (c : GitopsConfinementConfig)
    (h : strictSm32Admitted c = true) :
    anySm32ExploitReachable c = false := by
  cases c with
  | mk e f a b p tier =>
    simp [strictSm32Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨he, hf⟩, ha⟩, hb⟩, hp⟩, _⟩
    subst he; subst hf; subst ha; subst hb; subst hp
    rfl

/-- Theorem 7: Gentle ADV-L1/ADV-L2 tiers fail mandatory SM32 admission. -/
theorem sm32_gentle_pressure_rejected (c : GitopsConfinementConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm32Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm32Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm32Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 8: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm32_defective_configs_expose_live_exploits :
    anySm32ExploitReachable defectiveGitEnvConfig = true ∧
    anySm32ExploitReachable defectiveFsmonitorHooksConfig = true ∧
    anySm32ExploitReachable defectiveArgSnapshotConfig = true ∧
    anySm32ExploitReachable defectiveUnboundedOutputConfig = true ∧
    anySm32ExploitReachable defectivePanicCrashConfig = true ∧
    strictSm32Admitted defectiveGentleTierConfig = false ∧
    strictSm32Admitted hardenedSm32Config = true ∧
    anySm32ExploitReachable hardenedSm32Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive GitopsConfigKey where
  | completeGitEnvNeutralization
  | dualLayerHooksAndFsmonitorLockdown
  | argInjectionAndSnapshotConfinement
  | boundedSubprocessCapture
  | parallelPanicIsolationAndReceiptPath
  | pressureTier
  deriving DecidableEq, Repr

inductive GitopsIssue where
  | gitEnvOverrideHijack
  | repoFsmonitorOrHookExecution
  | optionInjectionOrSnapshotEscape
  | unboundedSubprocessOrOrphanChild
  | parallelPanicCrashOrInvalidReceiptPath
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def gitopsView : View GitopsConfinementConfig GitopsConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseGitopsContract :
    Contract GitopsConfinementConfig GitopsConfigKey Unit GitopsIssue where
  view := gitopsView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesCompleteGitEnvNeutralization then [] else [.rejected path .gitEnvOverrideHijack]) ++
    (if cfg.enforcesDualLayerHooksAndFsmonitorLockdown then [] else [.rejected path .repoFsmonitorOrHookExecution]) ++
    (if cfg.enforcesArgInjectionAndSnapshotConfinement then [] else [.rejected path .optionInjectionOrSnapshotEscape]) ++
    (if cfg.enforcesBoundedSubprocessCaptureAndKillOnDrop then [] else [.rejected path .unboundedSubprocessOrOrphanChild]) ++
    (if cfg.enforcesParallelPanicIsolationAndReceiptPathCheck then [] else [.rejected path .parallelPanicCrashOrInvalidReceiptPath])
  validInventory := Or.inl rfl

def marlinGitopsContract :
    Contract GitopsConfinementConfig GitopsConfigKey Unit GitopsIssue :=
  refine baseGitopsContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 9: Refined Marlin GitOps contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm32_marlin_contract_refinement_laws
    (cfg : GitopsConfinementConfig) (path : List GitopsConfigKey) :
    (diagnose baseGitopsContract cfg path ≠ [] →
      diagnose marlinGitopsContract cfg path ≠ []) ∧
    (diagnose marlinGitopsContract cfg path = [] ↔
      diagnose baseGitopsContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path GitopsIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseGitopsContract _ cfg path,
   refine_accepts_iff baseGitopsContract _ cfg path⟩

inductive GitopsProofKey where
  | completeGitEnvNeutralization
  | dualLayerHooksAndFsmonitorLockdown
  | argInjectionAndSnapshotConfinement
  | boundedSubprocessCapture
  | parallelPanicIsolationAndReceiptPath
  | pressureTier
  | providerTimeoutSecs
  deriving DecidableEq

abbrev GitopsProofValue : GitopsProofKey → Type
  | .completeGitEnvNeutralization => Bool
  | .dualLayerHooksAndFsmonitorLockdown => Bool
  | .argInjectionAndSnapshotConfinement => Bool
  | .boundedSubprocessCapture => Bool
  | .parallelPanicIsolationAndReceiptPath => Bool
  | .pressureTier => AdversarialPressureTier
  | .providerTimeoutSecs => Nat

def gitopsObligation :
    LeanPoo.Proof.Obligation GitopsProofKey GitopsProofValue where
  dependencies := [
    .completeGitEnvNeutralization,
    .dualLayerHooksAndFsmonitorLockdown,
    .argInjectionAndSnapshotConfinement,
    .boundedSubprocessCapture,
    .parallelPanicIsolationAndReceiptPath,
    .pressureTier
  ]
  holds := fun s =>
    s .completeGitEnvNeutralization = true ∧
    s .dualLayerHooksAndFsmonitorLockdown = true ∧
    s .argInjectionAndSnapshotConfinement = true ∧
    s .boundedSubprocessCapture = true ∧
    s .parallelPanicIsolationAndReceiptPath = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .completeGitEnvNeutralization = after .completeGitEnvNeutralization :=
      same .completeGitEnvNeutralization (by simp)
    have h2 : before .dualLayerHooksAndFsmonitorLockdown = after .dualLayerHooksAndFsmonitorLockdown :=
      same .dualLayerHooksAndFsmonitorLockdown (by simp)
    have h3 : before .argInjectionAndSnapshotConfinement = after .argInjectionAndSnapshotConfinement :=
      same .argInjectionAndSnapshotConfinement (by simp)
    have h4 : before .boundedSubprocessCapture = after .boundedSubprocessCapture :=
      same .boundedSubprocessCapture (by simp)
    have h5 : before .parallelPanicIsolationAndReceiptPath = after .parallelPanicIsolationAndReceiptPath :=
      same .parallelPanicIsolationAndReceiptPath (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineGitopsProof :
    LeanPoo.Proof.ProofObject GitopsProofKey GitopsProofValue where
  state := fun
    | .completeGitEnvNeutralization => true
    | .dualLayerHooksAndFsmonitorLockdown => true
    | .argInjectionAndSnapshotConfinement => true
    | .boundedSubprocessCapture => true
    | .parallelPanicIsolationAndReceiptPath => true
    | .pressureTier => .l4HostileAttack
    | .providerTimeoutSecs => 30
  obligations := [gitopsObligation]

/-- Theorem 10: Baseline ADV-L4 SM32 proof is certified. -/
theorem sm32_baseline_certified :
    LeanPoo.Proof.Certificate baselineGitopsProof := by
  intro obligation member
  have hEq : obligation = gitopsObligation := by
    simpa [baselineGitopsProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def timeoutTuningPatch :
    LeanPoo.Proof.Patch GitopsProofKey GitopsProofValue :=
  LeanPoo.Proof.Patch.set .providerTimeoutSecs 15

theorem sm32_obligation_untouched_by_timeout_tuning :
    LeanPoo.Proof.unaffected gitopsObligation timeoutTuningPatch := by
  intro key dep touched
  have hKey : key = .providerTimeoutSecs := by
    simpa [timeoutTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [gitopsObligation] at dep

/-- Theorem 11: Tuning bounded provider timeout cleanly reuses and closes the LeanPoo certificate. -/
theorem sm32_timeout_tuning_reuses_and_closes_certificate :
    gitopsObligation.holds
      (LeanPoo.Proof.append baselineGitopsProof timeoutTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineGitopsProof timeoutTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineGitopsProof timeoutTuningPatch
      sm32_baseline_certified gitopsObligation
      (by simp [baselineGitopsProof]) sm32_obligation_untouched_by_timeout_tuning
  · apply LeanPoo.Proof.close baselineGitopsProof timeoutTuningPatch
      sm32_baseline_certified
    · intro obligation member affected
      have hEq : obligation = gitopsObligation := by
        simpa [baselineGitopsProof] using member
      subst obligation
      exact False.elim (affected sm32_obligation_untouched_by_timeout_tuning)
    · intro obligation member
      simp [timeoutTuningPatch, LeanPoo.Proof.Patch.set] at member

def gitEnvRegressionPatch :
    LeanPoo.Proof.Patch GitopsProofKey GitopsProofValue :=
  LeanPoo.Proof.Patch.set .completeGitEnvNeutralization false

def fsmonitorHooksRegressionPatch :
    LeanPoo.Proof.Patch GitopsProofKey GitopsProofValue :=
  LeanPoo.Proof.Patch.set .dualLayerHooksAndFsmonitorLockdown false

def argSnapshotRegressionPatch :
    LeanPoo.Proof.Patch GitopsProofKey GitopsProofValue :=
  LeanPoo.Proof.Patch.set .argInjectionAndSnapshotConfinement false

def boundedCaptureRegressionPatch :
    LeanPoo.Proof.Patch GitopsProofKey GitopsProofValue :=
  LeanPoo.Proof.Patch.set .boundedSubprocessCapture false

def panicIsolationRegressionPatch :
    LeanPoo.Proof.Patch GitopsProofKey GitopsProofValue :=
  LeanPoo.Proof.Patch.set .parallelPanicIsolationAndReceiptPath false

/-- Theorem 12: Regressing any of the 5 SM32 GitOps defenses invalidates LeanPoo certificate reuse. -/
theorem sm32_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected gitopsObligation gitEnvRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected gitopsObligation fsmonitorHooksRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected gitopsObligation argSnapshotRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected gitopsObligation boundedCaptureRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected gitopsObligation panicIsolationRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .completeGitEnvNeutralization (by simp [gitopsObligation])
      (by simp [gitEnvRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .dualLayerHooksAndFsmonitorLockdown (by simp [gitopsObligation])
      (by simp [fsmonitorHooksRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .argInjectionAndSnapshotConfinement (by simp [gitopsObligation])
      (by simp [argSnapshotRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .boundedSubprocessCapture (by simp [gitopsObligation])
      (by simp [boundedCaptureRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .parallelPanicIsolationAndReceiptPath (by simp [gitopsObligation])
      (by simp [panicIsolationRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.GitopsSubprocessConfinementAndArgInjection
