/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM37: Adversarial (`ADV-L4`) Process Signal, Ledger & Fanout Confinement

Standalone objectified `LeanPoo` module (55th Lean module, zero edits to
`Core/Stability.lean`) formalizing four real `ADV-L4` boundary defects
discovered in `marlin-agent-runtime`:

1. **POSIX Process-Group Signal Target Confinement**:
   `process/shutdown.rs` (`signal_unix_target`, `is_process_group_alive`,
   `wait_for_process_group_exit`) and `cleanup.rs` accepted `pid`/`pgid <= 1`
   or equal to the host's own PID/PGID, turning `pgid = 0` into `kill(0, sig)`
   (caller process-group suicide) and `pgid = 1` into `kill(-1, sig)` (killing
   every user-owned process on the OS), while `managed_reaper.rs` waited on
   `ctx.pid` instead of `target_pgid`.
2. **Fail-Closed Anti-PID-Reuse Orphan Reconciliation & Reaping**:
   `process/reconcile.rs::matches_recorded_start_time` returned `true` on
   `os_start_time_secs: None` and never rejected protected/self PIDs or PGIDs,
   enabling crafted or legacy ledger records to signal unrelated live processes.
3. **Symlink-Safe, Byte-Bounded, Schema-Checked Process Ledger**:
   `process/ledger.rs::FileProcessLedgerStore` followed symlinks on ledger,
   lock, and parent paths, performed unbounded `read_to_string`, ignored
   `schema_version`, and left active and in-memory ledger entries unbounded.
4. **Hard-Capped Sub-Agent Fanout Parallelism & Abort-Drain Quiescence**:
   `tokio_runtime/fanout.rs::WorkingCopySubAgentFanoutRunner` permitted
   unbounded concurrency, returned after `abort_all()` without draining aborted
   tasks, and lost panicked input index attribution via `join_next()`.
-/

namespace DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- POSIX process/group signal admission predicate forbidding pid/pgid <= 1 and host self-kill. -/
def processSignalAdmitted (pid pgid hostPid hostPgid : Nat) : Bool :=
  (1 < pid) && (1 < pgid) && (pid != hostPid) && (pgid != hostPgid)

/-- Post-restart orphan identity verification requiring OS start-time fingerprint and safe target. -/
def orphanIdentityAdmitted
    (hasStartFingerprint : Bool) (startTimeDiff : Nat) (targetSafe : Bool) : Bool :=
  hasStartFingerprint && (startTimeDiff ≤ 1) && targetSafe

/-- Process ledger load/persist admission predicate. -/
def processLedgerAdmitted
    (symlinkFree : Bool)
    (fileBytes maxBytes : Nat)
    (schemaVersion expectedSchema : Nat)
    (activeEntries maxActive : Nat) : Bool :=
  symlinkFree &&
  (fileBytes ≤ maxBytes) &&
  (schemaVersion == expectedSchema) &&
  (activeEntries ≤ maxActive)

/-- Sub-agent working-copy fanout admission and abort-drain predicate. -/
def fanoutDispatchAdmitted
    (activeWorkers hardCap : Nat) (drainedOnAbort : Bool) : Bool :=
  (activeWorkers < hardCap) && drainedOnAbort

/-- Security and steady-state posture of runtime process signaling, ledger, and fanout boundaries. -/
structure ProcessSignalLedgerFanoutConfig where
  enforcesSignalTargetConfinement : Bool
  enforcesStartFingerprintReconciliation : Bool
  enforcesLedgerSymlinkByteSchemaCap : Bool
  enforcesFanoutHardCapAndAbortDrain : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a configuration satisfies strict SM37 confinement. -/
def strictSm37Admitted (c : ProcessSignalLedgerFanoutConfig) : Bool :=
  c.enforcesSignalTargetConfinement &&
  c.enforcesStartFingerprintReconciliation &&
  c.enforcesLedgerSymlinkByteSchemaCap &&
  c.enforcesFanoutHardCapAndAbortDrain &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 4 SM37 hostile exploit classes remain reachable. -/
def anySm37ExploitReachable (c : ProcessSignalLedgerFanoutConfig) : Bool :=
  !c.enforcesSignalTargetConfinement ||
  !c.enforcesStartFingerprintReconciliation ||
  !c.enforcesLedgerSymlinkByteSchemaCap ||
  !c.enforcesFanoutHardCapAndAbortDrain

/-- Canonical hardened SM37 posture. -/
def hardenedSm37Config : ProcessSignalLedgerFanoutConfig :=
  { enforcesSignalTargetConfinement := true
    enforcesStartFingerprintReconciliation := true
    enforcesLedgerSymlinkByteSchemaCap := true
    enforcesFanoutHardCapAndAbortDrain := true
    pressureTier := .l4HostileAttack }

def defectiveSignalConfig : ProcessSignalLedgerFanoutConfig :=
  { hardenedSm37Config with enforcesSignalTargetConfinement := false }

def defectiveReconcileConfig : ProcessSignalLedgerFanoutConfig :=
  { hardenedSm37Config with enforcesStartFingerprintReconciliation := false }

def defectiveLedgerConfig : ProcessSignalLedgerFanoutConfig :=
  { hardenedSm37Config with enforcesLedgerSymlinkByteSchemaCap := false }

def defectiveFanoutConfig : ProcessSignalLedgerFanoutConfig :=
  { hardenedSm37Config with enforcesFanoutHardCapAndAbortDrain := false }

def defectiveGentleTierConfig : ProcessSignalLedgerFanoutConfig :=
  { hardenedSm37Config with pressureTier := .l1Gentle }

/-- Theorem 1: Protected PID/PGID values (0, 1, or host self PID/PGID) fail closed in POSIX signaling. -/
theorem sm37_protected_pid_pgid_fail_closed (pid pgid hostPid hostPgid : Nat) :
    processSignalAdmitted 0 pgid hostPid hostPgid = false ∧
    processSignalAdmitted 1 pgid hostPid hostPgid = false ∧
    processSignalAdmitted pid 0 hostPid hostPgid = false ∧
    processSignalAdmitted pid 1 hostPid hostPgid = false ∧
    processSignalAdmitted hostPid pgid hostPid hostPgid = false ∧
    processSignalAdmitted pid hostPgid hostPid hostPgid = false := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [processSignalAdmitted]
  · simp [processSignalAdmitted]
  · simp [processSignalAdmitted]
  · simp [processSignalAdmitted]
  · simp [processSignalAdmitted]
  · simp [processSignalAdmitted]

/-- Theorem 2: Missing OS start-time fingerprint, start-time drift > 1s, or unsafe PID fails closed. -/
theorem sm37_orphan_identity_fail_closed (diff : Nat) (targetSafe : Bool) :
    orphanIdentityAdmitted false diff targetSafe = false ∧
    orphanIdentityAdmitted true (diff + 2) targetSafe = false ∧
    orphanIdentityAdmitted true 0 false = false ∧
    orphanIdentityAdmitted true 1 true = true := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · simp [orphanIdentityAdmitted]
  · simp [orphanIdentityAdmitted]
  · simp [orphanIdentityAdmitted]
  · decide

/-- Theorem 3: Symlinks, oversize ledger reads, schema mismatch, and active overflow fail closed. -/
theorem sm37_process_ledger_bounds_fail_closed
    (bytes maxBytes schema active maxActive : Nat) :
    processLedgerAdmitted false bytes maxBytes schema schema active maxActive = false ∧
    processLedgerAdmitted true (maxBytes + 1) maxBytes schema schema active maxActive = false ∧
    processLedgerAdmitted true bytes maxBytes (schema + 1) schema active maxActive = false ∧
    processLedgerAdmitted true bytes maxBytes schema schema (maxActive + 1) maxActive = false := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · simp [processLedgerAdmitted]
  · simp [processLedgerAdmitted]; omega
  · simp [processLedgerAdmitted]
  · simp [processLedgerAdmitted]

/-- Theorem 4: Sub-agent fanout saturation or undrained abort return fails closed. -/
theorem sm37_fanout_cap_and_drain_fail_closed (active hardCap : Nat) :
    fanoutDispatchAdmitted hardCap hardCap true = false ∧
    fanoutDispatchAdmitted active hardCap false = false := by
  refine ⟨?_, ?_⟩
  · simp [fanoutDispatchAdmitted]
  · simp [fanoutDispatchAdmitted]

/-- Theorem 5: Strict SM37 admission eliminates all 4 runtime process/ledger/fanout exploit classes. -/
theorem sm37_strict_admission_eliminates_all_exploits (c : ProcessSignalLedgerFanoutConfig)
    (h : strictSm37Admitted c = true) :
    anySm37ExploitReachable c = false := by
  cases c with
  | mk s r l f tier =>
    simp [strictSm37Admitted] at h
    rcases h with ⟨⟨⟨⟨hs, hr⟩, hl⟩, hf⟩, _⟩
    subst hs; subst hr; subst hl; subst hf
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 pressure tiers fail mandatory SM37 admission. -/
theorem sm37_gentle_pressure_rejected (c : ProcessSignalLedgerFanoutConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm37Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm37Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm37Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm37_defective_configs_expose_live_exploits :
    anySm37ExploitReachable defectiveSignalConfig = true ∧
    anySm37ExploitReachable defectiveReconcileConfig = true ∧
    anySm37ExploitReachable defectiveLedgerConfig = true ∧
    anySm37ExploitReachable defectiveFanoutConfig = true ∧
    strictSm37Admitted defectiveGentleTierConfig = false ∧
    strictSm37Admitted hardenedSm37Config = true ∧
    anySm37ExploitReachable hardenedSm37Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive ProcessSignalLedgerFanoutKey where
  | signalTargetConfinement
  | startFingerprintReconciliation
  | ledgerSymlinkByteSchemaCap
  | fanoutHardCapAndAbortDrain
  | pressureTier
  deriving DecidableEq, Repr

inductive ProcessSignalLedgerFanoutIssue where
  | protectedPidOrPgidKillReachable
  | unfingerprintedPidReuseReapReachable
  | symlinkOrUnboundedProcessLedger
  | unboundedFanoutOrUndrainedAbort
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def processSignalLedgerFanoutView :
    View ProcessSignalLedgerFanoutConfig ProcessSignalLedgerFanoutKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseProcessSignalLedgerFanoutContract :
    Contract ProcessSignalLedgerFanoutConfig ProcessSignalLedgerFanoutKey Unit ProcessSignalLedgerFanoutIssue where
  view := processSignalLedgerFanoutView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesSignalTargetConfinement then [] else [.rejected path .protectedPidOrPgidKillReachable]) ++
    (if cfg.enforcesStartFingerprintReconciliation then [] else [.rejected path .unfingerprintedPidReuseReapReachable]) ++
    (if cfg.enforcesLedgerSymlinkByteSchemaCap then [] else [.rejected path .symlinkOrUnboundedProcessLedger]) ++
    (if cfg.enforcesFanoutHardCapAndAbortDrain then [] else [.rejected path .unboundedFanoutOrUndrainedAbort])
  validInventory := Or.inl rfl

def marlinProcessSignalLedgerFanoutContract :
    Contract ProcessSignalLedgerFanoutConfig ProcessSignalLedgerFanoutKey Unit ProcessSignalLedgerFanoutIssue :=
  refine baseProcessSignalLedgerFanoutContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin SM37 contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm37_marlin_contract_refinement_laws
    (cfg : ProcessSignalLedgerFanoutConfig) (path : List ProcessSignalLedgerFanoutKey) :
    (diagnose baseProcessSignalLedgerFanoutContract cfg path ≠ [] →
      diagnose marlinProcessSignalLedgerFanoutContract cfg path ≠ []) ∧
    (diagnose marlinProcessSignalLedgerFanoutContract cfg path = [] ↔
      diagnose baseProcessSignalLedgerFanoutContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path ProcessSignalLedgerFanoutIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseProcessSignalLedgerFanoutContract _ cfg path,
   refine_accepts_iff baseProcessSignalLedgerFanoutContract _ cfg path⟩

inductive ProcessSignalLedgerFanoutProofKey where
  | signalTargetConfinement
  | startFingerprintReconciliation
  | ledgerSymlinkByteSchemaCap
  | fanoutHardCapAndAbortDrain
  | pressureTier
  | maxTerminalLedgerEntries
  deriving DecidableEq

abbrev ProcessSignalLedgerFanoutProofValue : ProcessSignalLedgerFanoutProofKey → Type
  | .signalTargetConfinement => Bool
  | .startFingerprintReconciliation => Bool
  | .ledgerSymlinkByteSchemaCap => Bool
  | .fanoutHardCapAndAbortDrain => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxTerminalLedgerEntries => Nat

def processSignalLedgerFanoutObligation :
    LeanPoo.Proof.Obligation ProcessSignalLedgerFanoutProofKey ProcessSignalLedgerFanoutProofValue where
  dependencies := [
    .signalTargetConfinement,
    .startFingerprintReconciliation,
    .ledgerSymlinkByteSchemaCap,
    .fanoutHardCapAndAbortDrain,
    .pressureTier
  ]
  holds := fun s =>
    s .signalTargetConfinement = true ∧
    s .startFingerprintReconciliation = true ∧
    s .ledgerSymlinkByteSchemaCap = true ∧
    s .fanoutHardCapAndAbortDrain = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .signalTargetConfinement = after .signalTargetConfinement :=
      same .signalTargetConfinement (by simp)
    have h2 : before .startFingerprintReconciliation = after .startFingerprintReconciliation :=
      same .startFingerprintReconciliation (by simp)
    have h3 : before .ledgerSymlinkByteSchemaCap = after .ledgerSymlinkByteSchemaCap :=
      same .ledgerSymlinkByteSchemaCap (by simp)
    have h4 : before .fanoutHardCapAndAbortDrain = after .fanoutHardCapAndAbortDrain :=
      same .fanoutHardCapAndAbortDrain (by simp)
    have h5 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5] using holds

def baselineProcessSignalLedgerFanoutProof :
    LeanPoo.Proof.ProofObject ProcessSignalLedgerFanoutProofKey ProcessSignalLedgerFanoutProofValue where
  state := fun
    | .signalTargetConfinement => true
    | .startFingerprintReconciliation => true
    | .ledgerSymlinkByteSchemaCap => true
    | .fanoutHardCapAndAbortDrain => true
    | .pressureTier => .l4HostileAttack
    | .maxTerminalLedgerEntries => 512
  obligations := [processSignalLedgerFanoutObligation]

/-- Theorem 9: Baseline ADV-L4 SM37 proof is certified. -/
theorem sm37_baseline_certified :
    LeanPoo.Proof.Certificate baselineProcessSignalLedgerFanoutProof := by
  intro obligation member
  have hEq : obligation = processSignalLedgerFanoutObligation := by
    simpa [baselineProcessSignalLedgerFanoutProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

def terminalLedgerRetentionPatch :
    LeanPoo.Proof.Patch ProcessSignalLedgerFanoutProofKey ProcessSignalLedgerFanoutProofValue :=
  LeanPoo.Proof.Patch.set .maxTerminalLedgerEntries 256

/-- Theorem 10: Tuning terminal ledger retention leaves SM37 security obligations untouched. -/
theorem sm37_obligation_untouched_by_terminal_retention_tuning :
    LeanPoo.Proof.unaffected processSignalLedgerFanoutObligation terminalLedgerRetentionPatch := by
  intro key dep touched
  have hKey : key = .maxTerminalLedgerEntries := by
    simpa [terminalLedgerRetentionPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [processSignalLedgerFanoutObligation] at dep

/-- Theorem 11: Terminal retention tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm37_terminal_retention_tuning_reuses_and_closes_certificate :
    processSignalLedgerFanoutObligation.holds
      (LeanPoo.Proof.append baselineProcessSignalLedgerFanoutProof terminalLedgerRetentionPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineProcessSignalLedgerFanoutProof terminalLedgerRetentionPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineProcessSignalLedgerFanoutProof terminalLedgerRetentionPatch
      sm37_baseline_certified processSignalLedgerFanoutObligation
      (by simp [baselineProcessSignalLedgerFanoutProof]) sm37_obligation_untouched_by_terminal_retention_tuning
  · apply LeanPoo.Proof.close baselineProcessSignalLedgerFanoutProof terminalLedgerRetentionPatch
      sm37_baseline_certified
    · intro obligation member affected
      have hEq : obligation = processSignalLedgerFanoutObligation := by
        simpa [baselineProcessSignalLedgerFanoutProof] using member
      subst obligation
      exact False.elim (affected sm37_obligation_untouched_by_terminal_retention_tuning)
    · intro obligation member
      simp [terminalLedgerRetentionPatch, LeanPoo.Proof.Patch.set] at member

def signalGuardRegressionPatch :
    LeanPoo.Proof.Patch ProcessSignalLedgerFanoutProofKey ProcessSignalLedgerFanoutProofValue :=
  LeanPoo.Proof.Patch.set .signalTargetConfinement false

def reconcileFingerprintRegressionPatch :
    LeanPoo.Proof.Patch ProcessSignalLedgerFanoutProofKey ProcessSignalLedgerFanoutProofValue :=
  LeanPoo.Proof.Patch.set .startFingerprintReconciliation false

def ledgerConfinementRegressionPatch :
    LeanPoo.Proof.Patch ProcessSignalLedgerFanoutProofKey ProcessSignalLedgerFanoutProofValue :=
  LeanPoo.Proof.Patch.set .ledgerSymlinkByteSchemaCap false

def fanoutCapRegressionPatch :
    LeanPoo.Proof.Patch ProcessSignalLedgerFanoutProofKey ProcessSignalLedgerFanoutProofValue :=
  LeanPoo.Proof.Patch.set .fanoutHardCapAndAbortDrain false

/-- Theorem 12: Regressing any of the 4 SM37 defenses invalidates LeanPoo certificate reuse. -/
theorem sm37_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected processSignalLedgerFanoutObligation signalGuardRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected processSignalLedgerFanoutObligation reconcileFingerprintRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected processSignalLedgerFanoutObligation ledgerConfinementRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected processSignalLedgerFanoutObligation fanoutCapRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    exact h .signalTargetConfinement (by simp [processSignalLedgerFanoutObligation])
      (by simp [signalGuardRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .startFingerprintReconciliation (by simp [processSignalLedgerFanoutObligation])
      (by simp [reconcileFingerprintRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .ledgerSymlinkByteSchemaCap (by simp [processSignalLedgerFanoutObligation])
      (by simp [ledgerConfinementRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .fanoutHardCapAndAbortDrain (by simp [processSignalLedgerFanoutObligation])
      (by simp [fanoutCapRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.ProcessSignalLedgerAndFanoutConfinement
