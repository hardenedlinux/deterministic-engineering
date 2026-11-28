/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM27: Adversarial (`ADV-L4`) Policy-Gate Blind-Spot, Dependency-Cycle Masking & Entrypoint Confinement

Standalone objectified `LeanPoo` module (45th Lean module, zero edits to
`Core/Stability.lean`) formalizing why multi-crate AI-authored workspaces
suffer architectural and security drift when policy gates are blinded:

1. **Cycle-Blinded Workspace Policy Gate (`cyclicSccs > 0`)**: Local Cargo
   `[dev-dependencies]` cycles panic workspace-wide policy checkers
   (`asp-rust` `workspace_policy`) before scanning any crate.
2. **Ungated Critical Crates / Mode Downgrade**: Omitting per-crate gates on
   control-plane crates or downgrading `mode = fail` (`advice = allow` /
   `#[ignore]` / `t.Skipf` / `|| true`) silently admits monolith drift.
3. **Fat Binary & Root-Test Entrypoints**: Putting server/auth/routing logic
   directly inside `src/bin/*.rs` or root `tests/*.rs` creates shadow surfaces
   diverging from hardened library owners.
4. **CI Gate Omission**: Leaving workspace/crate policy gates out of CI
   workflows lets blind spots persist across commits undetected.
5. **Mandatory `>= ADV-L3` Pressure Floor & `LeanPoo.Proof.reuse` Invalidation**:
   Gentle `ADV-L1`/`ADV-L2` checks fail admission, and any regression
   deterministically invalidates certificate reuse.
-/

namespace DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Architectural policy-gate posture of a multi-crate workspace. -/
structure WorkspacePolicyPosture where
  cyclicSccs : Nat
  ungatedCriticalCrates : Nat
  fatEntrypoints : Nat
  gateModeFailClosed : Bool
  ciInvokesPolicyGate : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether the workspace policy gate can traverse the local crate DAG without panicking. -/
def workspaceGateActive (p : WorkspacePolicyPosture) : Bool :=
  p.cyclicSccs == 0

/-- Whether a workspace satisfies strict SM27 fail-closed policy-gate confinement. -/
def strictPolicyAdmitted (p : WorkspacePolicyPosture) : Bool :=
  workspaceGateActive p &&
  (p.ungatedCriticalCrates == 0) &&
  (p.fatEntrypoints == 0) &&
  p.gateModeFailClosed &&
  p.ciInvokesPolicyGate &&
  p.pressureTier.meetsMinimumFloor

/-- Whether a cycle-blinded patch bypass is reachable. -/
def cycleBlindedBypassReachable (p : WorkspacePolicyPosture) : Bool :=
  p.cyclicSccs > 0

/-- Whether an ungated-crate or warn/allow-downgraded bypass is reachable. -/
def ungatedOrDowngradedBypassReachable (p : WorkspacePolicyPosture) : Bool :=
  (p.ungatedCriticalCrates > 0) || !p.gateModeFailClosed

/-- Whether a fat-entrypoint shadow-logic bypass is reachable. -/
def fatEntrypointBypassReachable (p : WorkspacePolicyPosture) : Bool :=
  p.fatEntrypoints > 0

/-- Whether a CI-omitted policy-gate release bypass is reachable. -/
def ciOmittedBypassReachable (p : WorkspacePolicyPosture) : Bool :=
  !p.ciInvokesPolicyGate

/-- Combined reachability of any SM27 policy-gate blind-spot exploit. -/
def anyBlindspotExploitReachable (p : WorkspacePolicyPosture) : Bool :=
  cycleBlindedBypassReachable p ||
  ungatedOrDowngradedBypassReachable p ||
  fatEntrypointBypassReachable p ||
  ciOmittedBypassReachable p

/-- Canonical hardened workspace posture. -/
def hardenedWorkspacePosture : WorkspacePolicyPosture :=
  { cyclicSccs := 0
    ungatedCriticalCrates := 0
    fatEntrypoints := 0
    gateModeFailClosed := true
    ciInvokesPolicyGate := true
    pressureTier := .l4HostileAttack }

/-- Historical defective Marlin posture prior to SM26/SM27 remediation. -/
def defectiveCycleBlindedPosture : WorkspacePolicyPosture :=
  { cyclicSccs := 3
    ungatedCriticalCrates := 1
    fatEntrypoints := 6
    gateModeFailClosed := false
    ciInvokesPolicyGate := false
    pressureTier := .l4HostileAttack }

/-- Defective posture with acyclic DAG but non-fail-closed gate mode. -/
def defectiveDowngradedPosture : WorkspacePolicyPosture :=
  { hardenedWorkspacePosture with gateModeFailClosed := false }

/-- Defective posture with fat binary / root-test entrypoints carrying shadow logic. -/
def defectiveFatEntrypointPosture : WorkspacePolicyPosture :=
  { hardenedWorkspacePosture with fatEntrypoints := 2 }

/-- Defective posture where CI omits workspace policy execution. -/
def defectiveCiOmittedPosture : WorkspacePolicyPosture :=
  { hardenedWorkspacePosture with ciInvokesPolicyGate := false }

/-- Defective posture attempting certification with gentle ADV-L1 tests. -/
def defectiveGentlePressurePosture : WorkspacePolicyPosture :=
  { hardenedWorkspacePosture with pressureTier := .l1Gentle }

/-- Theorem 1: Strict SM27 admission guarantees zero policy-gate blind-spot exploits across all 4 vectors. -/
theorem sm27_strict_admission_eliminates_all_blindspots (p : WorkspacePolicyPosture)
    (h : strictPolicyAdmitted p = true) :
    anyBlindspotExploitReachable p = false := by
  cases p with
  | mk cyc ung fat fc ci tier =>
    simp [strictPolicyAdmitted, workspaceGateActive] at h
    rcases h with ⟨⟨⟨⟨⟨hcyc, hung⟩, hfat⟩, hfc⟩, hci⟩, _htier⟩
    subst hcyc; subst hung; subst hfat; subst hfc; subst hci
    rfl

/-- Theorem 2: Any non-zero local Cargo dev-dependency cycle blinds the workspace policy gate and fails admission. -/
theorem sm27_cycle_blinded_workspace_fails_admission (p : WorkspacePolicyPosture)
    (hcyc : p.cyclicSccs > 0) :
    workspaceGateActive p = false ∧ strictPolicyAdmitted p = false := by
  have hne : (p.cyclicSccs == 0) = false := by
    simp [Nat.ne_of_gt hcyc]
  constructor
  · simp [workspaceGateActive, hne]
  · simp [strictPolicyAdmitted, workspaceGateActive, hne]

/-- Theorem 3: An ungated critical crate or downgraded gate mode fails strict admission. -/
theorem sm27_ungated_or_downgraded_fails_admission (p : WorkspacePolicyPosture)
    (hbad : p.ungatedCriticalCrates > 0 ∨ p.gateModeFailClosed = false) :
    strictPolicyAdmitted p = false := by
  rcases hbad with hung | hfc
  · have hne : (p.ungatedCriticalCrates == 0) = false := by
      simp [Nat.ne_of_gt hung]
    simp [strictPolicyAdmitted, hne]
  · simp [strictPolicyAdmitted, hfc]

/-- Theorem 4: Fat binary or root-test entrypoints carrying shadow logic fail strict admission. -/
theorem sm27_fat_entrypoint_fails_admission (p : WorkspacePolicyPosture)
    (hfat : p.fatEntrypoints > 0) :
    strictPolicyAdmitted p = false := by
  have hne : (p.fatEntrypoints == 0) = false := by
    simp [Nat.ne_of_gt hfat]
  simp [strictPolicyAdmitted, hne]

/-- Theorem 5: Omitting workspace policy execution in CI fails strict admission. -/
theorem sm27_ci_omission_fails_admission (p : WorkspacePolicyPosture)
    (hci : p.ciInvokesPolicyGate = false) :
    strictPolicyAdmitted p = false := by
  simp [strictPolicyAdmitted, hci]

/-- Theorem 6: Gentle ADV-L1 and edge-only ADV-L2 suites fail the mandatory >= ADV-L3 floor. -/
theorem sm27_gentle_pressure_tiers_rejected (p : WorkspacePolicyPosture)
    (htier : p.pressureTier = .l1Gentle ∨ p.pressureTier = .l2Edge) :
    strictPolicyAdmitted p = false := by
  rcases htier with h1 | h2
  · simp [strictPolicyAdmitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictPolicyAdmitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Breaking all cyclic SCCs strictly restores workspace policy-gate visibility. -/
theorem sm27_breaking_cycles_restores_gate_visibility (p : WorkspacePolicyPosture) :
    workspaceGateActive { p with cyclicSccs := 0 } = true := by
  rfl

/-- Theorem 8: Positive countermodels proving all 4 defective postures expose live exploits and ADV-L1 is refused. -/
theorem sm27_defective_postures_expose_live_exploits :
    cycleBlindedBypassReachable defectiveCycleBlindedPosture = true ∧
    ungatedOrDowngradedBypassReachable defectiveDowngradedPosture = true ∧
    fatEntrypointBypassReachable defectiveFatEntrypointPosture = true ∧
    ciOmittedBypassReachable defectiveCiOmittedPosture = true ∧
    strictPolicyAdmitted defectiveGentlePressurePosture = false ∧
    strictPolicyAdmitted hardenedWorkspacePosture = true ∧
    anyBlindspotExploitReachable hardenedWorkspacePosture = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive PolicyGateConfigKey where
  | acyclicWorkspaceDag
  | universalCrateGates
  | failClosedGateMode
  | thinEntrypointsOnly
  | ciPolicyGateEnforced
  | pressureTier
  deriving DecidableEq, Repr

inductive PolicyGateIssue where
  | devDepCycleBlindsGate
  | ungatedCriticalCrate
  | gateModeDowngraded
  | fatShadowEntrypoint
  | ciPolicyGateOmitted
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def policyGateView : View WorkspacePolicyPosture PolicyGateConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base SM27 workspace policy-gate contract. -/
def basePolicyGateContract :
    Contract WorkspacePolicyPosture PolicyGateConfigKey Unit PolicyGateIssue where
  view := policyGateView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.cyclicSccs == 0 then [] else [.rejected path .devDepCycleBlindsGate]) ++
    (if cfg.ungatedCriticalCrates == 0 then [] else [.rejected path .ungatedCriticalCrate]) ++
    (if cfg.gateModeFailClosed then [] else [.rejected path .gateModeDowngraded]) ++
    (if cfg.fatEntrypoints == 0 then [] else [.rejected path .fatShadowEntrypoint]) ++
    (if cfg.ciInvokesPolicyGate then [] else [.rejected path .ciPolicyGateOmitted])
  validInventory := Or.inl rfl

/-- Refined Marlin workspace policy contract adding the mandatory `>= ADV-L3` pressure floor. -/
def marlinPolicyGateContract :
    Contract WorkspacePolicyPosture PolicyGateConfigKey Unit PolicyGateIssue :=
  refine basePolicyGateContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 9: Refined contract preserves every base rejection and accepts iff both base controls and ADV-L3+ floor hold. -/
theorem sm27_marlin_policy_contract_refinement_laws
    (cfg : WorkspacePolicyPosture) (path : List PolicyGateConfigKey) :
    (diagnose basePolicyGateContract cfg path ≠ [] →
      diagnose marlinPolicyGateContract cfg path ≠ []) ∧
    (diagnose marlinPolicyGateContract cfg path = [] ↔
      diagnose basePolicyGateContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path PolicyGateIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection basePolicyGateContract _ cfg path,
   refine_accepts_iff basePolicyGateContract _ cfg path⟩

inductive PolicyProofKey where
  | cyclicSccs
  | ungatedCriticalCrates
  | fatEntrypoints
  | gateModeFailClosed
  | ciInvokesPolicyGate
  | pressureTier
  | maxReportLines
  deriving DecidableEq

abbrev PolicyProofValue : PolicyProofKey → Type
  | .cyclicSccs => Nat
  | .ungatedCriticalCrates => Nat
  | .fatEntrypoints => Nat
  | .gateModeFailClosed => Bool
  | .ciInvokesPolicyGate => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxReportLines => Nat

def policyGateObligation : LeanPoo.Proof.Obligation PolicyProofKey PolicyProofValue where
  dependencies := [
    .cyclicSccs,
    .ungatedCriticalCrates,
    .fatEntrypoints,
    .gateModeFailClosed,
    .ciInvokesPolicyGate,
    .pressureTier
  ]
  holds := fun s =>
    s .cyclicSccs = 0 ∧
    s .ungatedCriticalCrates = 0 ∧
    s .fatEntrypoints = 0 ∧
    s .gateModeFailClosed = true ∧
    s .ciInvokesPolicyGate = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .cyclicSccs = after .cyclicSccs := same .cyclicSccs (by simp)
    have h2 : before .ungatedCriticalCrates = after .ungatedCriticalCrates :=
      same .ungatedCriticalCrates (by simp)
    have h3 : before .fatEntrypoints = after .fatEntrypoints := same .fatEntrypoints (by simp)
    have h4 : before .gateModeFailClosed = after .gateModeFailClosed :=
      same .gateModeFailClosed (by simp)
    have h5 : before .ciInvokesPolicyGate = after .ciInvokesPolicyGate :=
      same .ciInvokesPolicyGate (by simp)
    have h6 : before .pressureTier = after .pressureTier := same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselinePolicyGateProof : LeanPoo.Proof.ProofObject PolicyProofKey PolicyProofValue where
  state := fun
    | .cyclicSccs => 0
    | .ungatedCriticalCrates => 0
    | .fatEntrypoints => 0
    | .gateModeFailClosed => true
    | .ciInvokesPolicyGate => true
    | .pressureTier => .l4HostileAttack
    | .maxReportLines => 120
  obligations := [policyGateObligation]

/-- Theorem 10: Baseline ADV-L4 workspace policy-gate proof is certified. -/
theorem sm27_baseline_certified :
    LeanPoo.Proof.Certificate baselinePolicyGateProof := by
  intro obligation member
  have hEq : obligation = policyGateObligation := by
    simpa [baselinePolicyGateProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Tuning report formatting (`maxReportLines` 120 -> 240) does not touch policy-gate dependencies. -/
def reportLinesTuningPatch : LeanPoo.Proof.Patch PolicyProofKey PolicyProofValue :=
  LeanPoo.Proof.Patch.set .maxReportLines 240

theorem sm27_obligation_untouched_by_report_tuning :
    LeanPoo.Proof.unaffected policyGateObligation reportLinesTuningPatch := by
  intro key dep touched
  have hKey : key = .maxReportLines := by
    simpa [reportLinesTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [policyGateObligation] at dep

/-- Theorem 11: Non-policy tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm27_report_tuning_reuses_and_closes_certificate :
    policyGateObligation.holds
      (LeanPoo.Proof.append baselinePolicyGateProof reportLinesTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselinePolicyGateProof reportLinesTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselinePolicyGateProof reportLinesTuningPatch
      sm27_baseline_certified policyGateObligation
      (by simp [baselinePolicyGateProof]) sm27_obligation_untouched_by_report_tuning
  · apply LeanPoo.Proof.close baselinePolicyGateProof reportLinesTuningPatch
      sm27_baseline_certified
    · intro obligation member affected
      have hEq : obligation = policyGateObligation := by
        simpa [baselinePolicyGateProof] using member
      subst obligation
      exact False.elim (affected sm27_obligation_untouched_by_report_tuning)
    · intro obligation member
      simp [reportLinesTuningPatch, LeanPoo.Proof.Patch.set] at member

def cycleRegressionPatch : LeanPoo.Proof.Patch PolicyProofKey PolicyProofValue :=
  LeanPoo.Proof.Patch.set .cyclicSccs 1

def modeDowngradeRegressionPatch : LeanPoo.Proof.Patch PolicyProofKey PolicyProofValue :=
  LeanPoo.Proof.Patch.set .gateModeFailClosed false

def fatEntrypointRegressionPatch : LeanPoo.Proof.Patch PolicyProofKey PolicyProofValue :=
  LeanPoo.Proof.Patch.set .fatEntrypoints 2

def ciOmissionRegressionPatch : LeanPoo.Proof.Patch PolicyProofKey PolicyProofValue :=
  LeanPoo.Proof.Patch.set .ciInvokesPolicyGate false

/-- Theorem 12: Reintroducing a dev-dep cycle, downgrading gate mode, adding fat entrypoints,
    or omitting CI policy enforcement all invalidate LeanPoo certificate reuse. -/
theorem sm27_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected policyGateObligation cycleRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected policyGateObligation modeDowngradeRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected policyGateObligation fatEntrypointRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected policyGateObligation ciOmissionRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    exact h .cyclicSccs (by simp [policyGateObligation])
      (by simp [cycleRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .gateModeFailClosed (by simp [policyGateObligation])
      (by simp [modeDowngradeRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .fatEntrypoints (by simp [policyGateObligation])
      (by simp [fatEntrypointRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .ciInvokesPolicyGate (by simp [policyGateObligation])
      (by simp [ciOmissionRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.PolicyGateBlindspotAndCycleConfinement
