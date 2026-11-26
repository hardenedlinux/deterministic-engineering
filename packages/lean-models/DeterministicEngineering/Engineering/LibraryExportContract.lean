/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.DurableGovernanceQuorum
import DeterministicEngineering.Engineering.HostAuthorizationBridge
import DeterministicEngineering.Engineering.InformationFlowAndTms
import DeterministicEngineering.Engineering.SagaAndSsi
import DeterministicEngineering.Engineering.HitlAndCoevolution

/-!
# LeanPoo Unified Library Export Contract (`deterministic-engineering-qnt` -> `cedar-poo-spec`)

Single top-level export facade unifying all 5 `LeanPoo` engineering governance modules:
- `DurableGovernanceQuorum` (19 theorems: `B10`, `B10b`, `B10c`, `R3`, `B6` budget, `B3`)
- `HostAuthorizationBridge` (11 theorems: Dual-Sovereignty `BoundOperation`/`PolicySnapshot`/`AuthorityConsumption`)
- `InformationFlowAndTms` (11 theorems: `B7` DIFC & CaMeL, `B8` Doyle/ATMS)
- `SagaAndSsi` (11 theorems: `B6` Saga pivot/compensation, `B4` AST Symbol SSI & `DE01`)
- `HitlAndCoevolution` (12 theorems: `B1`/`B5` HITL quorum SoD & veto, `R1` co-evolution, `B2`/`R5` AEAD)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Consuming authorization hosts (such as `cedar-poo-spec`) import this single facade and
refine `unifiedLibraryContract` with their concrete authorization, governance, and
admission policies while inheriting every library refusal guarantee monotonically.

Machine-checked export theorems (12 total -> **76 theorems across 6 modules**, zero `sorry`, zero custom axioms):
1. `unifiedLibraryContract_accepts_all_enabled` — complete library config yields zero issues
2. `missing_quorum_slashing_rejected` — disabling `B10/B10b/B10c` quorum/slashing fails closed
3. `missing_difc_atms_rejected` — disabling `B7/B8` DIFC/ATMS fails closed
4. `missing_saga_ssi_rejected` — disabling `B6/B4` Saga/SSI fails closed
5. `missing_hitl_aead_rejected` — disabling `B1/B2/B5/R1/R5` HITL/AEAD fails closed
6. `missing_r3_budget_rejected` — disabling `R3/B3/B6` non-leakage/budget fails closed
7. `consumingHost_oneStep_refinement_preserves_library_rejection` — 1-step host refinement (`Authorization`)
8. `consumingHost_twoStep_cedar_governance_refinement_preserves_rejection` — 2-step host refinement (`Authorization -> Governance`)
9. `consumingHost_threeStep_full_cedar_stack_preserves_rejection` — 3-step full `cedar-poo-spec` stack (`Authorization -> Governance -> Admission`)
10. `unifiedLibrary_telemetryTuning_preserves_certificate` — 1-line `Core.Transport` reuse on telemetry knob
11. `unifiedLibrary_hostPolicyBundlePatch_preserves_certificate` — 1-line `Core.Transport` reuse on disjoint host policy bundle tag
12. `unifiedLibrary_disablingDualSovereignty_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.LibraryExportContract

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Unified Library Contract Export Surface (`B1`–`B10c` × `R1`–`R5`) -/

section UnifiedExportContract

structure LibraryExportConfig where
  quorumFinalityAndSlashingEnforced : Bool
  hostDualSovereigntyBound : Bool
  difcAndAtmsEnforced : Bool
  sagaPivotAndSsiEnforced : Bool
  hitlCoevolutionAndAeadEnforced : Bool
  r3NonLeakageAndBudgetConserved : Bool
  deriving DecidableEq, Repr

inductive LibraryExportKey where
  | quorumFinalityAndSlashingEnforced
  | hostDualSovereigntyBound
  | difcAndAtmsEnforced
  | sagaPivotAndSsiEnforced
  | hitlCoevolutionAndAeadEnforced
  | r3NonLeakageAndBudgetConserved
  deriving DecidableEq, Repr

inductive LibraryExportIssue where
  | quorumOrSlashingDisabled
  | dualSovereigntyUnbound
  | difcOrAtmsDisabled
  | sagaOrSsiDisabled
  | hitlOrAeadDisabled
  | r3OrBudgetDisabled
  | hostPolicyRefused
  deriving DecidableEq, Repr

private def libraryExportView : View LibraryExportConfig LibraryExportKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- The canonical single-entry `LeanPoo` library contract exported to consuming hosts
    (e.g. `cedar-poo-spec`). Contains ZERO host-specific authorization policies. -/
def unifiedLibraryContract :
    Contract LibraryExportConfig LibraryExportKey Unit LibraryExportIssue where
  view := libraryExportView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.quorumFinalityAndSlashingEnforced then [] else [.rejected path .quorumOrSlashingDisabled]) ++
    (if cfg.hostDualSovereigntyBound then [] else [.rejected path .dualSovereigntyUnbound]) ++
    (if cfg.difcAndAtmsEnforced then [] else [.rejected path .difcOrAtmsDisabled]) ++
    (if cfg.sagaPivotAndSsiEnforced then [] else [.rejected path .sagaOrSsiDisabled]) ++
    (if cfg.hitlCoevolutionAndAeadEnforced then [] else [.rejected path .hitlOrAeadDisabled]) ++
    (if cfg.r3NonLeakageAndBudgetConserved then [] else [.rejected path .r3OrBudgetDisabled])
  validInventory := Or.inl rfl

def allEnabledLibraryConfig : LibraryExportConfig where
  quorumFinalityAndSlashingEnforced := true
  hostDualSovereigntyBound := true
  difcAndAtmsEnforced := true
  sagaPivotAndSsiEnforced := true
  hitlCoevolutionAndAeadEnforced := true
  r3NonLeakageAndBudgetConserved := true

private theorem diagnose_unifiedLibraryContract
    (cfg : LibraryExportConfig) (path : List LibraryExportKey) :
    diagnose unifiedLibraryContract cfg path =
      (if cfg.quorumFinalityAndSlashingEnforced then [] else [.rejected path .quorumOrSlashingDisabled]) ++
      (if cfg.hostDualSovereigntyBound then [] else [.rejected path .dualSovereigntyUnbound]) ++
      (if cfg.difcAndAtmsEnforced then [] else [.rejected path .difcOrAtmsDisabled]) ++
      (if cfg.sagaPivotAndSsiEnforced then [] else [.rejected path .sagaOrSsiDisabled]) ++
      (if cfg.hitlCoevolutionAndAeadEnforced then [] else [.rejected path .hitlOrAeadDisabled]) ++
      (if cfg.r3NonLeakageAndBudgetConserved then [] else [.rejected path .r3OrBudgetDisabled]) := by
  simp [diagnose, unifiedLibraryContract, libraryExportView, extras, required,
    LeanPoo.Functional.ObjectDiagnostics.andThen, LeanPoo.Functional.ObjectDiagnostics.all]

/-- **Theorem 1 (Sound Admissibility)**: When all 6 library mechanism pillars are enabled,
    `unifiedLibraryContract` emits zero issues. -/
theorem unifiedLibraryContract_accepts_all_enabled (path : List LibraryExportKey) :
    diagnose unifiedLibraryContract allEnabledLibraryConfig path = [] := by
  rw [diagnose_unifiedLibraryContract]
  rfl

private theorem append_ne_nil_of_mem {α : Type} {xs : List α} {x : α} (h : x ∈ xs) : xs ≠ [] := by
  intro hNil
  rw [hNil] at h
  exact nomatch h

/-- **Theorem 2 (`B10/B10b/B10c` Export Rejection)**: Disabling quorum finality or slashing
    always causes `unifiedLibraryContract` to reject. -/
theorem missing_quorum_slashing_rejected
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hOff : cfg.quorumFinalityAndSlashingEnforced = false) :
    diagnose unifiedLibraryContract cfg path ≠ [] := by
  rw [diagnose_unifiedLibraryContract]
  apply append_ne_nil_of_mem (x := Issue.rejected path .quorumOrSlashingDisabled)
  simp [hOff]

/-- **Theorem 3 (`B7/B8` Export Rejection)**: Disabling DIFC or ATMS always causes
    `unifiedLibraryContract` to reject. -/
theorem missing_difc_atms_rejected
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hOff : cfg.difcAndAtmsEnforced = false) :
    diagnose unifiedLibraryContract cfg path ≠ [] := by
  rw [diagnose_unifiedLibraryContract]
  apply append_ne_nil_of_mem (x := Issue.rejected path .difcOrAtmsDisabled)
  simp [hOff]

/-- **Theorem 4 (`B6/B4` Export Rejection)**: Disabling Saga pivot or AST Symbol SSI always
    causes `unifiedLibraryContract` to reject. -/
theorem missing_saga_ssi_rejected
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hOff : cfg.sagaPivotAndSsiEnforced = false) :
    diagnose unifiedLibraryContract cfg path ≠ [] := by
  rw [diagnose_unifiedLibraryContract]
  apply append_ne_nil_of_mem (x := Issue.rejected path .sagaOrSsiDisabled)
  simp [hOff]

/-- **Theorem 5 (`B1/B2/B5/R1/R5` Export Rejection)**: Disabling HITL co-evolution or AEAD
    tenant isolation always causes `unifiedLibraryContract` to reject. -/
theorem missing_hitl_aead_rejected
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hOff : cfg.hitlCoevolutionAndAeadEnforced = false) :
    diagnose unifiedLibraryContract cfg path ≠ [] := by
  rw [diagnose_unifiedLibraryContract]
  apply append_ne_nil_of_mem (x := Issue.rejected path .hitlOrAeadDisabled)
  simp [hOff]

/-- **Theorem 6 (`R3/B3/B6` Export Rejection)**: Disabling `R3` non-leakage or linear budget
    conservation always causes `unifiedLibraryContract` to reject. -/
theorem missing_r3_budget_rejected
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hOff : cfg.r3NonLeakageAndBudgetConserved = false) :
    diagnose unifiedLibraryContract cfg path ≠ [] := by
  rw [diagnose_unifiedLibraryContract]
  apply append_ne_nil_of_mem (x := Issue.rejected path .r3OrBudgetDisabled)
  simp [hOff]

end UnifiedExportContract

/-! ## Section 2: Consuming-Host Multi-Layer Refinement Theorems (for `cedar-poo-spec`) -/

section ConsumingHostRefinement

abbrev HostPolicyExtension :=
  LibraryExportConfig → List LibraryExportKey → List (Issue LibraryExportKey LibraryExportIssue)

/-- **Theorem 7 (1-Step Consuming-Host Refinement)**: Any downstream authorization host
    layer `hostAuthExt` (e.g. `CedarPooSpec.Authorization`) refining `unifiedLibraryContract`
    monotonically preserves every library rejection. -/
theorem consumingHost_oneStep_refinement_preserves_library_rejection
    (hostAuthExt : HostPolicyExtension)
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hRej : diagnose unifiedLibraryContract cfg path ≠ []) :
    diagnose (refine unifiedLibraryContract hostAuthExt) cfg path ≠ [] :=
  refine_preserves_rejection unifiedLibraryContract hostAuthExt cfg path hRej

/-- **Theorem 8 (2-Step `Authorization -> Governance` Refinement)**: Layering both
    `hostAuthExt` (`CedarPooSpec.Authorization`) and `hostGovExt`
    (`CedarPooSpec.Governance.{Veto,SeparationOfDuties,ScopedApproval}`) monotonically
    preserves every library rejection. -/
theorem consumingHost_twoStep_cedar_governance_refinement_preserves_rejection
    (hostAuthExt hostGovExt : HostPolicyExtension)
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hRej : diagnose unifiedLibraryContract cfg path ≠ []) :
    diagnose (refine (refine unifiedLibraryContract hostAuthExt) hostGovExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection unifiedLibraryContract hostAuthExt hostGovExt cfg path hRej

/-- **Theorem 9 (3-Step Full `cedar-poo-spec` Consuming-Host Stack)**: Layering all three
    consuming-host sovereignty layers — `hostAuthExt` (`Authorization`), `hostGovExt`
    (`Governance`), and `hostAdmissionExt` (`Admission`/`Data`) — over `unifiedLibraryContract`
    monotonically preserves every library rejection. -/
theorem consumingHost_threeStep_full_cedar_stack_preserves_rejection
    (hostAuthExt hostGovExt hostAdmissionExt : HostPolicyExtension)
    (cfg : LibraryExportConfig) (path : List LibraryExportKey)
    (hRej : diagnose unifiedLibraryContract cfg path ≠ []) :
    diagnose
      (refine (refine (refine unifiedLibraryContract hostAuthExt) hostGovExt) hostAdmissionExt)
      cfg path ≠ [] :=
  refine_preserves_rejection
    (refine (refine unifiedLibraryContract hostAuthExt) hostGovExt)
    hostAdmissionExt cfg path
    (refine_two_step_preserves_rejection unifiedLibraryContract hostAuthExt hostGovExt cfg path hRej)

end ConsumingHostRefinement

/-! ## Section 3: Unified Library `LeanPoo.Proof.ProofObject` & `Core.Transport` Proof Reuse -/

section UnifiedLibraryProofTransport

inductive UnifiedLibraryProofKey where
  | quorumFinalityAndSlashingEnforced
  | hostDualSovereigntyBound
  | difcAndAtmsEnforced
  | sagaPivotAndSsiEnforced
  | hitlCoevolutionAndAeadEnforced
  | r3NonLeakageAndBudgetConserved
  | metricsExportIntervalMs
  | hostPolicyBundleTag
  deriving DecidableEq

abbrev UnifiedLibraryProofValue : UnifiedLibraryProofKey → Type
  | .quorumFinalityAndSlashingEnforced => Bool
  | .hostDualSovereigntyBound => Bool
  | .difcAndAtmsEnforced => Bool
  | .sagaPivotAndSsiEnforced => Bool
  | .hitlCoevolutionAndAeadEnforced => Bool
  | .r3NonLeakageAndBudgetConserved => Bool
  | .metricsExportIntervalMs => Nat
  | .hostPolicyBundleTag => Nat

def unifiedLibraryObligation :
    LeanPoo.Proof.Obligation UnifiedLibraryProofKey UnifiedLibraryProofValue where
  dependencies :=
    [ .quorumFinalityAndSlashingEnforced
    , .hostDualSovereigntyBound
    , .difcAndAtmsEnforced
    , .sagaPivotAndSsiEnforced
    , .hitlCoevolutionAndAeadEnforced
    , .r3NonLeakageAndBudgetConserved
    ]
  holds := fun s =>
    s .quorumFinalityAndSlashingEnforced = true ∧
    s .hostDualSovereigntyBound = true ∧
    s .difcAndAtmsEnforced = true ∧
    s .sagaPivotAndSsiEnforced = true ∧
    s .hitlCoevolutionAndAeadEnforced = true ∧
    s .r3NonLeakageAndBudgetConserved = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4, h5, h6⟩
    exact ⟨(same .quorumFinalityAndSlashingEnforced (by simp)).symm.trans h1,
           (same .hostDualSovereigntyBound (by simp)).symm.trans h2,
           (same .difcAndAtmsEnforced (by simp)).symm.trans h3,
           (same .sagaPivotAndSsiEnforced (by simp)).symm.trans h4,
           (same .hitlCoevolutionAndAeadEnforced (by simp)).symm.trans h5,
           (same .r3NonLeakageAndBudgetConserved (by simp)).symm.trans h6⟩

def baselineUnifiedLibrarySystem :
    LeanPoo.Proof.ProofObject UnifiedLibraryProofKey UnifiedLibraryProofValue where
  state := fun
    | .quorumFinalityAndSlashingEnforced => true
    | .hostDualSovereigntyBound => true
    | .difcAndAtmsEnforced => true
    | .sagaPivotAndSsiEnforced => true
    | .hitlCoevolutionAndAeadEnforced => true
    | .r3NonLeakageAndBudgetConserved => true
    | .metricsExportIntervalMs => 5000
    | .hostPolicyBundleTag => 1
  obligations := [unifiedLibraryObligation]

theorem baselineUnifiedLibraryCertified :
    LeanPoo.Proof.Certificate baselineUnifiedLibrarySystem := by
  intro ob hMem
  have hEq : ob = unifiedLibraryObligation := by simpa [baselineUnifiedLibrarySystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- **Theorem 10**: Tuning `.metricsExportIntervalMs` transports the unified library
    `LeanPoo.Proof.Certificate` in 1 line with zero re-proving. -/
theorem unifiedLibrary_telemetryTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineUnifiedLibrarySystem
        (LeanPoo.Proof.Patch.set .metricsExportIntervalMs 15000)) :=
  close_single_set_untouched baselineUnifiedLibrarySystem unifiedLibraryObligation
    .metricsExportIntervalMs 15000 rfl baselineUnifiedLibraryCertified
    (by simp [unifiedLibraryObligation])

/-- **Theorem 11 (Disjoint Consuming-Host Policy Bundle Upgrade)**: Upgrading the opaque
    host policy-bundle tag `.hostPolicyBundleTag` (e.g. a new `cedar-poo-spec` Cedar policy
    snapshot) transports the unified library `LeanPoo.Proof.Certificate` automatically with
    ZERO library re-proving. -/
theorem unifiedLibrary_hostPolicyBundlePatch_preserves_certificate (nextTag : Nat) :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineUnifiedLibrarySystem
        (LeanPoo.Proof.Patch.set .hostPolicyBundleTag nextTag)) :=
  close_single_set_untouched baselineUnifiedLibrarySystem unifiedLibraryObligation
    .hostPolicyBundleTag nextTag rfl baselineUnifiedLibraryCertified
    (by simp [unifiedLibraryObligation])

/-- **Theorem 12 (Negative Control)**: Weakening `.hostDualSovereigntyBound` ALWAYS
    invalidates proof reuse across the unified library export contract. -/
theorem unifiedLibrary_disablingDualSovereignty_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected unifiedLibraryObligation
        (LeanPoo.Proof.Patch.set .hostDualSovereigntyBound false) :=
  set_dependency_invalidates_unaffected unifiedLibraryObligation
    .hostDualSovereigntyBound false (by simp [unifiedLibraryObligation])

end UnifiedLibraryProofTransport

end DeterministicEngineering.Engineering.LibraryExportContract
