/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.LibraryExportContract

/-!
# LeanPoo Four-Paradigm Cross-Consistency & Unbounded N-Version Release Gate

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `LibraryExportContract` (all 6 prior modules, 76 theorems) and adds
10 machine-checked meta-theorems unifying the **86-theorem, 7-module `LeanPoo` library**:

1. `any_paradigm_refuted_blocks_library_admit` — any `.refuted` paradigm blocks library & release admission
2. `any_paradigm_pending_blocks_library_admit` — any `.pendingMethod` paradigm blocks admission (anti-silent-ok)
3. `any_paradigm_setup_defect_blocks_library_admit` — any `.setupDefect` paradigm blocks admission
4. `host_permit_cannot_override_four_paradigm_failure` — `cedar-poo-spec` Permit cannot bypass library failure
5. `four_paradigm_proven_cannot_override_host_refusal` — 4/4 library Proven cannot bypass host refusal
6. `four_paradigm_admit_iff_all_proven` — sound & complete iff characterization of 4-paradigm convergence
7. `paradigm_list_convergence_requires_every_entry_proven` — unbounded `∀ N` N-version oracle convergence
8. `fourParadigmContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` release host)
9. `reportFormatTuning_preserves_fourParadigm_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingLeanPooGate_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.FourParadigmConsistency

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Four-Paradigm Epistemic Lattice & N-Version Release Gate -/

section FourParadigmGate

inductive EpistemicVerdict where
  | proven
  | refuted
  | pendingMethod
  | setupDefect
  deriving DecidableEq, Repr

def isProven : EpistemicVerdict → Bool
  | .proven => true
  | _ => false

structure ParadigmBundle where
  quintApalache : EpistemicVerdict
  gerbilAscent : EpistemicVerdict
  cbmcMultiLang : EpistemicVerdict
  leanPooUnbounded : EpistemicVerdict
  hostPolicyGate : EpistemicVerdict
  deriving DecidableEq, Repr

/-- Library-side four-paradigm convergence gate: requires ALL 4 orthogonal verification
    paradigms (Quint/Apalache, Gerbil ASCENT, CBMC/5-Language, Lean 4 + `LeanPoo`) to be `.proven`. -/
def fourParadigmLibraryAdmit (b : ParadigmBundle) : Bool :=
  isProven b.quintApalache &&
  isProven b.gerbilAscent &&
  isProven b.cbmcMultiLang &&
  isProven b.leanPooUnbounded

/-- Full release gate composing Library four-paradigm convergence with consuming-host
    authorization sovereignty (`cedar-poo-spec`). -/
def fullReleaseAdmit (b : ParadigmBundle) : Bool :=
  fourParadigmLibraryAdmit b && isProven b.hostPolicyGate

/-- **Theorem 1**: Any single `.refuted` library paradigm blocks both library and full release admission. -/
theorem any_paradigm_refuted_blocks_library_admit (b : ParadigmBundle)
    (hRef : b.quintApalache = .refuted ∨ b.gerbilAscent = .refuted ∨
            b.cbmcMultiLang = .refuted ∨ b.leanPooUnbounded = .refuted) :
    fourParadigmLibraryAdmit b = false ∧ fullReleaseAdmit b = false := by
  rcases hRef with h | h | h | h <;>
    simp [fourParadigmLibraryAdmit, fullReleaseAdmit, isProven, h]

/-- **Theorem 2 (Anti-Silent-Degradation)**: Any `.pendingMethod` (missing toolchain / skipped
    verifier) blocks library admission — NEVER degrades to `true`. -/
theorem any_paradigm_pending_blocks_library_admit (b : ParadigmBundle)
    (hPend : b.quintApalache = .pendingMethod ∨ b.gerbilAscent = .pendingMethod ∨
             b.cbmcMultiLang = .pendingMethod ∨ b.leanPooUnbounded = .pendingMethod) :
    fourParadigmLibraryAdmit b = false := by
  rcases hPend with h | h | h | h <;>
    simp [fourParadigmLibraryAdmit, isProven, h]

/-- **Theorem 3**: Any `.setupDefect` blocks library admission fail-closed. -/
theorem any_paradigm_setup_defect_blocks_library_admit (b : ParadigmBundle)
    (hDef : b.quintApalache = .setupDefect ∨ b.gerbilAscent = .setupDefect ∨
            b.cbmcMultiLang = .setupDefect ∨ b.leanPooUnbounded = .setupDefect) :
    fourParadigmLibraryAdmit b = false := by
  rcases hDef with h | h | h | h <;>
    simp [fourParadigmLibraryAdmit, isProven, h]

/-- **Theorem 4 (Library Sovereignty over Host Permit)**: Even when `cedar-poo-spec` emits
    `.proven` (`Permit`), a failing four-paradigm library gate STILL blocks release admission. -/
theorem host_permit_cannot_override_four_paradigm_failure (b : ParadigmBundle)
    (hLibFail : fourParadigmLibraryAdmit b = false) :
    fullReleaseAdmit b = false := by
  simp [fullReleaseAdmit, hLibFail]

/-- **Theorem 5 (Host Sovereignty over 4/4 Library Proven)**: Even when all 4 library
    paradigms are `.proven`, any non-`.proven` consuming-host verdict blocks release admission. -/
theorem four_paradigm_proven_cannot_override_host_refusal (b : ParadigmBundle)
    (hHostNotProven : b.hostPolicyGate ≠ .proven) :
    fullReleaseAdmit b = false := by
  cases h : b.hostPolicyGate with
  | proven => exact False.elim (hHostNotProven h)
  | refuted => simp [fullReleaseAdmit, isProven, h]
  | pendingMethod => simp [fullReleaseAdmit, isProven, h]
  | setupDefect => simp [fullReleaseAdmit, isProven, h]

private theorem isProven_eq_true_iff (v : EpistemicVerdict) :
    isProven v = true ↔ v = .proven := by
  cases v <;> simp [isProven]

/-- **Theorem 6 (Exact Sound & Complete Four-Paradigm Characterization)**:
    `fourParadigmLibraryAdmit b = true` if and only if all 4 paradigms are `.proven`. -/
theorem four_paradigm_admit_iff_all_proven (b : ParadigmBundle) :
    fourParadigmLibraryAdmit b = true ↔
      b.quintApalache = .proven ∧
      b.gerbilAscent = .proven ∧
      b.cbmcMultiLang = .proven ∧
      b.leanPooUnbounded = .proven := by
  simp [fourParadigmLibraryAdmit, isProven_eq_true_iff, and_assoc]

/-- **Theorem 7 (Unbounded `∀ N` N-Version Oracle Convergence)**: For ANY finite list of
    `N` verification oracles, conjunctive convergence holds iff EVERY oracle is `.proven`. -/
theorem paradigm_list_convergence_requires_every_entry_proven (oracles : List EpistemicVerdict) :
    oracles.all isProven = true ↔ ∀ v ∈ oracles, v = .proven := by
  constructor
  · intro hall v hv
    exact (isProven_eq_true_iff v).mp (List.all_eq_true.mp hall v hv)
  · intro hall
    apply List.all_eq_true.mpr
    intro v hv
    exact (isProven_eq_true_iff v).mpr (hall v hv)

end FourParadigmGate

/-! ## Section 2: LeanPoo Two-Step Refinement & `Core.Transport` Proof Reuse -/

section LeanPooFourParadigmContract

structure FourParadigmConfig where
  quintMbtVerified : Bool
  ascentFixedPointVerified : Bool
  cbmcMultiLangVerified : Bool
  leanPooFleetVerified : Bool
  zeroMathlibAndCedarChecked : Bool
  deriving DecidableEq, Repr

inductive FourParadigmKey where
  | quintMbtVerified
  | ascentFixedPointVerified
  | cbmcMultiLangVerified
  | leanPooFleetVerified
  | zeroMathlibAndCedarChecked
  deriving DecidableEq, Repr

inductive FourParadigmIssue where
  | quintMbtMissing
  | ascentOracleMissing
  | cbmcContrastMissing
  | leanPooFleetMissing
  | forbiddenDependencyDetected
  deriving DecidableEq, Repr

private def fourParadigmView : View FourParadigmConfig FourParadigmKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseFourParadigmContract :
    Contract FourParadigmConfig FourParadigmKey Unit FourParadigmIssue where
  view := fourParadigmView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.quintMbtVerified then [] else [.rejected path .quintMbtMissing]) ++
    (if cfg.ascentFixedPointVerified then [] else [.rejected path .ascentOracleMissing]) ++
    (if cfg.cbmcMultiLangVerified then [] else [.rejected path .cbmcContrastMissing]) ++
    (if cfg.leanPooFleetVerified then [] else [.rejected path .leanPooFleetMissing])
  validInventory := Or.inl rfl

def libraryHygieneExt (cfg : FourParadigmConfig) (path : List FourParadigmKey) :
    List (Issue FourParadigmKey FourParadigmIssue) :=
  if cfg.zeroMathlibAndCedarChecked then [] else [.rejected path .forbiddenDependencyDetected]

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Release Host)**:
    Layering `zeroMathlibAndCedar` library hygiene AND ANY downstream `cedar-poo-spec`
    release host extension `hostReleaseExt` onto `baseFourParadigmContract` monotonically
    preserves every four-paradigm rejection. -/
theorem fourParadigmContract_preserves_rejection
    (hostReleaseExt : FourParadigmConfig → List FourParadigmKey →
      List (Issue FourParadigmKey FourParadigmIssue))
    (cfg : FourParadigmConfig) (path : List FourParadigmKey)
    (hRej : diagnose baseFourParadigmContract cfg path ≠ []) :
    diagnose (refine (refine baseFourParadigmContract libraryHygieneExt) hostReleaseExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseFourParadigmContract libraryHygieneExt hostReleaseExt cfg path hRej

inductive FourParadigmProofKey where
  | quintMbtVerified
  | ascentFixedPointVerified
  | cbmcMultiLangVerified
  | leanPooFleetVerified
  | zeroMathlibAndCedarChecked
  | sarifReportPrettyPrint
  deriving DecidableEq

abbrev FourParadigmProofValue : FourParadigmProofKey → Type
  | .quintMbtVerified => Bool
  | .ascentFixedPointVerified => Bool
  | .cbmcMultiLangVerified => Bool
  | .leanPooFleetVerified => Bool
  | .zeroMathlibAndCedarChecked => Bool
  | .sarifReportPrettyPrint => Bool

def fourParadigmObligation :
    LeanPoo.Proof.Obligation FourParadigmProofKey FourParadigmProofValue where
  dependencies :=
    [ .quintMbtVerified
    , .ascentFixedPointVerified
    , .cbmcMultiLangVerified
    , .leanPooFleetVerified
    , .zeroMathlibAndCedarChecked
    ]
  holds := fun s =>
    s .quintMbtVerified = true ∧
    s .ascentFixedPointVerified = true ∧
    s .cbmcMultiLangVerified = true ∧
    s .leanPooFleetVerified = true ∧
    s .zeroMathlibAndCedarChecked = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4, h5⟩
    exact ⟨(same .quintMbtVerified (by simp)).symm.trans h1,
           (same .ascentFixedPointVerified (by simp)).symm.trans h2,
           (same .cbmcMultiLangVerified (by simp)).symm.trans h3,
           (same .leanPooFleetVerified (by simp)).symm.trans h4,
           (same .zeroMathlibAndCedarChecked (by simp)).symm.trans h5⟩

def baselineFourParadigmSystem :
    LeanPoo.Proof.ProofObject FourParadigmProofKey FourParadigmProofValue where
  state := fun
    | .quintMbtVerified => true
    | .ascentFixedPointVerified => true
    | .cbmcMultiLangVerified => true
    | .leanPooFleetVerified => true
    | .zeroMathlibAndCedarChecked => true
    | .sarifReportPrettyPrint => false
  obligations := [fourParadigmObligation]

theorem baselineFourParadigmCertified :
    LeanPoo.Proof.Certificate baselineFourParadigmSystem := by
  intro ob hMem
  have hEq : ob = fourParadigmObligation := by simpa [baselineFourParadigmSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Toggling `.sarifReportPrettyPrint` transports the four-paradigm
    `LeanPoo.Proof.Certificate` in 1 line. -/
theorem reportFormatTuning_preserves_fourParadigm_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineFourParadigmSystem
        (LeanPoo.Proof.Patch.set .sarifReportPrettyPrint true)) :=
  close_single_set_untouched baselineFourParadigmSystem fourParadigmObligation
    .sarifReportPrettyPrint true rfl baselineFourParadigmCertified
    (by simp [fourParadigmObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.leanPooFleetVerified` ALWAYS invalidates reuse. -/
theorem disablingLeanPooGate_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected fourParadigmObligation
        (LeanPoo.Proof.Patch.set .leanPooFleetVerified false) :=
  set_dependency_invalidates_unaffected fourParadigmObligation
    .leanPooFleetVerified false (by simp [fourParadigmObligation])

end LeanPooFourParadigmContract

end DeterministicEngineering.Engineering.FourParadigmConsistency
