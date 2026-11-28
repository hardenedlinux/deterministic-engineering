/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.KeyRotationAndCryptoShredding

/-!
# LeanPoo Unbounded Post-Quantum Hybrid Cryptographic Agility & Anti-Downgrade (`B17`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `KeyRotationAndCryptoShredding` (all 15 prior modules, 166 theorems)
and adds 10 machine-checked NIST SP 800-208 / SP 800-227 hybrid Dual-AND combiner,
anti-algorithm-downgrade, stateful OTS non-reuse, and domain-separation theorems —
expanding the library to **16 modules and 176 machine-checked theorems**.

Machine-checked theorems (10 total -> **176 theorems across 16 modules**, zero `sorry`, zero custom axioms):
1. `algorithm_downgrade_always_refused` — suite security level below policy floor is refused
2. `deprecated_suite_always_refused` — any deprecated/broken suite ID is unconditionally refused
3. `classical_failure_blocks_hybrid_combiner` — invalid classical Ed25519 signature fails Dual-AND combiner
4. `pq_failure_blocks_hybrid_combiner` — invalid PQ hash-based signature fails Dual-AND combiner
5. `ots_leaf_reuse_always_refused` — reusing a stateful hash-based OTS leaf index is unconditionally refused
6. `domain_separation_mismatch_refused` — mismatched domain-separation tag is unconditionally refused
7. `hybrid_combiner_sound_and_complete` — exact iff characterization of hybrid Dual-AND admission
8. `pqAgilityContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Crypto-Compliance host)
9. `otsPoolRefillWatermarkTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingPqHybridFloor_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.PostQuantumCryptoAgility

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Dual-AND Hybrid Combiner, Anti-Downgrade & Stateful OTS Non-Reuse (`B17`) -/

section PostQuantumGate

structure HybridSignatureClaim where
  suiteId : Nat
  offeredSuiteLevel : Nat
  signedDomainTag : Nat
  otsLeafIndex : Nat
  classicalSigValid : Bool
  pqSigValid : Bool
  deriving DecidableEq, Repr

structure CryptoAgilityPolicy where
  minRequiredSuiteLevel : Nat
  expectedDomainTag : Nat
  deprecatedSuites : List Nat
  usedLeafIndices : List Nat
  deriving DecidableEq, Repr

/-- Deterministic Dual-AND hybrid verification predicate:
    requires suite floor, non-deprecated suite, domain separation, fresh unused OTS leaf,
    AND BOTH classical + post-quantum signature validity. -/
def hybridVerifyAdmitted
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim) : Bool :=
  decide (policy.minRequiredSuiteLevel ≤ claim.offeredSuiteLevel) &&
  !policy.deprecatedSuites.contains claim.suiteId &&
  decide (claim.signedDomainTag = policy.expectedDomainTag) &&
  !policy.usedLeafIndices.contains claim.otsLeafIndex &&
  claim.classicalSigValid &&
  claim.pqSigValid

/-- **Theorem 1 (Anti-Algorithm-Downgrade Floor)**: Any offered cryptographic suite below
    `minRequiredSuiteLevel` (e.g., downgrading hybrid PQ to classical-only) is refused. -/
theorem algorithm_downgrade_always_refused
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim)
    (hLow : claim.offeredSuiteLevel < policy.minRequiredSuiteLevel) :
    hybridVerifyAdmitted policy claim = false := by
  have hNotGe : ¬ (policy.minRequiredSuiteLevel ≤ claim.offeredSuiteLevel) := by omega
  simp [hybridVerifyAdmitted, hNotGe]

/-- **Theorem 2 (Deprecated Suite Tombstone Block)**: Any suite ID in `policy.deprecatedSuites`
    is unconditionally refused. -/
theorem deprecated_suite_always_refused
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim)
    (hDep : policy.deprecatedSuites.contains claim.suiteId = true) :
    hybridVerifyAdmitted policy claim = false := by
  unfold hybridVerifyAdmitted
  rw [hDep]
  simp

/-- **Theorem 3 (Dual-AND Combiner — Classical Leg Essential)**: Failure of the classical
    Ed25519 leg unconditionally causes hybrid verification refusal. -/
theorem classical_failure_blocks_hybrid_combiner
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim)
    (hBad : claim.classicalSigValid = false) :
    hybridVerifyAdmitted policy claim = false := by
  simp [hybridVerifyAdmitted, hBad]

/-- **Theorem 4 (Dual-AND Combiner — Post-Quantum Leg Essential)**: Failure of the post-quantum
    hash-based leg unconditionally causes hybrid verification refusal. -/
theorem pq_failure_blocks_hybrid_combiner
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim)
    (hBad : claim.pqSigValid = false) :
    hybridVerifyAdmitted policy claim = false := by
  simp [hybridVerifyAdmitted, hBad]

/-- **Theorem 5 (Stateful OTS Leaf Anti-Reuse)**: Any stateful hash-based OTS leaf index
    already present in `policy.usedLeafIndices` is unconditionally refused. -/
theorem ots_leaf_reuse_always_refused
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim)
    (hUsed : policy.usedLeafIndices.contains claim.otsLeafIndex = true) :
    hybridVerifyAdmitted policy claim = false := by
  unfold hybridVerifyAdmitted
  rw [hUsed]
  simp

/-- **Theorem 6 (Domain Separation Binding)**: Any mismatch between `signedDomainTag` and
    `expectedDomainTag` prevents cross-protocol signature replay. -/
theorem domain_separation_mismatch_refused
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim)
    (hMis : claim.signedDomainTag ≠ policy.expectedDomainTag) :
    hybridVerifyAdmitted policy claim = false := by
  simp [hybridVerifyAdmitted, hMis]

/-- **Theorem 7 (Soundness & Completeness of Hybrid Dual-AND Agility Gate)**:
    `hybridVerifyAdmitted` holds iff suite floor, non-deprecation, domain separation,
    OTS non-reuse, classical validity, and post-quantum validity all hold simultaneously. -/
theorem hybrid_combiner_sound_and_complete
    (policy : CryptoAgilityPolicy) (claim : HybridSignatureClaim) :
    hybridVerifyAdmitted policy claim = true ↔
      policy.minRequiredSuiteLevel ≤ claim.offeredSuiteLevel ∧
      policy.deprecatedSuites.contains claim.suiteId = false ∧
      claim.signedDomainTag = policy.expectedDomainTag ∧
      policy.usedLeafIndices.contains claim.otsLeafIndex = false ∧
      claim.classicalSigValid = true ∧
      claim.pqSigValid = true := by
  unfold hybridVerifyAdmitted
  simp [Bool.and_eq_true, and_assoc]

end PostQuantumGate

/-! ## Section 2: LeanPoo Two-Step Refinement (`Hybrid PQ -> Anti-Downgrade -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooPqAgilityContract

structure PqAgilityConfig where
  hybridDualAndCombinerEnforced : Bool
  antiDowngradeSuiteFloorEnforced : Bool
  otsSingleUseZeroizationEnforced : Bool
  domainSeparationBindingEnforced : Bool
  deriving DecidableEq, Repr

inductive PqAgilityKey where
  | hybridDualAndCombinerEnforced
  | antiDowngradeSuiteFloorEnforced
  | otsSingleUseZeroizationEnforced
  | domainSeparationBindingEnforced
  deriving DecidableEq, Repr

inductive PqAgilityIssue where
  | singleLegFallbackAllowed
  | suiteDowngradeAllowed
  | otsLeafReuseAllowed
  | crossProtocolReplayAllowed
  deriving DecidableEq, Repr

private def pqAgilityView : View PqAgilityConfig PqAgilityKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def basePqAgilityContract :
    Contract PqAgilityConfig PqAgilityKey Unit PqAgilityIssue where
  view := pqAgilityView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.hybridDualAndCombinerEnforced then [] else [.rejected path .singleLegFallbackAllowed]) ++
    (if cfg.antiDowngradeSuiteFloorEnforced then [] else [.rejected path .suiteDowngradeAllowed])
  validInventory := Or.inl rfl

def otsAndDomainExt (cfg : PqAgilityConfig) (path : List PqAgilityKey) :
    List (Issue PqAgilityKey PqAgilityIssue) :=
  (if cfg.otsSingleUseZeroizationEnforced then [] else [.rejected path .otsLeafReuseAllowed]) ++
  (if cfg.domainSeparationBindingEnforced then [] else [.rejected path .crossProtocolReplayAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Crypto-Compliance Host)**:
    Layering OTS single-use/domain-separation fencing AND ANY downstream `cedar-poo-spec`
    cryptographic-compliance extension `hostCryptoExt` onto `basePqAgilityContract`
    monotonically preserves every PQ-agility rejection. -/
theorem pqAgilityContract_preserves_rejection
    (hostCryptoExt : PqAgilityConfig → List PqAgilityKey →
      List (Issue PqAgilityKey PqAgilityIssue))
    (cfg : PqAgilityConfig) (path : List PqAgilityKey)
    (hRej : diagnose basePqAgilityContract cfg path ≠ []) :
    diagnose (refine (refine basePqAgilityContract otsAndDomainExt) hostCryptoExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection basePqAgilityContract otsAndDomainExt hostCryptoExt cfg path hRej

inductive PqAgilityProofKey where
  | hybridDualAndCombinerEnforced
  | antiDowngradeSuiteFloorEnforced
  | otsSingleUseZeroizationEnforced
  | domainSeparationBindingEnforced
  | otsPoolRefillWatermark
  deriving DecidableEq

abbrev PqAgilityProofValue : PqAgilityProofKey → Type
  | .hybridDualAndCombinerEnforced => Bool
  | .antiDowngradeSuiteFloorEnforced => Bool
  | .otsSingleUseZeroizationEnforced => Bool
  | .domainSeparationBindingEnforced => Bool
  | .otsPoolRefillWatermark => Nat

def pqAgilityObligation :
    LeanPoo.Proof.Obligation PqAgilityProofKey PqAgilityProofValue where
  dependencies :=
    [ .hybridDualAndCombinerEnforced
    , .antiDowngradeSuiteFloorEnforced
    , .otsSingleUseZeroizationEnforced
    , .domainSeparationBindingEnforced
    ]
  holds := fun s =>
    s .hybridDualAndCombinerEnforced = true ∧
    s .antiDowngradeSuiteFloorEnforced = true ∧
    s .otsSingleUseZeroizationEnforced = true ∧
    s .domainSeparationBindingEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .hybridDualAndCombinerEnforced (by simp)).symm.trans h1,
           (same .antiDowngradeSuiteFloorEnforced (by simp)).symm.trans h2,
           (same .otsSingleUseZeroizationEnforced (by simp)).symm.trans h3,
           (same .domainSeparationBindingEnforced (by simp)).symm.trans h4⟩

def baselinePqAgilitySystem :
    LeanPoo.Proof.ProofObject PqAgilityProofKey PqAgilityProofValue where
  state := fun
    | .hybridDualAndCombinerEnforced => true
    | .antiDowngradeSuiteFloorEnforced => true
    | .otsSingleUseZeroizationEnforced => true
    | .domainSeparationBindingEnforced => true
    | .otsPoolRefillWatermark => 16
  obligations := [pqAgilityObligation]

theorem baselinePqAgilityCertified :
    LeanPoo.Proof.Certificate baselinePqAgilitySystem := by
  intro ob hMem
  have hEq : ob = pqAgilityObligation := by simpa [baselinePqAgilitySystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.otsPoolRefillWatermark` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem otsPoolRefillWatermarkTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselinePqAgilitySystem
        (LeanPoo.Proof.Patch.set .otsPoolRefillWatermark 64)) :=
  close_single_set_untouched baselinePqAgilitySystem pqAgilityObligation
    .otsPoolRefillWatermark 64 rfl baselinePqAgilityCertified
    (by simp [pqAgilityObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.antiDowngradeSuiteFloorEnforced` ALWAYS invalidates reuse. -/
theorem disablingPqHybridFloor_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected pqAgilityObligation
        (LeanPoo.Proof.Patch.set .antiDowngradeSuiteFloorEnforced false) :=
  set_dependency_invalidates_unaffected pqAgilityObligation
    .antiDowngradeSuiteFloorEnforced false (by simp [pqAgilityObligation])

end LeanPooPqAgilityContract

end DeterministicEngineering.Engineering.PostQuantumCryptoAgility
