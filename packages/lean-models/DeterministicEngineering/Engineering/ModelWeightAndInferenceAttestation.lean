/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.FederatedOrgReciprocity

/-!
# LeanPoo Unbounded Deterministic Model-Weight Pinning & Reproducible Inference Attestation (`B21`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `FederatedOrgReciprocity` (all 19 prior modules, 206 theorems)
and adds 10 machine-checked base-weight Merkle pinning, LoRA/PEFT adapter allowlisting,
deterministic sampling temperature/seed/kernel binding, and model-revocation theorems —
reaching the **20-module / 216-theorem** milestone.

Machine-checked theorems (10 total -> **216 theorems across 20 modules**, zero `sorry`, zero custom axioms):
1. `unpinned_base_weight_refused` — mismatched model weight Merkle root is unconditionally refused
2. `unauthorized_lora_adapter_refused` — any unapproved LoRA/PEFT adapter is unconditionally refused
3. `non_deterministic_sampling_temperature_refused` — temperature exceeding deterministic cap is refused
4. `missing_seed_or_kernel_pin_refused` — unpinned PRNG seed or mismatched kernel digest is refused
5. `forged_or_revoked_model_attestation_refused` — invalid signature or revoked model ID is refused
6. `clean_zero_adapter_base_model_admitted` — base model with zero adapters needs no adapter allowlist entries
7. `model_inference_attestation_sound_and_complete` — exact iff characterization of deterministic inference admission
8. `modelAttestationContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` AI-Model host)
9. `kvCacheEvictionTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingWeightRootPinning_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Deterministic Model-Weight & Reproducible Inference Gate (`B21`) -/

section ModelInferenceGate

structure ModelInferenceClaim where
  modelId : Nat
  observedWeightRoot : Nat
  attachedAdapters : List Nat
  runtimeKernelDigest : Nat
  temperatureBps : Nat
  hasExplicitSeed : Bool
  attestationSigValid : Bool
  deriving DecidableEq, Repr

structure ModelGovernancePolicy where
  pinnedWeightRoot : Nat
  approvedAdapters : List Nat
  pinnedKernelDigest : Nat
  maxAllowedTempBps : Nat
  revokedModelIds : List Nat
  deriving DecidableEq, Repr

/-- Deterministic model-weight & reproducible inference admission predicate:
    enforces pinned base-weight Merkle root, allowlisted LoRA/PEFT adapters, pinned
    deterministic runtime kernel, bounded sampling temperature, explicit PRNG seed,
    non-revoked model ID, AND valid serving-key attestation signature. -/
def modelInferenceAdmitted
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim) : Bool :=
  !policy.revokedModelIds.contains claim.modelId &&
  decide (claim.observedWeightRoot = policy.pinnedWeightRoot) &&
  claim.attachedAdapters.all (fun a => policy.approvedAdapters.contains a) &&
  decide (claim.runtimeKernelDigest = policy.pinnedKernelDigest) &&
  decide (claim.temperatureBps ≤ policy.maxAllowedTempBps) &&
  claim.hasExplicitSeed &&
  claim.attestationSigValid

/-- **Theorem 1 (Base Model Weight Pinning)**: Any silent weight swap where
    `observedWeightRoot ≠ pinnedWeightRoot` is unconditionally refused. -/
theorem unpinned_base_weight_refused
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim)
    (hMis : claim.observedWeightRoot ≠ policy.pinnedWeightRoot) :
    modelInferenceAdmitted policy claim = false := by
  simp [modelInferenceAdmitted, hMis]

/-- **Theorem 2 (Anti-Stealth-LoRA Poisoning)**: Attaching any LoRA/PEFT adapter not
    explicitly allowlisted in `policy.approvedAdapters` is unconditionally refused. -/
theorem unauthorized_lora_adapter_refused
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim)
    (a : Nat) (hIn : a ∈ claim.attachedAdapters)
    (hUnapproved : policy.approvedAdapters.contains a = false) :
    modelInferenceAdmitted policy claim = false := by
  have hAllFalse : claim.attachedAdapters.all (fun x => policy.approvedAdapters.contains x) = false := by
    cases hAll : claim.attachedAdapters.all (fun x => policy.approvedAdapters.contains x) with
    | false => rfl
    | true =>
      have hElem := List.all_eq_true.mp hAll a hIn
      rw [hUnapproved] at hElem
      simp at hElem
  unfold modelInferenceAdmitted
  rw [hAllFalse]
  simp

/-- **Theorem 3 (Deterministic Sampling Temperature Fence)**: Any inference exceeding
    `policy.maxAllowedTempBps` (e.g., `temperatureBps > 0` in strict greedy replay) is refused. -/
theorem non_deterministic_sampling_temperature_refused
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim)
    (hHot : policy.maxAllowedTempBps < claim.temperatureBps) :
    modelInferenceAdmitted policy claim = false := by
  have hNotLe : ¬ (claim.temperatureBps ≤ policy.maxAllowedTempBps) := by omega
  simp [modelInferenceAdmitted, hNotLe]

/-- **Theorem 4 (Seed & Kernel Determinism Pin)**: Missing an explicit PRNG seed or
    diverging runtime kernel digest unconditionally refuses reproducible admission. -/
theorem missing_seed_or_kernel_pin_refused
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim)
    (hBad : claim.hasExplicitSeed = false ∨
            claim.runtimeKernelDigest ≠ policy.pinnedKernelDigest) :
    modelInferenceAdmitted policy claim = false := by
  rcases hBad with hSeed | hKern
  · simp [modelInferenceAdmitted, hSeed]
  · simp [modelInferenceAdmitted, hKern]

/-- **Theorem 5 (Forged Signature & Revoked Model Block)**: Either an invalid serving
    attestation signature or a revoked `modelId` unconditionally refuses admission. -/
theorem forged_or_revoked_model_attestation_refused
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim)
    (hBad : claim.attestationSigValid = false ∨
            policy.revokedModelIds.contains claim.modelId = true) :
    modelInferenceAdmitted policy claim = false := by
  unfold modelInferenceAdmitted
  rcases hBad with hSig | hRev
  · rw [hSig]; simp
  · rw [hRev]; simp

/-- **Theorem 6 (Anti-P4 Base-Model Sufficiency)**: A clean base model with zero attached
    LoRA adapters (`attachedAdapters = []`) is admitted when weights, kernel, temp, seed,
    non-revocation, and signature hold. -/
theorem clean_zero_adapter_base_model_admitted
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim)
    (hNoAdapters : claim.attachedAdapters = [])
    (hNotRev : policy.revokedModelIds.contains claim.modelId = false)
    (hWeight : claim.observedWeightRoot = policy.pinnedWeightRoot)
    (hKern : claim.runtimeKernelDigest = policy.pinnedKernelDigest)
    (hTemp : claim.temperatureBps ≤ policy.maxAllowedTempBps)
    (hSeed : claim.hasExplicitSeed = true)
    (hSig : claim.attestationSigValid = true) :
    modelInferenceAdmitted policy claim = true := by
  unfold modelInferenceAdmitted
  rw [hNotRev, hNoAdapters, hSeed, hSig]
  simp [hWeight, hKern, hTemp]

/-- **Theorem 7 (Soundness & Completeness of Model-Weight & Inference Gate)**:
    `modelInferenceAdmitted` holds iff non-revoked model, pinned weight root, allowlisted
    adapters, pinned kernel, bounded temperature, explicit seed, and valid signature all hold. -/
theorem model_inference_attestation_sound_and_complete
    (policy : ModelGovernancePolicy) (claim : ModelInferenceClaim) :
    modelInferenceAdmitted policy claim = true ↔
      policy.revokedModelIds.contains claim.modelId = false ∧
      claim.observedWeightRoot = policy.pinnedWeightRoot ∧
      claim.attachedAdapters.all (fun a => policy.approvedAdapters.contains a) = true ∧
      claim.runtimeKernelDigest = policy.pinnedKernelDigest ∧
      claim.temperatureBps ≤ policy.maxAllowedTempBps ∧
      claim.hasExplicitSeed = true ∧
      claim.attestationSigValid = true := by
  unfold modelInferenceAdmitted
  simp [Bool.and_eq_true, and_assoc]

end ModelInferenceGate

/-! ## Section 2: LeanPoo Two-Step Refinement (`Weight Pin -> Deterministic Sampling -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooModelAttestationContract

structure ModelAttestationConfig where
  baseWeightMerklePinned : Bool
  loraAdapterAllowlistEnforced : Bool
  deterministicSamplingEnforced : Bool
  servingSignatureVerified : Bool
  deriving DecidableEq, Repr

inductive ModelAttestationKey where
  | baseWeightMerklePinned
  | loraAdapterAllowlistEnforced
  | deterministicSamplingEnforced
  | servingSignatureVerified
  deriving DecidableEq, Repr

inductive ModelAttestationIssue where
  | unpinnedWeightSwapAllowed
  | stealthLoraAdapterAllowed
  | nonDeterministicSamplingAllowed
  | unsignedInferenceAllowed
  deriving DecidableEq, Repr

private def modelAttestationView : View ModelAttestationConfig ModelAttestationKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseModelAttestationContract :
    Contract ModelAttestationConfig ModelAttestationKey Unit ModelAttestationIssue where
  view := modelAttestationView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.baseWeightMerklePinned then [] else [.rejected path .unpinnedWeightSwapAllowed]) ++
    (if cfg.loraAdapterAllowlistEnforced then [] else [.rejected path .stealthLoraAdapterAllowed])
  validInventory := Or.inl rfl

def samplingAndSigExt (cfg : ModelAttestationConfig) (path : List ModelAttestationKey) :
    List (Issue ModelAttestationKey ModelAttestationIssue) :=
  (if cfg.deterministicSamplingEnforced then [] else [.rejected path .nonDeterministicSamplingAllowed]) ++
  (if cfg.servingSignatureVerified then [] else [.rejected path .unsignedInferenceAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` AI-Model Governance Host)**:
    Layering deterministic-sampling/signature checks AND ANY downstream `cedar-poo-spec`
    model-governance extension `hostModelExt` onto `baseModelAttestationContract`
    monotonically preserves every model-integrity rejection. -/
theorem modelAttestationContract_preserves_rejection
    (hostModelExt : ModelAttestationConfig → List ModelAttestationKey →
      List (Issue ModelAttestationKey ModelAttestationIssue))
    (cfg : ModelAttestationConfig) (path : List ModelAttestationKey)
    (hRej : diagnose baseModelAttestationContract cfg path ≠ []) :
    diagnose (refine (refine baseModelAttestationContract samplingAndSigExt) hostModelExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseModelAttestationContract samplingAndSigExt hostModelExt cfg path hRej

inductive ModelAttestationProofKey where
  | baseWeightMerklePinned
  | loraAdapterAllowlistEnforced
  | deterministicSamplingEnforced
  | servingSignatureVerified
  | kvCacheEvictionWatermarkMb
  deriving DecidableEq

abbrev ModelAttestationProofValue : ModelAttestationProofKey → Type
  | .baseWeightMerklePinned => Bool
  | .loraAdapterAllowlistEnforced => Bool
  | .deterministicSamplingEnforced => Bool
  | .servingSignatureVerified => Bool
  | .kvCacheEvictionWatermarkMb => Nat

def modelAttestationObligation :
    LeanPoo.Proof.Obligation ModelAttestationProofKey ModelAttestationProofValue where
  dependencies :=
    [ .baseWeightMerklePinned
    , .loraAdapterAllowlistEnforced
    , .deterministicSamplingEnforced
    , .servingSignatureVerified
    ]
  holds := fun s =>
    s .baseWeightMerklePinned = true ∧
    s .loraAdapterAllowlistEnforced = true ∧
    s .deterministicSamplingEnforced = true ∧
    s .servingSignatureVerified = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .baseWeightMerklePinned (by simp)).symm.trans h1,
           (same .loraAdapterAllowlistEnforced (by simp)).symm.trans h2,
           (same .deterministicSamplingEnforced (by simp)).symm.trans h3,
           (same .servingSignatureVerified (by simp)).symm.trans h4⟩

def baselineModelAttestationSystem :
    LeanPoo.Proof.ProofObject ModelAttestationProofKey ModelAttestationProofValue where
  state := fun
    | .baseWeightMerklePinned => true
    | .loraAdapterAllowlistEnforced => true
    | .deterministicSamplingEnforced => true
    | .servingSignatureVerified => true
    | .kvCacheEvictionWatermarkMb => 4096
  obligations := [modelAttestationObligation]

theorem baselineModelAttestationCertified :
    LeanPoo.Proof.Certificate baselineModelAttestationSystem := by
  intro ob hMem
  have hEq : ob = modelAttestationObligation := by simpa [baselineModelAttestationSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.kvCacheEvictionWatermarkMb` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem kvCacheEvictionTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineModelAttestationSystem
        (LeanPoo.Proof.Patch.set .kvCacheEvictionWatermarkMb 8192)) :=
  close_single_set_untouched baselineModelAttestationSystem modelAttestationObligation
    .kvCacheEvictionWatermarkMb 8192 rfl baselineModelAttestationCertified
    (by simp [modelAttestationObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.baseWeightMerklePinned` ALWAYS invalidates reuse. -/
theorem disablingWeightRootPinning_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected modelAttestationObligation
        (LeanPoo.Proof.Patch.set .baseWeightMerklePinned false) :=
  set_dependency_invalidates_unaffected modelAttestationObligation
    .baseWeightMerklePinned false (by simp [modelAttestationObligation])

end LeanPooModelAttestationContract

end DeterministicEngineering.Engineering.ModelWeightAndInferenceAttestation
