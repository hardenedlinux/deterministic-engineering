/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.FederatedArbitrationLiveness

/-!
# LeanPoo Unbounded Hermetic Supply-Chain & Reproducible Build Provenance (`B14`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `FederatedArbitrationLiveness` (all 12 prior modules, 136 theorems)
and adds 10 machine-checked SLSA / in-toto hermetic provenance, anti-slopsquatting lockfile
pinning, CVE-tombstone blocking, and 2-builder reproducible-build theorems — expanding the
library to **13 modules and 146 machine-checked theorems**.

Machine-checked theorems (10 total -> **146 theorems across 13 modules**, zero `sorry`, zero custom axioms):
1. `unpinned_dependency_always_refused` — any SBOM dependency absent from the signed `M1` lockfile is refused
2. `tombstoned_cve_dependency_always_refused` — any revoked/CVE-tombstoned dependency digest is refused
3. `non_hermetic_network_build_always_refused` — non-hermetic builds accessing unpinned network inputs are refused
4. `reproducible_build_mismatch_always_refused` — diverging 2-builder artifact digests are unconditionally refused
5. `forged_or_revoked_builder_signature_refused` — invalid signature or revoked builder identity is refused
6. `mismatched_source_or_toolchain_digest_refused` — source or toolchain digest mismatch is refused
7. `hermetic_provenance_admit_sound_and_complete` — exact iff characterization of hermetic SLSA/in-toto admission
8. `supplyChainContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Artifact Admission host)
9. `buildLogVerbosityTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingLockfilePinning_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.SupplyChainProvenance

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Hermetic SLSA/in-toto Build Provenance & Reproducible Build Gate (`B14`) -/

section SupplyChainGate

structure BuildProvenanceClaim where
  sourceDigest : Nat
  toolchainDigest : Nat
  artifactDigest : Nat
  reproducedDigest : Nat
  hermeticNoNetwork : Bool
  builderSignatureValid : Bool
  builderRevoked : Bool
  sbomDeps : List Nat
  deriving DecidableEq, Repr

structure SupplyChainPolicy where
  expectedSourceDigest : Nat
  expectedToolchainDigest : Nat
  pinnedLockfileDeps : List Nat
  revokedCveDigests : List Nat
  deriving DecidableEq, Repr

/-- Every declared SBOM dependency must be pinned in the signed `M1` lockfile and
    must not appear in the CVE/compromised-digest tombstone set. -/
def allDepsPinnedAndClean (policy : SupplyChainPolicy) (deps : List Nat) : Bool :=
  deps.all fun d =>
    policy.pinnedLockfileDeps.contains d && !policy.revokedCveDigests.contains d

/-- Complete deterministic SLSA/in-toto hermetic & reproducible build admission predicate. -/
def buildProvenanceAdmitted (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim) : Bool :=
  decide (claim.sourceDigest = policy.expectedSourceDigest) &&
  decide (claim.toolchainDigest = policy.expectedToolchainDigest) &&
  decide (claim.reproducedDigest = claim.artifactDigest) &&
  claim.hermeticNoNetwork &&
  claim.builderSignatureValid &&
  !claim.builderRevoked &&
  allDepsPinnedAndClean policy claim.sbomDeps

/-- **Theorem 1 (Anti-Slopsquatting / Lockfile Pinning)**: Any SBOM dependency not present
    in `policy.pinnedLockfileDeps` unconditionally causes refusal. -/
theorem unpinned_dependency_always_refused
    (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim) (d : Nat)
    (hMem : d ∈ claim.sbomDeps)
    (hUnpinned : policy.pinnedLockfileDeps.contains d = false) :
    buildProvenanceAdmitted policy claim = false := by
  have hAllFalse : allDepsPinnedAndClean policy claim.sbomDeps = false := by
    cases h : allDepsPinnedAndClean policy claim.sbomDeps
    · rfl
    · unfold allDepsPinnedAndClean at h
      have hElem := (List.all_eq_true.mp h) d hMem
      rw [hUnpinned] at hElem
      simp at hElem
  simp only [buildProvenanceAdmitted, hAllFalse, Bool.and_false]

/-- **Theorem 2 (CVE / Compromised-Digest Tombstone Block)**: Any SBOM dependency in
    `policy.revokedCveDigests` unconditionally causes refusal. -/
theorem tombstoned_cve_dependency_always_refused
    (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim) (d : Nat)
    (hMem : d ∈ claim.sbomDeps)
    (hRevoked : policy.revokedCveDigests.contains d = true) :
    buildProvenanceAdmitted policy claim = false := by
  have hAllFalse : allDepsPinnedAndClean policy claim.sbomDeps = false := by
    cases h : allDepsPinnedAndClean policy claim.sbomDeps
    · rfl
    · unfold allDepsPinnedAndClean at h
      have hElem := (List.all_eq_true.mp h) d hMem
      rw [hRevoked] at hElem
      simp at hElem
  simp only [buildProvenanceAdmitted, hAllFalse, Bool.and_false]

/-- **Theorem 3 (Hermetic Isolation)**: Any non-hermetic build (`hermeticNoNetwork = false`)
    is unconditionally refused. -/
theorem non_hermetic_network_build_always_refused
    (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim)
    (hNonHerm : claim.hermeticNoNetwork = false) :
    buildProvenanceAdmitted policy claim = false := by
  simp [buildProvenanceAdmitted, hNonHerm]

/-- **Theorem 4 (2-Builder Reproducible Build Parity)**: Any bit-level divergence between
    primary `artifactDigest` and independent `reproducedDigest` is unconditionally refused. -/
theorem reproducible_build_mismatch_always_refused
    (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim)
    (hDiff : claim.reproducedDigest ≠ claim.artifactDigest) :
    buildProvenanceAdmitted policy claim = false := by
  simp [buildProvenanceAdmitted, hDiff]

/-- **Theorem 5 (Builder Signature & Non-Revocation)**: A forged builder signature OR
    a revoked builder identity unconditionally causes refusal. -/
theorem forged_or_revoked_builder_signature_refused
    (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim)
    (hBad : claim.builderSignatureValid = false ∨ claim.builderRevoked = true) :
    buildProvenanceAdmitted policy claim = false := by
  rcases hBad with hSig | hRev
  · simp [buildProvenanceAdmitted, hSig]
  · simp [buildProvenanceAdmitted, hRev]

/-- **Theorem 6 (Source & Toolchain Digest Binding)**: Any mismatch in attested source or
    toolchain digest unconditionally causes refusal. -/
theorem mismatched_source_or_toolchain_digest_refused
    (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim)
    (hMis : claim.sourceDigest ≠ policy.expectedSourceDigest ∨
            claim.toolchainDigest ≠ policy.expectedToolchainDigest) :
    buildProvenanceAdmitted policy claim = false := by
  rcases hMis with hSrc | hTool
  · simp [buildProvenanceAdmitted, hSrc]
  · simp [buildProvenanceAdmitted, hTool]

/-- **Theorem 7 (Soundness & Completeness of Hermetic Provenance Admission)**:
    `buildProvenanceAdmitted` holds iff source/toolchain/reproduced digests match, the build
    is hermetic, the builder signature is valid and non-revoked, and every SBOM dependency is
    lockfile-pinned and free of CVE tombstones. -/
theorem hermetic_provenance_admit_sound_and_complete
    (policy : SupplyChainPolicy) (claim : BuildProvenanceClaim) :
    buildProvenanceAdmitted policy claim = true ↔
      claim.sourceDigest = policy.expectedSourceDigest ∧
      claim.toolchainDigest = policy.expectedToolchainDigest ∧
      claim.reproducedDigest = claim.artifactDigest ∧
      claim.hermeticNoNetwork = true ∧
      claim.builderSignatureValid = true ∧
      claim.builderRevoked = false ∧
      (∀ d ∈ claim.sbomDeps,
        policy.pinnedLockfileDeps.contains d = true ∧
        policy.revokedCveDigests.contains d = false) := by
  unfold buildProvenanceAdmitted allDepsPinnedAndClean
  simp [Bool.and_eq_true, List.all_eq_true, and_assoc]

end SupplyChainGate

/-! ## Section 2: LeanPoo Two-Step Refinement (`Supply Chain -> Reproducibility -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooSupplyChainContract

structure SupplyChainConfig where
  lockfilePinningEnforced : Bool
  cveTombstoneBlockingEnforced : Bool
  hermeticSandboxEnforced : Bool
  twoBuilderReproducibilityEnforced : Bool
  deriving DecidableEq, Repr

inductive SupplyChainKey where
  | lockfilePinningEnforced
  | cveTombstoneBlockingEnforced
  | hermeticSandboxEnforced
  | twoBuilderReproducibilityEnforced
  deriving DecidableEq, Repr

inductive SupplyChainIssue where
  | unpinnedDependencyAllowed
  | cveTombstoneBypassAllowed
  | nonHermeticNetworkAllowed
  | nonReproducibleArtifactAllowed
  deriving DecidableEq, Repr

private def supplyChainView : View SupplyChainConfig SupplyChainKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseSupplyChainContract :
    Contract SupplyChainConfig SupplyChainKey Unit SupplyChainIssue where
  view := supplyChainView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.lockfilePinningEnforced then [] else [.rejected path .unpinnedDependencyAllowed]) ++
    (if cfg.cveTombstoneBlockingEnforced then [] else [.rejected path .cveTombstoneBypassAllowed])
  validInventory := Or.inl rfl

def reproducibleAttestationExt (cfg : SupplyChainConfig) (path : List SupplyChainKey) :
    List (Issue SupplyChainKey SupplyChainIssue) :=
  (if cfg.hermeticSandboxEnforced then [] else [.rejected path .nonHermeticNetworkAllowed]) ++
  (if cfg.twoBuilderReproducibilityEnforced then [] else [.rejected path .nonReproducibleArtifactAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Artifact Admission Host)**:
    Layering hermetic/2-builder reproducibility AND ANY downstream `cedar-poo-spec`
    artifact-admission extension `hostArtifactExt` onto `baseSupplyChainContract`
    monotonically preserves every supply-chain rejection. -/
theorem supplyChainContract_preserves_rejection
    (hostArtifactExt : SupplyChainConfig → List SupplyChainKey →
      List (Issue SupplyChainKey SupplyChainIssue))
    (cfg : SupplyChainConfig) (path : List SupplyChainKey)
    (hRej : diagnose baseSupplyChainContract cfg path ≠ []) :
    diagnose (refine (refine baseSupplyChainContract reproducibleAttestationExt) hostArtifactExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseSupplyChainContract reproducibleAttestationExt hostArtifactExt cfg path hRej

inductive SupplyChainProofKey where
  | lockfilePinningEnforced
  | cveTombstoneBlockingEnforced
  | hermeticSandboxEnforced
  | twoBuilderReproducibilityEnforced
  | buildLogVerbosity
  deriving DecidableEq

abbrev SupplyChainProofValue : SupplyChainProofKey → Type
  | .lockfilePinningEnforced => Bool
  | .cveTombstoneBlockingEnforced => Bool
  | .hermeticSandboxEnforced => Bool
  | .twoBuilderReproducibilityEnforced => Bool
  | .buildLogVerbosity => Nat

def supplyChainObligation :
    LeanPoo.Proof.Obligation SupplyChainProofKey SupplyChainProofValue where
  dependencies :=
    [ .lockfilePinningEnforced
    , .cveTombstoneBlockingEnforced
    , .hermeticSandboxEnforced
    , .twoBuilderReproducibilityEnforced
    ]
  holds := fun s =>
    s .lockfilePinningEnforced = true ∧
    s .cveTombstoneBlockingEnforced = true ∧
    s .hermeticSandboxEnforced = true ∧
    s .twoBuilderReproducibilityEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .lockfilePinningEnforced (by simp)).symm.trans h1,
           (same .cveTombstoneBlockingEnforced (by simp)).symm.trans h2,
           (same .hermeticSandboxEnforced (by simp)).symm.trans h3,
           (same .twoBuilderReproducibilityEnforced (by simp)).symm.trans h4⟩

def baselineSupplyChainSystem :
    LeanPoo.Proof.ProofObject SupplyChainProofKey SupplyChainProofValue where
  state := fun
    | .lockfilePinningEnforced => true
    | .cveTombstoneBlockingEnforced => true
    | .hermeticSandboxEnforced => true
    | .twoBuilderReproducibilityEnforced => true
    | .buildLogVerbosity => 1
  obligations := [supplyChainObligation]

theorem baselineSupplyChainCertified :
    LeanPoo.Proof.Certificate baselineSupplyChainSystem := by
  intro ob hMem
  have hEq : ob = supplyChainObligation := by simpa [baselineSupplyChainSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.buildLogVerbosity` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem buildLogVerbosityTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineSupplyChainSystem
        (LeanPoo.Proof.Patch.set .buildLogVerbosity 3)) :=
  close_single_set_untouched baselineSupplyChainSystem supplyChainObligation
    .buildLogVerbosity 3 rfl baselineSupplyChainCertified
    (by simp [supplyChainObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.lockfilePinningEnforced` ALWAYS invalidates reuse. -/
theorem disablingLockfilePinning_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected supplyChainObligation
        (LeanPoo.Proof.Patch.set .lockfilePinningEnforced false) :=
  set_dependency_invalidates_unaffected supplyChainObligation
    .lockfilePinningEnforced false (by simp [supplyChainObligation])

end LeanPooSupplyChainContract

end DeterministicEngineering.Engineering.SupplyChainProvenance
