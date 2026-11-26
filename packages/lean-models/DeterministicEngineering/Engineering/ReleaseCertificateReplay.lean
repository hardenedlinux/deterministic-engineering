/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.FourParadigmConsistency

/-!
# LeanPoo Air-Gapped Release Certificate Replay & Offline Verification (`deterministic-engineering-qnt` -> `cedar-poo-spec`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `FourParadigmConsistency` -> `LibraryExportContract` -> all 5 pillar
modules, bringing the **pure `LeanPoo` library to 96 machine-checked theorems across 8 modules**.

Enables consuming authorization hosts (`cedar-poo-spec`) to verify a signed,
threshold-witness-cosigned `LibraryReleaseCertificate` **100% offline** (zero `lake`,
zero network, public keys only) with anti-downgrade, revocation, and purity guarantees.

Machine-checked theorems (10 total -> **96 theorems across 8 modules**, zero `sorry`, zero custom axioms):
1. `forged_signature_always_rejected` — invalid publisher Ed25519 signature always rejected offline
2. `downgraded_theorem_count_always_rejected` — insufficient verified theorem count always rejected
3. `nonzero_mathlib_or_cedar_always_rejected` — impure Library cert (`zeroMathlib`/`zeroCedar` false) rejected
4. `expired_or_revoked_release_epoch_rejected` — anti-downgrade stale epoch or revoked `certId` rejected
5. `insufficient_witness_quorum_rejected` — sub-quorum witness cosignatures rejected
6. `mismatched_expected_digest_rejected` — cross-release digest mismatch blocks replay
7. `offline_verify_sound_and_complete` — exact iff characterization of offline verification admissibility
8. `releaseCertContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` runtime host)
9. `cacheTtlTuning_preserves_releaseCert_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingAntiDowngrade_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.ReleaseCertificateReplay

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Air-Gapped Signed Release Certificate Offline Verification -/

section OfflineReleaseCertificate

structure SignedReleaseCert (CertId Digest : Type) where
  certId : CertId
  attestationDigest : Digest
  releaseEpoch : Nat
  verifiedTheoremCount : Nat
  zeroMathlib : Bool
  zeroCedar : Bool
  publisherSigValid : Bool
  validDistinctWitnessCount : Nat
  deriving DecidableEq, Repr

structure OfflineVerifierPolicy (CertId Digest : Type) where
  expectedDigest : Digest
  minRequiredTheorems : Nat
  minAllowedEpoch : Nat
  minWitnessThreshold : Nat
  revokedCertIds : List CertId
  deriving DecidableEq, Repr

/-- Complete air-gapped offline release certificate verification predicate matching
    `verifyLibraryReleaseCertificateOffline` in `release-certificate-replay.ts`. -/
def verifyReleaseCertOffline [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest) : Bool :=
  cert.publisherSigValid &&
  cert.zeroMathlib &&
  cert.zeroCedar &&
  decide (cert.attestationDigest = pol.expectedDigest) &&
  decide (cert.verifiedTheoremCount ≥ pol.minRequiredTheorems) &&
  decide (cert.releaseEpoch ≥ pol.minAllowedEpoch) &&
  decide (cert.validDistinctWitnessCount ≥ pol.minWitnessThreshold) &&
  !(decide (cert.certId ∈ pol.revokedCertIds))

/-- **Theorem 1 (Publisher Ed25519 Forgery Refusal)**: Any forged or invalid publisher
    signature is unconditionally rejected offline. -/
theorem forged_signature_always_rejected [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest)
    (hBadSig : cert.publisherSigValid = false) :
    verifyReleaseCertOffline cert pol = false := by
  simp [verifyReleaseCertOffline, hBadSig]

/-- **Theorem 2 (Theorem-Count Downgrade Refusal)**: Any certificate attesting fewer
    theorems than `pol.minRequiredTheorems` is unconditionally rejected. -/
theorem downgraded_theorem_count_always_rejected [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest)
    (hLow : cert.verifiedTheoremCount < pol.minRequiredTheorems) :
    verifyReleaseCertOffline cert pol = false := by
  have hNotGe : ¬ (cert.verifiedTheoremCount ≥ pol.minRequiredTheorems) := by omega
  simp [verifyReleaseCertOffline, hNotGe]

/-- **Theorem 3 (Library Purity Enforcement Offline)**: Any certificate violating
    `zeroMathlib = true ∧ zeroCedar = true` is unconditionally rejected offline. -/
theorem nonzero_mathlib_or_cedar_always_rejected [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest)
    (hImpure : cert.zeroMathlib = false ∨ cert.zeroCedar = false) :
    verifyReleaseCertOffline cert pol = false := by
  rcases hImpure with h | h <;> simp [verifyReleaseCertOffline, h]

/-- **Theorem 4 (Anti-Downgrade Epoch & Emergency Revocation Fence)**: Any certificate
    older than `pol.minAllowedEpoch` OR listed in `pol.revokedCertIds` is rejected. -/
theorem expired_or_revoked_release_epoch_rejected [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest)
    (hBlocked : cert.releaseEpoch < pol.minAllowedEpoch ∨ cert.certId ∈ pol.revokedCertIds) :
    verifyReleaseCertOffline cert pol = false := by
  rcases hBlocked with hStale | hRev
  · have hNotGe : ¬ (cert.releaseEpoch ≥ pol.minAllowedEpoch) := by omega
    simp [verifyReleaseCertOffline, hNotGe]
  · simp [verifyReleaseCertOffline, hRev]

/-- **Theorem 5 (Threshold Witness Quorum Refusal)**: Any certificate carrying fewer than
    `pol.minWitnessThreshold` distinct valid witness cosignatures is rejected. -/
theorem insufficient_witness_quorum_rejected [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest)
    (hSubQuorum : cert.validDistinctWitnessCount < pol.minWitnessThreshold) :
    verifyReleaseCertOffline cert pol = false := by
  have hNotGe : ¬ (cert.validDistinctWitnessCount ≥ pol.minWitnessThreshold) := by omega
  simp [verifyReleaseCertOffline, hNotGe]

/-- **Theorem 6 (Cross-Release Digest Replay Refusal)**: A certificate signed for a
    different `attestationDigest ≠ pol.expectedDigest` is unconditionally rejected. -/
theorem mismatched_expected_digest_rejected [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest)
    (hDiff : cert.attestationDigest ≠ pol.expectedDigest) :
    verifyReleaseCertOffline cert pol = false := by
  simp [verifyReleaseCertOffline, hDiff]

/-- **Theorem 7 (Exact Sound & Complete Offline Verification Characterization)**:
    `verifyReleaseCertOffline cert pol = true` iff EVERY single cryptographic, purity,
    threshold-quorum, anti-downgrade, and non-revocation condition holds simultaneously. -/
theorem offline_verify_sound_and_complete [DecidableEq CertId] [DecidableEq Digest]
    (cert : SignedReleaseCert CertId Digest)
    (pol : OfflineVerifierPolicy CertId Digest) :
    verifyReleaseCertOffline cert pol = true ↔
      cert.publisherSigValid = true ∧
      cert.zeroMathlib = true ∧
      cert.zeroCedar = true ∧
      cert.attestationDigest = pol.expectedDigest ∧
      cert.verifiedTheoremCount ≥ pol.minRequiredTheorems ∧
      cert.releaseEpoch ≥ pol.minAllowedEpoch ∧
      cert.validDistinctWitnessCount ≥ pol.minWitnessThreshold ∧
      cert.certId ∉ pol.revokedCertIds := by
  simp [verifyReleaseCertOffline, and_assoc]

end OfflineReleaseCertificate

/-! ## Section 2: LeanPoo Two-Step Refinement (`Offline Cert -> Replay Fence -> cedar-poo-spec Runtime`) & `Core.Transport` -/

section LeanPooReleaseCertContract

structure ReleaseCertConfig where
  ed25519PublisherVerified : Bool
  witnessQuorumCosigned : Bool
  antiDowngradeEpochEnforced : Bool
  revocationListChecked : Bool
  purityFlagsVerified : Bool
  deriving DecidableEq, Repr

inductive ReleaseCertKey where
  | ed25519PublisherVerified
  | witnessQuorumCosigned
  | antiDowngradeEpochEnforced
  | revocationListChecked
  | purityFlagsVerified
  deriving DecidableEq, Repr

inductive ReleaseCertIssue where
  | publisherSigUnverified
  | witnessQuorumMissing
  | antiDowngradeDisabled
  | revocationCheckSkipped
  | purityFlagUnchecked
  deriving DecidableEq, Repr

private def releaseCertView : View ReleaseCertConfig ReleaseCertKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseReleaseCertContract :
    Contract ReleaseCertConfig ReleaseCertKey Unit ReleaseCertIssue where
  view := releaseCertView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.ed25519PublisherVerified then [] else [.rejected path .publisherSigUnverified]) ++
    (if cfg.witnessQuorumCosigned then [] else [.rejected path .witnessQuorumMissing]) ++
    (if cfg.purityFlagsVerified then [] else [.rejected path .purityFlagUnchecked])
  validInventory := Or.inl rfl

def offlineReplayFenceExt (cfg : ReleaseCertConfig) (path : List ReleaseCertKey) :
    List (Issue ReleaseCertKey ReleaseCertIssue) :=
  (if cfg.antiDowngradeEpochEnforced then [] else [.rejected path .antiDowngradeDisabled]) ++
  (if cfg.revocationListChecked then [] else [.rejected path .revocationCheckSkipped])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Runtime Host)**:
    Layering anti-downgrade/revocation replay fencing AND ANY downstream `cedar-poo-spec`
    runtime admission extension `hostRuntimeExt` onto `baseReleaseCertContract` monotonically
    preserves every offline certificate rejection. -/
theorem releaseCertContract_preserves_rejection
    (hostRuntimeExt : ReleaseCertConfig → List ReleaseCertKey →
      List (Issue ReleaseCertKey ReleaseCertIssue))
    (cfg : ReleaseCertConfig) (path : List ReleaseCertKey)
    (hRej : diagnose baseReleaseCertContract cfg path ≠ []) :
    diagnose (refine (refine baseReleaseCertContract offlineReplayFenceExt) hostRuntimeExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseReleaseCertContract offlineReplayFenceExt hostRuntimeExt cfg path hRej

inductive ReleaseCertProofKey where
  | ed25519PublisherVerified
  | witnessQuorumCosigned
  | antiDowngradeEpochEnforced
  | revocationListChecked
  | purityFlagsVerified
  | certCacheTtlSec
  deriving DecidableEq

abbrev ReleaseCertProofValue : ReleaseCertProofKey → Type
  | .ed25519PublisherVerified => Bool
  | .witnessQuorumCosigned => Bool
  | .antiDowngradeEpochEnforced => Bool
  | .revocationListChecked => Bool
  | .purityFlagsVerified => Bool
  | .certCacheTtlSec => Nat

def releaseCertObligation :
    LeanPoo.Proof.Obligation ReleaseCertProofKey ReleaseCertProofValue where
  dependencies :=
    [ .ed25519PublisherVerified
    , .witnessQuorumCosigned
    , .antiDowngradeEpochEnforced
    , .revocationListChecked
    , .purityFlagsVerified
    ]
  holds := fun s =>
    s .ed25519PublisherVerified = true ∧
    s .witnessQuorumCosigned = true ∧
    s .antiDowngradeEpochEnforced = true ∧
    s .revocationListChecked = true ∧
    s .purityFlagsVerified = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4, h5⟩
    exact ⟨(same .ed25519PublisherVerified (by simp)).symm.trans h1,
           (same .witnessQuorumCosigned (by simp)).symm.trans h2,
           (same .antiDowngradeEpochEnforced (by simp)).symm.trans h3,
           (same .revocationListChecked (by simp)).symm.trans h4,
           (same .purityFlagsVerified (by simp)).symm.trans h5⟩

def baselineReleaseCertSystem :
    LeanPoo.Proof.ProofObject ReleaseCertProofKey ReleaseCertProofValue where
  state := fun
    | .ed25519PublisherVerified => true
    | .witnessQuorumCosigned => true
    | .antiDowngradeEpochEnforced => true
    | .revocationListChecked => true
    | .purityFlagsVerified => true
    | .certCacheTtlSec => 300
  obligations := [releaseCertObligation]

theorem baselineReleaseCertCertified :
    LeanPoo.Proof.Certificate baselineReleaseCertSystem := by
  intro ob hMem
  have hEq : ob = releaseCertObligation := by simpa [baselineReleaseCertSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.certCacheTtlSec` transports the offline release-cert
    `LeanPoo.Proof.Certificate` in 1 line. -/
theorem cacheTtlTuning_preserves_releaseCert_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineReleaseCertSystem
        (LeanPoo.Proof.Patch.set .certCacheTtlSec 900)) :=
  close_single_set_untouched baselineReleaseCertSystem releaseCertObligation
    .certCacheTtlSec 900 rfl baselineReleaseCertCertified
    (by simp [releaseCertObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.antiDowngradeEpochEnforced` ALWAYS invalidates reuse. -/
theorem disablingAntiDowngrade_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected releaseCertObligation
        (LeanPoo.Proof.Patch.set .antiDowngradeEpochEnforced false) :=
  set_dependency_invalidates_unaffected releaseCertObligation
    .antiDowngradeEpochEnforced false (by simp [releaseCertObligation])

end LeanPooReleaseCertContract

end DeterministicEngineering.Engineering.ReleaseCertificateReplay
