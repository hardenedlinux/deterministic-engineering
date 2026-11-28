/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.SupplyChainProvenance

/-!
# LeanPoo Unbounded Confidential Compute / TEE Enclave Attestation & Measured Key-Release (`B15`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `SupplyChainProvenance` (all 13 prior modules, 146 theorems)
and adds 10 machine-checked confidential-compute / hardware TEE quote verification,
anti-rollback TCB floor, nonce freshness, and **`B14 -> B15` build-to-runtime chain-of-trust**
theorems — expanding the library to **14 modules and 156 machine-checked theorems**.

Machine-checked theorems (10 total -> **156 theorems across 14 modules**, zero `sorry`, zero custom axioms):
1. `debug_enclave_always_refused` — debug-enabled enclaves can NEVER receive production `M3` keys
2. `enclave_measurement_mismatch_always_refused` — running `MRENCLAVE`/`RTMR` must match expected `B14` artifact
3. `tcb_svn_rollback_always_refused` — vulnerable/downgraded firmware TCB SVN below floor is refused
4. `replayed_or_mismatched_nonce_always_refused` — stale or mismatched anti-replay challenge nonce is refused
5. `forged_or_revoked_hardware_quote_refused` — forged hardware root signature or revoked platform is refused
6. `b14_to_b15_end_to_end_chain_binds_running_binary` — composes `B14` reproducible build with `B15` TEE quote
7. `enclave_key_release_sound_and_complete` — exact iff characterization of measured key-release admission
8. `enclaveAttestationContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Key-Release host)
9. `quoteCacheTtlTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingDebugLockout_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.ConfidentialEnclaveAttestation

open DeterministicEngineering.Core.Transport
open DeterministicEngineering.Engineering.SupplyChainProvenance
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Hardware TEE Enclave Quote Verification & Measured Key-Release (`B15`) -/

section EnclaveAttestationGate

structure EnclaveQuoteClaim where
  measuredEnclaveDigest : Nat
  tcbSvn : Nat
  challengeNonce : Nat
  debugModeDisabled : Bool
  hardwareSignatureValid : Bool
  platformRevoked : Bool
  deriving DecidableEq, Repr

structure EnclaveKeyReleasePolicy where
  expectedArtifactDigest : Nat
  minRequiredTcbSvn : Nat
  expectedChallengeNonce : Nat
  deriving DecidableEq, Repr

/-- Deterministic zero-trust TEE measured key-release admission predicate. -/
def enclaveKeyReleaseAdmitted
    (policy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim) : Bool :=
  decide (quote.measuredEnclaveDigest = policy.expectedArtifactDigest) &&
  decide (policy.minRequiredTcbSvn ≤ quote.tcbSvn) &&
  decide (quote.challengeNonce = policy.expectedChallengeNonce) &&
  quote.debugModeDisabled &&
  quote.hardwareSignatureValid &&
  !quote.platformRevoked

/-- **Theorem 1 (Production Debug-Mode Lockout)**: Any enclave with `debugModeDisabled = false`
    is unconditionally refused `M3` key release. -/
theorem debug_enclave_always_refused
    (policy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim)
    (hDebug : quote.debugModeDisabled = false) :
    enclaveKeyReleaseAdmitted policy quote = false := by
  simp [enclaveKeyReleaseAdmitted, hDebug]

/-- **Theorem 2 (Measured Binary Pinning)**: Any enclave whose hardware measurement differs
    from the expected `B14` reproducible artifact digest is unconditionally refused. -/
theorem enclave_measurement_mismatch_always_refused
    (policy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim)
    (hMis : quote.measuredEnclaveDigest ≠ policy.expectedArtifactDigest) :
    enclaveKeyReleaseAdmitted policy quote = false := by
  simp [enclaveKeyReleaseAdmitted, hMis]

/-- **Theorem 3 (Hardware TCB Security-Version Floor / Anti-Rollback)**: Any platform with
    `tcbSvn < minRequiredTcbSvn` is unconditionally refused. -/
theorem tcb_svn_rollback_always_refused
    (policy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim)
    (hOld : quote.tcbSvn < policy.minRequiredTcbSvn) :
    enclaveKeyReleaseAdmitted policy quote = false := by
  have hNotGe : ¬ (policy.minRequiredTcbSvn ≤ quote.tcbSvn) := by omega
  simp [enclaveKeyReleaseAdmitted, hNotGe]

/-- **Theorem 4 (Anti-Replay Challenge Nonce Binding)**: Any quote whose nonce does not match
    the verifier's fresh challenge nonce is unconditionally refused. -/
theorem replayed_or_mismatched_nonce_always_refused
    (policy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim)
    (hNonce : quote.challengeNonce ≠ policy.expectedChallengeNonce) :
    enclaveKeyReleaseAdmitted policy quote = false := by
  simp [enclaveKeyReleaseAdmitted, hNonce]

/-- **Theorem 5 (Hardware Root Signature & Platform Non-Revocation)**: A forged hardware
    attestation signature OR a revoked platform identity unconditionally causes refusal. -/
theorem forged_or_revoked_hardware_quote_refused
    (policy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim)
    (hBad : quote.hardwareSignatureValid = false ∨ quote.platformRevoked = true) :
    enclaveKeyReleaseAdmitted policy quote = false := by
  rcases hBad with hSig | hRev
  · simp [enclaveKeyReleaseAdmitted, hSig]
  · simp [enclaveKeyReleaseAdmitted, hRev]

/-- **Theorem 6 (End-to-End `B14 -> B15` Supply-Chain-to-Hardware Binding)**:
    If a `B14` hermetic reproducible build is admitted AND a `B15` TEE quote bound to that
    artifact digest is admitted, then the running hardware enclave measurement equals the
    independent second builder's reproduced digest AND debug mode is locked out. -/
theorem b14_to_b15_end_to_end_chain_binds_running_binary
    (scPolicy : SupplyChainPolicy) (scClaim : BuildProvenanceClaim)
    (teePolicy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim)
    (hBuild : buildProvenanceAdmitted scPolicy scClaim = true)
    (hTee : enclaveKeyReleaseAdmitted teePolicy quote = true)
    (hBind : teePolicy.expectedArtifactDigest = scClaim.artifactDigest) :
    quote.measuredEnclaveDigest = scClaim.reproducedDigest ∧
    quote.debugModeDisabled = true := by
  have hB := (hermetic_provenance_admit_sound_and_complete scPolicy scClaim).mp hBuild
  unfold enclaveKeyReleaseAdmitted at hTee
  simp [Bool.and_eq_true] at hTee
  rcases hB with ⟨_, _, hRepro, _, _, _, _⟩
  rcases hTee with ⟨⟨⟨⟨⟨hMeas, _⟩, _⟩, hNoDebug⟩, _⟩, _⟩
  exact ⟨hMeas.trans (hBind.trans hRepro.symm), hNoDebug⟩

/-- **Theorem 7 (Soundness & Completeness of Measured Key-Release Admission)**:
    `enclaveKeyReleaseAdmitted` holds iff measurement, TCB SVN floor, challenge nonce,
    debug-mode lockout, hardware signature, and non-revocation all hold simultaneously. -/
theorem enclave_key_release_sound_and_complete
    (policy : EnclaveKeyReleasePolicy) (quote : EnclaveQuoteClaim) :
    enclaveKeyReleaseAdmitted policy quote = true ↔
      quote.measuredEnclaveDigest = policy.expectedArtifactDigest ∧
      policy.minRequiredTcbSvn ≤ quote.tcbSvn ∧
      quote.challengeNonce = policy.expectedChallengeNonce ∧
      quote.debugModeDisabled = true ∧
      quote.hardwareSignatureValid = true ∧
      quote.platformRevoked = false := by
  unfold enclaveKeyReleaseAdmitted
  simp [Bool.and_eq_true, and_assoc]

end EnclaveAttestationGate

/-! ## Section 2: LeanPoo Two-Step Refinement (`TEE Attestation -> TCB Floor -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooEnclaveContract

structure EnclavePolicyConfig where
  debugModeLockoutEnforced : Bool
  measurementPinningEnforced : Bool
  tcbSvnFloorEnforced : Bool
  freshNonceChallengeEnforced : Bool
  deriving DecidableEq, Repr

inductive EnclavePolicyKey where
  | debugModeLockoutEnforced
  | measurementPinningEnforced
  | tcbSvnFloorEnforced
  | freshNonceChallengeEnforced
  deriving DecidableEq, Repr

inductive EnclavePolicyIssue where
  | debugEnclaveKeyReleaseAllowed
  | unmeasuredBinaryAllowed
  | tcbRollbackAllowed
  | quoteReplayAllowed
  deriving DecidableEq, Repr

private def enclaveView : View EnclavePolicyConfig EnclavePolicyKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseEnclaveContract :
    Contract EnclavePolicyConfig EnclavePolicyKey Unit EnclavePolicyIssue where
  view := enclaveView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.debugModeLockoutEnforced then [] else [.rejected path .debugEnclaveKeyReleaseAllowed]) ++
    (if cfg.measurementPinningEnforced then [] else [.rejected path .unmeasuredBinaryAllowed])
  validInventory := Or.inl rfl

def tcbAntiRollbackExt (cfg : EnclavePolicyConfig) (path : List EnclavePolicyKey) :
    List (Issue EnclavePolicyKey EnclavePolicyIssue) :=
  (if cfg.tcbSvnFloorEnforced then [] else [.rejected path .tcbRollbackAllowed]) ++
  (if cfg.freshNonceChallengeEnforced then [] else [.rejected path .quoteReplayAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Key-Release Host)**:
    Layering TCB anti-rollback/fresh-nonce fencing AND ANY downstream `cedar-poo-spec`
    key-release authorization extension `hostKeyExt` onto `baseEnclaveContract`
    monotonically preserves every enclave attestation rejection. -/
theorem enclaveAttestationContract_preserves_rejection
    (hostKeyExt : EnclavePolicyConfig → List EnclavePolicyKey →
      List (Issue EnclavePolicyKey EnclavePolicyIssue))
    (cfg : EnclavePolicyConfig) (path : List EnclavePolicyKey)
    (hRej : diagnose baseEnclaveContract cfg path ≠ []) :
    diagnose (refine (refine baseEnclaveContract tcbAntiRollbackExt) hostKeyExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseEnclaveContract tcbAntiRollbackExt hostKeyExt cfg path hRej

inductive EnclaveProofKey where
  | debugModeLockoutEnforced
  | measurementPinningEnforced
  | tcbSvnFloorEnforced
  | freshNonceChallengeEnforced
  | quoteCacheTtlSeconds
  deriving DecidableEq

abbrev EnclaveProofValue : EnclaveProofKey → Type
  | .debugModeLockoutEnforced => Bool
  | .measurementPinningEnforced => Bool
  | .tcbSvnFloorEnforced => Bool
  | .freshNonceChallengeEnforced => Bool
  | .quoteCacheTtlSeconds => Nat

def enclaveObligation :
    LeanPoo.Proof.Obligation EnclaveProofKey EnclaveProofValue where
  dependencies :=
    [ .debugModeLockoutEnforced
    , .measurementPinningEnforced
    , .tcbSvnFloorEnforced
    , .freshNonceChallengeEnforced
    ]
  holds := fun s =>
    s .debugModeLockoutEnforced = true ∧
    s .measurementPinningEnforced = true ∧
    s .tcbSvnFloorEnforced = true ∧
    s .freshNonceChallengeEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .debugModeLockoutEnforced (by simp)).symm.trans h1,
           (same .measurementPinningEnforced (by simp)).symm.trans h2,
           (same .tcbSvnFloorEnforced (by simp)).symm.trans h3,
           (same .freshNonceChallengeEnforced (by simp)).symm.trans h4⟩

def baselineEnclaveSystem :
    LeanPoo.Proof.ProofObject EnclaveProofKey EnclaveProofValue where
  state := fun
    | .debugModeLockoutEnforced => true
    | .measurementPinningEnforced => true
    | .tcbSvnFloorEnforced => true
    | .freshNonceChallengeEnforced => true
    | .quoteCacheTtlSeconds => 60
  obligations := [enclaveObligation]

theorem baselineEnclaveCertified :
    LeanPoo.Proof.Certificate baselineEnclaveSystem := by
  intro ob hMem
  have hEq : ob = enclaveObligation := by simpa [baselineEnclaveSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.quoteCacheTtlSeconds` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem quoteCacheTtlTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineEnclaveSystem
        (LeanPoo.Proof.Patch.set .quoteCacheTtlSeconds 300)) :=
  close_single_set_untouched baselineEnclaveSystem enclaveObligation
    .quoteCacheTtlSeconds 300 rfl baselineEnclaveCertified
    (by simp [enclaveObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.debugModeLockoutEnforced` ALWAYS invalidates reuse. -/
theorem disablingDebugLockout_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected enclaveObligation
        (LeanPoo.Proof.Patch.set .debugModeLockoutEnforced false) :=
  set_dependency_invalidates_unaffected enclaveObligation
    .debugModeLockoutEnforced false (by simp [enclaveObligation])

end LeanPooEnclaveContract

end DeterministicEngineering.Engineering.ConfidentialEnclaveAttestation
