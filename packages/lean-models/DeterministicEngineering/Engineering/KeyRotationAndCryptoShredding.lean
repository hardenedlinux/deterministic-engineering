/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.ConfidentialEnclaveAttestation

/-!
# LeanPoo Unbounded Zero-Downtime AEAD Key Rotation & Cryptographic Erasure (`B16`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `ConfidentialEnclaveAttestation` (all 14 prior modules, 156 theorems)
and adds 10 machine-checked theorems resolving the immutable-Merkle-log vs. GDPR
right-to-erasure paradox via **forward-secure AEAD key rotation, lossless envelope
re-wrapping, and cryptographic erasure (crypto-shredding)** — expanding the library
to **15 modules and 166 machine-checked theorems**.

Machine-checked theorems (10 total -> **166 theorems across 15 modules**, zero `sorry`, zero custom axioms):
1. `retired_key_epoch_cannot_encrypt_new_writes` — new writes under `writeEpoch < activeEpoch` are refused
2. `shredded_key_epoch_permanently_unreadable` — any decrypt under a crypto-shredded epoch is refused
3. `shredded_key_cannot_encrypt_or_rewrap` — shredded epochs can never encrypt or accept re-wraps
4. `rewrap_must_preserve_plaintext_digest` — re-wrapping cannot silently mutate plaintext digest
5. `rewrap_must_strictly_advance_epoch` — re-wrapping to an equal or older epoch is refused
6. `aad_tenant_or_epoch_mismatch_refused` — decrypting with mismatched `(tenantId, keyEpoch)` AAD is refused
7. `crypto_shred_preserves_merkle_root_integrity` — shredding makes data unreadable while preserving `M1` audit root
8. `keyRotationContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Data-Erasure host)
9. `rewrapBatchSizeTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingCryptoShredTombstone_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.KeyRotationAndCryptoShredding

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Multi-Epoch AEAD Key Rotation, Re-Wrapping & Crypto-Shredding (`B16`) -/

section KeyRotationLifecycle

structure KeyRingState where
  tenantId : Nat
  activeEpoch : Nat
  shreddedEpochs : List Nat
  merkleAuditRootIntact : Bool
  deriving DecidableEq, Repr

structure AeadEnvelopeMeta where
  aadTenantId : Nat
  aadKeyEpoch : Nat
  plaintextDigest : Nat
  deriving DecidableEq, Repr

/-- New writes MUST target `activeEpoch` and that epoch MUST NOT be crypto-shredded. -/
def encryptAdmitted (ring : KeyRingState) (writeEpoch : Nat) : Bool :=
  decide (writeEpoch = ring.activeEpoch) &&
  !ring.shreddedEpochs.contains writeEpoch

/-- Decryption MUST bind `(tenantId, keyEpoch)` AAD and refuse any crypto-shredded epoch. -/
def decryptAdmitted
    (ring : KeyRingState) (env : AeadEnvelopeMeta) (requestedEpoch : Nat) : Bool :=
  decide (env.aadTenantId = ring.tenantId) &&
  decide (env.aadKeyEpoch = requestedEpoch) &&
  !ring.shreddedEpochs.contains requestedEpoch

/-- Lossless envelope re-wrapping MUST read from a non-shredded source epoch, strictly advance
    to `activeEpoch`, and preserve the exact plaintext SHA-256 digest. -/
def rewrapAdmitted
    (ring : KeyRingState) (srcEnv : AeadEnvelopeMeta)
    (targetEpoch : Nat) (rewrappedPlaintextDigest : Nat) : Bool :=
  decryptAdmitted ring srcEnv srcEnv.aadKeyEpoch &&
  encryptAdmitted ring targetEpoch &&
  decide (srcEnv.aadKeyEpoch < targetEpoch) &&
  decide (rewrappedPlaintextDigest = srcEnv.plaintextDigest)

/-- Cryptographic erasure records epoch `k` in `shreddedEpochs` while leaving the immutable
    `M1` Merkle audit root intact (`merkleAuditRootIntact` preserved verbatim). -/
def applyCryptoShred (ring : KeyRingState) (epochToShred : Nat) : KeyRingState :=
  { ring with shreddedEpochs := epochToShred :: ring.shreddedEpochs }

/-- **Theorem 1 (No Stale-Epoch Encryption)**: Encrypting a new `M1` blob under any retired
    epoch (`writeEpoch < activeEpoch`) is unconditionally refused. -/
theorem retired_key_epoch_cannot_encrypt_new_writes
    (ring : KeyRingState) (writeEpoch : Nat)
    (hOld : writeEpoch < ring.activeEpoch) :
    encryptAdmitted ring writeEpoch = false := by
  have hNe : writeEpoch ≠ ring.activeEpoch := by omega
  simp [encryptAdmitted, hNe]

/-- **Theorem 2 (Permanent Cryptographic Erasure)**: Any decrypt attempt targeting a
    crypto-shredded epoch (`shreddedEpochs.contains epoch = true`) is unconditionally refused. -/
theorem shredded_key_epoch_permanently_unreadable
    (ring : KeyRingState) (env : AeadEnvelopeMeta) (epoch : Nat)
    (hShred : ring.shreddedEpochs.contains epoch = true) :
    decryptAdmitted ring env epoch = false := by
  unfold decryptAdmitted
  rw [hShred]
  simp

/-- **Theorem 3 (Shredded Key Cannot Encrypt or Accept Re-Wraps)**: Any crypto-shredded epoch
    is unconditionally refused for both new encryption and re-wrap target writes. -/
theorem shredded_key_cannot_encrypt_or_rewrap
    (ring : KeyRingState) (srcEnv : AeadEnvelopeMeta) (epoch : Nat) (dig : Nat)
    (hShred : ring.shreddedEpochs.contains epoch = true) :
    encryptAdmitted ring epoch = false ∧
    rewrapAdmitted ring srcEnv epoch dig = false := by
  have hEnc : encryptAdmitted ring epoch = false := by
    unfold encryptAdmitted
    rw [hShred]
    simp
  refine ⟨hEnc, ?_⟩
  simp [rewrapAdmitted, hEnc]

/-- **Theorem 4 (Lossless Re-Wrapping Digest Preservation)**: Re-wrapping an envelope with a
    mutated plaintext digest (`rewrappedPlaintextDigest ≠ srcEnv.plaintextDigest`) is refused. -/
theorem rewrap_must_preserve_plaintext_digest
    (ring : KeyRingState) (srcEnv : AeadEnvelopeMeta) (targetEpoch dig : Nat)
    (hDiff : dig ≠ srcEnv.plaintextDigest) :
    rewrapAdmitted ring srcEnv targetEpoch dig = false := by
  simp [rewrapAdmitted, hDiff]

/-- **Theorem 5 (Strictly Monotonic Epoch Advancement on Re-Wrap)**: Re-wrapping to an equal
    or older epoch (`targetEpoch ≤ srcEnv.aadKeyEpoch`) is unconditionally refused. -/
theorem rewrap_must_strictly_advance_epoch
    (ring : KeyRingState) (srcEnv : AeadEnvelopeMeta) (targetEpoch dig : Nat)
    (hNoAdv : targetEpoch ≤ srcEnv.aadKeyEpoch) :
    rewrapAdmitted ring srcEnv targetEpoch dig = false := by
  have hNotLt : ¬ (srcEnv.aadKeyEpoch < targetEpoch) := by omega
  simp [rewrapAdmitted, hNotLt]

/-- **Theorem 6 (Cross-Tenant / Cross-Epoch AAD Transplant Refusal)**: Decryption fails closed
    whenever either `aadTenantId ≠ ring.tenantId` OR `aadKeyEpoch ≠ requestedEpoch`. -/
theorem aad_tenant_or_epoch_mismatch_refused
    (ring : KeyRingState) (env : AeadEnvelopeMeta) (requestedEpoch : Nat)
    (hMis : env.aadTenantId ≠ ring.tenantId ∨ env.aadKeyEpoch ≠ requestedEpoch) :
    decryptAdmitted ring env requestedEpoch = false := by
  rcases hMis with hTenant | hEp
  · simp [decryptAdmitted, hTenant]
  · simp [decryptAdmitted, hEp]

/-- **Theorem 7 (GDPR Right-to-Erasure vs. Immutable Merkle Audit Log Resolution)**:
    Applying `applyCryptoShred ring k` renders epoch `k` permanently unreadable
    (`decryptAdmitted = false`) while preserving `merkleAuditRootIntact = true`. -/
theorem crypto_shred_preserves_merkle_root_integrity
    (ring : KeyRingState) (env : AeadEnvelopeMeta) (k : Nat)
    (hIntact : ring.merkleAuditRootIntact = true) :
    decryptAdmitted (applyCryptoShred ring k) env k = false ∧
    (applyCryptoShred ring k).merkleAuditRootIntact = true := by
  refine ⟨?_, by simp [applyCryptoShred, hIntact]⟩
  unfold decryptAdmitted applyCryptoShred
  simp

end KeyRotationLifecycle

/-! ## Section 2: LeanPoo Two-Step Refinement (`Key Rotation -> Crypto-Shredding -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooKeyRotationContract

structure KeyRotationConfig where
  activeEpochWriteOnlyEnforced : Bool
  losslessRewrapDigestVerified : Bool
  cryptoShredTombstoneEnforced : Bool
  physicalKeyZeroizationEnforced : Bool
  deriving DecidableEq, Repr

inductive KeyRotationKey where
  | activeEpochWriteOnlyEnforced
  | losslessRewrapDigestVerified
  | cryptoShredTombstoneEnforced
  | physicalKeyZeroizationEnforced
  deriving DecidableEq, Repr

inductive KeyRotationIssue where
  | staleEpochWriteAllowed
  | silentRewrapMutationAllowed
  | unshreddedErasureAllowed
  | lingeringKeyBytesAllowed
  deriving DecidableEq, Repr

private def keyRotationView : View KeyRotationConfig KeyRotationKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseKeyRotationContract :
    Contract KeyRotationConfig KeyRotationKey Unit KeyRotationIssue where
  view := keyRotationView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.activeEpochWriteOnlyEnforced then [] else [.rejected path .staleEpochWriteAllowed]) ++
    (if cfg.losslessRewrapDigestVerified then [] else [.rejected path .silentRewrapMutationAllowed])
  validInventory := Or.inl rfl

def cryptoShreddingExt (cfg : KeyRotationConfig) (path : List KeyRotationKey) :
    List (Issue KeyRotationKey KeyRotationIssue) :=
  (if cfg.cryptoShredTombstoneEnforced then [] else [.rejected path .unshreddedErasureAllowed]) ++
  (if cfg.physicalKeyZeroizationEnforced then [] else [.rejected path .lingeringKeyBytesAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Data-Erasure Host)**:
    Layering crypto-shredding/zeroization AND ANY downstream `cedar-poo-spec`
    data-lifecycle extension `hostErasureExt` onto `baseKeyRotationContract`
    monotonically preserves every key-rotation rejection. -/
theorem keyRotationContract_preserves_rejection
    (hostErasureExt : KeyRotationConfig → List KeyRotationKey →
      List (Issue KeyRotationKey KeyRotationIssue))
    (cfg : KeyRotationConfig) (path : List KeyRotationKey)
    (hRej : diagnose baseKeyRotationContract cfg path ≠ []) :
    diagnose (refine (refine baseKeyRotationContract cryptoShreddingExt) hostErasureExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseKeyRotationContract cryptoShreddingExt hostErasureExt cfg path hRej

inductive KeyRotationProofKey where
  | activeEpochWriteOnlyEnforced
  | losslessRewrapDigestVerified
  | cryptoShredTombstoneEnforced
  | physicalKeyZeroizationEnforced
  | rewrapBatchSize
  deriving DecidableEq

abbrev KeyRotationProofValue : KeyRotationProofKey → Type
  | .activeEpochWriteOnlyEnforced => Bool
  | .losslessRewrapDigestVerified => Bool
  | .cryptoShredTombstoneEnforced => Bool
  | .physicalKeyZeroizationEnforced => Bool
  | .rewrapBatchSize => Nat

def keyRotationObligation :
    LeanPoo.Proof.Obligation KeyRotationProofKey KeyRotationProofValue where
  dependencies :=
    [ .activeEpochWriteOnlyEnforced
    , .losslessRewrapDigestVerified
    , .cryptoShredTombstoneEnforced
    , .physicalKeyZeroizationEnforced
    ]
  holds := fun s =>
    s .activeEpochWriteOnlyEnforced = true ∧
    s .losslessRewrapDigestVerified = true ∧
    s .cryptoShredTombstoneEnforced = true ∧
    s .physicalKeyZeroizationEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .activeEpochWriteOnlyEnforced (by simp)).symm.trans h1,
           (same .losslessRewrapDigestVerified (by simp)).symm.trans h2,
           (same .cryptoShredTombstoneEnforced (by simp)).symm.trans h3,
           (same .physicalKeyZeroizationEnforced (by simp)).symm.trans h4⟩

def baselineKeyRotationSystem :
    LeanPoo.Proof.ProofObject KeyRotationProofKey KeyRotationProofValue where
  state := fun
    | .activeEpochWriteOnlyEnforced => true
    | .losslessRewrapDigestVerified => true
    | .cryptoShredTombstoneEnforced => true
    | .physicalKeyZeroizationEnforced => true
    | .rewrapBatchSize => 128
  obligations := [keyRotationObligation]

theorem baselineKeyRotationCertified :
    LeanPoo.Proof.Certificate baselineKeyRotationSystem := by
  intro ob hMem
  have hEq : ob = keyRotationObligation := by simpa [baselineKeyRotationSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.rewrapBatchSize` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem rewrapBatchSizeTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineKeyRotationSystem
        (LeanPoo.Proof.Patch.set .rewrapBatchSize 512)) :=
  close_single_set_untouched baselineKeyRotationSystem keyRotationObligation
    .rewrapBatchSize 512 rfl baselineKeyRotationCertified
    (by simp [keyRotationObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.cryptoShredTombstoneEnforced` ALWAYS invalidates reuse. -/
theorem disablingCryptoShredTombstone_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected keyRotationObligation
        (LeanPoo.Proof.Patch.set .cryptoShredTombstoneEnforced false) :=
  set_dependency_invalidates_unaffected keyRotationObligation
    .cryptoShredTombstoneEnforced false (by simp [keyRotationObligation])

end LeanPooKeyRotationContract

end DeterministicEngineering.Engineering.KeyRotationAndCryptoShredding
