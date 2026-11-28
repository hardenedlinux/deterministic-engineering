/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM38: Adversarial (`ADV-L4`) Defense Pillar Cryptographic & State-Machine Integrity Confinement

Standalone objectified `LeanPoo` module (56th committed Lean module, zero edits to
`Core/Stability.lean`) formalizing five real `ADV-L4` boundary defects discovered
in `marlin-agent-kernel`'s unified `B9`/`B14`/`B16`/`B18`/`B20`/`B21` defense pillars:

1. **B16 Key Rotation & Crypto-Shredding Epoch Confinement (`key_rotation_shredding.rs`)**:
   `shred_retired_epoch` only checked `epoch == self.active_epoch`, allowing callers
   to tombstone future epochs (`epoch > active_epoch`) or epoch `0` and permanently
   DoS `rotate_to_epoch`; `admit_rewrap` admitted non-existent `from_epoch == 0`;
   `rotate_to_epoch` used `saturating_add(1)` instead of `checked_add(1)`.
2. **B18 ZK Selective-Disclosure Canonical Secret Filtering & Challenge Freshness (`zk_selective_disclosure.rs`)**:
   `admit_disclosure` checked `forbidden_secret_fields.contains(field)` without
   trim/ASCII case-folding (allowing `"RAW_PII"` or `" raw_pii "` to leak `"raw_pii"`),
   and `issue_challenge_nonce` lacked `consumed_challenges` tracking and blank-nonce
   refusal, permitting verifier challenge nonce replay.
3. **B14 Supply-Chain Canonical 2-Builder Parity, Immutable Pinning & Anti-Replay (`supply_chain_provenance.rs`)**:
   `admit_build` compared `builder_a_id == builder_b_id` without trim/case-folding
   (single-builder spoofing), `register_pinned_dependency` silently overwrote existing
   pins and admitted CVE-tombstoned or blank coordinates, and `admit_build` admitted
   duplicate dependency entries and replayed `release_id` values.
4. **B20 Federated Org Treaty Freeze Preservation, Monotonic Epochs & Anti-Self-Spoofing (`federated_org_reciprocity.rs`)**:
   `register_treaty` blindly overwrote existing treaties, wiping an active
   `dispute_freeze_active = true` without calling `resolve_dispute_freeze` and
   allowing `treaty_epoch` rollback, while org identity checks lacked trim/case-folding.
5. **B9 RFC 6962 Empty-Head Verification & B21 Non-Duplicating Shard Merkle Root (`transparency_log.rs`, `model_weight_attestation.rs`)**:
   `verify_tree_head_progression` accepted forged non-empty root hashes when
   `prev.tree_size == 0` and omitted proof size checks on equal/zero branches, while
   `compute_shard_merkle_root` duplicated odd trailing nodes (`CVE-2012-2459`
   second-preimage malleability: `root([A, B, C]) == root([A, B, C, C])`).
-/

namespace DeterministicEngineering.Engineering.DefensePillarCryptoStateConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- B16 retired-epoch shredding admission: strictly `0 < epoch < activeEpoch`. -/
def b16ShredEpochAdmitted (epoch activeEpoch : Nat) : Bool :=
  (0 < epoch) && (epoch < activeEpoch)

/-- B16 ciphertext rewrap admission: `fromEpoch` must be committed (`0 < fromEpoch < activeEpoch`) and `toEpoch == activeEpoch`. -/
def b16RewrapAdmitted (fromEpoch toEpoch activeEpoch : Nat) (fromCommitted : Bool) : Bool :=
  (0 < fromEpoch) && (fromEpoch < toEpoch) && (toEpoch == activeEpoch) && fromCommitted

/-- B18 selective disclosure admission: canonical secret overlap must be absent and challenge non-blank and unconsumed. -/
def b18DisclosureAdmitted
    (canonicalSecretOverlap : Bool) (nonceNonBlank : Bool) (noncePreviouslyConsumed : Bool) : Bool :=
  (!canonicalSecretOverlap) && nonceNonBlank && (!noncePreviouslyConsumed)

/-- B14 supply-chain admission: canonical builders distinct, pin immutable/CVE-free, deps unique, release fresh. -/
def b14BuildAdmitted
    (canonicalBuildersDistinct : Bool)
    (pinConflictOrCve : Bool)
    (duplicateDep : Bool)
    (releaseReplayed : Bool) : Bool :=
  canonicalBuildersDistinct && (!pinConflictOrCve) && (!duplicateDep) && (!releaseReplayed)

/-- B20 treaty registration/update admission: canonical orgs distinct, existing freeze preserved, epoch non-decreasing. -/
def b20TreatyUpdateAdmitted
    (canonicalOrgsDistinct : Bool)
    (existingFreezeActive : Bool)
    (newFreezeActive : Bool)
    (existingEpoch newEpoch : Nat) : Bool :=
  canonicalOrgsDistinct &&
  ((!existingFreezeActive) || newFreezeActive) &&
  (existingEpoch ≤ newEpoch)

/-- B9/B21 Merkle & tree-head admission: empty-tree root matches `SHA256("")`, proof sizes match, and odd nodes are never duplicated. -/
def b9B21MerkleAdmitted
    (prevSize : Nat)
    (prevRootIsEmptyHash : Bool)
    (proofSizesMatch : Bool)
    (oddLeafDuplicated : Bool) : Bool :=
  ((prevSize != 0) || prevRootIsEmptyHash) && proofSizesMatch && (!oddLeafDuplicated)

/-- Security posture of Marlin defense-pillar cryptographic and state-machine boundaries. -/
structure DefensePillarCryptoStateConfig where
  enforcesB16RetiredOnlyShredAndLiveRewrap : Bool
  enforcesB18CanonicalSecretAndFreshNonce : Bool
  enforcesB14CanonicalBuildersAndImmutablePins : Bool
  enforcesB20FreezePreservationAndMonotonicEpoch : Bool
  enforcesB9B21MerkleAndEmptyHeadSoundness : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a configuration satisfies strict SM38 confinement. -/
def strictSm38Admitted (c : DefensePillarCryptoStateConfig) : Bool :=
  c.enforcesB16RetiredOnlyShredAndLiveRewrap &&
  c.enforcesB18CanonicalSecretAndFreshNonce &&
  c.enforcesB14CanonicalBuildersAndImmutablePins &&
  c.enforcesB20FreezePreservationAndMonotonicEpoch &&
  c.enforcesB9B21MerkleAndEmptyHeadSoundness &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM38 hostile exploit classes remain reachable. -/
def anySm38ExploitReachable (c : DefensePillarCryptoStateConfig) : Bool :=
  !c.enforcesB16RetiredOnlyShredAndLiveRewrap ||
  !c.enforcesB18CanonicalSecretAndFreshNonce ||
  !c.enforcesB14CanonicalBuildersAndImmutablePins ||
  !c.enforcesB20FreezePreservationAndMonotonicEpoch ||
  !c.enforcesB9B21MerkleAndEmptyHeadSoundness

/-- Canonical hardened SM38 posture. -/
def hardenedSm38Config : DefensePillarCryptoStateConfig :=
  { enforcesB16RetiredOnlyShredAndLiveRewrap := true
    enforcesB18CanonicalSecretAndFreshNonce := true
    enforcesB14CanonicalBuildersAndImmutablePins := true
    enforcesB20FreezePreservationAndMonotonicEpoch := true
    enforcesB9B21MerkleAndEmptyHeadSoundness := true
    pressureTier := .l4HostileAttack }

def defectiveB16Config : DefensePillarCryptoStateConfig :=
  { hardenedSm38Config with enforcesB16RetiredOnlyShredAndLiveRewrap := false }

def defectiveB18Config : DefensePillarCryptoStateConfig :=
  { hardenedSm38Config with enforcesB18CanonicalSecretAndFreshNonce := false }

def defectiveB14Config : DefensePillarCryptoStateConfig :=
  { hardenedSm38Config with enforcesB14CanonicalBuildersAndImmutablePins := false }

def defectiveB20Config : DefensePillarCryptoStateConfig :=
  { hardenedSm38Config with enforcesB20FreezePreservationAndMonotonicEpoch := false }

def defectiveB9B21Config : DefensePillarCryptoStateConfig :=
  { hardenedSm38Config with enforcesB9B21MerkleAndEmptyHeadSoundness := false }

def defectiveGentleTierConfig : DefensePillarCryptoStateConfig :=
  { hardenedSm38Config with pressureTier := .l1Gentle }

/-- Theorem 1: B16 shredding fails closed on epoch 0, active epoch, and any future epoch; rewrap fails closed on epoch 0 or uncommitted source epochs. -/
theorem sm38_b16_epoch_shred_and_rewrap_fail_closed (active delta : Nat) :
    b16ShredEpochAdmitted 0 active = false ∧
    b16ShredEpochAdmitted active active = false ∧
    b16ShredEpochAdmitted (active + delta + 1) active = false ∧
    b16RewrapAdmitted 0 active active true = false ∧
    b16RewrapAdmitted 1 2 2 false = false ∧
    b16ShredEpochAdmitted 1 2 = true ∧
    b16RewrapAdmitted 1 2 2 true = true := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [b16ShredEpochAdmitted]
  · simp [b16ShredEpochAdmitted]
  · simp [b16ShredEpochAdmitted]; omega
  · simp [b16RewrapAdmitted]
  · simp [b16RewrapAdmitted]
  · decide
  · decide

/-- Theorem 2: B18 disclosure fails closed on canonical case/whitespace secret overlap, blank challenge nonce, or previously consumed challenge nonce replay. -/
theorem sm38_b18_zk_secret_and_nonce_replay_fail_closed (nb nc ov : Bool) :
    b18DisclosureAdmitted true nb nc = false ∧
    b18DisclosureAdmitted ov false nc = false ∧
    b18DisclosureAdmitted ov nb true = false ∧
    b18DisclosureAdmitted false true false = true := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · simp [b18DisclosureAdmitted]
  · simp [b18DisclosureAdmitted]
  · simp [b18DisclosureAdmitted]
  · decide

/-- Theorem 3: B14 builder spoofing/pin conflict/duplicate dep/release replay and B20 freeze wipeout/epoch rollback/self-reciprocity fail closed. -/
theorem sm38_b14_b20_builder_pin_and_treaty_fail_closed (epoch delta : Nat) :
    b14BuildAdmitted false false false false = false ∧
    b14BuildAdmitted true true false false = false ∧
    b14BuildAdmitted true false true false = false ∧
    b14BuildAdmitted true false false true = false ∧
    b20TreatyUpdateAdmitted false false false epoch epoch = false ∧
    b20TreatyUpdateAdmitted true true false epoch (epoch + 1) = false ∧
    b20TreatyUpdateAdmitted true false false (epoch + delta + 1) epoch = false ∧
    b14BuildAdmitted true false false false = true ∧
    b20TreatyUpdateAdmitted true true true epoch epoch = true := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · decide
  · decide
  · decide
  · decide
  · simp [b20TreatyUpdateAdmitted]
  · simp [b20TreatyUpdateAdmitted]
  · simp [b20TreatyUpdateAdmitted]; omega
  · decide
  · simp [b20TreatyUpdateAdmitted]

/-- Theorem 4: B9 forged empty-tree root or mismatched consistency proof sizes and B21 odd-leaf Merkle duplication fail closed. -/
theorem sm38_b9_b21_merkle_and_empty_head_fail_closed (prevSize : Nat) :
    b9B21MerkleAdmitted 0 false true false = false ∧
    b9B21MerkleAdmitted prevSize true false false = false ∧
    b9B21MerkleAdmitted prevSize true true true = false ∧
    b9B21MerkleAdmitted 0 true true false = true := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · decide
  · simp [b9B21MerkleAdmitted]
  · simp [b9B21MerkleAdmitted]
  · decide

/-- Theorem 5: Strict SM38 admission eliminates all 5 defense-pillar cryptographic and state-machine exploit classes. -/
theorem sm38_strict_admission_eliminates_all_exploits (c : DefensePillarCryptoStateConfig)
    (h : strictSm38Admitted c = true) :
    anySm38ExploitReachable c = false := by
  cases c with
  | mk b16 b18 b14 b20 b9b21 tier =>
    simp [strictSm38Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨h16, h18⟩, h14⟩, h20⟩, h921⟩, _⟩
    subst h16; subst h18; subst h14; subst h20; subst h921
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 pressure tiers fail mandatory SM38 admission. -/
theorem sm38_gentle_pressure_rejected (c : DefensePillarCryptoStateConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm38Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm38Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm38Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm38_defective_configs_expose_live_exploits :
    anySm38ExploitReachable defectiveB16Config = true ∧
    anySm38ExploitReachable defectiveB18Config = true ∧
    anySm38ExploitReachable defectiveB14Config = true ∧
    anySm38ExploitReachable defectiveB20Config = true ∧
    anySm38ExploitReachable defectiveB9B21Config = true ∧
    strictSm38Admitted defectiveGentleTierConfig = false ∧
    strictSm38Admitted hardenedSm38Config = true ∧
    anySm38ExploitReachable hardenedSm38Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive DefensePillarCryptoStateKey where
  | b16EpochConfinement
  | b18ZkSecretAndNonceFreshness
  | b14BuilderAndPinIntegrity
  | b20TreatyFreezeAndEpochMonotonicity
  | b9B21MerkleAndEmptyHeadSoundness
  | pressureTier
  deriving DecidableEq, Repr

inductive DefensePillarCryptoStateIssue where
  | b16FutureEpochShredOrEpoch0Rewrap
  | b18ZkCaseSecretLeakOrNonceReplay
  | b14BuilderSpoofOrPinOverwrite
  | b20TreatyFreezeWipeOrSelfSpoof
  | b9B21MerkleMalleabilityOrForgedEmptyHead
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def defensePillarCryptoStateView :
    View DefensePillarCryptoStateConfig DefensePillarCryptoStateKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseDefensePillarCryptoStateContract :
    Contract DefensePillarCryptoStateConfig DefensePillarCryptoStateKey Unit DefensePillarCryptoStateIssue where
  view := defensePillarCryptoStateView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesB16RetiredOnlyShredAndLiveRewrap then [] else [.rejected path .b16FutureEpochShredOrEpoch0Rewrap]) ++
    (if cfg.enforcesB18CanonicalSecretAndFreshNonce then [] else [.rejected path .b18ZkCaseSecretLeakOrNonceReplay]) ++
    (if cfg.enforcesB14CanonicalBuildersAndImmutablePins then [] else [.rejected path .b14BuilderSpoofOrPinOverwrite]) ++
    (if cfg.enforcesB20FreezePreservationAndMonotonicEpoch then [] else [.rejected path .b20TreatyFreezeWipeOrSelfSpoof]) ++
    (if cfg.enforcesB9B21MerkleAndEmptyHeadSoundness then [] else [.rejected path .b9B21MerkleMalleabilityOrForgedEmptyHead])
  validInventory := Or.inl rfl

def marlinDefensePillarCryptoStateContract :
    Contract DefensePillarCryptoStateConfig DefensePillarCryptoStateKey Unit DefensePillarCryptoStateIssue :=
  refine baseDefensePillarCryptoStateContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin SM38 contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm38_marlin_contract_refinement_laws
    (cfg : DefensePillarCryptoStateConfig) (path : List DefensePillarCryptoStateKey) :
    (diagnose baseDefensePillarCryptoStateContract cfg path ≠ [] →
      diagnose marlinDefensePillarCryptoStateContract cfg path ≠ []) ∧
    (diagnose marlinDefensePillarCryptoStateContract cfg path = [] ↔
      diagnose baseDefensePillarCryptoStateContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path DefensePillarCryptoStateIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseDefensePillarCryptoStateContract _ cfg path,
   refine_accepts_iff baseDefensePillarCryptoStateContract _ cfg path⟩

inductive DefensePillarCryptoStateProofKey where
  | b16EpochConfinement
  | b18ZkSecretAndNonceFreshness
  | b14BuilderAndPinIntegrity
  | b20TreatyFreezeAndEpochMonotonicity
  | b9B21MerkleAndEmptyHeadSoundness
  | pressureTier
  | maxAuditReceiptWindow
  deriving DecidableEq

abbrev DefensePillarCryptoStateProofValue : DefensePillarCryptoStateProofKey → Type
  | .b16EpochConfinement => Bool
  | .b18ZkSecretAndNonceFreshness => Bool
  | .b14BuilderAndPinIntegrity => Bool
  | .b20TreatyFreezeAndEpochMonotonicity => Bool
  | .b9B21MerkleAndEmptyHeadSoundness => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxAuditReceiptWindow => Nat

def defensePillarCryptoStateObligation :
    LeanPoo.Proof.Obligation DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue where
  dependencies := [
    .b16EpochConfinement,
    .b18ZkSecretAndNonceFreshness,
    .b14BuilderAndPinIntegrity,
    .b20TreatyFreezeAndEpochMonotonicity,
    .b9B21MerkleAndEmptyHeadSoundness,
    .pressureTier
  ]
  holds := fun s =>
    s .b16EpochConfinement = true ∧
    s .b18ZkSecretAndNonceFreshness = true ∧
    s .b14BuilderAndPinIntegrity = true ∧
    s .b20TreatyFreezeAndEpochMonotonicity = true ∧
    s .b9B21MerkleAndEmptyHeadSoundness = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .b16EpochConfinement = after .b16EpochConfinement :=
      same .b16EpochConfinement (by simp)
    have h2 : before .b18ZkSecretAndNonceFreshness = after .b18ZkSecretAndNonceFreshness :=
      same .b18ZkSecretAndNonceFreshness (by simp)
    have h3 : before .b14BuilderAndPinIntegrity = after .b14BuilderAndPinIntegrity :=
      same .b14BuilderAndPinIntegrity (by simp)
    have h4 : before .b20TreatyFreezeAndEpochMonotonicity = after .b20TreatyFreezeAndEpochMonotonicity :=
      same .b20TreatyFreezeAndEpochMonotonicity (by simp)
    have h5 : before .b9B21MerkleAndEmptyHeadSoundness = after .b9B21MerkleAndEmptyHeadSoundness :=
      same .b9B21MerkleAndEmptyHeadSoundness (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineDefensePillarCryptoStateProof :
    LeanPoo.Proof.ProofObject DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue where
  state := fun
    | .b16EpochConfinement => true
    | .b18ZkSecretAndNonceFreshness => true
    | .b14BuilderAndPinIntegrity => true
    | .b20TreatyFreezeAndEpochMonotonicity => true
    | .b9B21MerkleAndEmptyHeadSoundness => true
    | .pressureTier => .l4HostileAttack
    | .maxAuditReceiptWindow => 1024
  obligations := [defensePillarCryptoStateObligation]

/-- Theorem 9: Baseline ADV-L4 SM38 proof is certified. -/
theorem sm38_baseline_certified :
    LeanPoo.Proof.Certificate baselineDefensePillarCryptoStateProof := by
  intro obligation member
  have hEq : obligation = defensePillarCryptoStateObligation := by
    simpa [baselineDefensePillarCryptoStateProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def auditReceiptWindowPatch :
    LeanPoo.Proof.Patch DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue :=
  LeanPoo.Proof.Patch.set .maxAuditReceiptWindow 512

/-- Theorem 10: Tuning audit receipt retention window leaves SM38 security obligations untouched. -/
theorem sm38_obligation_untouched_by_audit_retention_tuning :
    LeanPoo.Proof.unaffected defensePillarCryptoStateObligation auditReceiptWindowPatch := by
  intro key dep touched
  have hKey : key = .maxAuditReceiptWindow := by
    simpa [auditReceiptWindowPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [defensePillarCryptoStateObligation] at dep

/-- Theorem 11: Audit receipt window tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm38_audit_retention_tuning_reuses_and_closes_certificate :
    defensePillarCryptoStateObligation.holds
      (LeanPoo.Proof.append baselineDefensePillarCryptoStateProof auditReceiptWindowPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineDefensePillarCryptoStateProof auditReceiptWindowPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineDefensePillarCryptoStateProof auditReceiptWindowPatch
      sm38_baseline_certified defensePillarCryptoStateObligation
      (by simp [baselineDefensePillarCryptoStateProof]) sm38_obligation_untouched_by_audit_retention_tuning
  · apply LeanPoo.Proof.close baselineDefensePillarCryptoStateProof auditReceiptWindowPatch
      sm38_baseline_certified
    · intro obligation member affected
      have hEq : obligation = defensePillarCryptoStateObligation := by
        simpa [baselineDefensePillarCryptoStateProof] using member
      subst obligation
      exact False.elim (affected sm38_obligation_untouched_by_audit_retention_tuning)
    · intro obligation member
      simp [auditReceiptWindowPatch, LeanPoo.Proof.Patch.set] at member

def b16RegressionPatch :
    LeanPoo.Proof.Patch DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue :=
  LeanPoo.Proof.Patch.set .b16EpochConfinement false

def b18RegressionPatch :
    LeanPoo.Proof.Patch DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue :=
  LeanPoo.Proof.Patch.set .b18ZkSecretAndNonceFreshness false

def b14RegressionPatch :
    LeanPoo.Proof.Patch DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue :=
  LeanPoo.Proof.Patch.set .b14BuilderAndPinIntegrity false

def b20RegressionPatch :
    LeanPoo.Proof.Patch DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue :=
  LeanPoo.Proof.Patch.set .b20TreatyFreezeAndEpochMonotonicity false

def b9B21RegressionPatch :
    LeanPoo.Proof.Patch DefensePillarCryptoStateProofKey DefensePillarCryptoStateProofValue :=
  LeanPoo.Proof.Patch.set .b9B21MerkleAndEmptyHeadSoundness false

/-- Theorem 12: Regressing any of the 5 SM38 defenses invalidates LeanPoo certificate reuse. -/
theorem sm38_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected defensePillarCryptoStateObligation b16RegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected defensePillarCryptoStateObligation b18RegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected defensePillarCryptoStateObligation b14RegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected defensePillarCryptoStateObligation b20RegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected defensePillarCryptoStateObligation b9B21RegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .b16EpochConfinement (by simp [defensePillarCryptoStateObligation])
      (by simp [b16RegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .b18ZkSecretAndNonceFreshness (by simp [defensePillarCryptoStateObligation])
      (by simp [b18RegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .b14BuilderAndPinIntegrity (by simp [defensePillarCryptoStateObligation])
      (by simp [b14RegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .b20TreatyFreezeAndEpochMonotonicity (by simp [defensePillarCryptoStateObligation])
      (by simp [b20RegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .b9B21MerkleAndEmptyHeadSoundness (by simp [defensePillarCryptoStateObligation])
      (by simp [b9B21RegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.DefensePillarCryptoStateConfinement
