/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.GeoResidencyAndSovereignty

/-!
# LeanPoo Unbounded Multi-Org Federated Reciprocity & Cross-Domain Dispute Arbitration (`B20`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `GeoResidencyAndSovereignty` (all 18 prior modules, 196 theorems)
and adds 10 machine-checked bilateral federation reciprocity, anti-self-reciprocity,
organization revocation, active dispute-freeze, and treaty-ratification theorems —
**surpassing 200+ theorems** to reach **19 modules and 206 machine-checked theorems**.

Machine-checked theorems (10 total -> **206 theorems across 19 modules**, zero `sorry`, zero custom axioms):
1. `unilateral_org_approval_always_refused` — missing either origin or target org countersignature is refused
2. `self_federated_same_org_spoof_refused` — claiming bilateral reciprocity with `originOrg = targetOrg` is refused
3. `revoked_or_suspended_org_always_refused` — any revoked/suspended federation member org is refused
4. `active_dispute_freeze_always_blocks` — an active bilateral dispute freeze unconditionally blocks execution
5. `unratified_federation_treaty_refused` — unratified bilateral treaty ID is unconditionally refused
6. `expired_reciprocity_epoch_refused` — execution epoch past treaty expiration is unconditionally refused
7. `federated_reciprocity_sound_and_complete` — exact iff characterization of multi-org reciprocity admission
8. `federatedOrgContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Federation host)
9. `federationHeartbeatTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingBilateralReciprocity_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.FederatedOrgReciprocity

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Multi-Org Bilateral Reciprocity & Dispute Arbitration Gate (`B20`) -/

section FederatedOrgGate

structure FederatedReciprocityClaim where
  originOrg : Nat
  targetOrg : Nat
  treatyId : Nat
  currentEpoch : Nat
  treatyExpiresEpoch : Nat
  originSigValid : Bool
  targetSigValid : Bool
  disputeFreezeActive : Bool
  deriving DecidableEq, Repr

structure FederationRegistryPolicy where
  ratifiedTreaties : List Nat
  revokedOrgs : List Nat
  deriving DecidableEq, Repr

/-- Deterministic bilateral multi-org federated reciprocity predicate:
    enforces distinct org identities (`originOrg ≠ targetOrg`), non-revoked members on
    BOTH sides, ratified bilateral treaty, non-expired treaty epoch, zero active dispute
    freeze, AND valid countersignatures from BOTH origin and target organizations. -/
def federatedReciprocityAdmitted
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim) : Bool :=
  decide (claim.originOrg ≠ claim.targetOrg) &&
  !policy.revokedOrgs.contains claim.originOrg &&
  !policy.revokedOrgs.contains claim.targetOrg &&
  policy.ratifiedTreaties.contains claim.treatyId &&
  decide (claim.currentEpoch ≤ claim.treatyExpiresEpoch) &&
  !claim.disputeFreezeActive &&
  claim.originSigValid &&
  claim.targetSigValid

/-- **Theorem 1 (Bilateral Countersignature Essential)**: Missing or invalid signature from
    either the originating OR receiving organization unconditionally refuses admission. -/
theorem unilateral_org_approval_always_refused
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim)
    (hUni : claim.originSigValid = false ∨ claim.targetSigValid = false) :
    federatedReciprocityAdmitted policy claim = false := by
  rcases hUni with hO | hT
  · simp [federatedReciprocityAdmitted, hO]
  · simp [federatedReciprocityAdmitted, hT]

/-- **Theorem 2 (Anti-Self-Reciprocity Spoofing)**: A single organization cannot forge
    a bilateral federation receipt with itself (`originOrg = targetOrg`). -/
theorem self_federated_same_org_spoof_refused
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim)
    (hSame : claim.originOrg = claim.targetOrg) :
    federatedReciprocityAdmitted policy claim = false := by
  simp [federatedReciprocityAdmitted, hSame]

/-- **Theorem 3 (Federation Member Revocation Fence)**: If either `originOrg` or `targetOrg`
    is revoked or suspended in `policy.revokedOrgs`, admission is unconditionally refused. -/
theorem revoked_or_suspended_org_always_refused
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim)
    (hRev : policy.revokedOrgs.contains claim.originOrg = true ∨
            policy.revokedOrgs.contains claim.targetOrg = true) :
    federatedReciprocityAdmitted policy claim = false := by
  unfold federatedReciprocityAdmitted
  rcases hRev with hO | hT
  · rw [hO]; simp
  · rw [hT]; simp

/-- **Theorem 4 (Active Dispute Freeze Preemption)**: When `disputeFreezeActive = true`,
    bilateral execution is unconditionally halted regardless of prior signatures. -/
theorem active_dispute_freeze_always_blocks
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim)
    (hFreeze : claim.disputeFreezeActive = true) :
    federatedReciprocityAdmitted policy claim = false := by
  simp [federatedReciprocityAdmitted, hFreeze]

/-- **Theorem 5 (Treaty Ratification Essential)**: Any bilateral request referencing an
    unratified `treatyId` not in `policy.ratifiedTreaties` is unconditionally refused. -/
theorem unratified_federation_treaty_refused
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim)
    (hUnrat : policy.ratifiedTreaties.contains claim.treatyId = false) :
    federatedReciprocityAdmitted policy claim = false := by
  unfold federatedReciprocityAdmitted
  rw [hUnrat]
  simp

/-- **Theorem 6 (Reciprocity Epoch Expiration Fence)**: Any operation whose `currentEpoch`
    exceeds `treatyExpiresEpoch` is unconditionally refused. -/
theorem expired_reciprocity_epoch_refused
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim)
    (hExp : claim.treatyExpiresEpoch < claim.currentEpoch) :
    federatedReciprocityAdmitted policy claim = false := by
  have hNotLe : ¬ (claim.currentEpoch ≤ claim.treatyExpiresEpoch) := by omega
  simp [federatedReciprocityAdmitted, hNotLe]

/-- **Theorem 7 (Soundness & Completeness of Multi-Org Federated Reciprocity Gate)**:
    `federatedReciprocityAdmitted` holds iff distinct non-revoked orgs, ratified non-expired
    treaty, no active dispute freeze, and BOTH countersignatures hold simultaneously. -/
theorem federated_reciprocity_sound_and_complete
    (policy : FederationRegistryPolicy) (claim : FederatedReciprocityClaim) :
    federatedReciprocityAdmitted policy claim = true ↔
      claim.originOrg ≠ claim.targetOrg ∧
      policy.revokedOrgs.contains claim.originOrg = false ∧
      policy.revokedOrgs.contains claim.targetOrg = false ∧
      policy.ratifiedTreaties.contains claim.treatyId = true ∧
      claim.currentEpoch ≤ claim.treatyExpiresEpoch ∧
      claim.disputeFreezeActive = false ∧
      claim.originSigValid = true ∧
      claim.targetSigValid = true := by
  unfold federatedReciprocityAdmitted
  simp [Bool.and_eq_true, and_assoc]

end FederatedOrgGate

/-! ## Section 2: LeanPoo Two-Step Refinement (`Bilateral Reciprocity -> Dispute Freeze -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooFederatedOrgContract

structure FederatedOrgConfig where
  bilateralReciprocityEnforced : Bool
  treatyRatificationEnforced : Bool
  disputeFreezePreemptionEnforced : Bool
  memberRevocationChecked : Bool
  deriving DecidableEq, Repr

inductive FederatedOrgKey where
  | bilateralReciprocityEnforced
  | treatyRatificationEnforced
  | disputeFreezePreemptionEnforced
  | memberRevocationChecked
  deriving DecidableEq, Repr

inductive FederatedOrgIssue where
  | unilateralOrgExecutionAllowed
  | unratifiedTreatyAllowed
  | disputeFreezeBypassAllowed
  | revokedMemberOrgAllowed
  deriving DecidableEq, Repr

private def federatedOrgView : View FederatedOrgConfig FederatedOrgKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseFederatedOrgContract :
    Contract FederatedOrgConfig FederatedOrgKey Unit FederatedOrgIssue where
  view := federatedOrgView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.bilateralReciprocityEnforced then [] else [.rejected path .unilateralOrgExecutionAllowed]) ++
    (if cfg.treatyRatificationEnforced then [] else [.rejected path .unratifiedTreatyAllowed])
  validInventory := Or.inl rfl

def disputeAndRevocationExt (cfg : FederatedOrgConfig) (path : List FederatedOrgKey) :
    List (Issue FederatedOrgKey FederatedOrgIssue) :=
  (if cfg.disputeFreezePreemptionEnforced then [] else [.rejected path .disputeFreezeBypassAllowed]) ++
  (if cfg.memberRevocationChecked then [] else [.rejected path .revokedMemberOrgAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Multi-Org Federation Host)**:
    Layering dispute-freeze/member-revocation AND ANY downstream `cedar-poo-spec` federation
    policy extension `hostFedExt` onto `baseFederatedOrgContract` monotonically preserves
    every federation-reciprocity rejection. -/
theorem federatedOrgContract_preserves_rejection
    (hostFedExt : FederatedOrgConfig → List FederatedOrgKey →
      List (Issue FederatedOrgKey FederatedOrgIssue))
    (cfg : FederatedOrgConfig) (path : List FederatedOrgKey)
    (hRej : diagnose baseFederatedOrgContract cfg path ≠ []) :
    diagnose (refine (refine baseFederatedOrgContract disputeAndRevocationExt) hostFedExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseFederatedOrgContract disputeAndRevocationExt hostFedExt cfg path hRej

inductive FederatedOrgProofKey where
  | bilateralReciprocityEnforced
  | treatyRatificationEnforced
  | disputeFreezePreemptionEnforced
  | memberRevocationChecked
  | federationHeartbeatSec
  deriving DecidableEq

abbrev FederatedOrgProofValue : FederatedOrgProofKey → Type
  | .bilateralReciprocityEnforced => Bool
  | .treatyRatificationEnforced => Bool
  | .disputeFreezePreemptionEnforced => Bool
  | .memberRevocationChecked => Bool
  | .federationHeartbeatSec => Nat

def federatedOrgObligation :
    LeanPoo.Proof.Obligation FederatedOrgProofKey FederatedOrgProofValue where
  dependencies :=
    [ .bilateralReciprocityEnforced
    , .treatyRatificationEnforced
    , .disputeFreezePreemptionEnforced
    , .memberRevocationChecked
    ]
  holds := fun s =>
    s .bilateralReciprocityEnforced = true ∧
    s .treatyRatificationEnforced = true ∧
    s .disputeFreezePreemptionEnforced = true ∧
    s .memberRevocationChecked = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .bilateralReciprocityEnforced (by simp)).symm.trans h1,
           (same .treatyRatificationEnforced (by simp)).symm.trans h2,
           (same .disputeFreezePreemptionEnforced (by simp)).symm.trans h3,
           (same .memberRevocationChecked (by simp)).symm.trans h4⟩

def baselineFederatedOrgSystem :
    LeanPoo.Proof.ProofObject FederatedOrgProofKey FederatedOrgProofValue where
  state := fun
    | .bilateralReciprocityEnforced => true
    | .treatyRatificationEnforced => true
    | .disputeFreezePreemptionEnforced => true
    | .memberRevocationChecked => true
    | .federationHeartbeatSec => 30
  obligations := [federatedOrgObligation]

theorem baselineFederatedOrgCertified :
    LeanPoo.Proof.Certificate baselineFederatedOrgSystem := by
  intro ob hMem
  have hEq : ob = federatedOrgObligation := by simpa [baselineFederatedOrgSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.federationHeartbeatSec` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem federationHeartbeatTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineFederatedOrgSystem
        (LeanPoo.Proof.Patch.set .federationHeartbeatSec 60)) :=
  close_single_set_untouched baselineFederatedOrgSystem federatedOrgObligation
    .federationHeartbeatSec 60 rfl baselineFederatedOrgCertified
    (by simp [federatedOrgObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.bilateralReciprocityEnforced` ALWAYS invalidates reuse. -/
theorem disablingBilateralReciprocity_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected federatedOrgObligation
        (LeanPoo.Proof.Patch.set .bilateralReciprocityEnforced false) :=
  set_dependency_invalidates_unaffected federatedOrgObligation
    .bilateralReciprocityEnforced false (by simp [federatedOrgObligation])

end LeanPooFederatedOrgContract

end DeterministicEngineering.Engineering.FederatedOrgReciprocity
