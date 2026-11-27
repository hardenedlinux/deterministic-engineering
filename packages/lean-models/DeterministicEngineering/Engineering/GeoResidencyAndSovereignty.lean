/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.ZeroKnowledgeSelectiveDisclosure

/-!
# LeanPoo Unbounded Cross-Region Sovereign Data-Residency & Geo-Fenced Governance (`B19`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `ZeroKnowledgeSelectiveDisclosure` (all 17 prior modules, 186 theorems)
and adds 10 machine-checked GDPR Chapter V / sovereign data-residency, cross-border transfer
adequacy permit, LLM inference-endpoint geo-fencing, and regional-authority revocation theorems —
expanding the library to **18 modules and 196 machine-checked theorems**.

Machine-checked theorems (10 total -> **196 theorems across 18 modules**, zero `sorry`, zero custom axioms):
1. `forbidden_region_placement_refused` — placing data in a disallowed or sanctioned region is refused
2. `unapproved_cross_border_egress_refused` — cross-region movement without valid transfer permit is refused
3. `unverified_region_attestation_refused` — invalid/unverified regional sovereignty attestation is refused
4. `revoked_jurisdiction_cert_refused` — any revoked regional authority/adequacy decision is refused
5. `model_inference_residency_escape_refused` — routing inference outside allowed sovereign regions is refused
6. `same_region_local_transfer_no_egress_permit_needed` — intra-region placement needs no cross-border permit
7. `geo_residency_admit_sound_and_complete` — exact iff characterization of geo-fenced residency admission
8. `geoResidencyContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Sovereignty host)
9. `regionHealthPollTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingCrossBorderFence_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.GeoResidencyAndSovereignty

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Sovereign Data-Residency & Cross-Border Transfer Gate (`B19`) -/

section GeoResidencyGate

structure GeoResidencyClaim where
  sourceRegion : Nat
  targetRegion : Nat
  inferenceEndpointRegion : Nat
  authorityId : Nat
  regionAttestationValid : Bool
  crossBorderPermitValid : Bool
  deriving DecidableEq, Repr

structure GeoResidencyPolicy where
  allowedRegions : List Nat
  sanctionedRegions : List Nat
  revokedAuthorities : List Nat
  deriving DecidableEq, Repr

/-- Deterministic geo-fenced sovereign data-residency predicate:
    enforces allowed & non-sanctioned target and inference regions, non-revoked regional
    authority, valid regional attestation, AND requires a valid cross-border adequacy/SCC
    transfer permit whenever `sourceRegion ≠ targetRegion`. -/
def geoResidencyAdmitted
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim) : Bool :=
  policy.allowedRegions.contains claim.targetRegion &&
  !policy.sanctionedRegions.contains claim.targetRegion &&
  policy.allowedRegions.contains claim.inferenceEndpointRegion &&
  !policy.sanctionedRegions.contains claim.inferenceEndpointRegion &&
  !policy.revokedAuthorities.contains claim.authorityId &&
  claim.regionAttestationValid &&
  (decide (claim.sourceRegion = claim.targetRegion) || claim.crossBorderPermitValid)

/-- **Theorem 1 (Forbidden or Sanctioned Region Placement Refused)**:
    Placing an artifact into a region either outside `allowedRegions` or inside
    `sanctionedRegions` is unconditionally refused. -/
theorem forbidden_region_placement_refused
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim)
    (hBad : policy.allowedRegions.contains claim.targetRegion = false ∨
            policy.sanctionedRegions.contains claim.targetRegion = true) :
    geoResidencyAdmitted policy claim = false := by
  unfold geoResidencyAdmitted
  rcases hBad with hNotAllowed | hSanctioned
  · rw [hNotAllowed]; simp
  · rw [hSanctioned]; simp

/-- **Theorem 2 (Unapproved Cross-Border Egress Refused)**:
    Any cross-jurisdiction transfer (`sourceRegion ≠ targetRegion`) lacking a valid
    transfer adequacy/SCC permit is unconditionally refused. -/
theorem unapproved_cross_border_egress_refused
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim)
    (hCross : claim.sourceRegion ≠ claim.targetRegion)
    (hNoPermit : claim.crossBorderPermitValid = false) :
    geoResidencyAdmitted policy claim = false := by
  simp [geoResidencyAdmitted, hCross, hNoPermit]

/-- **Theorem 3 (Unverified Regional Attestation Refused)**:
    Any placement with an unverified or forged regional hardware/authority attestation
    is unconditionally refused. -/
theorem unverified_region_attestation_refused
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim)
    (hBad : claim.regionAttestationValid = false) :
    geoResidencyAdmitted policy claim = false := by
  simp [geoResidencyAdmitted, hBad]

/-- **Theorem 4 (Revoked Jurisdiction Authority Refused)**:
    Any placement attested by a revoked regional authority is unconditionally refused. -/
theorem revoked_jurisdiction_cert_refused
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim)
    (hRev : policy.revokedAuthorities.contains claim.authorityId = true) :
    geoResidencyAdmitted policy claim = false := by
  unfold geoResidencyAdmitted
  rw [hRev]
  simp

/-- **Theorem 5 (Model Inference Residency Escape Refused)**:
    Routing LLM inference to an endpoint outside `allowedRegions` or inside
    `sanctionedRegions` is unconditionally refused even if storage is in-region. -/
theorem model_inference_residency_escape_refused
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim)
    (hEscape : policy.allowedRegions.contains claim.inferenceEndpointRegion = false ∨
               policy.sanctionedRegions.contains claim.inferenceEndpointRegion = true) :
    geoResidencyAdmitted policy claim = false := by
  unfold geoResidencyAdmitted
  rcases hEscape with hOut | hSanc
  · rw [hOut]; simp
  · rw [hSanc]; simp

/-- **Theorem 6 (Anti-P4 Intra-Region Sufficiency)**:
    When `sourceRegion = targetRegion` inside a permitted, non-sanctioned, cleanly attested
    jurisdiction, admission succeeds even with `crossBorderPermitValid = false`. -/
theorem same_region_local_transfer_no_egress_permit_needed
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim)
    (hLocal : claim.sourceRegion = claim.targetRegion)
    (hTargetAllow : policy.allowedRegions.contains claim.targetRegion = true)
    (hTargetClean : policy.sanctionedRegions.contains claim.targetRegion = false)
    (hInfAllow : policy.allowedRegions.contains claim.inferenceEndpointRegion = true)
    (hInfClean : policy.sanctionedRegions.contains claim.inferenceEndpointRegion = false)
    (hAuthClean : policy.revokedAuthorities.contains claim.authorityId = false)
    (hAtt : claim.regionAttestationValid = true) :
    geoResidencyAdmitted policy claim = true := by
  unfold geoResidencyAdmitted
  rw [hTargetAllow, hTargetClean, hInfAllow, hInfClean, hAuthClean, hAtt]
  simp [hLocal]

/-- **Theorem 7 (Soundness & Completeness of Geo-Residency Gate)**:
    `geoResidencyAdmitted` holds iff target and inference regions are allowed & non-sanctioned,
    authority is non-revoked, attestation is valid, and either placement is intra-region or a
    valid cross-border permit is present. -/
theorem geo_residency_admit_sound_and_complete
    (policy : GeoResidencyPolicy) (claim : GeoResidencyClaim) :
    geoResidencyAdmitted policy claim = true ↔
      policy.allowedRegions.contains claim.targetRegion = true ∧
      policy.sanctionedRegions.contains claim.targetRegion = false ∧
      policy.allowedRegions.contains claim.inferenceEndpointRegion = true ∧
      policy.sanctionedRegions.contains claim.inferenceEndpointRegion = false ∧
      policy.revokedAuthorities.contains claim.authorityId = false ∧
      claim.regionAttestationValid = true ∧
      (claim.sourceRegion = claim.targetRegion ∨ claim.crossBorderPermitValid = true) := by
  unfold geoResidencyAdmitted
  simp [Bool.and_eq_true, Bool.or_eq_true, and_assoc]

end GeoResidencyGate

/-! ## Section 2: LeanPoo Two-Step Refinement (`Geo-Residency -> Cross-Border -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooGeoResidencyContract

structure GeoResidencyConfig where
  regionAllowlistEnforced : Bool
  crossBorderPermitEnforced : Bool
  inferenceEndpointFenced : Bool
  authorityRevocationChecked : Bool
  deriving DecidableEq, Repr

inductive GeoResidencyKey where
  | regionAllowlistEnforced
  | crossBorderPermitEnforced
  | inferenceEndpointFenced
  | authorityRevocationChecked
  deriving DecidableEq, Repr

inductive GeoResidencyIssue where
  | sanctionedRegionPlacementAllowed
  | unapprovedCrossBorderEgressAllowed
  | outOfRegionInferenceAllowed
  | revokedJurisdictionAuthorityAllowed
  deriving DecidableEq, Repr

private def geoResidencyView : View GeoResidencyConfig GeoResidencyKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseGeoResidencyContract :
    Contract GeoResidencyConfig GeoResidencyKey Unit GeoResidencyIssue where
  view := geoResidencyView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.regionAllowlistEnforced then [] else [.rejected path .sanctionedRegionPlacementAllowed]) ++
    (if cfg.crossBorderPermitEnforced then [] else [.rejected path .unapprovedCrossBorderEgressAllowed])
  validInventory := Or.inl rfl

def inferenceAndAuthorityExt (cfg : GeoResidencyConfig) (path : List GeoResidencyKey) :
    List (Issue GeoResidencyKey GeoResidencyIssue) :=
  (if cfg.inferenceEndpointFenced then [] else [.rejected path .outOfRegionInferenceAllowed]) ++
  (if cfg.authorityRevocationChecked then [] else [.rejected path .revokedJurisdictionAuthorityAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Sovereign-Jurisdiction Host)**:
    Layering LLM inference-endpoint geo-fencing/revocation AND ANY downstream `cedar-poo-spec`
    sovereignty policy extension `hostGeoExt` onto `baseGeoResidencyContract` monotonically
    preserves every geo-residency rejection. -/
theorem geoResidencyContract_preserves_rejection
    (hostGeoExt : GeoResidencyConfig → List GeoResidencyKey →
      List (Issue GeoResidencyKey GeoResidencyIssue))
    (cfg : GeoResidencyConfig) (path : List GeoResidencyKey)
    (hRej : diagnose baseGeoResidencyContract cfg path ≠ []) :
    diagnose (refine (refine baseGeoResidencyContract inferenceAndAuthorityExt) hostGeoExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseGeoResidencyContract inferenceAndAuthorityExt hostGeoExt cfg path hRej

inductive GeoResidencyProofKey where
  | regionAllowlistEnforced
  | crossBorderPermitEnforced
  | inferenceEndpointFenced
  | authorityRevocationChecked
  | regionHealthPollIntervalMs
  deriving DecidableEq

abbrev GeoResidencyProofValue : GeoResidencyProofKey → Type
  | .regionAllowlistEnforced => Bool
  | .crossBorderPermitEnforced => Bool
  | .inferenceEndpointFenced => Bool
  | .authorityRevocationChecked => Bool
  | .regionHealthPollIntervalMs => Nat

def geoResidencyObligation :
    LeanPoo.Proof.Obligation GeoResidencyProofKey GeoResidencyProofValue where
  dependencies :=
    [ .regionAllowlistEnforced
    , .crossBorderPermitEnforced
    , .inferenceEndpointFenced
    , .authorityRevocationChecked
    ]
  holds := fun s =>
    s .regionAllowlistEnforced = true ∧
    s .crossBorderPermitEnforced = true ∧
    s .inferenceEndpointFenced = true ∧
    s .authorityRevocationChecked = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .regionAllowlistEnforced (by simp)).symm.trans h1,
           (same .crossBorderPermitEnforced (by simp)).symm.trans h2,
           (same .inferenceEndpointFenced (by simp)).symm.trans h3,
           (same .authorityRevocationChecked (by simp)).symm.trans h4⟩

def baselineGeoResidencySystem :
    LeanPoo.Proof.ProofObject GeoResidencyProofKey GeoResidencyProofValue where
  state := fun
    | .regionAllowlistEnforced => true
    | .crossBorderPermitEnforced => true
    | .inferenceEndpointFenced => true
    | .authorityRevocationChecked => true
    | .regionHealthPollIntervalMs => 5000
  obligations := [geoResidencyObligation]

theorem baselineGeoResidencyCertified :
    LeanPoo.Proof.Certificate baselineGeoResidencySystem := by
  intro ob hMem
  have hEq : ob = geoResidencyObligation := by simpa [baselineGeoResidencySystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.regionHealthPollIntervalMs` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem regionHealthPollTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineGeoResidencySystem
        (LeanPoo.Proof.Patch.set .regionHealthPollIntervalMs 15000)) :=
  close_single_set_untouched baselineGeoResidencySystem geoResidencyObligation
    .regionHealthPollIntervalMs 15000 rfl baselineGeoResidencyCertified
    (by simp [geoResidencyObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.crossBorderPermitEnforced` ALWAYS invalidates reuse. -/
theorem disablingCrossBorderFence_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected geoResidencyObligation
        (LeanPoo.Proof.Patch.set .crossBorderPermitEnforced false) :=
  set_dependency_invalidates_unaffected geoResidencyObligation
    .crossBorderPermitEnforced false (by simp [geoResidencyObligation])

end LeanPooGeoResidencyContract

end DeterministicEngineering.Engineering.GeoResidencyAndSovereignty
