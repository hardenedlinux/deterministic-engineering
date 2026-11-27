/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM29: Adversarial (`ADV-L4`) Governance Policy-Evaluation Fail-Closed, Monotonic Revision/Latch Anti-Rollback & Causal Retraction Persistence

Standalone objectified `LeanPoo` module (47th Lean module, zero edits to
`Core/Stability.lean`) formalizing the "Inverted Fail-Closed & Same-Epoch Rollback"
vulnerability class discovered directly inside a production Rust governance kernel:

1. **Cedar `forbid ... unless` Fail-Open Inversion**: Evaluating `unless` blocks with
   `eval_condition_block != Some(false)` treats missing context keys (`None`) identically
   to `Some(true)` — silently disabling `forbid` rules when an attacker omits an
   exemption key! For `forbid`, `unless` MUST waive ONLY on `Some(true)`; for `permit`,
   `unless` MUST fail closed on `None` or `Some(true)` (`!= Some(false)`).
2. **Same-Epoch `policy_revision` Rollback**: Checking only
   `envelope.revocation_epoch < min_revocation_epoch` lets an attacker replay an earlier
   `policy_revision` at the same epoch, wiping ASCENT `fenced_actors`, `blocked_tools`,
   and compiled Cedar `forbid` rules.
3. **Same-Epoch Pre-Trip Checkpoint Replay**: Checking only
   `trip_epoch < guard.trip_epoch` lets a pre-trip durable checkpoint at the same epoch
   overwrite `guard.tripped = false` — silently clearing an active Operator E-Stop
   without verified human re-arm.
4. **Retraction Resurrection on Human Re-Arm**: Calling `retracted_derivations.clear()`
   inside `rearm_by_verified_human` resurrects permanently invalidated Bi-Temporal Truth
   Maintenance derivations.
5. **Constant-Time Digest Comparison & Bounded Lease Registration**: Comparing SHA-256
   integrity tags via constant-time XOR reduction and enforcing bounded active leases /
   tripped-breaker rejection on `register_derived_lease`.
-/

namespace DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Effect of a compiled Cedar policy rule. -/
inductive CedarEffect where
  | permit
  | forbid
  deriving DecidableEq, Repr

/-- Fail-closed `unless` waiver law:
    - A `forbid ... unless { B }` policy is waived ONLY when `B` evaluates to `some true`.
      Missing context (`none`) keeps the `forbid` active (fail closed).
    - A `permit ... unless { B }` policy is suppressed whenever `B ≠ some false`,
      so missing context (`none`) suppresses the `permit` (fail closed). -/
def unlessWaivesPolicy (effect : CedarEffect) (condVal : Option Bool) : Bool :=
  match effect with
  | .forbid => condVal == some true
  | .permit => condVal != some false

/-- Monotonic proof-envelope admission law forbidding stale epoch, same-epoch
    `policy_revision` rollback, and same-epoch un-denial while tripped. -/
def proofEnvelopeAdmitted
    (curEpoch curRev newEpoch newRev : Nat)
    (curAdmitted newAdmitted breakerTripped : Bool) : Bool :=
  if newEpoch < curEpoch then false
  else if newEpoch == curEpoch && newRev < curRev then false
  else if newEpoch == curEpoch && !curAdmitted && newAdmitted && breakerTripped then false
  else true

/-- Monotonic durable breaker restore law forbidding epoch regression and
    same-epoch pre-trip un-tripping of an active Operator E-Stop latch. -/
def durableBreakerRestoreAdmitted
    (curEpoch newEpoch : Nat) (curTripped newTripped : Bool) : Bool :=
  if newEpoch < curEpoch then false
  else if newEpoch == curEpoch && curTripped && !newTripped then false
  else true

/-- Retraction set preservation across human re-arm (`true` means derivation remains retracted). -/
def retractionRetainedAfterRearm (retractedBefore : Bool) (preservesRetractions : Bool) : Bool :=
  retractedBefore && preservesRetractions

/-- Security posture of a governance admission & circuit-breaker kernel. -/
structure GovernanceKernelSecurityConfig where
  forbidUnlessFailClosed : Bool
  enforcesSameEpochRevisionAntiRollback : Bool
  forbidsSameEpochEstopUntrip : Bool
  preservesRetractionsAcrossRearm : Bool
  enforcesConstantTimeTagAndBoundedLeases : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a governance kernel configuration satisfies strict SM29 confinement. -/
def strictSm29Admitted (c : GovernanceKernelSecurityConfig) : Bool :=
  c.forbidUnlessFailClosed &&
  c.enforcesSameEpochRevisionAntiRollback &&
  c.forbidsSameEpochEstopUntrip &&
  c.preservesRetractionsAcrossRearm &&
  c.enforcesConstantTimeTagAndBoundedLeases &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM29 hostile exploit classes remain reachable. -/
def anySm29ExploitReachable (c : GovernanceKernelSecurityConfig) : Bool :=
  !c.forbidUnlessFailClosed ||
  !c.enforcesSameEpochRevisionAntiRollback ||
  !c.forbidsSameEpochEstopUntrip ||
  !c.preservesRetractionsAcrossRearm ||
  !c.enforcesConstantTimeTagAndBoundedLeases

/-- Canonical hardened SM29 Marlin governance kernel posture. -/
def hardenedSm29Config : GovernanceKernelSecurityConfig :=
  { forbidUnlessFailClosed := true
    enforcesSameEpochRevisionAntiRollback := true
    forbidsSameEpochEstopUntrip := true
    preservesRetractionsAcrossRearm := true
    enforcesConstantTimeTagAndBoundedLeases := true
    pressureTier := .l4HostileAttack }

def defectiveForbidUnlessConfig : GovernanceKernelSecurityConfig :=
  { hardenedSm29Config with forbidUnlessFailClosed := false }

def defectiveRevisionRollbackConfig : GovernanceKernelSecurityConfig :=
  { hardenedSm29Config with enforcesSameEpochRevisionAntiRollback := false }

def defectiveSameEpochUntripConfig : GovernanceKernelSecurityConfig :=
  { hardenedSm29Config with forbidsSameEpochEstopUntrip := false }

def defectiveRearmClearRetractionConfig : GovernanceKernelSecurityConfig :=
  { hardenedSm29Config with preservesRetractionsAcrossRearm := false }

def defectiveTagAndLeaseConfig : GovernanceKernelSecurityConfig :=
  { hardenedSm29Config with enforcesConstantTimeTagAndBoundedLeases := false }

def defectiveGentleTierConfig : GovernanceKernelSecurityConfig :=
  { hardenedSm29Config with pressureTier := .l1Gentle }

/-- Theorem 1: Missing context keys NEVER waive a Cedar `forbid ... unless` rule,
    and ALWAYS suppress a Cedar `permit ... unless` rule (both fail closed). -/
theorem sm29_unless_missing_context_fails_closed_for_both_effects :
    unlessWaivesPolicy .forbid none = false ∧
    unlessWaivesPolicy .forbid (some false) = false ∧
    unlessWaivesPolicy .forbid (some true) = true ∧
    unlessWaivesPolicy .permit none = true ∧
    unlessWaivesPolicy .permit (some true) = true ∧
    unlessWaivesPolicy .permit (some false) = false := by
  decide

/-- Theorem 2: Same-epoch `policy_revision` rollback (`newRev < curRev`) is unconditionally rejected. -/
theorem sm29_same_epoch_revision_rollback_rejected
    (epoch curRev newRev : Nat) (curAdmitted newAdmitted tripped : Bool)
    (hdown : newRev < curRev) :
    proofEnvelopeAdmitted epoch curRev epoch newRev curAdmitted newAdmitted tripped = false := by
  have hlt : (epoch < epoch) = false := by simp
  have hrev : (newRev < curRev) = true := by simp [hdown]
  simp [proofEnvelopeAdmitted, hlt, hrev]

/-- Theorem 3: Same-epoch un-denial (`false -> true`) while the breaker is still tripped is rejected. -/
theorem sm29_same_epoch_tripped_undeny_rejected (epoch rev : Nat) :
    proofEnvelopeAdmitted epoch rev epoch rev false true true = false := by
  simp [proofEnvelopeAdmitted]

/-- Theorem 4: Same-epoch pre-trip durable checkpoint replay can NEVER untrip an active E-Stop. -/
theorem sm29_same_epoch_checkpoint_cannot_untrip_estop (epoch : Nat) :
    durableBreakerRestoreAdmitted epoch epoch true false = false := by
  simp [durableBreakerRestoreAdmitted]

/-- Theorem 5: Stale-epoch durable checkpoint restore (`newEpoch < curEpoch`) is always rejected. -/
theorem sm29_stale_epoch_checkpoint_rejected (curEpoch newEpoch : Nat) (ct nt : Bool)
    (hlt : newEpoch < curEpoch) :
    durableBreakerRestoreAdmitted curEpoch newEpoch ct nt = false := by
  simp [durableBreakerRestoreAdmitted, hlt]

/-- Theorem 6: Human re-arm with retraction preservation keeps every retracted derivation fenced. -/
theorem sm29_rearm_preserves_retracted_derivations (retractedBefore : Bool)
    (hret : retractedBefore = true) :
    retractionRetainedAfterRearm retractedBefore true = true := by
  simp [retractionRetainedAfterRearm, hret]

/-- Theorem 7: Strict SM29 admission eliminates all 5 governance kernel exploit classes. -/
theorem sm29_strict_admission_eliminates_all_exploits (c : GovernanceKernelSecurityConfig)
    (h : strictSm29Admitted c = true) :
    anySm29ExploitReachable c = false := by
  cases c with
  | mk f r u p t tier =>
    simp [strictSm29Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨hf, hr⟩, hu⟩, hp⟩, ht⟩, _⟩
    subst hf; subst hr; subst hu; subst hp; subst ht
    rfl

/-- Theorem 8: Gentle ADV-L1/ADV-L2 tiers fail mandatory SM29 admission. -/
theorem sm29_gentle_pressure_rejected (c : GovernanceKernelSecurityConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm29Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm29Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm29Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 9: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm29_defective_configs_expose_live_exploits :
    anySm29ExploitReachable defectiveForbidUnlessConfig = true ∧
    anySm29ExploitReachable defectiveRevisionRollbackConfig = true ∧
    anySm29ExploitReachable defectiveSameEpochUntripConfig = true ∧
    anySm29ExploitReachable defectiveRearmClearRetractionConfig = true ∧
    anySm29ExploitReachable defectiveTagAndLeaseConfig = true ∧
    strictSm29Admitted defectiveGentleTierConfig = false ∧
    strictSm29Admitted hardenedSm29Config = true ∧
    anySm29ExploitReachable hardenedSm29Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive GovernanceKernelConfigKey where
  | forbidUnlessFailClosed
  | sameEpochRevisionAntiRollback
  | sameEpochEstopAntiUntrip
  | retractionPersistenceAcrossRearm
  | constantTimeTagAndBoundedLeases
  | pressureTier
  deriving DecidableEq, Repr

inductive GovernanceKernelIssue where
  | forbidUnlessMissingKeyFailOpen
  | sameEpochPolicyRevisionRollback
  | sameEpochEstopUntripReplay
  | rearmResurrectsRetractedDerivations
  | nonConstantTimeTagOrUnboundedLeases
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def governanceKernelView : View GovernanceKernelSecurityConfig GovernanceKernelConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseGovernanceKernelContract :
    Contract GovernanceKernelSecurityConfig GovernanceKernelConfigKey Unit GovernanceKernelIssue where
  view := governanceKernelView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.forbidUnlessFailClosed then [] else [.rejected path .forbidUnlessMissingKeyFailOpen]) ++
    (if cfg.enforcesSameEpochRevisionAntiRollback then [] else [.rejected path .sameEpochPolicyRevisionRollback]) ++
    (if cfg.forbidsSameEpochEstopUntrip then [] else [.rejected path .sameEpochEstopUntripReplay]) ++
    (if cfg.preservesRetractionsAcrossRearm then [] else [.rejected path .rearmResurrectsRetractedDerivations]) ++
    (if cfg.enforcesConstantTimeTagAndBoundedLeases then [] else [.rejected path .nonConstantTimeTagOrUnboundedLeases])
  validInventory := Or.inl rfl

def marlinGovernanceKernelContract :
    Contract GovernanceKernelSecurityConfig GovernanceKernelConfigKey Unit GovernanceKernelIssue :=
  refine baseGovernanceKernelContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 10: Refined Marlin governance contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm29_marlin_contract_refinement_laws
    (cfg : GovernanceKernelSecurityConfig) (path : List GovernanceKernelConfigKey) :
    (diagnose baseGovernanceKernelContract cfg path ≠ [] →
      diagnose marlinGovernanceKernelContract cfg path ≠ []) ∧
    (diagnose marlinGovernanceKernelContract cfg path = [] ↔
      diagnose baseGovernanceKernelContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path GovernanceKernelIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseGovernanceKernelContract _ cfg path,
   refine_accepts_iff baseGovernanceKernelContract _ cfg path⟩

inductive GovernanceKernelProofKey where
  | forbidUnlessFailClosed
  | sameEpochRevisionAntiRollback
  | sameEpochEstopAntiUntrip
  | retractionPersistenceAcrossRearm
  | constantTimeTagAndBoundedLeases
  | pressureTier
  | maxActiveLeasesBound
  deriving DecidableEq

abbrev GovernanceKernelProofValue : GovernanceKernelProofKey → Type
  | .forbidUnlessFailClosed => Bool
  | .sameEpochRevisionAntiRollback => Bool
  | .sameEpochEstopAntiUntrip => Bool
  | .retractionPersistenceAcrossRearm => Bool
  | .constantTimeTagAndBoundedLeases => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxActiveLeasesBound => Nat

def governanceKernelObligation :
    LeanPoo.Proof.Obligation GovernanceKernelProofKey GovernanceKernelProofValue where
  dependencies := [
    .forbidUnlessFailClosed,
    .sameEpochRevisionAntiRollback,
    .sameEpochEstopAntiUntrip,
    .retractionPersistenceAcrossRearm,
    .constantTimeTagAndBoundedLeases,
    .pressureTier
  ]
  holds := fun s =>
    s .forbidUnlessFailClosed = true ∧
    s .sameEpochRevisionAntiRollback = true ∧
    s .sameEpochEstopAntiUntrip = true ∧
    s .retractionPersistenceAcrossRearm = true ∧
    s .constantTimeTagAndBoundedLeases = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .forbidUnlessFailClosed = after .forbidUnlessFailClosed :=
      same .forbidUnlessFailClosed (by simp)
    have h2 : before .sameEpochRevisionAntiRollback = after .sameEpochRevisionAntiRollback :=
      same .sameEpochRevisionAntiRollback (by simp)
    have h3 : before .sameEpochEstopAntiUntrip = after .sameEpochEstopAntiUntrip :=
      same .sameEpochEstopAntiUntrip (by simp)
    have h4 : before .retractionPersistenceAcrossRearm = after .retractionPersistenceAcrossRearm :=
      same .retractionPersistenceAcrossRearm (by simp)
    have h5 : before .constantTimeTagAndBoundedLeases = after .constantTimeTagAndBoundedLeases :=
      same .constantTimeTagAndBoundedLeases (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineGovernanceKernelProof :
    LeanPoo.Proof.ProofObject GovernanceKernelProofKey GovernanceKernelProofValue where
  state := fun
    | .forbidUnlessFailClosed => true
    | .sameEpochRevisionAntiRollback => true
    | .sameEpochEstopAntiUntrip => true
    | .retractionPersistenceAcrossRearm => true
    | .constantTimeTagAndBoundedLeases => true
    | .pressureTier => .l4HostileAttack
    | .maxActiveLeasesBound => 4096
  obligations := [governanceKernelObligation]

/-- Theorem 11: Baseline ADV-L4 SM29 proof is certified. -/
theorem sm29_baseline_certified :
    LeanPoo.Proof.Certificate baselineGovernanceKernelProof := by
  intro obligation member
  have hEq : obligation = governanceKernelObligation := by
    simpa [baselineGovernanceKernelProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def leaseBoundTuningPatch :
    LeanPoo.Proof.Patch GovernanceKernelProofKey GovernanceKernelProofValue :=
  LeanPoo.Proof.Patch.set .maxActiveLeasesBound 8192

theorem sm29_obligation_untouched_by_lease_bound_tuning :
    LeanPoo.Proof.unaffected governanceKernelObligation leaseBoundTuningPatch := by
  intro key dep touched
  have hKey : key = .maxActiveLeasesBound := by
    simpa [leaseBoundTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [governanceKernelObligation] at dep

/-- Theorem 12: Tuning the lease capacity bound cleanly reuses and closes the LeanPoo certificate. -/
theorem sm29_lease_bound_tuning_reuses_and_closes_certificate :
    governanceKernelObligation.holds
      (LeanPoo.Proof.append baselineGovernanceKernelProof leaseBoundTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineGovernanceKernelProof leaseBoundTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineGovernanceKernelProof leaseBoundTuningPatch
      sm29_baseline_certified governanceKernelObligation
      (by simp [baselineGovernanceKernelProof]) sm29_obligation_untouched_by_lease_bound_tuning
  · apply LeanPoo.Proof.close baselineGovernanceKernelProof leaseBoundTuningPatch
      sm29_baseline_certified
    · intro obligation member affected
      have hEq : obligation = governanceKernelObligation := by
        simpa [baselineGovernanceKernelProof] using member
      subst obligation
      exact False.elim (affected sm29_obligation_untouched_by_lease_bound_tuning)
    · intro obligation member
      simp [leaseBoundTuningPatch, LeanPoo.Proof.Patch.set] at member

def forbidUnlessRegressionPatch :
    LeanPoo.Proof.Patch GovernanceKernelProofKey GovernanceKernelProofValue :=
  LeanPoo.Proof.Patch.set .forbidUnlessFailClosed false

def revRollbackRegressionPatch :
    LeanPoo.Proof.Patch GovernanceKernelProofKey GovernanceKernelProofValue :=
  LeanPoo.Proof.Patch.set .sameEpochRevisionAntiRollback false

def estopUntripRegressionPatch :
    LeanPoo.Proof.Patch GovernanceKernelProofKey GovernanceKernelProofValue :=
  LeanPoo.Proof.Patch.set .sameEpochEstopAntiUntrip false

def retractionClearRegressionPatch :
    LeanPoo.Proof.Patch GovernanceKernelProofKey GovernanceKernelProofValue :=
  LeanPoo.Proof.Patch.set .retractionPersistenceAcrossRearm false

def tagLeaseRegressionPatch :
    LeanPoo.Proof.Patch GovernanceKernelProofKey GovernanceKernelProofValue :=
  LeanPoo.Proof.Patch.set .constantTimeTagAndBoundedLeases false

/-- Theorem 13: Regressing any of the 5 SM29 defenses invalidates LeanPoo certificate reuse. -/
theorem sm29_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected governanceKernelObligation forbidUnlessRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected governanceKernelObligation revRollbackRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected governanceKernelObligation estopUntripRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected governanceKernelObligation retractionClearRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected governanceKernelObligation tagLeaseRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .forbidUnlessFailClosed (by simp [governanceKernelObligation])
      (by simp [forbidUnlessRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .sameEpochRevisionAntiRollback (by simp [governanceKernelObligation])
      (by simp [revRollbackRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .sameEpochEstopAntiUntrip (by simp [governanceKernelObligation])
      (by simp [estopUntripRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .retractionPersistenceAcrossRearm (by simp [governanceKernelObligation])
      (by simp [retractionClearRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .constantTimeTagAndBoundedLeases (by simp [governanceKernelObligation])
      (by simp [tagLeaseRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.GovernancePolicyAndLatchAntirollback
