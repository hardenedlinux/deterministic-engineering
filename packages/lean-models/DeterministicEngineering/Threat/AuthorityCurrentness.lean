/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Transport

/-!
# Zero-Trust Authority Currentness & Epoch Monotonicity (`Threat.AuthorityCurrentness`)

Completes Layer B2 of the 10.154 LeanPoo hierarchy (`Threat/CapabilityContainment.lean` +
`Threat/AuthorityCurrentness.lean`), sharing `Core.Order` and `Core.Transport` with
Engineering subjects with zero duplicated base math.

Complements `packages/quint-models/threat/zero-trust/authority-currentness/AuthorityCurrentness.qnt`:
proves unbounded epoch currentness rejection across arbitrary `Nat` epochs, four-factor
authority conjunction soundness (`paused`, `fresh`, `credential`, `bytes`), zero-trust
governance floor monotonicity, 2-step `ObjectContract.refine`, and 1-line `Proof.reuse`.
-/

namespace DeterministicEngineering.Threat.AuthorityCurrentness

open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## 1. Four-Factor Zero-Trust Currentness Predicate (Constructive, Zero Axioms) -/

/-- Exact Boolean specification matching `AuthorityCurrentness.qnt::isCurrent`. -/
def isCurrent (paused fresh credential bytes : Bool) : Bool :=
  !paused && fresh && credential && bytes

/-- Four-factor soundness: `isCurrent` returns `true` iff unpaused, fresh, valid credential, and valid bytes. -/
theorem isCurrent_eq_true_iff (paused fresh credential bytes : Bool) :
    isCurrent paused fresh credential bytes = true ↔
      paused = false ∧ fresh = true ∧ credential = true ∧ bytes = true := by
  cases paused <;> cases fresh <;> cases credential <;> cases bytes <;> simp [isCurrent]

/-- Pausing authority unconditionally revokes currentness regardless of credential/freshness bits. -/
theorem paused_never_current (fresh credential bytes : Bool) :
    isCurrent true fresh credential bytes = false := by
  simp [isCurrent]

/-! ## 2. Unbounded Monotonic Epoch Invalidation & Governance Floor Lattice (`Core.Order`) -/

/-- Any authority plan minted at a strictly older epoch is rejected after any epoch advance. -/
theorem epochAdvance_invalidates_all_prior_plans
    (currentEpoch nextEpoch plannedEpoch : Nat)
    (hOlder : plannedEpoch < currentEpoch) :
    admitEpoch (advanceEpoch currentEpoch nextEpoch) plannedEpoch = false :=
  advanceEpoch_rejects_strictly_older currentEpoch nextEpoch plannedEpoch hOlder

/-- Composing a zero-trust authority floor with any tenant policy can never weaken the base floor. -/
theorem authorityFloor_join_never_weakens (base tenant : GovernanceFloor) :
    base.le (base.join tenant) ∧ tenant.le (base.join tenant) :=
  ⟨join_never_weakens_left base tenant, join_never_weakens_right base tenant⟩

/-! ## 3. Two-Step LeanPoo `ObjectContract.refine` (`Core.Transport`) -/

structure ZeroTrustAuthConfig where
  checksPausedFlag : Bool
  checksFreshnessWindow : Bool
  checksCredentialAndBytes : Bool
  deriving DecidableEq, Repr

inductive AuthConfigKey where
  | checksPausedFlag
  | checksFreshnessWindow
  | checksCredentialAndBytes
  deriving DecidableEq, Repr

inductive AuthIssue where
  | ignoresPausedFlag
  | ignoresFreshnessWindow
  | ignoresCredentialOrBytes
  deriving DecidableEq, Repr

private def authView : View ZeroTrustAuthConfig AuthConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseCurrentnessContract : Contract ZeroTrustAuthConfig AuthConfigKey Unit AuthIssue where
  view := authView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.checksPausedFlag then [] else [.rejected path .ignoresPausedFlag]
  validInventory := Or.inl rfl

def freshnessExt (cfg : ZeroTrustAuthConfig) (path : List AuthConfigKey) :
    List (Issue AuthConfigKey AuthIssue) :=
  if cfg.checksFreshnessWindow then [] else [.rejected path .ignoresFreshnessWindow]

def credentialBytesExt (cfg : ZeroTrustAuthConfig) (path : List AuthConfigKey) :
    List (Issue AuthConfigKey AuthIssue) :=
  if cfg.checksCredentialAndBytes then [] else [.rejected path .ignoresCredentialOrBytes]

def strictZeroTrustContract : Contract ZeroTrustAuthConfig AuthConfigKey Unit AuthIssue :=
  refine (refine baseCurrentnessContract freshnessExt) credentialBytesExt

theorem strictZeroTrustContract_preserves_rejection
    (cfg : ZeroTrustAuthConfig) (path : List AuthConfigKey)
    (hRej : diagnose baseCurrentnessContract cfg path ≠ []) :
    diagnose strictZeroTrustContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseCurrentnessContract freshnessExt credentialBytesExt cfg path hRej

/-! ## 4. One-Line Proof Transport (`Core.Transport`) -/

inductive CurrentnessProofKey where
  | freshnessEnforced
  | pauseChecked
  | telemetrySampleMs
  deriving DecidableEq

abbrev CurrentnessProofValue : CurrentnessProofKey → Type
  | .freshnessEnforced => Bool
  | .pauseChecked => Bool
  | .telemetrySampleMs => Nat

def currentnessObligation : LeanPoo.Proof.Obligation CurrentnessProofKey CurrentnessProofValue where
  dependencies := [.freshnessEnforced, .pauseChecked]
  holds := fun s => s .freshnessEnforced = true ∧ s .pauseChecked = true
  stable := by
    intro before after same holds
    exact ⟨(same .freshnessEnforced (by simp)).symm.trans holds.1,
           (same .pauseChecked (by simp)).symm.trans holds.2⟩

def baselineAuthority : LeanPoo.Proof.ProofObject CurrentnessProofKey CurrentnessProofValue where
  state := fun
    | .freshnessEnforced => true
    | .pauseChecked => true
    | .telemetrySampleMs => 250
  obligations := [currentnessObligation]

theorem baselineAuthorityCertified : LeanPoo.Proof.Certificate baselineAuthority := by
  intro ob hMem
  have hEq : ob = currentnessObligation := by simpa [baselineAuthority] using hMem
  subst ob
  exact ⟨rfl, rfl⟩

/-- Tuning telemetry sampling transports the zero-trust currentness certificate in 1 line. -/
theorem telemetryTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineAuthority
        (LeanPoo.Proof.Patch.set .telemetrySampleMs 1000)) :=
  close_single_set_untouched baselineAuthority currentnessObligation
    .telemetrySampleMs 1000 rfl baselineAuthorityCertified (by simp [currentnessObligation])

/-- Negative control: disabling freshness enforcement invalidates proof reuse. -/
theorem disableFreshnessCheck_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected currentnessObligation
        (LeanPoo.Proof.Patch.set .freshnessEnforced false) :=
  set_dependency_invalidates_unaffected currentnessObligation
    .freshnessEnforced false (by simp [currentnessObligation])

end DeterministicEngineering.Threat.AuthorityCurrentness
