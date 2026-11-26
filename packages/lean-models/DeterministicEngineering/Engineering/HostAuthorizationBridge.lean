/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport

/-!
# LeanPoo Dual-Sovereignty Bridge: Library (`deterministic-engineering-qnt`) ↔ Authorization Host (`cedar-poo-spec`)

Defines the policy-engine-agnostic `LeanPoo` composition boundary between:
- **This Library (`deterministic-engineering-qnt`)**: owns cryptographic quorum
  finality (`B10`), dynamic epoch handover (`B10b`), equivocation slashing (`B10c`),
  and stratified `M1/M2/M3` persistence (`R1`–`R5`).
- **Consuming Authorization Host (`cedar-poo-spec`)**: owns concrete Cedar policies
  (`Forbid`-overrides-`Permit`), `BoundOperation` / `OperationIdentity`,
  `PolicySnapshot`, and `AuthorityConsumption` (`CedarPooSpec.Admission.*`).

Built strictly on **Lean 4 core + `LeanPoo`** (zero Mathlib, zero Cedar dependency).
Proves 10 machine-checked theorems with zero `sorry` and zero custom axioms:
1. `forbid_always_overrides_permit`
2. `default_deny_when_no_permit`
3. `cedar_permit_cannot_bypass_library_refusal`
4. `library_finalized_cannot_bypass_host_forbid`
5. `library_finalized_cannot_bypass_host_pending`
6. `cross_operation_permit_replay_blocked`
7. `stale_policy_snapshot_permit_blocked`
8. `revoked_use_time_authority_blocked`
9. `dualSovereignBridge_preserves_library_rejection` (`LeanPoo.Functional.ObjectContract.refine`)
10. `disjointHostPolicyEvolution_preserves_bridge_certificate` +
    `weakeningBoundOperation_invalidates_reuse` (`LeanPoo.Proof.Reuse` / `Core.Transport`)
-/

namespace DeterministicEngineering.Engineering.HostAuthorizationBridge

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Abstract Host Policy Algebra (Cedar `Forbid`-Overrides-`Permit`) -/

inductive HostPolicyDecision where
  | permit
  | forbid
  | pending
  deriving DecidableEq, Repr

structure HostPolicyEvalInput where
  permitMatched : Bool
  forbidMatched : Bool
  contextReady : Bool
  deriving DecidableEq, Repr

/-- Canonical closed-world Cedar-compatible host evaluation:
    - Any `forbid` match yields `.forbid` unconditionally (even if `permitMatched = true`).
    - Incomplete evaluation context yields `.pending` (never silently `.permit`).
    - Only `contextReady = true ∧ forbidMatched = false ∧ permitMatched = true` yields `.permit`. -/
def evalHostPolicy (inp : HostPolicyEvalInput) : HostPolicyDecision :=
  if inp.forbidMatched then
    .forbid
  else if !inp.contextReady then
    .pending
  else if inp.permitMatched then
    .permit
  else
    .forbid

/-- **Theorem 1**: Any matching `forbid` rule overrides any `permit` match unconditionally. -/
theorem forbid_always_overrides_permit (inp : HostPolicyEvalInput)
    (hForbid : inp.forbidMatched = true) :
    evalHostPolicy inp = .forbid := by
  simp [evalHostPolicy, hForbid]

/-- **Theorem 2**: Without an explicit `permit` match, closed-world evaluation never permits. -/
theorem default_deny_when_no_permit (inp : HostPolicyEvalInput)
    (hNoPermit : inp.permitMatched = false) :
    evalHostPolicy inp ≠ .permit := by
  unfold evalHostPolicy
  cases hForb : inp.forbidMatched <;> cases hCtx : inp.contextReady <;> simp [hNoPermit]

/-! ## Section 2: Dual-Sovereignty Conjunction Gate (`Library × cedar-poo-spec`) -/

inductive LibraryVerdict where
  | finalized (opDigest : Nat) (policyDigest : Nat)
  | refused
  deriving DecidableEq, Repr

/-- Abstract consuming-host authorization receipt aligned with `CedarPooSpec.Admission`:
    - `boundOpDigest` (`BoundOperation` / `OperationIdentity`)
    - `policySnapshotDigest` (`PolicySnapshot`)
    - `authorityLiveAtUse` (`AuthorityConsumption`) -/
structure HostAuthReceipt where
  decision : HostPolicyDecision
  boundOpDigest : Nat
  policySnapshotDigest : Nat
  authorityLiveAtUse : Bool
  deriving DecidableEq, Repr

/-- Dual-sovereignty admission gate: requires BOTH Library cryptographic finality AND
    consuming-host `permit` bound to the exact operation, active policy snapshot, and live M3 authority. -/
def admitDualSovereignEffect
    (lib : LibraryVerdict)
    (host : HostAuthReceipt)
    (expectedOpDigest expectedPolicyDigest : Nat) : Bool :=
  match lib with
  | .refused => false
  | .finalized libOp libPol =>
    decide (libOp = expectedOpDigest) &&
    decide (libPol = expectedPolicyDigest) &&
    decide (host.decision = .permit) &&
    decide (host.boundOpDigest = expectedOpDigest) &&
    decide (host.policySnapshotDigest = expectedPolicyDigest) &&
    host.authorityLiveAtUse

/-- **Theorem 3**: A consuming-host Cedar `Permit` can NEVER bypass a Library refusal. -/
theorem cedar_permit_cannot_bypass_library_refusal
    (host : HostAuthReceipt) (opDigest polDigest : Nat) :
    admitDualSovereignEffect .refused host opDigest polDigest = false := rfl

/-- **Theorem 4**: Library `Finalized` can NEVER bypass a consuming-host Cedar `Forbid`. -/
theorem library_finalized_cannot_bypass_host_forbid
    (lib : LibraryVerdict) (host : HostAuthReceipt) (opDigest polDigest : Nat)
    (hForbid : host.decision = .forbid) :
    admitDualSovereignEffect lib host opDigest polDigest = false := by
  cases lib with
  | refused => rfl
  | finalized libOp libPol =>
    simp [admitDualSovereignEffect, hForbid]

/-- **Theorem 5**: Library `Finalized` can NEVER bypass an unresolved `Pending` host decision. -/
theorem library_finalized_cannot_bypass_host_pending
    (lib : LibraryVerdict) (host : HostAuthReceipt) (opDigest polDigest : Nat)
    (hPending : host.decision = .pending) :
    admitDualSovereignEffect lib host opDigest polDigest = false := by
  cases lib with
  | refused => rfl
  | finalized libOp libPol =>
    simp [admitDualSovereignEffect, hPending]

/-- **Theorem 6 (`BoundOperation` Anti-Replay)**: A host `Permit` bound to `op1 ≠ op2`
    can NEVER authorize execution of `op2`. -/
theorem cross_operation_permit_replay_blocked
    (lib : LibraryVerdict) (host : HostAuthReceipt) (expectedOp expectedPol : Nat)
    (hNe : host.boundOpDigest ≠ expectedOp) :
    admitDualSovereignEffect lib host expectedOp expectedPol = false := by
  cases lib with
  | refused => rfl
  | finalized libOp libPol =>
    simp [admitDualSovereignEffect, hNe]

/-- **Theorem 7 (`PolicySnapshot` Drift Fence)**: A host `Permit` evaluated under a stale
    policy snapshot `pol1 ≠ pol2` can NEVER authorize execution under active policy `pol2`. -/
theorem stale_policy_snapshot_permit_blocked
    (lib : LibraryVerdict) (host : HostAuthReceipt) (expectedOp expectedPol : Nat)
    (hNe : host.policySnapshotDigest ≠ expectedPol) :
    admitDualSovereignEffect lib host expectedOp expectedPol = false := by
  cases lib with
  | refused => rfl
  | finalized libOp libPol =>
    simp [admitDualSovereignEffect, hNe]

/-- **Theorem 8 (`AuthorityConsumption` Use-Time TOCTOU Fence)**: Revoked use-time authority
    always blocks dispatch even when both Library and preflight host `Permit` matched. -/
theorem revoked_use_time_authority_blocked
    (lib : LibraryVerdict) (host : HostAuthReceipt) (expectedOp expectedPol : Nat)
    (hRev : host.authorityLiveAtUse = false) :
    admitDualSovereignEffect lib host expectedOp expectedPol = false := by
  cases lib with
  | refused => rfl
  | finalized libOp libPol =>
    simp [admitDualSovereignEffect, hRev]

/-! ## Section 3: LeanPoo Two-Step Refinement & `R1` Disjoint Cedar Policy Transport -/

structure DualSovereignBridgeConfig where
  libraryMechanismEnforced : Bool
  boundOperationEnforced : Bool
  policySnapshotPinned : Bool
  useTimeAuthorityChecked : Bool
  deriving DecidableEq, Repr

inductive BridgeConfigKey where
  | libraryMechanismEnforced
  | boundOperationEnforced
  | policySnapshotPinned
  | useTimeAuthorityChecked
  deriving DecidableEq, Repr

inductive BridgeIssue where
  | libraryMechanismBypassed
  | unboundOperationPermitReplay
  | unpinnedPolicySnapshotDrift
  | missingUseTimeAuthorityCheck
  deriving DecidableEq, Repr

private def bridgeView : View DualSovereignBridgeConfig BridgeConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseLibraryBridgeContract :
    Contract DualSovereignBridgeConfig BridgeConfigKey Unit BridgeIssue where
  view := bridgeView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.libraryMechanismEnforced then [] else [.rejected path .libraryMechanismBypassed]
  validInventory := Or.inl rfl

def boundOperationExt (cfg : DualSovereignBridgeConfig) (path : List BridgeConfigKey) :
    List (Issue BridgeConfigKey BridgeIssue) :=
  if cfg.boundOperationEnforced then [] else [.rejected path .unboundOperationPermitReplay]

def policySnapshotAndAuthorityExt (cfg : DualSovereignBridgeConfig) (path : List BridgeConfigKey) :
    List (Issue BridgeConfigKey BridgeIssue) :=
  (if cfg.policySnapshotPinned then [] else [.rejected path .unpinnedPolicySnapshotDrift]) ++
  (if cfg.useTimeAuthorityChecked then [] else [.rejected path .missingUseTimeAuthorityCheck])

def fullDualSovereignBridgeContract :
    Contract DualSovereignBridgeConfig BridgeConfigKey Unit BridgeIssue :=
  refine (refine baseLibraryBridgeContract boundOperationExt) policySnapshotAndAuthorityExt

/-- **Theorem 9 (`LeanPoo` Two-Step Refinement)**: Layering `cedar-poo-spec` admission
    constraints (`BoundOperation`, `PolicySnapshot`, `AuthorityConsumption`) onto the
    library base contract monotonically preserves every library safety rejection. -/
theorem dualSovereignBridge_preserves_library_rejection
    (cfg : DualSovereignBridgeConfig) (path : List BridgeConfigKey)
    (hRej : diagnose baseLibraryBridgeContract cfg path ≠ []) :
    diagnose fullDualSovereignBridgeContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection
    baseLibraryBridgeContract boundOperationExt policySnapshotAndAuthorityExt cfg path hRej

inductive BridgeProofKey where
  | libraryQuorumEnforced
  | hostForbidOverridesPermit
  | boundOperationEnforced
  | policySnapshotPinned
  | unrelatedDomainCedarPolicyDigest
  deriving DecidableEq

abbrev BridgeProofValue : BridgeProofKey → Type
  | .libraryQuorumEnforced => Bool
  | .hostForbidOverridesPermit => Bool
  | .boundOperationEnforced => Bool
  | .policySnapshotPinned => Bool
  | .unrelatedDomainCedarPolicyDigest => Nat

def bridgeSafetyObligation : LeanPoo.Proof.Obligation BridgeProofKey BridgeProofValue where
  dependencies :=
    [.libraryQuorumEnforced, .hostForbidOverridesPermit,
     .boundOperationEnforced, .policySnapshotPinned]
  holds := fun s =>
    s .libraryQuorumEnforced = true ∧
    s .hostForbidOverridesPermit = true ∧
    s .boundOperationEnforced = true ∧
    s .policySnapshotPinned = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .libraryQuorumEnforced (by simp)).symm.trans h1,
           (same .hostForbidOverridesPermit (by simp)).symm.trans h2,
           (same .boundOperationEnforced (by simp)).symm.trans h3,
           (same .policySnapshotPinned (by simp)).symm.trans h4⟩

def baselineBridgeDeployment : LeanPoo.Proof.ProofObject BridgeProofKey BridgeProofValue where
  state := fun
    | .libraryQuorumEnforced => true
    | .hostForbidOverridesPermit => true
    | .boundOperationEnforced => true
    | .policySnapshotPinned => true
    | .unrelatedDomainCedarPolicyDigest => 101
  obligations := [bridgeSafetyObligation]

theorem baselineBridgeCertified : LeanPoo.Proof.Certificate baselineBridgeDeployment := by
  intro ob hMem
  have hEq : ob = bridgeSafetyObligation := by simpa [baselineBridgeDeployment] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 10a (`R1` Disjoint Cedar Policy Co-Evolution Transport)**:
    When `cedar-poo-spec` upgrades a Cedar policy in an unrelated domain
    (`.unrelatedDomainCedarPolicyDigest`), the `LeanPoo.Proof.Certificate` transports
    in 1 line with zero re-proof! -/
theorem disjointHostPolicyEvolution_preserves_bridge_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineBridgeDeployment
        (LeanPoo.Proof.Patch.set .unrelatedDomainCedarPolicyDigest 202)) :=
  close_single_set_untouched baselineBridgeDeployment bridgeSafetyObligation
    .unrelatedDomainCedarPolicyDigest 202 rfl baselineBridgeCertified (by simp [bridgeSafetyObligation])

/-- **Theorem 10b (Negative Control)**: Weakening `.boundOperationEnforced` ALWAYS
    invalidates proof reuse via `Core.Transport`. -/
theorem weakeningBoundOperation_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected bridgeSafetyObligation
        (LeanPoo.Proof.Patch.set .boundOperationEnforced false) :=
  set_dependency_invalidates_unaffected bridgeSafetyObligation
    .boundOperationEnforced false (by simp [bridgeSafetyObligation])

end DeterministicEngineering.Engineering.HostAuthorizationBridge
