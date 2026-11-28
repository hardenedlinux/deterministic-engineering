/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM28: Adversarial (`ADV-L4`) Plugin Grant, Anti-Rollback, Entry-Path & Bound-Lease Confinement

Standalone objectified `LeanPoo` module (46th Lean module, zero edits to
`Core/Stability.lean`) formalizing the "Decorative Capability & Unbound Lease"
failure mode observed when AI-authored sibling control-plane surfaces omit
invariants enforced by older sibling subsystems:

1. **Decorative Grant Storage Bypass**: Storing project capability grants in
   `self.grants` while never enforcing `required ⊆ granted` on `enable_panel`
   and never closing active generations when `set_project_grants` revokes grants.
2. **Release Anti-Rollback, Publisher Continuity & `entry_path` Confinement**:
   Blindly overwriting `self.releases[plugin_id]` allows signed version
   downgrades (`v2.0.0 -> v1.0.0`) and cross-publisher hijacking; leaving
   `contrib.panel.entry_path` unvalidated admits `../` traversal payloads.
3. **Bound Device-Lease Validation & E-Stop Gate Mediation**: Accepting forged
   `lease_id` frames in `open_device_channel` evicts legitimate registered
   devices; omitting `ensure_governance_live` in `ApprovalGateService` and
   `open_device_channel` dispatches live device invocations during E-Stop.
4. **Digest-Verified Idempotency Replay & Bounded Activations**: Returning a
   cached action receipt when `idempotency_key` is reused with conflicting
   `(action_name, args_digest)` corrupts execution semantics.
-/

namespace DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Security posture of a plugin & device control-plane host. -/
structure PluginLeaseSecurityConfig where
  enforcesRequiredGrantsAndRevocation : Bool
  enforcesAntiRollbackAndPublisherPin : Bool
  confinesEntryPath : Bool
  enforcesBoundDeviceLeaseAndEstop : Bool
  enforcesDigestCheckedIdempotency : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a host configuration satisfies strict SM28 confinement. -/
def strictSm28Admitted (c : PluginLeaseSecurityConfig) : Bool :=
  c.enforcesRequiredGrantsAndRevocation &&
  c.enforcesAntiRollbackAndPublisherPin &&
  c.confinesEntryPath &&
  c.enforcesBoundDeviceLeaseAndEstop &&
  c.enforcesDigestCheckedIdempotency &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM28 hostile exploit classes remain reachable. -/
def anySm28ExploitReachable (c : PluginLeaseSecurityConfig) : Bool :=
  !c.enforcesRequiredGrantsAndRevocation ||
  !c.enforcesAntiRollbackAndPublisherPin ||
  !c.confinesEntryPath ||
  !c.enforcesBoundDeviceLeaseAndEstop ||
  !c.enforcesDigestCheckedIdempotency

/-- Release update admission law: same publisher and monotonic version (never downgrade), plus confined entry path. -/
def releaseUpdateAdmitted (curVer newVer curPub newPub : Nat) (entryPathConfined : Bool) : Bool :=
  (curPub == newPub) && (curVer <= newVer) && entryPathConfined

/-- Idempotency replay judgment: matching key with equal digest replays cached receipt; differing digest MUST refuse. -/
inductive IdempotencyVerdict where
  | freshAdmit
  | exactReplay
  | conflictRefuse
  deriving DecidableEq, Repr

def judgeIdempotency (existingDigest : Option Nat) (incomingDigest : Nat) : IdempotencyVerdict :=
  match existingDigest with
  | none => .freshAdmit
  | some d => if d == incomingDigest then .exactReplay else .conflictRefuse

/-- Canonical hardened SM28 Marlin host posture. -/
def hardenedSm28Config : PluginLeaseSecurityConfig :=
  { enforcesRequiredGrantsAndRevocation := true
    enforcesAntiRollbackAndPublisherPin := true
    confinesEntryPath := true
    enforcesBoundDeviceLeaseAndEstop := true
    enforcesDigestCheckedIdempotency := true
    pressureTier := .l4HostileAttack }

/-- Historical defective Marlin posture prior to SM28 hardening. -/
def defectiveDecorativeGrantConfig : PluginLeaseSecurityConfig :=
  { hardenedSm28Config with enforcesRequiredGrantsAndRevocation := false }

def defectiveRollbackHijackConfig : PluginLeaseSecurityConfig :=
  { hardenedSm28Config with enforcesAntiRollbackAndPublisherPin := false }

def defectiveEntryPathConfig : PluginLeaseSecurityConfig :=
  { hardenedSm28Config with confinesEntryPath := false }

def defectiveForgedLeaseConfig : PluginLeaseSecurityConfig :=
  { hardenedSm28Config with enforcesBoundDeviceLeaseAndEstop := false }

def defectiveIdempotencyConfig : PluginLeaseSecurityConfig :=
  { hardenedSm28Config with enforcesDigestCheckedIdempotency := false }

def defectiveGentleTierConfig : PluginLeaseSecurityConfig :=
  { hardenedSm28Config with pressureTier := .l1Gentle }

/-- Theorem 1: Strict SM28 admission eliminates all 5 plugin/device control-plane exploits. -/
theorem sm28_strict_admission_eliminates_all_exploits (c : PluginLeaseSecurityConfig)
    (h : strictSm28Admitted c = true) :
    anySm28ExploitReachable c = false := by
  cases c with
  | mk g r e l i tier =>
    simp [strictSm28Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨hg, hr⟩, he⟩, hl⟩, hi⟩, _⟩
    subst hg; subst hr; subst he; subst hl; subst hi
    rfl

/-- Theorem 2: Version downgrade (`newVer < curVer`) is unconditionally rejected by release admission. -/
theorem sm28_version_downgrade_rejected (curVer newVer curPub newPub : Nat) (confined : Bool)
    (hdown : newVer < curVer) :
    releaseUpdateAdmitted curVer newVer curPub newPub confined = false := by
  have hle : (curVer <= newVer) = false := by
    simp [Nat.not_le_of_gt hdown]
  simp [releaseUpdateAdmitted, hle]

/-- Theorem 3: Cross-publisher takeover (`newPub ≠ curPub`) is unconditionally rejected. -/
theorem sm28_cross_publisher_hijack_rejected (curVer newVer curPub newPub : Nat) (confined : Bool)
    (hne : curPub ≠ newPub) :
    releaseUpdateAdmitted curVer newVer curPub newPub confined = false := by
  have heq : (curPub == newPub) = false := by
    simp [hne]
  simp [releaseUpdateAdmitted, heq]

/-- Theorem 4: Unconfined `entry_path` (`../` or absolute path) is unconditionally rejected. -/
theorem sm28_unconfined_entry_path_rejected (curVer newVer curPub newPub : Nat) :
    releaseUpdateAdmitted curVer newVer curPub newPub false = false := by
  simp [releaseUpdateAdmitted]

/-- Theorem 5: Reusing an idempotency key with a differing payload digest is unconditionally refused. -/
theorem sm28_conflicting_idempotency_refused (d1 d2 : Nat) (hne : d1 ≠ d2) :
    judgeIdempotency (some d1) d2 = .conflictRefuse := by
  have heq : (d1 == d2) = false := by simp [hne]
  simp [judgeIdempotency, heq]

/-- Theorem 6: Reusing an idempotency key with identical digest replays cleanly. -/
theorem sm28_matching_idempotency_replays (d : Nat) :
    judgeIdempotency (some d) d = .exactReplay := by
  simp [judgeIdempotency]

/-- Theorem 7: Gentle ADV-L1/ADV-L2 tiers fail mandatory SM28 admission. -/
theorem sm28_gentle_pressure_rejected (c : PluginLeaseSecurityConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm28Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm28Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm28Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 8: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm28_defective_configs_expose_live_exploits :
    anySm28ExploitReachable defectiveDecorativeGrantConfig = true ∧
    anySm28ExploitReachable defectiveRollbackHijackConfig = true ∧
    anySm28ExploitReachable defectiveEntryPathConfig = true ∧
    anySm28ExploitReachable defectiveForgedLeaseConfig = true ∧
    anySm28ExploitReachable defectiveIdempotencyConfig = true ∧
    strictSm28Admitted defectiveGentleTierConfig = false ∧
    strictSm28Admitted hardenedSm28Config = true ∧
    anySm28ExploitReachable hardenedSm28Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive PluginLeaseConfigKey where
  | grantsAndRevocation
  | antiRollbackAndPublisher
  | entryPathConfinement
  | boundLeaseAndEstop
  | digestCheckedIdempotency
  | pressureTier
  deriving DecidableEq, Repr

inductive PluginLeaseIssue where
  | decorativeGrantBypass
  | releaseRollbackOrHijack
  | unconfinedEntryPath
  | forgedLeaseOrEstopBypass
  | conflictingIdempotencyReplay
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def pluginLeaseView : View PluginLeaseSecurityConfig PluginLeaseConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def basePluginLeaseContract :
    Contract PluginLeaseSecurityConfig PluginLeaseConfigKey Unit PluginLeaseIssue where
  view := pluginLeaseView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesRequiredGrantsAndRevocation then [] else [.rejected path .decorativeGrantBypass]) ++
    (if cfg.enforcesAntiRollbackAndPublisherPin then [] else [.rejected path .releaseRollbackOrHijack]) ++
    (if cfg.confinesEntryPath then [] else [.rejected path .unconfinedEntryPath]) ++
    (if cfg.enforcesBoundDeviceLeaseAndEstop then [] else [.rejected path .forgedLeaseOrEstopBypass]) ++
    (if cfg.enforcesDigestCheckedIdempotency then [] else [.rejected path .conflictingIdempotencyReplay])
  validInventory := Or.inl rfl

def marlinPluginLeaseContract :
    Contract PluginLeaseSecurityConfig PluginLeaseConfigKey Unit PluginLeaseIssue :=
  refine basePluginLeaseContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 9: Refined Marlin contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm28_marlin_contract_refinement_laws
    (cfg : PluginLeaseSecurityConfig) (path : List PluginLeaseConfigKey) :
    (diagnose basePluginLeaseContract cfg path ≠ [] →
      diagnose marlinPluginLeaseContract cfg path ≠ []) ∧
    (diagnose marlinPluginLeaseContract cfg path = [] ↔
      diagnose basePluginLeaseContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path PluginLeaseIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection basePluginLeaseContract _ cfg path,
   refine_accepts_iff basePluginLeaseContract _ cfg path⟩

inductive PluginLeaseProofKey where
  | grantsAndRevocation
  | antiRollbackAndPublisher
  | entryPathConfinement
  | boundLeaseAndEstop
  | digestCheckedIdempotency
  | pressureTier
  | maxRetainedActivations
  deriving DecidableEq

abbrev PluginLeaseProofValue : PluginLeaseProofKey → Type
  | .grantsAndRevocation => Bool
  | .antiRollbackAndPublisher => Bool
  | .entryPathConfinement => Bool
  | .boundLeaseAndEstop => Bool
  | .digestCheckedIdempotency => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxRetainedActivations => Nat

def pluginLeaseObligation : LeanPoo.Proof.Obligation PluginLeaseProofKey PluginLeaseProofValue where
  dependencies := [
    .grantsAndRevocation,
    .antiRollbackAndPublisher,
    .entryPathConfinement,
    .boundLeaseAndEstop,
    .digestCheckedIdempotency,
    .pressureTier
  ]
  holds := fun s =>
    s .grantsAndRevocation = true ∧
    s .antiRollbackAndPublisher = true ∧
    s .entryPathConfinement = true ∧
    s .boundLeaseAndEstop = true ∧
    s .digestCheckedIdempotency = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .grantsAndRevocation = after .grantsAndRevocation :=
      same .grantsAndRevocation (by simp)
    have h2 : before .antiRollbackAndPublisher = after .antiRollbackAndPublisher :=
      same .antiRollbackAndPublisher (by simp)
    have h3 : before .entryPathConfinement = after .entryPathConfinement :=
      same .entryPathConfinement (by simp)
    have h4 : before .boundLeaseAndEstop = after .boundLeaseAndEstop :=
      same .boundLeaseAndEstop (by simp)
    have h5 : before .digestCheckedIdempotency = after .digestCheckedIdempotency :=
      same .digestCheckedIdempotency (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselinePluginLeaseProof : LeanPoo.Proof.ProofObject PluginLeaseProofKey PluginLeaseProofValue where
  state := fun
    | .grantsAndRevocation => true
    | .antiRollbackAndPublisher => true
    | .entryPathConfinement => true
    | .boundLeaseAndEstop => true
    | .digestCheckedIdempotency => true
    | .pressureTier => .l4HostileAttack
    | .maxRetainedActivations => 512
  obligations := [pluginLeaseObligation]

/-- Theorem 10: Baseline ADV-L4 SM28 proof is certified. -/
theorem sm28_baseline_certified :
    LeanPoo.Proof.Certificate baselinePluginLeaseProof := by
  intro obligation member
  have hEq : obligation = pluginLeaseObligation := by
    simpa [baselinePluginLeaseProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def activationRetentionTuningPatch : LeanPoo.Proof.Patch PluginLeaseProofKey PluginLeaseProofValue :=
  LeanPoo.Proof.Patch.set .maxRetainedActivations 1024

theorem sm28_obligation_untouched_by_retention_tuning :
    LeanPoo.Proof.unaffected pluginLeaseObligation activationRetentionTuningPatch := by
  intro key dep touched
  have hKey : key = .maxRetainedActivations := by
    simpa [activationRetentionTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [pluginLeaseObligation] at dep

/-- Theorem 11: Tuning activation retention cleanly reuses and closes the LeanPoo certificate. -/
theorem sm28_retention_tuning_reuses_and_closes_certificate :
    pluginLeaseObligation.holds
      (LeanPoo.Proof.append baselinePluginLeaseProof activationRetentionTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselinePluginLeaseProof activationRetentionTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselinePluginLeaseProof activationRetentionTuningPatch
      sm28_baseline_certified pluginLeaseObligation
      (by simp [baselinePluginLeaseProof]) sm28_obligation_untouched_by_retention_tuning
  · apply LeanPoo.Proof.close baselinePluginLeaseProof activationRetentionTuningPatch
      sm28_baseline_certified
    · intro obligation member affected
      have hEq : obligation = pluginLeaseObligation := by
        simpa [baselinePluginLeaseProof] using member
      subst obligation
      exact False.elim (affected sm28_obligation_untouched_by_retention_tuning)
    · intro obligation member
      simp [activationRetentionTuningPatch, LeanPoo.Proof.Patch.set] at member

def grantBypassPatch : LeanPoo.Proof.Patch PluginLeaseProofKey PluginLeaseProofValue :=
  LeanPoo.Proof.Patch.set .grantsAndRevocation false

def rollbackPatch : LeanPoo.Proof.Patch PluginLeaseProofKey PluginLeaseProofValue :=
  LeanPoo.Proof.Patch.set .antiRollbackAndPublisher false

def entryPathPatch : LeanPoo.Proof.Patch PluginLeaseProofKey PluginLeaseProofValue :=
  LeanPoo.Proof.Patch.set .entryPathConfinement false

def leaseBypassPatch : LeanPoo.Proof.Patch PluginLeaseProofKey PluginLeaseProofValue :=
  LeanPoo.Proof.Patch.set .boundLeaseAndEstop false

def idempotencyPatch : LeanPoo.Proof.Patch PluginLeaseProofKey PluginLeaseProofValue :=
  LeanPoo.Proof.Patch.set .digestCheckedIdempotency false

/-- Theorem 12: Regressing any of the 5 SM28 defenses invalidates LeanPoo certificate reuse. -/
theorem sm28_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected pluginLeaseObligation grantBypassPatch ∧
    ¬ LeanPoo.Proof.unaffected pluginLeaseObligation rollbackPatch ∧
    ¬ LeanPoo.Proof.unaffected pluginLeaseObligation entryPathPatch ∧
    ¬ LeanPoo.Proof.unaffected pluginLeaseObligation leaseBypassPatch ∧
    ¬ LeanPoo.Proof.unaffected pluginLeaseObligation idempotencyPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .grantsAndRevocation (by simp [pluginLeaseObligation])
      (by simp [grantBypassPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .antiRollbackAndPublisher (by simp [pluginLeaseObligation])
      (by simp [rollbackPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .entryPathConfinement (by simp [pluginLeaseObligation])
      (by simp [entryPathPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .boundLeaseAndEstop (by simp [pluginLeaseObligation])
      (by simp [leaseBypassPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .digestCheckedIdempotency (by simp [pluginLeaseObligation])
      (by simp [idempotencyPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.PluginGrantRollbackAndLeaseConfinement
