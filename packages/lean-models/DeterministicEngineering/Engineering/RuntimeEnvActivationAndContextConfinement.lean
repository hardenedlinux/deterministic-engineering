/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM34: Adversarial (`ADV-L4`) Runtime Environment Activation & Governed Context Confinement

Standalone objectified `LeanPoo` module (52nd Lean module, zero edits to
`Core/Stability.lean`) formalizing five real `ADV-L4` runtime environment
activation and governed context vulnerabilities discovered in
`marlin-agent-runtime/src/environment/` and `marlin-agent-context/src/`:

1. **Direnv Loader-Hijack, Denylist & Bounded Subprocess Capture**:
   `apply_direnv_json` admitted `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`BASH_ENV`,
   explicitly denylisted vars, and invalid/NUL env keys; `direnv_output` used
   unbounded `wait_with_output()` without byte cap or timeout; `allow` ran bare
   `direnv allow` walking parent directories.
2. **Symlink-Safe Explicit `.envrc`, Sub-Agent Home & State-Home Confinement**:
   `direnv_cwd` accepted explicit `.envrc` paths escaping `cwd`/`project.root`,
   empty parent paths, and symlinked `.envrc` files; `resolve_sub_agent` admitted
   escaping `home_path` overrides; `ensure_layout` followed symlinks.
3. **Symlink-Safe Bounded `FileSystemOrgSourceStore`**:
   Lexical-only `validated_relative_path` allowed intermediate/leaf symlinks to
   exfiltrate or write files outside store root, read unbounded files, and staged
   temp files without an atomic sequence counter.
4. **Monotonic Org Snapshot / Shared-Channel Anti-Rollback & Atomic Rebase**:
   `OrgGovernanceLedger::register_snapshot` permitted generation rollback and
   stale active leases; `commit_subtree` lacked lease-digest parity, replacement
   size cap, and atomic rebase ordering; `SharedContextGovernanceLedger::create_channel`
   overwrote existing channels resetting `acl_epoch` to 1 and wiping `tainted=true`.
5. **Recomputed Two-Zone KV-Prefix Digest & Cross-Task Proxy Refusal**:
   `assemble_two_zone_gateway_messages` checked `envelope.kv_prefix_digest`
   without recomputing SHA-256 over `envelope.frozen_prefix`, allowing Zone-1
   System prompt injection with a copied digest; `commit_governed_org_subtree`
   omitted `proposal.task_id == cursor.task_id` binding.
-/

namespace DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Direnv export admission predicate rejecting loader hijacks, denylisted vars, malformed keys, and oversize payloads. -/
def direnvExportAdmitted
    (notLoaderHijack : Bool)
    (notDenylisted : Bool)
    (validKeyAndValue : Bool)
    (withinByteAndEntryCap : Bool) : Bool :=
  notLoaderHijack && notDenylisted && validKeyAndValue && withinByteAndEntryCap

/-- Path & symlink confinement predicate for explicit `.envrc`, sub-agent homes, state-home, and Org source store. -/
def confinedPathAdmitted
    (noTraversal : Bool)
    (withinRoot : Bool)
    (noSymlinkComponent : Bool) : Bool :=
  noTraversal && withinRoot && noSymlinkComponent

/-- Monotonic snapshot generation & shared-channel ACL-epoch/taint transition law. -/
def governanceSnapshotAdmitted
    (currentGen incomingGen : Nat)
    (activeLeasesOnSource : Nat) : Bool :=
  (currentGen < incomingGen) && (activeLeasesOnSource == 0)

/-- Recomputed Two-Zone KV-Prefix integrity & cursor/proposal task binding predicate. -/
def twoZonePromptAndTaskAdmitted
    (claimedDigestMatchesAdmitted : Bool)
    (recomputedPrefixMatchesAdmitted : Bool)
    (proposalTaskMatchesCursor : Bool) : Bool :=
  claimedDigestMatchesAdmitted && recomputedPrefixMatchesAdmitted && proposalTaskMatchesCursor

/-- Security posture of Marlin runtime environment activation & governed context boundaries. -/
structure RuntimeEnvContextConfinementConfig where
  enforcesDirenvFilterAndBoundedCapture : Bool
  enforcesEnvrcAndSubAgentHomeConfinement : Bool
  enforcesOrgStoreSymlinkAndReadBounds : Bool
  enforcesMonotonicOrgAndChannelAntiRollback : Bool
  enforcesRecomputedTwoZoneDigestAndTaskBinding : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a runtime-env + context configuration satisfies strict SM34 confinement. -/
def strictSm34Admitted (c : RuntimeEnvContextConfinementConfig) : Bool :=
  c.enforcesDirenvFilterAndBoundedCapture &&
  c.enforcesEnvrcAndSubAgentHomeConfinement &&
  c.enforcesOrgStoreSymlinkAndReadBounds &&
  c.enforcesMonotonicOrgAndChannelAntiRollback &&
  c.enforcesRecomputedTwoZoneDigestAndTaskBinding &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM34 hostile exploit classes remain reachable. -/
def anySm34ExploitReachable (c : RuntimeEnvContextConfinementConfig) : Bool :=
  !c.enforcesDirenvFilterAndBoundedCapture ||
  !c.enforcesEnvrcAndSubAgentHomeConfinement ||
  !c.enforcesOrgStoreSymlinkAndReadBounds ||
  !c.enforcesMonotonicOrgAndChannelAntiRollback ||
  !c.enforcesRecomputedTwoZoneDigestAndTaskBinding

/-- Canonical hardened SM34 posture. -/
def hardenedSm34Config : RuntimeEnvContextConfinementConfig :=
  { enforcesDirenvFilterAndBoundedCapture := true
    enforcesEnvrcAndSubAgentHomeConfinement := true
    enforcesOrgStoreSymlinkAndReadBounds := true
    enforcesMonotonicOrgAndChannelAntiRollback := true
    enforcesRecomputedTwoZoneDigestAndTaskBinding := true
    pressureTier := .l4HostileAttack }

def defectiveDirenvConfig : RuntimeEnvContextConfinementConfig :=
  { hardenedSm34Config with enforcesDirenvFilterAndBoundedCapture := false }

def defectiveEnvrcHomeConfig : RuntimeEnvContextConfinementConfig :=
  { hardenedSm34Config with enforcesEnvrcAndSubAgentHomeConfinement := false }

def defectiveOrgStoreConfig : RuntimeEnvContextConfinementConfig :=
  { hardenedSm34Config with enforcesOrgStoreSymlinkAndReadBounds := false }

def defectiveRollbackConfig : RuntimeEnvContextConfinementConfig :=
  { hardenedSm34Config with enforcesMonotonicOrgAndChannelAntiRollback := false }

def defectiveTwoZoneConfig : RuntimeEnvContextConfinementConfig :=
  { hardenedSm34Config with enforcesRecomputedTwoZoneDigestAndTaskBinding := false }

def defectiveGentleTierConfig : RuntimeEnvContextConfinementConfig :=
  { hardenedSm34Config with pressureTier := .l1Gentle }

/-- Theorem 1: Loader hijacks, denylisted vars, malformed keys, or oversize direnv payloads fail closed. -/
theorem sm34_direnv_export_fail_closed (a b c d : Bool) :
    direnvExportAdmitted false b c d = false ∧
    direnvExportAdmitted a false c d = false ∧
    direnvExportAdmitted a b false d = false ∧
    direnvExportAdmitted a b c false = false ∧
    direnvExportAdmitted true true true true = true := by
  cases a <;> cases b <;> cases c <;> cases d <;> decide

/-- Theorem 2: Traversal, root escape, or any symlink component fails path confinement across envrc/home/Org store. -/
theorem sm34_confined_path_refuses_traversal_escape_and_symlink (a b c : Bool) :
    confinedPathAdmitted false b c = false ∧
    confinedPathAdmitted a false c = false ∧
    confinedPathAdmitted a b false = false ∧
    confinedPathAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 3: Same-or-lower generation snapshot rollbacks and snapshot swaps under active leases are refused. -/
theorem sm34_snapshot_rollback_and_active_lease_swap_refused
    (cur inc leases : Nat) :
    (inc ≤ cur → governanceSnapshotAdmitted cur inc leases = false) ∧
    (0 < leases → governanceSnapshotAdmitted cur inc leases = false) ∧
    governanceSnapshotAdmitted cur (cur + 1) 0 = true := by
  refine ⟨?_, ?_, ?_⟩
  · intro hle
    have hnot : ¬ (cur < inc) := Nat.not_lt_of_ge hle
    simp [governanceSnapshotAdmitted, hnot]
  · intro hpos
    have hne : leases ≠ 0 := Nat.ne_of_gt hpos
    simp [governanceSnapshotAdmitted, hne]
  · simp [governanceSnapshotAdmitted]

/-- Theorem 4: Copied kv_prefix_digest with tampered frozen_prefix or mismatched proposal task_id fails closed. -/
theorem sm34_two_zone_recomputed_digest_and_task_binding (a b c : Bool) :
    twoZonePromptAndTaskAdmitted false b c = false ∧
    twoZonePromptAndTaskAdmitted a false c = false ∧
    twoZonePromptAndTaskAdmitted a b false = false ∧
    twoZonePromptAndTaskAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 5: Strict SM34 admission eliminates all 5 runtime-env & context exploit classes. -/
theorem sm34_strict_admission_eliminates_all_exploits (c : RuntimeEnvContextConfinementConfig)
    (h : strictSm34Admitted c = true) :
    anySm34ExploitReachable c = false := by
  cases c with
  | mk d e o r t tier =>
    simp [strictSm34Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨hd, he⟩, ho⟩, hr⟩, ht⟩, _⟩
    subst hd; subst he; subst ho; subst hr; subst ht
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 pressure tiers fail mandatory SM34 admission. -/
theorem sm34_gentle_pressure_rejected (c : RuntimeEnvContextConfinementConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm34Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm34Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm34Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm34_defective_configs_expose_live_exploits :
    anySm34ExploitReachable defectiveDirenvConfig = true ∧
    anySm34ExploitReachable defectiveEnvrcHomeConfig = true ∧
    anySm34ExploitReachable defectiveOrgStoreConfig = true ∧
    anySm34ExploitReachable defectiveRollbackConfig = true ∧
    anySm34ExploitReachable defectiveTwoZoneConfig = true ∧
    strictSm34Admitted defectiveGentleTierConfig = false ∧
    strictSm34Admitted hardenedSm34Config = true ∧
    anySm34ExploitReachable hardenedSm34Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive RuntimeEnvContextConfigKey where
  | direnvFilterAndCapture
  | envrcAndHomeConfinement
  | orgStoreSymlinkBounds
  | monotonicRollbackGuard
  | recomputedTwoZoneDigest
  | pressureTier
  deriving DecidableEq, Repr

inductive RuntimeEnvContextIssue where
  | direnvLoaderHijackOrUnboundedOutput
  | envrcOrSubAgentHomeEscape
  | orgStoreSymlinkEscapeOrUnboundedRead
  | orgSnapshotOrChannelEpochRollback
  | twoZonePrefixTamperOrTaskProxy
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def runtimeEnvContextView :
    View RuntimeEnvContextConfinementConfig RuntimeEnvContextConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseRuntimeEnvContextContract :
    Contract RuntimeEnvContextConfinementConfig RuntimeEnvContextConfigKey Unit RuntimeEnvContextIssue where
  view := runtimeEnvContextView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesDirenvFilterAndBoundedCapture then [] else [.rejected path .direnvLoaderHijackOrUnboundedOutput]) ++
    (if cfg.enforcesEnvrcAndSubAgentHomeConfinement then [] else [.rejected path .envrcOrSubAgentHomeEscape]) ++
    (if cfg.enforcesOrgStoreSymlinkAndReadBounds then [] else [.rejected path .orgStoreSymlinkEscapeOrUnboundedRead]) ++
    (if cfg.enforcesMonotonicOrgAndChannelAntiRollback then [] else [.rejected path .orgSnapshotOrChannelEpochRollback]) ++
    (if cfg.enforcesRecomputedTwoZoneDigestAndTaskBinding then [] else [.rejected path .twoZonePrefixTamperOrTaskProxy])
  validInventory := Or.inl rfl

def marlinRuntimeEnvContextContract :
    Contract RuntimeEnvContextConfinementConfig RuntimeEnvContextConfigKey Unit RuntimeEnvContextIssue :=
  refine baseRuntimeEnvContextContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin runtime-env/context contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm34_marlin_contract_refinement_laws
    (cfg : RuntimeEnvContextConfinementConfig) (path : List RuntimeEnvContextConfigKey) :
    (diagnose baseRuntimeEnvContextContract cfg path ≠ [] →
      diagnose marlinRuntimeEnvContextContract cfg path ≠ []) ∧
    (diagnose marlinRuntimeEnvContextContract cfg path = [] ↔
      diagnose baseRuntimeEnvContextContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path RuntimeEnvContextIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseRuntimeEnvContextContract _ cfg path,
   refine_accepts_iff baseRuntimeEnvContextContract _ cfg path⟩

inductive RuntimeEnvContextProofKey where
  | direnvFilterAndCapture
  | envrcAndHomeConfinement
  | orgStoreSymlinkBounds
  | monotonicRollbackGuard
  | recomputedTwoZoneDigest
  | pressureTier
  | maxDirenvJsonBytes
  deriving DecidableEq

abbrev RuntimeEnvContextProofValue : RuntimeEnvContextProofKey → Type
  | .direnvFilterAndCapture => Bool
  | .envrcAndHomeConfinement => Bool
  | .orgStoreSymlinkBounds => Bool
  | .monotonicRollbackGuard => Bool
  | .recomputedTwoZoneDigest => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxDirenvJsonBytes => Nat

def runtimeEnvContextObligation :
    LeanPoo.Proof.Obligation RuntimeEnvContextProofKey RuntimeEnvContextProofValue where
  dependencies := [
    .direnvFilterAndCapture,
    .envrcAndHomeConfinement,
    .orgStoreSymlinkBounds,
    .monotonicRollbackGuard,
    .recomputedTwoZoneDigest,
    .pressureTier
  ]
  holds := fun s =>
    s .direnvFilterAndCapture = true ∧
    s .envrcAndHomeConfinement = true ∧
    s .orgStoreSymlinkBounds = true ∧
    s .monotonicRollbackGuard = true ∧
    s .recomputedTwoZoneDigest = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .direnvFilterAndCapture = after .direnvFilterAndCapture :=
      same .direnvFilterAndCapture (by simp)
    have h2 : before .envrcAndHomeConfinement = after .envrcAndHomeConfinement :=
      same .envrcAndHomeConfinement (by simp)
    have h3 : before .orgStoreSymlinkBounds = after .orgStoreSymlinkBounds :=
      same .orgStoreSymlinkBounds (by simp)
    have h4 : before .monotonicRollbackGuard = after .monotonicRollbackGuard :=
      same .monotonicRollbackGuard (by simp)
    have h5 : before .recomputedTwoZoneDigest = after .recomputedTwoZoneDigest :=
      same .recomputedTwoZoneDigest (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineRuntimeEnvContextProof :
    LeanPoo.Proof.ProofObject RuntimeEnvContextProofKey RuntimeEnvContextProofValue where
  state := fun
    | .direnvFilterAndCapture => true
    | .envrcAndHomeConfinement => true
    | .orgStoreSymlinkBounds => true
    | .monotonicRollbackGuard => true
    | .recomputedTwoZoneDigest => true
    | .pressureTier => .l4HostileAttack
    | .maxDirenvJsonBytes => 1048576
  obligations := [runtimeEnvContextObligation]

/-- Theorem 9: Baseline ADV-L4 SM34 proof is certified. -/
theorem sm34_baseline_certified :
    LeanPoo.Proof.Certificate baselineRuntimeEnvContextProof := by
  intro obligation member
  have hEq : obligation = runtimeEnvContextObligation := by
    simpa [baselineRuntimeEnvContextProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def direnvByteCapTuningPatch :
    LeanPoo.Proof.Patch RuntimeEnvContextProofKey RuntimeEnvContextProofValue :=
  LeanPoo.Proof.Patch.set .maxDirenvJsonBytes 524288

/-- Theorem 10: Tuning bounded direnv JSON byte ceiling leaves SM34 security obligations untouched. -/
theorem sm34_obligation_untouched_by_byte_cap_tuning :
    LeanPoo.Proof.unaffected runtimeEnvContextObligation direnvByteCapTuningPatch := by
  intro key dep touched
  have hKey : key = .maxDirenvJsonBytes := by
    simpa [direnvByteCapTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [runtimeEnvContextObligation] at dep

/-- Theorem 11: Byte-cap tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm34_byte_cap_tuning_reuses_and_closes_certificate :
    runtimeEnvContextObligation.holds
      (LeanPoo.Proof.append baselineRuntimeEnvContextProof direnvByteCapTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineRuntimeEnvContextProof direnvByteCapTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineRuntimeEnvContextProof direnvByteCapTuningPatch
      sm34_baseline_certified runtimeEnvContextObligation
      (by simp [baselineRuntimeEnvContextProof]) sm34_obligation_untouched_by_byte_cap_tuning
  · apply LeanPoo.Proof.close baselineRuntimeEnvContextProof direnvByteCapTuningPatch
      sm34_baseline_certified
    · intro obligation member affected
      have hEq : obligation = runtimeEnvContextObligation := by
        simpa [baselineRuntimeEnvContextProof] using member
      subst obligation
      exact False.elim (affected sm34_obligation_untouched_by_byte_cap_tuning)
    · intro obligation member
      simp [direnvByteCapTuningPatch, LeanPoo.Proof.Patch.set] at member

def direnvFilterRegressionPatch :
    LeanPoo.Proof.Patch RuntimeEnvContextProofKey RuntimeEnvContextProofValue :=
  LeanPoo.Proof.Patch.set .direnvFilterAndCapture false

def envrcHomeRegressionPatch :
    LeanPoo.Proof.Patch RuntimeEnvContextProofKey RuntimeEnvContextProofValue :=
  LeanPoo.Proof.Patch.set .envrcAndHomeConfinement false

def orgStoreRegressionPatch :
    LeanPoo.Proof.Patch RuntimeEnvContextProofKey RuntimeEnvContextProofValue :=
  LeanPoo.Proof.Patch.set .orgStoreSymlinkBounds false

def rollbackRegressionPatch :
    LeanPoo.Proof.Patch RuntimeEnvContextProofKey RuntimeEnvContextProofValue :=
  LeanPoo.Proof.Patch.set .monotonicRollbackGuard false

def twoZoneRegressionPatch :
    LeanPoo.Proof.Patch RuntimeEnvContextProofKey RuntimeEnvContextProofValue :=
  LeanPoo.Proof.Patch.set .recomputedTwoZoneDigest false

/-- Theorem 12: Regressing any of the 5 SM34 runtime-env/context defenses invalidates LeanPoo certificate reuse. -/
theorem sm34_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected runtimeEnvContextObligation direnvFilterRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected runtimeEnvContextObligation envrcHomeRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected runtimeEnvContextObligation orgStoreRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected runtimeEnvContextObligation rollbackRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected runtimeEnvContextObligation twoZoneRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .direnvFilterAndCapture (by simp [runtimeEnvContextObligation])
      (by simp [direnvFilterRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .envrcAndHomeConfinement (by simp [runtimeEnvContextObligation])
      (by simp [envrcHomeRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .orgStoreSymlinkBounds (by simp [runtimeEnvContextObligation])
      (by simp [orgStoreRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .monotonicRollbackGuard (by simp [runtimeEnvContextObligation])
      (by simp [rollbackRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .recomputedTwoZoneDigest (by simp [runtimeEnvContextObligation])
      (by simp [twoZoneRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.RuntimeEnvActivationAndContextConfinement
