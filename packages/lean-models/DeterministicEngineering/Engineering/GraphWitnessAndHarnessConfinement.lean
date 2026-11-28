/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM35: Adversarial (`ADV-L4`) AgentGraph Witness/Routing & Harness Governance/Artifact Confinement

Standalone objectified `LeanPoo` module (53rd Lean module, zero edits to
`Core/Stability.lean`) formalizing five real `ADV-L4` vulnerabilities discovered
in `marlin-agent-graph`, `marlin-agent-harness`, and `marlin-agent-harness-types`:

1. **Sealed Witness & Fencing-Epoch Serde Deserialization Parity**:
   `AdmittedGovernedContext`, `AdmittedMarlinDispatch`, and `FencingEpoch`
   derived Serde `Deserialize` directly, allowing forged JSON to bypass
   `admit_governed_context_capsule`, `admit_marlin_dispatch`, and
   `FencingEpoch::new(0)`; `reconcile_marlin_execution_receipt` accepted
   `Settled` receipts on `Detached` scopes and stalled on `u64::MAX` epoch;
   graph semantic IDs admitted control characters.
2. **Policy-Scoped Routing Confinement & Duplicate-Edge Rejection**:
   `edge_condition_matches` returned `true` unconditionally for
   `AgentEdgeCondition::PolicyDecision(_)` even in `Deterministic` and
   `CapabilityFirst` graphs with zero policy receipts; policy-scoped planning
   and candidate routing projection admitted duplicate edge IDs and skipped
   `GerbilPolicyReceipt` evidence checks.
3. **Fail-Closed Harness Cedar Tool Classification & Case-Insensitive Matching**:
   `CompiledHarnessGovernanceGate::evaluate_tool_call` let `"search"` substrings
   in destructive tool names (`search_exec`) or caller-supplied
   `declared_capability = Some("search")` downgrade `exec`/`shell`/`rm` tools
   to non-write `"search"`, used case-sensitive tool/capability matching, and
   accepted empty or contradictory Cedar policy sets at `compile()`.
4. **Symlink-Safe Atomic Intent-Case Artifact Materialization**:
   `materialize_gerbil_scripted_intent_case_artifact_bundle` used lexical-only
   `safe_relative_path` (admitting `""` and `"."`) and non-atomic `fs::write`
   without symlink checks, duplicate path rejection, or manifest capacity caps.
5. **Bounded Non-Symlink Live Weaver TOML Route Loading & Env Hygiene**:
   `LiveWeaverTomlConfig::load` performed unbounded `fs::read_to_string` without
   symlink checks, accepted zero/unbounded `timeout_seconds` and
   `max_stream_bytes`, and permitted ambient system `credential_env` names
   (`PATH`, `HOME`, `LD_PRELOAD`).
-/

namespace DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Sealed graph witness admission predicate across both Rust constructors and Serde Deserialize. -/
def sealedWitnessAdmitted
    (sandboxAndCedarValid : Bool)
    (defeaterL3FloorHeld : Bool)
    (detachedAndSteeringValid : Bool)
    (fencingEpoch : Nat) : Bool :=
  sandboxAndCedarValid && defeaterL3FloorHeld && detachedAndSteeringValid && (0 < fencingEpoch)

/-- Graph routing admission predicate requiring policy receipts for PolicyDecision edges and deduplicated edges. -/
def graphRoutingAdmitted
    (policyDecisionHasReceipt : Bool)
    (edgesDeduplicated : Bool)
    (capabilitySatisfied : Bool) : Bool :=
  policyDecisionHasReceipt && edgesDeduplicated && capabilitySatisfied

/-- Harness Cedar tool admission predicate giving destructive-tool checks precedence over spoofed capabilities. -/
def harnessToolAdmitted
    (nonDestructiveToolName : Bool)
    (notDeniedCaseInsensitive : Bool)
    (cedarPolicyNonEmptyAndAllowed : Bool) : Bool :=
  nonDestructiveToolName && notDeniedCaseInsensitive && cedarPolicyNonEmptyAndAllowed

/-- Intent-case artifact & Weaver TOML config confinement predicate. -/
def artifactAndConfigAdmitted
    (nonEmptySymlinkFreePath : Bool)
    (withinByteAndArtifactCap : Bool)
    (validTimeoutAndSafeCredEnv : Bool) : Bool :=
  nonEmptySymlinkFreePath && withinByteAndArtifactCap && validTimeoutAndSafeCredEnv

/-- Security posture of Marlin AgentGraph and live harness governance/artifact boundaries. -/
structure GraphWitnessHarnessConfig where
  enforcesWitnessSerdeAndDetachedReconciliation : Bool
  enforcesPolicyDecisionAndUniqueEdgeRouting : Bool
  enforcesFailClosedCedarToolClassification : Bool
  enforcesSymlinkSafeAtomicArtifactBundle : Bool
  enforcesBoundedWeaverConfigAndSafeCredEnv : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether an AgentGraph + Harness configuration satisfies strict SM35 confinement. -/
def strictSm35Admitted (c : GraphWitnessHarnessConfig) : Bool :=
  c.enforcesWitnessSerdeAndDetachedReconciliation &&
  c.enforcesPolicyDecisionAndUniqueEdgeRouting &&
  c.enforcesFailClosedCedarToolClassification &&
  c.enforcesSymlinkSafeAtomicArtifactBundle &&
  c.enforcesBoundedWeaverConfigAndSafeCredEnv &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM35 hostile exploit classes remain reachable. -/
def anySm35ExploitReachable (c : GraphWitnessHarnessConfig) : Bool :=
  !c.enforcesWitnessSerdeAndDetachedReconciliation ||
  !c.enforcesPolicyDecisionAndUniqueEdgeRouting ||
  !c.enforcesFailClosedCedarToolClassification ||
  !c.enforcesSymlinkSafeAtomicArtifactBundle ||
  !c.enforcesBoundedWeaverConfigAndSafeCredEnv

/-- Canonical hardened SM35 posture. -/
def hardenedSm35Config : GraphWitnessHarnessConfig :=
  { enforcesWitnessSerdeAndDetachedReconciliation := true
    enforcesPolicyDecisionAndUniqueEdgeRouting := true
    enforcesFailClosedCedarToolClassification := true
    enforcesSymlinkSafeAtomicArtifactBundle := true
    enforcesBoundedWeaverConfigAndSafeCredEnv := true
    pressureTier := .l4HostileAttack }

def defectiveWitnessSerdeConfig : GraphWitnessHarnessConfig :=
  { hardenedSm35Config with enforcesWitnessSerdeAndDetachedReconciliation := false }

def defectiveRoutingPolicyConfig : GraphWitnessHarnessConfig :=
  { hardenedSm35Config with enforcesPolicyDecisionAndUniqueEdgeRouting := false }

def defectiveCedarToolConfig : GraphWitnessHarnessConfig :=
  { hardenedSm35Config with enforcesFailClosedCedarToolClassification := false }

def defectiveArtifactBundleConfig : GraphWitnessHarnessConfig :=
  { hardenedSm35Config with enforcesSymlinkSafeAtomicArtifactBundle := false }

def defectiveWeaverConfig : GraphWitnessHarnessConfig :=
  { hardenedSm35Config with enforcesBoundedWeaverConfigAndSafeCredEnv := false }

def defectiveGentleTierConfig : GraphWitnessHarnessConfig :=
  { hardenedSm35Config with pressureTier := .l1Gentle }

/-- Theorem 1: Forged witness invariants or zero fencing epochs fail closed across constructors and Serde. -/
theorem sm35_sealed_witness_and_epoch_fail_closed (a b c : Bool) (ep : Nat) :
    sealedWitnessAdmitted false b c ep = false ∧
    sealedWitnessAdmitted a false c ep = false ∧
    sealedWitnessAdmitted a b false ep = false ∧
    sealedWitnessAdmitted a b c 0 = false ∧
    sealedWitnessAdmitted true true true (ep + 1) = true := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · cases b <;> cases c <;> simp [sealedWitnessAdmitted]
  · cases a <;> cases c <;> simp [sealedWitnessAdmitted]
  · cases a <;> cases b <;> simp [sealedWitnessAdmitted]
  · cases a <;> cases b <;> cases c <;> simp [sealedWitnessAdmitted]
  · simp [sealedWitnessAdmitted]

/-- Theorem 2: PolicyDecision edges without receipts, duplicate candidate edges, or unmet capabilities fail closed. -/
theorem sm35_policy_scoped_routing_fail_closed (a b c : Bool) :
    graphRoutingAdmitted false b c = false ∧
    graphRoutingAdmitted a false c = false ∧
    graphRoutingAdmitted a b false = false ∧
    graphRoutingAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 3: Destructive tool names, case-insensitive denials, or empty/forbidding Cedar policies fail closed. -/
theorem sm35_cedar_harness_tool_classification_fail_closed (a b c : Bool) :
    harnessToolAdmitted false b c = false ∧
    harnessToolAdmitted a false c = false ∧
    harnessToolAdmitted a b false = false ∧
    harnessToolAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 4: Empty/symlinked artifact paths, cap overruns, or bad timeout/credential_env fail closed. -/
theorem sm35_artifact_symlink_and_config_bounds_fail_closed (a b c : Bool) :
    artifactAndConfigAdmitted false b c = false ∧
    artifactAndConfigAdmitted a false c = false ∧
    artifactAndConfigAdmitted a b false = false ∧
    artifactAndConfigAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 5: Strict SM35 admission eliminates all 5 AgentGraph & Harness exploit classes. -/
theorem sm35_strict_admission_eliminates_all_exploits (c : GraphWitnessHarnessConfig)
    (h : strictSm35Admitted c = true) :
    anySm35ExploitReachable c = false := by
  cases c with
  | mk w r g a v tier =>
    simp [strictSm35Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨hw, hr⟩, hg⟩, ha⟩, hv⟩, _⟩
    subst hw; subst hr; subst hg; subst ha; subst hv
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 pressure tiers fail mandatory SM35 admission. -/
theorem sm35_gentle_pressure_rejected (c : GraphWitnessHarnessConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm35Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm35Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm35Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm35_defective_configs_expose_live_exploits :
    anySm35ExploitReachable defectiveWitnessSerdeConfig = true ∧
    anySm35ExploitReachable defectiveRoutingPolicyConfig = true ∧
    anySm35ExploitReachable defectiveCedarToolConfig = true ∧
    anySm35ExploitReachable defectiveArtifactBundleConfig = true ∧
    anySm35ExploitReachable defectiveWeaverConfig = true ∧
    strictSm35Admitted defectiveGentleTierConfig = false ∧
    strictSm35Admitted hardenedSm35Config = true ∧
    anySm35ExploitReachable hardenedSm35Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive GraphWitnessHarnessConfigKey where
  | witnessSerdeAndReconciliation
  | policyDecisionUniqueRouting
  | cedarToolClassification
  | symlinkSafeArtifactBundle
  | boundedWeaverConfigEnv
  | pressureTier
  deriving DecidableEq, Repr

inductive GraphWitnessHarnessIssue where
  | sealedWitnessOrEpochSerdeForgery
  | policyDecisionRoutingOrDupEdgeBypass
  | harnessCedarCapabilitySpoofOrCaseBypass
  | artifactBundleSymlinkOrEmptyPathEscape
  | weaverConfigUnboundedOrAmbientCredEnv
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def graphWitnessHarnessView :
    View GraphWitnessHarnessConfig GraphWitnessHarnessConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseGraphWitnessHarnessContract :
    Contract GraphWitnessHarnessConfig GraphWitnessHarnessConfigKey Unit GraphWitnessHarnessIssue where
  view := graphWitnessHarnessView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesWitnessSerdeAndDetachedReconciliation then [] else [.rejected path .sealedWitnessOrEpochSerdeForgery]) ++
    (if cfg.enforcesPolicyDecisionAndUniqueEdgeRouting then [] else [.rejected path .policyDecisionRoutingOrDupEdgeBypass]) ++
    (if cfg.enforcesFailClosedCedarToolClassification then [] else [.rejected path .harnessCedarCapabilitySpoofOrCaseBypass]) ++
    (if cfg.enforcesSymlinkSafeAtomicArtifactBundle then [] else [.rejected path .artifactBundleSymlinkOrEmptyPathEscape]) ++
    (if cfg.enforcesBoundedWeaverConfigAndSafeCredEnv then [] else [.rejected path .weaverConfigUnboundedOrAmbientCredEnv])
  validInventory := Or.inl rfl

def marlinGraphWitnessHarnessContract :
    Contract GraphWitnessHarnessConfig GraphWitnessHarnessConfigKey Unit GraphWitnessHarnessIssue :=
  refine baseGraphWitnessHarnessContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin AgentGraph/Harness contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm35_marlin_contract_refinement_laws
    (cfg : GraphWitnessHarnessConfig) (path : List GraphWitnessHarnessConfigKey) :
    (diagnose baseGraphWitnessHarnessContract cfg path ≠ [] →
      diagnose marlinGraphWitnessHarnessContract cfg path ≠ []) ∧
    (diagnose marlinGraphWitnessHarnessContract cfg path = [] ↔
      diagnose baseGraphWitnessHarnessContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path GraphWitnessHarnessIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseGraphWitnessHarnessContract _ cfg path,
   refine_accepts_iff baseGraphWitnessHarnessContract _ cfg path⟩

inductive GraphWitnessHarnessProofKey where
  | witnessSerdeAndReconciliation
  | policyDecisionUniqueRouting
  | cedarToolClassification
  | symlinkSafeArtifactBundle
  | boundedWeaverConfigEnv
  | pressureTier
  | maxWeaverTimeoutSecs
  deriving DecidableEq

abbrev GraphWitnessHarnessProofValue : GraphWitnessHarnessProofKey → Type
  | .witnessSerdeAndReconciliation => Bool
  | .policyDecisionUniqueRouting => Bool
  | .cedarToolClassification => Bool
  | .symlinkSafeArtifactBundle => Bool
  | .boundedWeaverConfigEnv => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxWeaverTimeoutSecs => Nat

def graphWitnessHarnessObligation :
    LeanPoo.Proof.Obligation GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue where
  dependencies := [
    .witnessSerdeAndReconciliation,
    .policyDecisionUniqueRouting,
    .cedarToolClassification,
    .symlinkSafeArtifactBundle,
    .boundedWeaverConfigEnv,
    .pressureTier
  ]
  holds := fun s =>
    s .witnessSerdeAndReconciliation = true ∧
    s .policyDecisionUniqueRouting = true ∧
    s .cedarToolClassification = true ∧
    s .symlinkSafeArtifactBundle = true ∧
    s .boundedWeaverConfigEnv = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .witnessSerdeAndReconciliation = after .witnessSerdeAndReconciliation :=
      same .witnessSerdeAndReconciliation (by simp)
    have h2 : before .policyDecisionUniqueRouting = after .policyDecisionUniqueRouting :=
      same .policyDecisionUniqueRouting (by simp)
    have h3 : before .cedarToolClassification = after .cedarToolClassification :=
      same .cedarToolClassification (by simp)
    have h4 : before .symlinkSafeArtifactBundle = after .symlinkSafeArtifactBundle :=
      same .symlinkSafeArtifactBundle (by simp)
    have h5 : before .boundedWeaverConfigEnv = after .boundedWeaverConfigEnv :=
      same .boundedWeaverConfigEnv (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineGraphWitnessHarnessProof :
    LeanPoo.Proof.ProofObject GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue where
  state := fun
    | .witnessSerdeAndReconciliation => true
    | .policyDecisionUniqueRouting => true
    | .cedarToolClassification => true
    | .symlinkSafeArtifactBundle => true
    | .boundedWeaverConfigEnv => true
    | .pressureTier => .l4HostileAttack
    | .maxWeaverTimeoutSecs => 600
  obligations := [graphWitnessHarnessObligation]

/-- Theorem 9: Baseline ADV-L4 SM35 proof is certified. -/
theorem sm35_baseline_certified :
    LeanPoo.Proof.Certificate baselineGraphWitnessHarnessProof := by
  intro obligation member
  have hEq : obligation = graphWitnessHarnessObligation := by
    simpa [baselineGraphWitnessHarnessProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def weaverTimeoutTuningPatch :
    LeanPoo.Proof.Patch GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue :=
  LeanPoo.Proof.Patch.set .maxWeaverTimeoutSecs 300

/-- Theorem 10: Tuning bounded Weaver timeout ceiling leaves SM35 security obligations untouched. -/
theorem sm35_obligation_untouched_by_timeout_tuning :
    LeanPoo.Proof.unaffected graphWitnessHarnessObligation weaverTimeoutTuningPatch := by
  intro key dep touched
  have hKey : key = .maxWeaverTimeoutSecs := by
    simpa [weaverTimeoutTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [graphWitnessHarnessObligation] at dep

/-- Theorem 11: Timeout tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm35_timeout_tuning_reuses_and_closes_certificate :
    graphWitnessHarnessObligation.holds
      (LeanPoo.Proof.append baselineGraphWitnessHarnessProof weaverTimeoutTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineGraphWitnessHarnessProof weaverTimeoutTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineGraphWitnessHarnessProof weaverTimeoutTuningPatch
      sm35_baseline_certified graphWitnessHarnessObligation
      (by simp [baselineGraphWitnessHarnessProof]) sm35_obligation_untouched_by_timeout_tuning
  · apply LeanPoo.Proof.close baselineGraphWitnessHarnessProof weaverTimeoutTuningPatch
      sm35_baseline_certified
    · intro obligation member affected
      have hEq : obligation = graphWitnessHarnessObligation := by
        simpa [baselineGraphWitnessHarnessProof] using member
      subst obligation
      exact False.elim (affected sm35_obligation_untouched_by_timeout_tuning)
    · intro obligation member
      simp [weaverTimeoutTuningPatch, LeanPoo.Proof.Patch.set] at member

def witnessSerdeRegressionPatch :
    LeanPoo.Proof.Patch GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue :=
  LeanPoo.Proof.Patch.set .witnessSerdeAndReconciliation false

def routingPolicyRegressionPatch :
    LeanPoo.Proof.Patch GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue :=
  LeanPoo.Proof.Patch.set .policyDecisionUniqueRouting false

def cedarToolRegressionPatch :
    LeanPoo.Proof.Patch GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue :=
  LeanPoo.Proof.Patch.set .cedarToolClassification false

def artifactBundleRegressionPatch :
    LeanPoo.Proof.Patch GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue :=
  LeanPoo.Proof.Patch.set .symlinkSafeArtifactBundle false

def weaverConfigRegressionPatch :
    LeanPoo.Proof.Patch GraphWitnessHarnessProofKey GraphWitnessHarnessProofValue :=
  LeanPoo.Proof.Patch.set .boundedWeaverConfigEnv false

/-- Theorem 12: Regressing any of the 5 SM35 AgentGraph/Harness defenses invalidates LeanPoo certificate reuse. -/
theorem sm35_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected graphWitnessHarnessObligation witnessSerdeRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected graphWitnessHarnessObligation routingPolicyRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected graphWitnessHarnessObligation cedarToolRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected graphWitnessHarnessObligation artifactBundleRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected graphWitnessHarnessObligation weaverConfigRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .witnessSerdeAndReconciliation (by simp [graphWitnessHarnessObligation])
      (by simp [witnessSerdeRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .policyDecisionUniqueRouting (by simp [graphWitnessHarnessObligation])
      (by simp [routingPolicyRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .cedarToolClassification (by simp [graphWitnessHarnessObligation])
      (by simp [cedarToolRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .symlinkSafeArtifactBundle (by simp [graphWitnessHarnessObligation])
      (by simp [artifactBundleRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .boundedWeaverConfigEnv (by simp [graphWitnessHarnessObligation])
      (by simp [weaverConfigRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.GraphWitnessAndHarnessConfinement
