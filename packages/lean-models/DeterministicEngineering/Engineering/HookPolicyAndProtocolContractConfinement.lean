/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM33: Adversarial (`ADV-L4`) Hook Policy Confinement, Anti-Shadowing Registry & Protocol Contract Validation

Standalone objectified `LeanPoo` module (51st Lean module, zero edits to
`Core/Stability.lean`) formalizing five real `ADV-L4` hook-orchestration and
protocol-contract vulnerabilities discovered in `marlin-agent-hooks` and
`marlin-agent-protocol`:

1. **Fail-Closed Hook TOML Config**: `HookConfigurationEnvelope`,
   `HookPolicyConfiguration`, and `HookRegistrationDefaults` omitted
   `#[serde(deny_unknown_fields)]` while defaulting to `ObserveOnly`, silently
   downgrading `EnforceTrusted` on typos/unknown fields; `from_toml_path` read
   unboundedly and `GerbilScheme` extensions admitted empty/traversal paths.
2. **Unique Hook Registry & Bounded Async Fan-Out**: `HookRegistry::register`
   admitted duplicate `hook_id` entries while `set_enabled` and `unregister`
   mutated only the first match, leaving sticky ghost hooks executing;
   `run_permitted_hook_registrations` spawned unbounded concurrent `Async` tasks.
3. **Immutable Trust-Floor Audit & Bounded Dynamic Actions**:
   `apply_dynamic_decision_action` overwrote `UntrustedRejected`/`ModifiedRejected`
   reasons with `ExtensionDeferred`/`ExtensionRejected`, and `prepare_dispatch`
   accepted unbounded dynamic actions and oversize/NUL `Rewrite` payloads.
4. **Contradiction-Free Sub-Agent Spawn Policy**: `SubAgentSpawnConfigSet`
   admitted `read_only = true && workspace_write = true`, zero budgets
   (`max_concurrency = 0` / `timeout_ms = 0` / `token_budget = 0`), unbounded
   descendant spawn depth, malformed Scheme modules, and unbounded file reads.
5. **Validated Session Deserialize & Endpoint Injection Refusal**:
   `RuntimeSessionId` bypassed `try_new` via derived `Deserialize`, and
   `ModelEndpoint::validate_contract` admitted CRLF/NUL/whitespace and
   `?`/`#`/`@`/`\`/`..` selector injection.
-/

namespace DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Fail-closed hook TOML configuration admission predicate. -/
def hookTomlConfigAdmitted
    (noUnknownFields : Bool)
    (withinByteCap : Bool)
    (extensionValid : Bool) : Bool :=
  noUnknownFields && withinByteCap && extensionValid

/-- Hook policy decision reason preservation law: Rust trust-floor rejections are immutable. -/
inductive HookDecisionReasonClass where
  | allowed
  | rustTrustRejected
  | extensionDeferred
  | extensionRejected
  deriving DecidableEq, Repr

def applyExtensionActionToReason
    (current : HookDecisionReasonClass)
    (isDeny : Bool) : HookDecisionReasonClass :=
  match current with
  | .rustTrustRejected => .rustTrustRejected
  | _ => if isDeny then .extensionRejected else .extensionDeferred

/-- Sub-agent spawn policy admission predicate rejecting contradictions, zero budgets, and runaway depth. -/
def subAgentPolicyAdmitted
    (readOnly workspaceWrite descendantSpawn : Bool)
    (maxConcurrency timeoutMs maxDepth maxAllowedDepth : Nat) : Bool :=
  !(readOnly && workspaceWrite) &&
  (0 < maxConcurrency) &&
  (0 < timeoutMs) &&
  (maxDepth ≤ maxAllowedDepth) &&
  (!descendantSpawn || (0 < maxDepth))

/-- Protocol identifier & model endpoint boundary admission law. -/
def protocolIdentifierAdmitted
    (nonBlank : Bool)
    (noControlOrWhitespace : Bool)
    (noUrlMetaOrTraversal : Bool) : Bool :=
  nonBlank && noControlOrWhitespace && noUrlMetaOrTraversal

/-- Security posture of Marlin hook orchestration & protocol contracts. -/
structure HookProtocolConfinementConfig where
  enforcesStrictHookTomlAndBoundedRead : Bool
  enforcesUniqueHookIdsAndBoundedAsyncFanout : Bool
  enforcesImmutableTrustFloorAndBoundedActions : Bool
  enforcesConsistentSubAgentPolicyAndBudgets : Bool
  enforcesValidatedSessionSerdeAndEndpointBoundary : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a hook/protocol configuration satisfies strict SM33 confinement. -/
def strictSm33Admitted (c : HookProtocolConfinementConfig) : Bool :=
  c.enforcesStrictHookTomlAndBoundedRead &&
  c.enforcesUniqueHookIdsAndBoundedAsyncFanout &&
  c.enforcesImmutableTrustFloorAndBoundedActions &&
  c.enforcesConsistentSubAgentPolicyAndBudgets &&
  c.enforcesValidatedSessionSerdeAndEndpointBoundary &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM33 hostile exploit classes remain reachable. -/
def anySm33ExploitReachable (c : HookProtocolConfinementConfig) : Bool :=
  !c.enforcesStrictHookTomlAndBoundedRead ||
  !c.enforcesUniqueHookIdsAndBoundedAsyncFanout ||
  !c.enforcesImmutableTrustFloorAndBoundedActions ||
  !c.enforcesConsistentSubAgentPolicyAndBudgets ||
  !c.enforcesValidatedSessionSerdeAndEndpointBoundary

/-- Canonical hardened SM33 posture. -/
def hardenedSm33Config : HookProtocolConfinementConfig :=
  { enforcesStrictHookTomlAndBoundedRead := true
    enforcesUniqueHookIdsAndBoundedAsyncFanout := true
    enforcesImmutableTrustFloorAndBoundedActions := true
    enforcesConsistentSubAgentPolicyAndBudgets := true
    enforcesValidatedSessionSerdeAndEndpointBoundary := true
    pressureTier := .l4HostileAttack }

def defectiveHookTomlConfig : HookProtocolConfinementConfig :=
  { hardenedSm33Config with enforcesStrictHookTomlAndBoundedRead := false }

def defectiveHookShadowConfig : HookProtocolConfinementConfig :=
  { hardenedSm33Config with enforcesUniqueHookIdsAndBoundedAsyncFanout := false }

def defectiveTrustMaskConfig : HookProtocolConfinementConfig :=
  { hardenedSm33Config with enforcesImmutableTrustFloorAndBoundedActions := false }

def defectiveSubAgentPolicyConfig : HookProtocolConfinementConfig :=
  { hardenedSm33Config with enforcesConsistentSubAgentPolicyAndBudgets := false }

def defectiveProtocolBoundaryConfig : HookProtocolConfinementConfig :=
  { hardenedSm33Config with enforcesValidatedSessionSerdeAndEndpointBoundary := false }

def defectiveGentleTierConfig : HookProtocolConfinementConfig :=
  { hardenedSm33Config with pressureTier := .l1Gentle }

/-- Theorem 1: Unknown TOML fields, oversize config files, or malformed GerbilScheme extensions fail hook config admission. -/
theorem sm33_hook_toml_config_fail_closed (a b c : Bool) :
    hookTomlConfigAdmitted false b c = false ∧
    hookTomlConfigAdmitted a false c = false ∧
    hookTomlConfigAdmitted a b false = false ∧
    hookTomlConfigAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 2: Rust trust-floor rejections (`UntrustedRejected` / `ModifiedRejected`) are immutable under extension `Defer` and `Deny`. -/
theorem sm33_rust_trust_rejection_immutable_under_extension (isDeny : Bool) :
    applyExtensionActionToReason .rustTrustRejected isDeny = .rustTrustRejected ∧
    applyExtensionActionToReason .extensionDeferred true = .extensionRejected := by
  cases isDeny <;> decide

/-- Theorem 3: Contradictory `read_only && workspace_write`, zero concurrency/timeout, and depth-0 descendant spawn are unconditionally refused. -/
theorem sm33_subagent_policy_refuses_contradiction_zero_budget_and_runaway
    (d : Bool) (c t depth cap : Nat) :
    subAgentPolicyAdmitted true true d c t depth cap = false ∧
    subAgentPolicyAdmitted false true d 0 t depth cap = false ∧
    subAgentPolicyAdmitted false true d c 0 depth cap = false ∧
    subAgentPolicyAdmitted false false true c t 0 cap = false ∧
    (cap < depth → subAgentPolicyAdmitted false false d c t depth cap = false) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · simp [subAgentPolicyAdmitted]
  · simp [subAgentPolicyAdmitted]
  · simp [subAgentPolicyAdmitted]
  · simp [subAgentPolicyAdmitted]
  · intro hgt
    have hnotle : ¬ (depth ≤ cap) := Nat.not_le_of_gt hgt
    simp [subAgentPolicyAdmitted, hnotle]

/-- Theorem 4: Blank session IDs, control/whitespace bytes, and URL meta/traversal characters fail protocol admission. -/
theorem sm33_protocol_identifier_refuses_blank_control_and_meta (a b c : Bool) :
    protocolIdentifierAdmitted false b c = false ∧
    protocolIdentifierAdmitted a false c = false ∧
    protocolIdentifierAdmitted a b false = false ∧
    protocolIdentifierAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 5: Strict SM33 admission eliminates all 5 hook/protocol exploit classes. -/
theorem sm33_strict_admission_eliminates_all_exploits (c : HookProtocolConfinementConfig)
    (h : strictSm33Admitted c = true) :
    anySm33ExploitReachable c = false := by
  cases c with
  | mk t u m s p tier =>
    simp [strictSm33Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨ht, hu⟩, hm⟩, hs⟩, hp⟩, _⟩
    subst ht; subst hu; subst hm; subst hs; subst hp
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 tiers fail mandatory SM33 admission. -/
theorem sm33_gentle_pressure_rejected (c : HookProtocolConfinementConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm33Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm33Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm33Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm33_defective_configs_expose_live_exploits :
    anySm33ExploitReachable defectiveHookTomlConfig = true ∧
    anySm33ExploitReachable defectiveHookShadowConfig = true ∧
    anySm33ExploitReachable defectiveTrustMaskConfig = true ∧
    anySm33ExploitReachable defectiveSubAgentPolicyConfig = true ∧
    anySm33ExploitReachable defectiveProtocolBoundaryConfig = true ∧
    strictSm33Admitted defectiveGentleTierConfig = false ∧
    strictSm33Admitted hardenedSm33Config = true ∧
    anySm33ExploitReachable hardenedSm33Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive HookProtocolConfigKey where
  | strictHookToml
  | uniqueHookIdsAndAsyncCap
  | immutableTrustFloor
  | consistentSubAgentPolicy
  | validatedProtocolBoundary
  | pressureTier
  deriving DecidableEq, Repr

inductive HookProtocolIssue where
  | hookTomlFailOpenOrUnbounded
  | duplicateHookShadowOrUnboundedAsync
  | trustRejectionMaskedOrActionFlood
  | subAgentContradictionOrZeroBudget
  | sessionSerdeBypassOrEndpointInjection
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def hookProtocolView : View HookProtocolConfinementConfig HookProtocolConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseHookProtocolContract :
    Contract HookProtocolConfinementConfig HookProtocolConfigKey Unit HookProtocolIssue where
  view := hookProtocolView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesStrictHookTomlAndBoundedRead then [] else [.rejected path .hookTomlFailOpenOrUnbounded]) ++
    (if cfg.enforcesUniqueHookIdsAndBoundedAsyncFanout then [] else [.rejected path .duplicateHookShadowOrUnboundedAsync]) ++
    (if cfg.enforcesImmutableTrustFloorAndBoundedActions then [] else [.rejected path .trustRejectionMaskedOrActionFlood]) ++
    (if cfg.enforcesConsistentSubAgentPolicyAndBudgets then [] else [.rejected path .subAgentContradictionOrZeroBudget]) ++
    (if cfg.enforcesValidatedSessionSerdeAndEndpointBoundary then [] else [.rejected path .sessionSerdeBypassOrEndpointInjection])
  validInventory := Or.inl rfl

def marlinHookProtocolContract :
    Contract HookProtocolConfinementConfig HookProtocolConfigKey Unit HookProtocolIssue :=
  refine baseHookProtocolContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin hook/protocol contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm33_marlin_contract_refinement_laws
    (cfg : HookProtocolConfinementConfig) (path : List HookProtocolConfigKey) :
    (diagnose baseHookProtocolContract cfg path ≠ [] →
      diagnose marlinHookProtocolContract cfg path ≠ []) ∧
    (diagnose marlinHookProtocolContract cfg path = [] ↔
      diagnose baseHookProtocolContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path HookProtocolIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseHookProtocolContract _ cfg path,
   refine_accepts_iff baseHookProtocolContract _ cfg path⟩

inductive HookProtocolProofKey where
  | strictHookToml
  | uniqueHookIdsAndAsyncCap
  | immutableTrustFloor
  | consistentSubAgentPolicy
  | validatedProtocolBoundary
  | pressureTier
  | maxAsyncHooks
  deriving DecidableEq

abbrev HookProtocolProofValue : HookProtocolProofKey → Type
  | .strictHookToml => Bool
  | .uniqueHookIdsAndAsyncCap => Bool
  | .immutableTrustFloor => Bool
  | .consistentSubAgentPolicy => Bool
  | .validatedProtocolBoundary => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxAsyncHooks => Nat

def hookProtocolObligation :
    LeanPoo.Proof.Obligation HookProtocolProofKey HookProtocolProofValue where
  dependencies := [
    .strictHookToml,
    .uniqueHookIdsAndAsyncCap,
    .immutableTrustFloor,
    .consistentSubAgentPolicy,
    .validatedProtocolBoundary,
    .pressureTier
  ]
  holds := fun s =>
    s .strictHookToml = true ∧
    s .uniqueHookIdsAndAsyncCap = true ∧
    s .immutableTrustFloor = true ∧
    s .consistentSubAgentPolicy = true ∧
    s .validatedProtocolBoundary = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .strictHookToml = after .strictHookToml :=
      same .strictHookToml (by simp)
    have h2 : before .uniqueHookIdsAndAsyncCap = after .uniqueHookIdsAndAsyncCap :=
      same .uniqueHookIdsAndAsyncCap (by simp)
    have h3 : before .immutableTrustFloor = after .immutableTrustFloor :=
      same .immutableTrustFloor (by simp)
    have h4 : before .consistentSubAgentPolicy = after .consistentSubAgentPolicy :=
      same .consistentSubAgentPolicy (by simp)
    have h5 : before .validatedProtocolBoundary = after .validatedProtocolBoundary :=
      same .validatedProtocolBoundary (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineHookProtocolProof :
    LeanPoo.Proof.ProofObject HookProtocolProofKey HookProtocolProofValue where
  state := fun
    | .strictHookToml => true
    | .uniqueHookIdsAndAsyncCap => true
    | .immutableTrustFloor => true
    | .consistentSubAgentPolicy => true
    | .validatedProtocolBoundary => true
    | .pressureTier => .l4HostileAttack
    | .maxAsyncHooks => 16
  obligations := [hookProtocolObligation]

/-- Theorem 9: Baseline ADV-L4 SM33 proof is certified. -/
theorem sm33_baseline_certified :
    LeanPoo.Proof.Certificate baselineHookProtocolProof := by
  intro obligation member
  have hEq : obligation = hookProtocolObligation := by
    simpa [baselineHookProtocolProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def asyncConcurrencyTuningPatch :
    LeanPoo.Proof.Patch HookProtocolProofKey HookProtocolProofValue :=
  LeanPoo.Proof.Patch.set .maxAsyncHooks 8

/-- Theorem 10: Tuning bounded async hook concurrency cap leaves SM33 security obligations untouched. -/
theorem sm33_obligation_untouched_by_concurrency_tuning :
    LeanPoo.Proof.unaffected hookProtocolObligation asyncConcurrencyTuningPatch := by
  intro key dep touched
  have hKey : key = .maxAsyncHooks := by
    simpa [asyncConcurrencyTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [hookProtocolObligation] at dep

/-- Theorem 11: Concurrency-cap tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm33_concurrency_tuning_reuses_and_closes_certificate :
    hookProtocolObligation.holds
      (LeanPoo.Proof.append baselineHookProtocolProof asyncConcurrencyTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineHookProtocolProof asyncConcurrencyTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineHookProtocolProof asyncConcurrencyTuningPatch
      sm33_baseline_certified hookProtocolObligation
      (by simp [baselineHookProtocolProof]) sm33_obligation_untouched_by_concurrency_tuning
  · apply LeanPoo.Proof.close baselineHookProtocolProof asyncConcurrencyTuningPatch
      sm33_baseline_certified
    · intro obligation member affected
      have hEq : obligation = hookProtocolObligation := by
        simpa [baselineHookProtocolProof] using member
      subst obligation
      exact False.elim (affected sm33_obligation_untouched_by_concurrency_tuning)
    · intro obligation member
      simp [asyncConcurrencyTuningPatch, LeanPoo.Proof.Patch.set] at member

def hookTomlRegressionPatch :
    LeanPoo.Proof.Patch HookProtocolProofKey HookProtocolProofValue :=
  LeanPoo.Proof.Patch.set .strictHookToml false

def hookShadowRegressionPatch :
    LeanPoo.Proof.Patch HookProtocolProofKey HookProtocolProofValue :=
  LeanPoo.Proof.Patch.set .uniqueHookIdsAndAsyncCap false

def trustMaskRegressionPatch :
    LeanPoo.Proof.Patch HookProtocolProofKey HookProtocolProofValue :=
  LeanPoo.Proof.Patch.set .immutableTrustFloor false

def subAgentPolicyRegressionPatch :
    LeanPoo.Proof.Patch HookProtocolProofKey HookProtocolProofValue :=
  LeanPoo.Proof.Patch.set .consistentSubAgentPolicy false

def protocolBoundaryRegressionPatch :
    LeanPoo.Proof.Patch HookProtocolProofKey HookProtocolProofValue :=
  LeanPoo.Proof.Patch.set .validatedProtocolBoundary false

/-- Theorem 12: Regressing any of the 5 SM33 hook/protocol defenses invalidates LeanPoo certificate reuse. -/
theorem sm33_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected hookProtocolObligation hookTomlRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected hookProtocolObligation hookShadowRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected hookProtocolObligation trustMaskRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected hookProtocolObligation subAgentPolicyRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected hookProtocolObligation protocolBoundaryRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .strictHookToml (by simp [hookProtocolObligation])
      (by simp [hookTomlRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .uniqueHookIdsAndAsyncCap (by simp [hookProtocolObligation])
      (by simp [hookShadowRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .immutableTrustFloor (by simp [hookProtocolObligation])
      (by simp [trustMaskRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .consistentSubAgentPolicy (by simp [hookProtocolObligation])
      (by simp [subAgentPolicyRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .validatedProtocolBoundary (by simp [hookProtocolObligation])
      (by simp [protocolBoundaryRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.HookPolicyAndProtocolContractConfinement
