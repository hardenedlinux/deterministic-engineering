/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM25: Adversarial (`ADV-L4`) Single-Owner Graph Execution Convergence & Reachable Production Governance Confinement

Standalone objectified `LeanPoo` module (zero edits to `Core/Stability.lean`)
formalizing the real-world AI defensive-programming anti-pattern discovered in
`marlin-agent-core`:

When AI coding agents migrate an agent runtime from a legacy flat FSM loop engine
(`GenericLoopMachine` / `LoopProgramRuntimeSideEffectExecutor`) to an authoritative
GraphEngine (`GraphEngineOracle` + `TaskActorControlPlane` + `TaskActorKernelExecutor`
+ `CompositeAtomicEffectExecutor`), *additive defensive accretion* (keeping the
legacy Loop engine unretired and wiring `GovernanceAdmissionGate` /
`ExecutionCircuitBreaker` ONLY onto the legacy Loop executor) leaves the live
production GraphEngine host (`marlin_mygo_host`) completely ungated — unit tests
on the legacy Loop engine pass green while live production tools bypass E-Stop and
Cedar `forbid` rules!

This module proves:
1. Complete production mediation (`sm25_tripped_breaker_blocks_all_effects`,
   `sm25_cedar_forbid_blocks_all_effects`): when production GraphEngine executors
   and TaskActors are wired fail-closed to `GovernanceAdmissionGate`, a tripped
   E-Stop breaker or Cedar/ASCENT denial blocks EVERY side effect.
2. Disconnected-governance counterexample (`sm25_disconnected_governance_allows_bypass`):
   proves algebraically that wiring governance ONLY on a legacy Loop engine while
   leaving `prodExecutorWired = false` yields a concrete bypass even under E-Stop.
3. Single-owner shadow-engine retirement (`sm25_shadow_legacy_breaks_single_owner`):
   active unretired shadow legacy engines break single-owner mediation.
4. Unbounded `ADV-L4` zero-bypass induction (`sm25_compound_adv_l4_zero_bypass_invariant`).
5. `LeanPoo.Functional.ObjectContract.refine` & `LeanPoo.Proof.reuse`/`close`:
   tuning `maxToolBudgetUnits` reuses the certificate, whereas unwiring the
   production executor, reactivating shadow legacy execution, relaxing E-Stop, or
   downgrading pressure to `l1Gentle` invalidates certificate reuse.
-/

namespace DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement

open LeanPoo.Functional.ObjectContract
open LeanPoo.Functional.ObjectDiagnostics
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-! ## 1. Complete Mediation, Governance Reachability & Single-Owner Laws -/

inductive EngineOwner where
  | graphEngineCanonical
  | legacyLoopShadow
  deriving DecidableEq, Repr

inductive GovernanceVerdict where
  | permit
  | denyTrippedBreaker
  | denyCedarForbid
  | denyAscentFenced
  | denyStaleEpoch
  deriving DecidableEq, Repr

inductive SideEffectKind where
  | sandboxRun
  | casPut
  | llmComplete
  | taskActorDispatch
  deriving DecidableEq, Repr

structure GraphGovernanceTopology where
  prodExecutorWired : Bool
  taskActorWired : Bool
  shadowLegacyRetired : Bool
  breakerFailClosed : Bool
  epochBound : Bool
  maxToolBudgetUnits : Nat
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

def GraphGovernanceTopology.isHardened (t : GraphGovernanceTopology) : Prop :=
  t.prodExecutorWired = true ∧
  t.taskActorWired = true ∧
  t.shadowLegacyRetired = true ∧
  t.breakerFailClosed = true ∧
  t.epochBound = true ∧
  t.maxToolBudgetUnits > 0 ∧
  t.pressureTier.meetsMinimumFloor = true

/-- Evaluates whether an attempted side effect executes on the given engine owner
    under a given governance verdict. Returns `true` iff the effect actually runs. -/
def effectExecutes (t : GraphGovernanceTopology) (owner : EngineOwner)
    (kind : SideEffectKind) (verdict : GovernanceVerdict) : Bool :=
  match owner with
  | .legacyLoopShadow =>
    -- If shadow legacy engine is unretired, it can still execute outside canonical GraphEngine!
    !t.shadowLegacyRetired
  | .graphEngineCanonical =>
    let wired := match kind with
      | .taskActorDispatch => t.taskActorWired
      | _ => t.prodExecutorWired
    if !wired then
      -- Disconnected governance: production path executes blindly even when verdict denies!
      true
    else
      match verdict with
      | .permit => true
      | .denyTrippedBreaker => !t.breakerFailClosed
      | .denyCedarForbid => false
      | .denyAscentFenced => false
      | .denyStaleEpoch => !t.epochBound

/-- Theorem 1: Under hardened topology, a tripped E-Stop breaker blocks EVERY
    production GraphEngine effect (sandbox, CAS, LLM, TaskActor). -/
theorem sm25_tripped_breaker_blocks_all_effects
    (t : GraphGovernanceTopology) (hhard : t.isHardened) (kind : SideEffectKind) :
    effectExecutes t .graphEngineCanonical kind .denyTrippedBreaker = false := by
  rcases hhard with ⟨hp, ht, _, hb, _, _, _⟩
  cases kind <;> simp [effectExecutes, hp, ht, hb]

/-- Theorem 2: Under hardened topology, Cedar `forbid`, ASCENT fencing, and stale
    fencing/governance epochs block EVERY production effect and shadow engines
    execute ZERO effects. -/
theorem sm25_cedar_ascent_epoch_and_shadow_blocked
    (t : GraphGovernanceTopology) (hhard : t.isHardened) (kind : SideEffectKind) :
    effectExecutes t .graphEngineCanonical kind .denyCedarForbid = false ∧
    effectExecutes t .graphEngineCanonical kind .denyAscentFenced = false ∧
    effectExecutes t .graphEngineCanonical kind .denyStaleEpoch = false ∧
    effectExecutes t .legacyLoopShadow kind .permit = false := by
  rcases hhard with ⟨hp, ht, hs, _, he, _, _⟩
  cases kind <;> simp [effectExecutes, hp, ht, hs, he]

/-- Theorem 3 (Real-Repo Marlin Counterexample): If `prodExecutorWired = false`
    (governance attached only to legacy Loop engine), a tripped E-Stop STILL
    executes `sandboxRun` on the production GraphEngine! -/
theorem sm25_disconnected_governance_allows_bypass
    (t : GraphGovernanceTopology) (hunwired : t.prodExecutorWired = false) :
    effectExecutes t .graphEngineCanonical .sandboxRun .denyTrippedBreaker = true ∧
    effectExecutes t .graphEngineCanonical .sandboxRun .denyCedarForbid = true := by
  simp [effectExecutes, hunwired]

/-- Theorem 4: Leaving the shadow legacy Loop engine unretired breaks single-owner
    confinement (allows shadow execution bypassing canonical GraphEngine). -/
theorem sm25_shadow_legacy_breaks_single_owner
    (t : GraphGovernanceTopology) (hunretired : t.shadowLegacyRetired = false)
    (kind : SideEffectKind) :
    effectExecutes t .legacyLoopShadow kind .denyTrippedBreaker = true := by
  simp [effectExecutes, hunretired]

inductive HostileGraphGovProbe where
  | prodSandboxUnderEstop
  | prodSandboxUnderCedarForbid
  | taskActorUnderEstop
  | taskActorUnderStaleEpoch
  | shadowLegacyLoopBypass
  | cleanGovernedDispatch
  deriving DecidableEq, Repr

def probeBypassed (t : GraphGovernanceTopology) (probe : HostileGraphGovProbe) : Bool :=
  match probe with
  | .prodSandboxUnderEstop =>
    effectExecutes t .graphEngineCanonical .sandboxRun .denyTrippedBreaker
  | .prodSandboxUnderCedarForbid =>
    effectExecutes t .graphEngineCanonical .sandboxRun .denyCedarForbid
  | .taskActorUnderEstop =>
    effectExecutes t .graphEngineCanonical .taskActorDispatch .denyTrippedBreaker
  | .taskActorUnderStaleEpoch =>
    effectExecutes t .graphEngineCanonical .taskActorDispatch .denyStaleEpoch
  | .shadowLegacyLoopBypass =>
    effectExecutes t .legacyLoopShadow .sandboxRun .denyTrippedBreaker
  | .cleanGovernedDispatch => false

def countBypasses (t : GraphGovernanceTopology) : List HostileGraphGovProbe → Nat
  | [] => 0
  | x :: xs => (if probeBypassed t x then 1 else 0) + countBypasses t xs

/-- Theorem 5: Over any unbounded sequence of ADV-L4 split-brain and governance-evasion
    probes, hardened single-owner GraphEngine topology guarantees zero bypasses. -/
theorem sm25_compound_adv_l4_zero_bypass_invariant
    (t : GraphGovernanceTopology) (hhard : t.isHardened)
    (probes : List HostileGraphGovProbe) :
    countBypasses t probes = 0 := by
  rcases hhard with ⟨hp, ht, hs, hb, he, _, _⟩
  induction probes with
  | nil => rfl
  | cons x xs ih =>
    cases x <;> simp [countBypasses, probeBypassed, effectExecutes, hp, ht, hs, hb, he, ih]

/-- Theorem 6: Gentle L1/L2 pressure tiers fail hardened policy admission. -/
theorem sm25_gentle_pressure_rejected
    (t : GraphGovernanceTopology)
    (hgentle : t.pressureTier = .l1Gentle ∨ t.pressureTier = .l2Edge) :
    ¬ t.isHardened := by
  intro hhard
  rcases hhard with ⟨_, _, _, _, _, _, hfloor⟩
  rcases hgentle with h1 | h2
  · rw [h1] at hfloor
    simp [AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank] at hfloor
  · rw [h2] at hfloor
    simp [AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank] at hfloor

/-! ## 2. LeanPoo ObjectContract Refinement (`Marlin GraphEngine`) -/

inductive GraphGovConfigKey where
  | prodExecutorWired
  | taskActorWired
  | shadowLegacyRetired
  | breakerFailClosed
  | epochBound
  | pressureTier
  deriving DecidableEq, Repr

inductive GraphGovIssue where
  | prodExecutorGovernanceDisconnected
  | taskActorGovernanceDisconnected
  | shadowLegacyLoopUnretired
  | breakerNotFailClosed
  | fencingEpochUnbound
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def graphGovView : View GraphGovernanceTopology GraphGovConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base SM25 single-owner GraphEngine governance contract. -/
def baseGraphGovContract : Contract GraphGovernanceTopology GraphGovConfigKey Unit GraphGovIssue where
  view := graphGovView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.prodExecutorWired then [] else [.rejected path .prodExecutorGovernanceDisconnected]) ++
    (if cfg.taskActorWired then [] else [.rejected path .taskActorGovernanceDisconnected]) ++
    (if cfg.shadowLegacyRetired then [] else [.rejected path .shadowLegacyLoopUnretired]) ++
    (if cfg.breakerFailClosed then [] else [.rejected path .breakerNotFailClosed]) ++
    (if cfg.epochBound then [] else [.rejected path .fencingEpochUnbound])
  validInventory := Or.inl rfl

/-- Refined Marlin GraphEngine contract enforcing the mandatory `>= ADV-L3`
    adversarial pressure floor. -/
def marlinGraphGovContract : Contract GraphGovernanceTopology GraphGovConfigKey Unit GraphGovIssue :=
  refine baseGraphGovContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 7: Refined Marlin contract preserves every base governance rejection. -/
theorem sm25_marlin_graph_gov_preserves_rejection
    (cfg : GraphGovernanceTopology) (path : List GraphGovConfigKey)
    (hRej : diagnose baseGraphGovContract cfg path ≠ []) :
    diagnose marlinGraphGovContract cfg path ≠ [] :=
  refine_preserves_rejection baseGraphGovContract _ cfg path hRej

/-- Theorem 8: Exact acceptance characterization of refined contract. -/
theorem sm25_marlin_graph_gov_accepts_iff
    (cfg : GraphGovernanceTopology) (path : List GraphGovConfigKey) :
    diagnose marlinGraphGovContract cfg path = [] ↔
      diagnose baseGraphGovContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path GraphGovIssue.insufficientAdversarialPressure]) = [] :=
  refine_accepts_iff baseGraphGovContract _ cfg path

/-! ## 3. Dependency-Certified Proof Transport (`LeanPoo.Proof.Reuse`) -/

inductive GraphGovProofKey where
  | prodExecutorWired
  | taskActorWired
  | shadowLegacyRetired
  | breakerFailClosed
  | pressureTier
  | maxToolBudgetUnits
  deriving DecidableEq

abbrev GraphGovProofValue : GraphGovProofKey → Type
  | .prodExecutorWired => Bool
  | .taskActorWired => Bool
  | .shadowLegacyRetired => Bool
  | .breakerFailClosed => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxToolBudgetUnits => Nat

def graphGovObligation : LeanPoo.Proof.Obligation GraphGovProofKey GraphGovProofValue where
  dependencies := [.prodExecutorWired, .taskActorWired, .shadowLegacyRetired, .breakerFailClosed, .pressureTier]
  holds := fun s =>
    s .prodExecutorWired = true ∧
      s .taskActorWired = true ∧
      s .shadowLegacyRetired = true ∧
      s .breakerFailClosed = true ∧
      (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .prodExecutorWired = after .prodExecutorWired :=
      same .prodExecutorWired (by simp)
    have h2 : before .taskActorWired = after .taskActorWired :=
      same .taskActorWired (by simp)
    have h3 : before .shadowLegacyRetired = after .shadowLegacyRetired :=
      same .shadowLegacyRetired (by simp)
    have h4 : before .breakerFailClosed = after .breakerFailClosed :=
      same .breakerFailClosed (by simp)
    have h5 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5] using holds

def baselineGraphGovProof : LeanPoo.Proof.ProofObject GraphGovProofKey GraphGovProofValue where
  state := fun
    | .prodExecutorWired => true
    | .taskActorWired => true
    | .shadowLegacyRetired => true
    | .breakerFailClosed => true
    | .pressureTier => .l4HostileAttack
    | .maxToolBudgetUnits => 64
  obligations := [graphGovObligation]

/-- Theorem 9: Baseline ADV-L4 single-owner GraphEngine governance proof is certified. -/
theorem sm25_baseline_certified :
    LeanPoo.Proof.Certificate baselineGraphGovProof := by
  intro obligation member
  have hEq : obligation = graphGovObligation := by
    simpa [baselineGraphGovProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- Tuning `maxToolBudgetUnits` (`64 -> 128`) leaves governance wiring dependencies untouched. -/
def toolBudgetTuningPatch : LeanPoo.Proof.Patch GraphGovProofKey GraphGovProofValue :=
  LeanPoo.Proof.Patch.set .maxToolBudgetUnits 128

theorem sm25_obligation_untouched_by_budget_tuning :
    LeanPoo.Proof.unaffected graphGovObligation toolBudgetTuningPatch := by
  intro key dep touched
  have hKey : key = .maxToolBudgetUnits := by
    simpa [toolBudgetTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [graphGovObligation] at dep

/-- Theorems 10 & 11: Tool-budget tuning reuses and closes the LeanPoo certificate. -/
theorem sm25_budget_tuning_reuses_and_closes_certificate :
    graphGovObligation.holds
      (LeanPoo.Proof.append baselineGraphGovProof toolBudgetTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineGraphGovProof toolBudgetTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineGraphGovProof toolBudgetTuningPatch
      sm25_baseline_certified graphGovObligation
      (by simp [baselineGraphGovProof]) sm25_obligation_untouched_by_budget_tuning
  · apply LeanPoo.Proof.close baselineGraphGovProof toolBudgetTuningPatch
      sm25_baseline_certified
    · intro obligation member affected
      have hEq : obligation = graphGovObligation := by
        simpa [baselineGraphGovProof] using member
      subst obligation
      exact False.elim (affected sm25_obligation_untouched_by_budget_tuning)
    · intro obligation member
      simp [toolBudgetTuningPatch, LeanPoo.Proof.Patch.set] at member

/-- Theorem 12: Unwiring production executor governance, reactivating shadow legacy
    Loop execution, relaxing E-Stop fail-closed behavior, or downgrading pressure to
    `l1Gentle` all invalidate LeanPoo certificate reuse. -/
def unwireProdExecutorPatch : LeanPoo.Proof.Patch GraphGovProofKey GraphGovProofValue :=
  LeanPoo.Proof.Patch.set .prodExecutorWired false

def unretireShadowLoopPatch : LeanPoo.Proof.Patch GraphGovProofKey GraphGovProofValue :=
  LeanPoo.Proof.Patch.set .shadowLegacyRetired false

def relaxBreakerPatch : LeanPoo.Proof.Patch GraphGovProofKey GraphGovProofValue :=
  LeanPoo.Proof.Patch.set .breakerFailClosed false

def downgradeGraphGovPressurePatch : LeanPoo.Proof.Patch GraphGovProofKey GraphGovProofValue :=
  LeanPoo.Proof.Patch.set .pressureTier .l1Gentle

theorem sm25_architecture_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected graphGovObligation unwireProdExecutorPatch ∧
    ¬ LeanPoo.Proof.unaffected graphGovObligation unretireShadowLoopPatch ∧
    ¬ LeanPoo.Proof.unaffected graphGovObligation relaxBreakerPatch ∧
    ¬ LeanPoo.Proof.unaffected graphGovObligation downgradeGraphGovPressurePatch := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    exact h .prodExecutorWired (by simp [graphGovObligation])
      (by simp [unwireProdExecutorPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .shadowLegacyRetired (by simp [graphGovObligation])
      (by simp [unretireShadowLoopPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .breakerFailClosed (by simp [graphGovObligation])
      (by simp [relaxBreakerPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .pressureTier (by simp [graphGovObligation])
      (by simp [downgradeGraphGovPressurePatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.SingleOwnerGraphGovernanceConfinement
