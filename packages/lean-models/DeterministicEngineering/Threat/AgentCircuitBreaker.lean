/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Budget
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Transport

/-!
# AI Agent Tool Circuit Breaker, Lease-Epoch Fencing & Human-Only Re-Arm (`Threat.AgentCircuitBreaker`)

LeanPoo AI-Security refinement (E-Stop / fail-safe latched trip-wire outside AI agent
authority) sharing `Core.Budget` (tool execution budget ceiling), `Core.Order`
(monotonic trip-epoch fencing), and `Core.Transport` (`ObjectContract.refine` +
`Patch.frame` + `Proof.reuse`) with zero duplicated base mathematics.

Orthogonal to Quint (`packages/quint-models/threat/execution/agent-tool-circuit-breaker/AgentToolCircuitBreaker.qnt`,
which bounds `tripEpoch <= 4` and checks 4 finite guard-pruned countermodels):
this module proves:
1. **Tripped breaker unconditionally blocks all tool commits**.
2. **Unbounded trip-epoch fencing (`Core.Order`)**: advancing `tripEpoch` upon human
   re-arm rejects every pre-trip stale tool lease at any epoch `e < tripEpoch`.
3. **Human-only E-Stop re-arm**: an AI agent can never self-rearm a tripped breaker.
4. **Unbounded armed-window tool budget conservation (`Core.Budget`)**: for any tool-call
   cap `limit` and per-call cost `unitCost`, conserving `queued + active ≤ limit` bounds
   total retained tool-effect cost across arbitrary window sizes.
5. **Two-step LeanPoo `ObjectContract.refine` & one-line `Proof.reuse` (`Core.Transport`)**:
   AI-safe telemetry tuning transports the certificate cleanly, while allowing AI
   self-rearm invalidates proof reuse.
-/

namespace DeterministicEngineering.Threat.AgentCircuitBreaker

open DeterministicEngineering.Core.Budget
open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## 1. Unbounded Breaker Latch, Epoch Fencing & Human-Only Re-Arm Laws -/

/-- Whether a tool effect commit is admitted under the circuit breaker. -/
def toolCommitAdmitted
    (breakerTripped : Bool) (currentTripEpoch leaseEpoch : Nat)
    (budgetUsed budgetCap : Nat) : Bool :=
  match breakerTripped with
  | true => false
  | false =>
    match admitEpoch currentTripEpoch leaseEpoch with
    | false => false
    | true => decide (budgetUsed < budgetCap)

/-- Whether a breaker re-arm request is admitted (strictly human-only, never AI self-rearm). -/
def rearmAdmitted (isAiAgent verifiedHuman : Bool) : Bool :=
  match isAiAgent with
  | true => false
  | false => verifiedHuman

/-- Theorem 1: A tripped circuit breaker unconditionally blocks every tool commit. -/
theorem trippedBreaker_blocks_all_toolCommits
    (tripEp leaseEp used cap : Nat) :
    toolCommitAdmitted true tripEp leaseEp used cap = false :=
  rfl

/-- Theorem 2: Re-arming at an advanced trip epoch unconditionally rejects every pre-trip
    stale tool lease (reusing `Core.Order.advanceEpoch_rejects_strictly_older`). -/
theorem rearmTripEpoch_rejects_all_preTrip_staleLeases
    (tripEpoch nextEpoch staleLeaseEpoch used cap : Nat)
    (hStale : staleLeaseEpoch < tripEpoch) :
    toolCommitAdmitted false (advanceEpoch tripEpoch nextEpoch) staleLeaseEpoch used cap = false := by
  unfold toolCommitAdmitted
  rw [advanceEpoch_rejects_strictly_older tripEpoch nextEpoch staleLeaseEpoch hStale]

/-- Theorem 3: An AI agent can never self-rearm a tripped breaker, and an unverified actor
    cannot re-arm either. -/
theorem aiAgent_never_selfRearms_trippedBreaker (verifiedHuman : Bool) :
    rearmAdmitted true verifiedHuman = false ∧
    rearmAdmitted false false = false ∧
    rearmAdmitted false true = true :=
  ⟨rfl, rfl, rfl⟩

/-- Theorem 4: Unbounded armed-window tool budget ceiling (reusing `Core.Budget.conservation_bounds_peak`). -/
theorem toolCallBudget_bounded_within_armedWindow
    (queuedCalls activeCalls maxCalls unitCost fixedOverhead auditOverhead : Nat)
    (hConserved : queuedCalls + activeCalls ≤ maxCalls) :
    retainedBytes queuedCalls activeCalls unitCost fixedOverhead auditOverhead ≤
      maxCalls * unitCost + fixedOverhead + auditOverhead :=
  conservation_bounds_peak queuedCalls activeCalls maxCalls unitCost fixedOverhead auditOverhead hConserved

/-! ## 2. Two-Step LeanPoo `ObjectContract.refine` (reusing `Core.Transport`) -/

structure CircuitBreakerConfig where
  enforcesLatchedTripCheck : Bool
  enforcesHumanOnlyRearm : Bool
  enforcesLeaseEpochAndBudgetCap : Bool
  deriving DecidableEq, Repr

inductive CircuitBreakerConfigKey where
  | enforcesLatchedTripCheck
  | enforcesHumanOnlyRearm
  | enforcesLeaseEpochAndBudgetCap
  deriving DecidableEq, Repr

inductive CircuitBreakerIssue where
  | missingLatchedTripCheck
  | missingHumanOnlyRearm
  | missingLeaseEpochOrBudgetCap
  deriving DecidableEq, Repr

private def breakerView : View CircuitBreakerConfig CircuitBreakerConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseCircuitBreakerContract :
    Contract CircuitBreakerConfig CircuitBreakerConfigKey Unit CircuitBreakerIssue where
  view := breakerView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.enforcesLatchedTripCheck then [] else [.rejected path .missingLatchedTripCheck]
  validInventory := Or.inl rfl

def humanOnlyRearmExt (cfg : CircuitBreakerConfig) (path : List CircuitBreakerConfigKey) :
    List (Issue CircuitBreakerConfigKey CircuitBreakerIssue) :=
  if cfg.enforcesHumanOnlyRearm then [] else [.rejected path .missingHumanOnlyRearm]

def leaseBudgetExt (cfg : CircuitBreakerConfig) (path : List CircuitBreakerConfigKey) :
    List (Issue CircuitBreakerConfigKey CircuitBreakerIssue) :=
  if cfg.enforcesLeaseEpochAndBudgetCap then [] else [.rejected path .missingLeaseEpochOrBudgetCap]

def circuitBreakerContract :
    Contract CircuitBreakerConfig CircuitBreakerConfigKey Unit CircuitBreakerIssue :=
  refine (refine baseCircuitBreakerContract humanOnlyRearmExt) leaseBudgetExt

/-- Theorem 5: Two-step circuit breaker refinement monotonically preserves all base rejections. -/
theorem circuitBreakerContract_preserves_rejection
    (cfg : CircuitBreakerConfig) (path : List CircuitBreakerConfigKey)
    (hRej : diagnose baseCircuitBreakerContract cfg path ≠ []) :
    diagnose circuitBreakerContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseCircuitBreakerContract humanOnlyRearmExt leaseBudgetExt cfg path hRej

/-! ## 3. AI-SE Proof Transport via `Core.Transport` -/

inductive CircuitBreakerProofKey where
  | latchedTripChecked
  | humanOnlyRearmChecked
  | leaseEpochChecked
  | metricsFlushIntervalMs
  deriving DecidableEq

abbrev CircuitBreakerProofValue : CircuitBreakerProofKey → Type
  | .latchedTripChecked => Bool
  | .humanOnlyRearmChecked => Bool
  | .leaseEpochChecked => Bool
  | .metricsFlushIntervalMs => Nat

def circuitBreakerObligation :
    LeanPoo.Proof.Obligation CircuitBreakerProofKey CircuitBreakerProofValue where
  dependencies := [.latchedTripChecked, .humanOnlyRearmChecked, .leaseEpochChecked]
  holds := fun s =>
    s .latchedTripChecked = true ∧
    s .humanOnlyRearmChecked = true ∧
    s .leaseEpochChecked = true
  stable := by
    intro before after same holds
    exact ⟨(same .latchedTripChecked (by simp)).symm.trans holds.1,
           (same .humanOnlyRearmChecked (by simp)).symm.trans holds.2.1,
           (same .leaseEpochChecked (by simp)).symm.trans holds.2.2⟩

def baselineCircuitBreaker :
    LeanPoo.Proof.ProofObject CircuitBreakerProofKey CircuitBreakerProofValue where
  state := fun
    | .latchedTripChecked => true
    | .humanOnlyRearmChecked => true
    | .leaseEpochChecked => true
    | .metricsFlushIntervalMs => 500
  obligations := [circuitBreakerObligation]

theorem baselineCircuitBreakerCertified : LeanPoo.Proof.Certificate baselineCircuitBreaker := by
  intro ob hMem
  have hEq : ob = circuitBreakerObligation := by simpa [baselineCircuitBreaker] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl⟩

/-- Theorem 6: AI-safe telemetry flush interval tuning transports the breaker certificate in 1 line. -/
theorem breakerTelemetryTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineCircuitBreaker
        (LeanPoo.Proof.Patch.set .metricsFlushIntervalMs 1000)) :=
  close_single_set_untouched baselineCircuitBreaker circuitBreakerObligation
    .metricsFlushIntervalMs 1000 rfl baselineCircuitBreakerCertified (by simp [circuitBreakerObligation])

/-- Theorem 7: Negative control — AI regression allowing self-rearm invalidates proof reuse. -/
theorem allowAgentSelfRearm_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected circuitBreakerObligation
        (LeanPoo.Proof.Patch.set .humanOnlyRearmChecked false) :=
  set_dependency_invalidates_unaffected circuitBreakerObligation
    .humanOnlyRearmChecked false (by simp [circuitBreakerObligation])

end DeterministicEngineering.Threat.AgentCircuitBreaker
