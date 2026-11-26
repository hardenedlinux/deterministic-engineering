/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.ContextDistillationAndProvenance

/-!
# LeanPoo Unbounded Federated Multi-Agent Arbitration, Bounded Liveness & Non-Blocking Escalation (`B13`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `ContextDistillationAndProvenance` (all 11 prior modules, 126 theorems)
and adds 10 machine-checked liveness, deadlock-termination, and absorbing-terminal-state
theorems — completing the **12-module, 136-theorem pure `LeanPoo` formal library**.

Machine-checked theorems (10 total -> **136 theorems across 12 modules**, zero `sorry`, zero custom axioms):
1. `retry_budget_exhaustion_blocks_auto_retry` — reaching `maxAttempts` unconditionally halts auto-retry
2. `deadlock_immediately_blocks_auto_retry` — detected wait-cycle immediately halts auto-retry
3. `exhausted_or_deadlocked_leaves_active_phase` — bounded liveness: active swarm never stalls forever
4. `routed_escalation_reaches_human_phase` — routed exhaustion/deadlock deterministically escalates to human
5. `unrouted_escalation_fails_closed_to_safe_abort` — unrouted exhaustion/deadlock fails closed to safe abort
6. `terminal_phases_are_absorbing` — escalated, safely-aborted, and admitted phases are strictly absorbing
7. `bounded_transition_never_auto_admits_on_failure` — fallback transition can NEVER silently flip to `.admitted`
8. `federatedArbitrationContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Escalation host)
9. `escalationAlertDelayTuning_preserves_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingRetryCap_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.FederatedArbitrationLiveness

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Bounded Retry Termination, Deadlock Preemption & Absorbing Terminal Phases (`B13`) -/

section FederatedArbitration

inductive ArbitrationPhase where
  | active
  | escalatedToHuman
  | safelyAborted
  | admitted
  deriving DecidableEq, Repr

structure SwarmArbitrationState where
  attemptsUsed : Nat
  maxAttempts : Nat
  deadlockDetected : Bool
  rollbackCutPinned : Bool
  humanEscalationRouted : Bool
  phase : ArbitrationPhase
  deriving DecidableEq, Repr

/-- Auto-retry is strictly permitted ONLY while `.active`, deadlock-free, and strictly
    below `maxAttempts`. -/
def canAttemptAutoRetry (s : SwarmArbitrationState) : Bool :=
  decide (s.phase = .active) &&
  !s.deadlockDetected &&
  decide (s.attemptsUsed < s.maxAttempts)

/-- Deterministic bounded liveness transition matching `FederatedSwarmArbitrator.stepBoundary`.
    Never stalls in `.active` once deadlocked or exhausted, and NEVER silently flips to `.admitted`. -/
def nextBoundedTransition (s : SwarmArbitrationState) : ArbitrationPhase :=
  match s.phase with
  | .active =>
    if s.deadlockDetected || decide (s.attemptsUsed ≥ s.maxAttempts) then
      if s.humanEscalationRouted then .escalatedToHuman else .safelyAborted
    else
      .active
  | p => p

/-- **Theorem 1 (Finite Retry Termination)**: Once `attemptsUsed ≥ maxAttempts`,
    automatic retry is unconditionally forbidden. -/
theorem retry_budget_exhaustion_blocks_auto_retry (s : SwarmArbitrationState)
    (hExhausted : s.attemptsUsed ≥ s.maxAttempts) :
    canAttemptAutoRetry s = false := by
  have hNotLt : ¬ (s.attemptsUsed < s.maxAttempts) := by omega
  simp [canAttemptAutoRetry, hNotLt]

/-- **Theorem 2 (Deadlock Preemption)**: Any detected circular wait deadlock immediately
    blocks further automatic retries regardless of remaining budget. -/
theorem deadlock_immediately_blocks_auto_retry (s : SwarmArbitrationState)
    (hDeadlock : s.deadlockDetected = true) :
    canAttemptAutoRetry s = false := by
  simp [canAttemptAutoRetry, hDeadlock]

/-- **Theorem 3 (Bounded Liveness — Guaranteed Exit From `.active`)**: Any active swarm
    that either deadlocks OR exhausts its retry budget deterministically leaves `.active`. -/
theorem exhausted_or_deadlocked_leaves_active_phase (s : SwarmArbitrationState)
    (hActive : s.phase = .active)
    (hStop : s.deadlockDetected = true ∨ s.attemptsUsed ≥ s.maxAttempts) :
    nextBoundedTransition s ≠ .active := by
  rw [nextBoundedTransition, hActive]
  rcases hStop with hDead | hExh
  · cases s.humanEscalationRouted <;> simp [hDead]
  · cases s.humanEscalationRouted <;> simp [hExh]

/-- **Theorem 4 (Deterministic Human Escalation)**: When `humanEscalationRouted = true`,
    any deadlocked or exhausted active swarm transitions directly to `.escalatedToHuman`. -/
theorem routed_escalation_reaches_human_phase (s : SwarmArbitrationState)
    (hActive : s.phase = .active)
    (hStop : s.deadlockDetected = true ∨ s.attemptsUsed ≥ s.maxAttempts)
    (hRouted : s.humanEscalationRouted = true) :
    nextBoundedTransition s = .escalatedToHuman := by
  rw [nextBoundedTransition, hActive]
  rcases hStop with hDead | hExh
  · simp [hDead, hRouted]
  · simp [hExh, hRouted]

/-- **Theorem 5 (Fail-Closed Safe Abort)**: When no human escalation route is available
    (`humanEscalationRouted = false`), deadlock or retry exhaustion fails closed to `.safelyAborted`. -/
theorem unrouted_escalation_fails_closed_to_safe_abort (s : SwarmArbitrationState)
    (hActive : s.phase = .active)
    (hStop : s.deadlockDetected = true ∨ s.attemptsUsed ≥ s.maxAttempts)
    (hUnrouted : s.humanEscalationRouted = false) :
    nextBoundedTransition s = .safelyAborted := by
  rw [nextBoundedTransition, hActive]
  rcases hStop with hDead | hExh
  · simp [hDead, hUnrouted]
  · simp [hExh, hUnrouted]

/-- **Theorem 6 (Absorbing Terminal Phases — No Zombie Re-Activation)**: Once in
    `.escalatedToHuman`, `.safelyAborted`, or `.admitted`, `nextBoundedTransition` is
    strictly the identity function. -/
theorem terminal_phases_are_absorbing (s : SwarmArbitrationState)
    (hTerm : s.phase = .escalatedToHuman ∨ s.phase = .safelyAborted ∨ s.phase = .admitted) :
    nextBoundedTransition s = s.phase := by
  rcases hTerm with h | h | h <;> simp [nextBoundedTransition, h]

/-- **Theorem 7 (No Silent Auto-Admission Fallback)**: Starting from `.active`,
    `nextBoundedTransition` can NEVER silently emit `.admitted`. -/
theorem bounded_transition_never_auto_admits_on_failure (s : SwarmArbitrationState)
    (hActive : s.phase = .active) :
    nextBoundedTransition s ≠ .admitted := by
  rw [nextBoundedTransition, hActive]
  cases s.deadlockDetected <;> cases decide (s.attemptsUsed ≥ s.maxAttempts) <;>
    cases s.humanEscalationRouted <;> simp

end FederatedArbitration

/-! ## Section 2: LeanPoo Two-Step Refinement (`Bounded Arbitration -> Escalation -> cedar-poo-spec Host`) & `Core.Transport` -/

section LeanPooArbitrationContract

structure ArbitrationConfig where
  boundedRetryCapEnforced : Bool
  deadlockPreemptionEnforced : Bool
  pinnedRollbackCutRequired : Bool
  absorbingTerminalPhasesEnforced : Bool
  deriving DecidableEq, Repr

inductive ArbitrationKey where
  | boundedRetryCapEnforced
  | deadlockPreemptionEnforced
  | pinnedRollbackCutRequired
  | absorbingTerminalPhasesEnforced
  deriving DecidableEq, Repr

inductive ArbitrationIssue where
  | unboundedRetryLoopAllowed
  | deadlockStallAllowed
  | unpinnedAbortAllowed
  | terminalPhaseReentryAllowed
  deriving DecidableEq, Repr

private def arbitrationView : View ArbitrationConfig ArbitrationKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseArbitrationContract :
    Contract ArbitrationConfig ArbitrationKey Unit ArbitrationIssue where
  view := arbitrationView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.boundedRetryCapEnforced then [] else [.rejected path .unboundedRetryLoopAllowed]) ++
    (if cfg.deadlockPreemptionEnforced then [] else [.rejected path .deadlockStallAllowed])
  validInventory := Or.inl rfl

def nonBlockingEscalationExt (cfg : ArbitrationConfig) (path : List ArbitrationKey) :
    List (Issue ArbitrationKey ArbitrationIssue) :=
  (if cfg.pinnedRollbackCutRequired then [] else [.rejected path .unpinnedAbortAllowed]) ++
  (if cfg.absorbingTerminalPhasesEnforced then [] else [.rejected path .terminalPhaseReentryAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Escalation Authority Host)**:
    Layering rollback-cut/absorbing-terminal fencing AND ANY downstream `cedar-poo-spec`
    escalation-authority extension `hostEscExt` onto `baseArbitrationContract` monotonically
    preserves every arbitration/liveness rejection. -/
theorem federatedArbitrationContract_preserves_rejection
    (hostEscExt : ArbitrationConfig → List ArbitrationKey →
      List (Issue ArbitrationKey ArbitrationIssue))
    (cfg : ArbitrationConfig) (path : List ArbitrationKey)
    (hRej : diagnose baseArbitrationContract cfg path ≠ []) :
    diagnose (refine (refine baseArbitrationContract nonBlockingEscalationExt) hostEscExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseArbitrationContract nonBlockingEscalationExt hostEscExt cfg path hRej

inductive ArbitrationProofKey where
  | boundedRetryCapEnforced
  | deadlockPreemptionEnforced
  | pinnedRollbackCutRequired
  | absorbingTerminalPhasesEnforced
  | escalationNotifyDelayMs
  deriving DecidableEq

abbrev ArbitrationProofValue : ArbitrationProofKey → Type
  | .boundedRetryCapEnforced => Bool
  | .deadlockPreemptionEnforced => Bool
  | .pinnedRollbackCutRequired => Bool
  | .absorbingTerminalPhasesEnforced => Bool
  | .escalationNotifyDelayMs => Nat

def arbitrationObligation :
    LeanPoo.Proof.Obligation ArbitrationProofKey ArbitrationProofValue where
  dependencies :=
    [ .boundedRetryCapEnforced
    , .deadlockPreemptionEnforced
    , .pinnedRollbackCutRequired
    , .absorbingTerminalPhasesEnforced
    ]
  holds := fun s =>
    s .boundedRetryCapEnforced = true ∧
    s .deadlockPreemptionEnforced = true ∧
    s .pinnedRollbackCutRequired = true ∧
    s .absorbingTerminalPhasesEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .boundedRetryCapEnforced (by simp)).symm.trans h1,
           (same .deadlockPreemptionEnforced (by simp)).symm.trans h2,
           (same .pinnedRollbackCutRequired (by simp)).symm.trans h3,
           (same .absorbingTerminalPhasesEnforced (by simp)).symm.trans h4⟩

def baselineArbitrationSystem :
    LeanPoo.Proof.ProofObject ArbitrationProofKey ArbitrationProofValue where
  state := fun
    | .boundedRetryCapEnforced => true
    | .deadlockPreemptionEnforced => true
    | .pinnedRollbackCutRequired => true
    | .absorbingTerminalPhasesEnforced => true
    | .escalationNotifyDelayMs => 500
  obligations := [arbitrationObligation]

theorem baselineArbitrationCertified :
    LeanPoo.Proof.Certificate baselineArbitrationSystem := by
  intro ob hMem
  have hEq : ob = arbitrationObligation := by simpa [baselineArbitrationSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Tuning `.escalationNotifyDelayMs` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem escalationAlertDelayTuning_preserves_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineArbitrationSystem
        (LeanPoo.Proof.Patch.set .escalationNotifyDelayMs 2000)) :=
  close_single_set_untouched baselineArbitrationSystem arbitrationObligation
    .escalationNotifyDelayMs 2000 rfl baselineArbitrationCertified
    (by simp [arbitrationObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.boundedRetryCapEnforced` ALWAYS invalidates reuse. -/
theorem disablingRetryCap_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected arbitrationObligation
        (LeanPoo.Proof.Patch.set .boundedRetryCapEnforced false) :=
  set_dependency_invalidates_unaffected arbitrationObligation
    .boundedRetryCapEnforced false (by simp [arbitrationObligation])

end LeanPooArbitrationContract

end DeterministicEngineering.Engineering.FederatedArbitrationLiveness
