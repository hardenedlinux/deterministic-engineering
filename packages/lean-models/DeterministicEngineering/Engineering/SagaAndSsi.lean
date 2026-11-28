/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport

/-!
# LeanPoo Unbounded Compensable Saga Pivot Safety & Multi-Agent AST SSI (`B6` & `B4`)

Built strictly on **Lean 4 core + `LeanPoo`** (zero Mathlib, zero Cedar dependency).
Completes the **52-theorem `LeanPoo` formal library** spanning `B3`, `B4`, `B6`,
`B7`, `B8`, `B10`, `B10b`, `B10c`, `R3`, and the `cedar-poo-spec` Dual-Sovereignty
Bridge.

Machine-checked theorems (11 total, zero `sorry`, zero custom axioms):
1. `post_pivot_rollback_always_forbidden` — zero-axiom proof that rollback past Pivot is blocked
2. `pending_unknown_fences_both_forward_and_rollback` — `PendingUnknownEffect` blocks retry & undo
3. `reverse_compensation_covers_all_executed_steps` — exact arbitrary-length reverse compensation
4. `second_pivot_breaks_at_most_one_pivot` — arbitrary-length saga rejects 2nd irreversible pivot
5. `mutual_write_skew_always_blocked` — arbitrary symbol sets block cyclic `rw` write-skew
6. `direct_ww_conflict_always_blocked` — direct `ww` write-write overlap is blocked
7. `de01_independent_peer_always_admitted` — `DE01` bounded partial admission for unrelated peers
8. `read_only_agents_never_conflict` — read-only concurrent peers always compose cleanly
9. `sagaSsiContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` host)
10. `retryBackoffTuning_preserves_saga_ssi_certificate` — 1-line `Core.Transport` proof reuse
11. `disablingPivotFence_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.SagaAndSsi

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Unbounded Compensable Saga Pivot Safety & Reverse Compensation (`B6`) -/

section CompensableSaga

inductive SagaPhase where
  | prePivot
  | pivotCrossed
  | pendingUnknown
  | compensated
  | completed
  deriving DecidableEq, Repr

structure SagaStepSpec where
  stepId : Nat
  isPivot : Bool
  hasCompensator : Bool
  deriving DecidableEq, Repr

/-- Rollback is strictly permitted ONLY in `.prePivot`. Crossing the irreversible
    Pivot or holding a `PendingUnknownEffect` unconditionally blocks rollback. -/
def canRollback : SagaPhase → Bool
  | .prePivot => true
  | _ => false

/-- Forward execution is strictly blocked while an external effect is `.pendingUnknown`. -/
def canExecuteNext : SagaPhase → Bool
  | .pendingUnknown => false
  | .compensated => false
  | .completed => false
  | _ => true

def reverseCompensateOrder (executed : List Nat) : List Nat :=
  executed.reverse

/-- **Theorem 1 (Zero-Axiom Post-Pivot Rollback Refusal)**: Once an irreversible Pivot
    is crossed, backward compensation is unconditionally forbidden. -/
theorem post_pivot_rollback_always_forbidden :
    canRollback .pivotCrossed = false := rfl

/-- **Theorem 2 (`PendingUnknownEffect` Bidirectional Fence)**: An unresolved timeout
    blocks BOTH blind forward retry AND blind backward compensation. -/
theorem pending_unknown_fences_both_forward_and_rollback :
    canExecuteNext .pendingUnknown = false ∧ canRollback .pendingUnknown = false :=
  ⟨rfl, rfl⟩

/-- **Theorem 3 (Unbounded Exact Reverse Compensation Coverage)**: For ANY `k`-step
    pre-pivot execution history, reverse compensation covers EVERY executed step with
    exact cardinality preservation (zero dropped or duplicated compensators). -/
theorem reverse_compensation_covers_all_executed_steps (executed : List Nat) :
    (∀ s, s ∈ reverseCompensateOrder executed ↔ s ∈ executed) ∧
    (reverseCompensateOrder executed).length = executed.length := by
  refine ⟨?_, List.length_reverse⟩
  intro s
  exact List.mem_reverse

/-- Helper: any list containing an element satisfying `p` has `(xs.filter p).length ≥ 1`. -/
theorem length_filter_pos_of_mem {α : Type} (p : α → Bool) :
    ∀ {xs : List α} {x : α}, x ∈ xs → p x = true → (xs.filter p).length ≥ 1
  | [], _, h, _ => nomatch h
  | y :: ys, x, hmem, hp => by
    simp only [List.filter_cons]
    cases List.mem_cons.mp hmem with
    | inl heq =>
      subst heq
      simp only [hp, ↓reduceIte, List.length_cons]
      omega
    | inr htail =>
      have ih := length_filter_pos_of_mem p htail hp
      cases p y <;> simp <;> omega

/-- **Theorem 4 (Unbounded At-Most-One Pivot Violation Detection)**: If a saga of ANY
    length already contains a pivot step `p0`, appending a second pivot `p2` guarantees
    pivot count `≥ 2` (violating at-most-one pivot admission). -/
theorem second_pivot_breaks_at_most_one_pivot
    (steps : List SagaStepSpec) (p0 p2 : SagaStepSpec)
    (hp0Mem : p0 ∈ steps) (hp0Pivot : p0.isPivot = true) (hp2Pivot : p2.isPivot = true) :
    ((steps ++ [p2]).filter (fun s => s.isPivot)).length ≥ 2 := by
  have h1 : (steps.filter (fun s => s.isPivot)).length ≥ 1 :=
    length_filter_pos_of_mem (fun s => s.isPivot) hp0Mem hp0Pivot
  simp only [List.filter_append, List.filter_cons, hp2Pivot, ↓reduceIte, List.filter_nil,
    List.length_append, List.length_cons, List.length_nil]
  omega

end CompensableSaga

/-! ## Section 2: Unbounded Multi-Agent AST Symbol `ReadSet × WriteSet` SSI & `DE01` (`B4`) -/

section MultiAgentSymbolSsi

structure AgentTx (Sym : Type) where
  agentId : Nat
  readSet : List Sym
  writeSet : List Sym
  deriving DecidableEq, Repr

variable {Sym : Type}

def rwDependency (a b : AgentTx Sym) : Prop :=
  ∃ s, s ∈ a.readSet ∧ s ∈ b.writeSet

def wwConflict (a b : AgentTx Sym) : Prop :=
  ∃ s, s ∈ a.writeSet ∧ s ∈ b.writeSet

def hasMutualWriteSkew (a b : AgentTx Sym) : Prop :=
  rwDependency a b ∧ rwDependency b a

def isIndependentPeer (peer : AgentTx Sym) (others : List (AgentTx Sym)) : Prop :=
  ∀ o ∈ others, ¬ rwDependency peer o ∧ ¬ rwDependency o peer ∧ ¬ wwConflict peer o

def ssiAdmitPair [DecidableEq Sym] (a b : AgentTx Sym) : Bool :=
  let rwAB := a.readSet.any (fun s => decide (s ∈ b.writeSet))
  let rwBA := b.readSet.any (fun s => decide (s ∈ a.writeSet))
  let ww := a.writeSet.any (fun s => decide (s ∈ b.writeSet))
  !(rwAB && rwBA) && !ww

/-- **Theorem 5 (Unbounded Cyclic Write-Skew Refusal)**: For ANY two concurrent agents
    over arbitrary symbol sets, a mutual `rw` dependency cycle (`A -> B -> A`) is ALWAYS
    refused by `ssiAdmitPair`. -/
theorem mutual_write_skew_always_blocked [DecidableEq Sym] (a b : AgentTx Sym)
    (hskew : hasMutualWriteSkew a b) :
    ssiAdmitPair a b = false := by
  rcases hskew with ⟨⟨s1, hs1R, hs1W⟩, ⟨s2, hs2R, hs2W⟩⟩
  have hab : a.readSet.any (fun s => decide (s ∈ b.writeSet)) = true :=
    List.any_eq_true.mpr ⟨s1, hs1R, decide_eq_true hs1W⟩
  have hba : b.readSet.any (fun s => decide (s ∈ a.writeSet)) = true :=
    List.any_eq_true.mpr ⟨s2, hs2R, decide_eq_true hs2W⟩
  simp [ssiAdmitPair, hab, hba]

/-- **Theorem 6 (Unbounded Direct Write-Write Conflict Refusal)**: Any shared written
    symbol forces `ssiAdmitPair = false` (forbids silent last-writer-wins). -/
theorem direct_ww_conflict_always_blocked [DecidableEq Sym] (a b : AgentTx Sym)
    (hww : wwConflict a b) :
    ssiAdmitPair a b = false := by
  rcases hww with ⟨s, hsA, hsB⟩
  have hwwB : a.writeSet.any (fun x => decide (x ∈ b.writeSet)) = true :=
    List.any_eq_true.mpr ⟨s, hsA, decide_eq_true hsB⟩
  simp [ssiAdmitPair, hwwB]

/-- **Theorem 7 (`DE01` Unbounded Independent-Peer Partial Admission)**: Any peer whose
    read/write symbol sets are disjoint from all conflicting swarm agents is admitted
    against EVERY other agent (zero collateral starvation). -/
theorem de01_independent_peer_always_admitted [DecidableEq Sym]
    (peer : AgentTx Sym) (others : List (AgentTx Sym))
    (hindep : isIndependentPeer peer others) :
    ∀ o ∈ others, ssiAdmitPair peer o = true := by
  intro o ho
  rcases hindep o ho with ⟨hnoRwPO, _, hnoWw⟩
  have h1 : peer.readSet.any (fun s => decide (s ∈ o.writeSet)) = false := by
    cases h : peer.readSet.any (fun s => decide (s ∈ o.writeSet)) with
    | false => rfl
    | true =>
      obtain ⟨s, hsR, hsW⟩ := List.any_eq_true.mp h
      exact False.elim (hnoRwPO ⟨s, hsR, of_decide_eq_true hsW⟩)
  have h2 : peer.writeSet.any (fun s => decide (s ∈ o.writeSet)) = false := by
    cases h : peer.writeSet.any (fun s => decide (s ∈ o.writeSet)) with
    | false => rfl
    | true =>
      obtain ⟨s, hsA, hsB⟩ := List.any_eq_true.mp h
      exact False.elim (hnoWw ⟨s, hsA, of_decide_eq_true hsB⟩)
  simp [ssiAdmitPair, h1, h2]

/-- **Theorem 8**: Any two read-only agents (`writeSet = []`) always compose conflict-free. -/
theorem read_only_agents_never_conflict [DecidableEq Sym] (a b : AgentTx Sym)
    (ha : a.writeSet = []) (hb : b.writeSet = []) :
    ssiAdmitPair a b = true := by
  have h1 : a.readSet.any (fun s => decide (s ∈ b.writeSet)) = false := by
    cases h : a.readSet.any (fun s => decide (s ∈ b.writeSet)) with
    | false => rfl
    | true =>
      obtain ⟨s, _, hsW⟩ := List.any_eq_true.mp h
      have hmem : s ∈ b.writeSet := of_decide_eq_true hsW
      rw [hb] at hmem
      exact nomatch hmem
  simp [ssiAdmitPair, ha, h1]

end MultiAgentSymbolSsi

/-! ## Section 3: LeanPoo Two-Step Refinement (`B6 -> B4 -> cedar-poo-spec`) & Proof Transport -/

section LeanPooSagaSsiContract

structure SagaSsiConfig where
  pivotIrreversibilityEnforced : Bool
  unknownEffectFenceEnforced : Bool
  ssiCycleBlockingEnforced : Bool
  hostTransactionPolicyBound : Bool
  deriving DecidableEq, Repr

inductive SagaSsiKey where
  | pivotIrreversibilityEnforced
  | unknownEffectFenceEnforced
  | ssiCycleBlockingEnforced
  | hostTransactionPolicyBound
  deriving DecidableEq, Repr

inductive SagaSsiIssue where
  | postPivotRollbackAllowed
  | blindRetryOnUnknownEffect
  | cyclicWriteSkewAdmitted
  | hostTransactionPolicyBypassed
  deriving DecidableEq, Repr

private def sagaSsiView : View SagaSsiConfig SagaSsiKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseSagaContract :
    Contract SagaSsiConfig SagaSsiKey Unit SagaSsiIssue where
  view := sagaSsiView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.pivotIrreversibilityEnforced then [] else [.rejected path .postPivotRollbackAllowed]) ++
    (if cfg.unknownEffectFenceEnforced then [] else [.rejected path .blindRetryOnUnknownEffect])
  validInventory := Or.inl rfl

def ssiCycleExt (cfg : SagaSsiConfig) (path : List SagaSsiKey) :
    List (Issue SagaSsiKey SagaSsiIssue) :=
  if cfg.ssiCycleBlockingEnforced then [] else [.rejected path .cyclicWriteSkewAdmitted]

/-- **Theorem 9 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Transaction Host)**:
    Layering `B4` SSI cycle blocking AND ANY downstream `cedar-poo-spec` transaction
    authorization extension `hostTxExt` onto `baseSagaContract` monotonically preserves
    every `B6` Saga safety rejection. -/
theorem sagaSsiContract_preserves_rejection
    (hostTxExt : SagaSsiConfig → List SagaSsiKey → List (Issue SagaSsiKey SagaSsiIssue))
    (cfg : SagaSsiConfig) (path : List SagaSsiKey)
    (hRej : diagnose baseSagaContract cfg path ≠ []) :
    diagnose (refine (refine baseSagaContract ssiCycleExt) hostTxExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseSagaContract ssiCycleExt hostTxExt cfg path hRej

inductive SagaSsiProofKey where
  | pivotIrreversibilityEnforced
  | unknownEffectFenceEnforced
  | ssiCycleBlockingEnforced
  | retryBackoffMs
  deriving DecidableEq

abbrev SagaSsiProofValue : SagaSsiProofKey → Type
  | .pivotIrreversibilityEnforced => Bool
  | .unknownEffectFenceEnforced => Bool
  | .ssiCycleBlockingEnforced => Bool
  | .retryBackoffMs => Nat

def sagaSsiSafetyObligation : LeanPoo.Proof.Obligation SagaSsiProofKey SagaSsiProofValue where
  dependencies :=
    [.pivotIrreversibilityEnforced, .unknownEffectFenceEnforced, .ssiCycleBlockingEnforced]
  holds := fun s =>
    s .pivotIrreversibilityEnforced = true ∧
    s .unknownEffectFenceEnforced = true ∧
    s .ssiCycleBlockingEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3⟩
    exact ⟨(same .pivotIrreversibilityEnforced (by simp)).symm.trans h1,
           (same .unknownEffectFenceEnforced (by simp)).symm.trans h2,
           (same .ssiCycleBlockingEnforced (by simp)).symm.trans h3⟩

def baselineSagaSsiSystem : LeanPoo.Proof.ProofObject SagaSsiProofKey SagaSsiProofValue where
  state := fun
    | .pivotIrreversibilityEnforced => true
    | .unknownEffectFenceEnforced => true
    | .ssiCycleBlockingEnforced => true
    | .retryBackoffMs => 250
  obligations := [sagaSsiSafetyObligation]

theorem baselineSagaSsiCertified : LeanPoo.Proof.Certificate baselineSagaSsiSystem := by
  intro ob hMem
  have hEq : ob = sagaSsiSafetyObligation := by simpa [baselineSagaSsiSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl⟩

/-- **Theorem 10**: Tuning `.retryBackoffMs` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem retryBackoffTuning_preserves_saga_ssi_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineSagaSsiSystem
        (LeanPoo.Proof.Patch.set .retryBackoffMs 1000)) :=
  close_single_set_untouched baselineSagaSsiSystem sagaSsiSafetyObligation
    .retryBackoffMs 1000 rfl baselineSagaSsiCertified (by simp [sagaSsiSafetyObligation])

/-- **Theorem 11 (Negative Control)**: Disabling `.pivotIrreversibilityEnforced` always invalidates reuse. -/
theorem disablingPivotFence_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected sagaSsiSafetyObligation
        (LeanPoo.Proof.Patch.set .pivotIrreversibilityEnforced false) :=
  set_dependency_invalidates_unaffected sagaSsiSafetyObligation
    .pivotIrreversibilityEnforced false (by simp [sagaSsiSafetyObligation])

end LeanPooSagaSsiContract

end DeterministicEngineering.Engineering.SagaAndSsi
