/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

/-!
# Reusable Fencing-Token Order & Band-5 Governance Floor Lattice (`Core.Order`)

Formalizes two unbounded order structures shared across the repository:
1. Monotonic fencing-token epochs (`admitEpoch`) ensuring stale writers/leases
   from any prior epoch `e < current` are rejected unconditionally.
2. Join-semilattice over Band-5 governance floors (`GovernanceFloor`), proving
   commutativity, associativity, idempotence, and non-weakening monotonicity
   (`f ≤ join f g` and `g ≤ join f g`) matching 10.151 / 10.153 Band-5 discipline.
-/

namespace DeterministicEngineering.Core.Order

/-! ## 1. Monotonic Fencing-Token Epoch Guard -/

/-- A write carrying token `incoming` is admitted iff `current ≤ incoming`. -/
def admitEpoch (current incoming : Nat) : Bool :=
  decide (current ≤ incoming)

def advanceEpoch (current incoming : Nat) : Nat :=
  if current ≤ incoming then incoming else current

theorem staleEpoch_rejected (current incoming : Nat) (hStale : incoming < current) :
    admitEpoch current incoming = false := by
  unfold admitEpoch
  exact decide_eq_false (Nat.not_le_of_gt hStale)

theorem advanceEpoch_monotone (current incoming : Nat) :
    current ≤ advanceEpoch current incoming := by
  unfold advanceEpoch
  split
  · assumption
  · exact Nat.le_refl current

theorem advanceEpoch_rejects_strictly_older (current incoming older : Nat)
    (hOlder : older < current) :
    admitEpoch (advanceEpoch current incoming) older = false :=
  staleEpoch_rejected (advanceEpoch current incoming) older
    (Nat.lt_of_lt_of_le hOlder (advanceEpoch_monotone current incoming))

/-! ## 2. Band-5 Governance Floor Join-Semilattice -/

/-- Monotonic Band-5 verification floor (higher booleans / counts are strictly stronger). -/
structure GovernanceFloor where
  requireCountermodels : Bool
  requireEmergentInvariants : Bool
  requireZeroSorry : Bool
  minCountermodelCount : Nat
  deriving DecidableEq, Repr

def GovernanceFloor.le (a b : GovernanceFloor) : Prop :=
  (a.requireCountermodels = true → b.requireCountermodels = true) ∧
  (a.requireEmergentInvariants = true → b.requireEmergentInvariants = true) ∧
  (a.requireZeroSorry = true → b.requireZeroSorry = true) ∧
  a.minCountermodelCount ≤ b.minCountermodelCount

def GovernanceFloor.join (a b : GovernanceFloor) : GovernanceFloor where
  requireCountermodels := a.requireCountermodels || b.requireCountermodels
  requireEmergentInvariants := a.requireEmergentInvariants || b.requireEmergentInvariants
  requireZeroSorry := a.requireZeroSorry || b.requireZeroSorry
  minCountermodelCount := max a.minCountermodelCount b.minCountermodelCount

theorem join_idempotent (a : GovernanceFloor) : a.join a = a := by
  cases a
  simp [GovernanceFloor.join]

theorem join_comm (a b : GovernanceFloor) : a.join b = b.join a := by
  cases a; cases b
  simp [GovernanceFloor.join, Bool.or_comm, Nat.max_comm]

theorem join_assoc (a b c : GovernanceFloor) : (a.join b).join c = a.join (b.join c) := by
  cases a; cases b; cases c
  simp [GovernanceFloor.join, Bool.or_assoc, Nat.max_assoc]

/-- Joining a child profile onto a Band-5 floor can NEVER weaken the parent floor. -/
theorem join_never_weakens_left (a b : GovernanceFloor) : a.le (a.join b) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h; simp [GovernanceFloor.join, h]
  · intro h; simp [GovernanceFloor.join, h]
  · intro h; simp [GovernanceFloor.join, h]
  · exact Nat.le_max_left _ _

theorem join_never_weakens_right (a b : GovernanceFloor) : b.le (a.join b) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h; simp [GovernanceFloor.join, h]
  · intro h; simp [GovernanceFloor.join, h]
  · intro h; simp [GovernanceFloor.join, h]
  · exact Nat.le_max_right _ _

/-- Negative control: dropping `requireCountermodels` from `true` to `false` weakens the floor. -/
theorem dropping_countermodels_violates_floor :
    let band5 : GovernanceFloor := ⟨true, true, true, 1⟩
    let weakened : GovernanceFloor := ⟨false, true, true, 0⟩
    ¬ band5.le weakened := by
  dsimp only
  intro h
  have hCm := h.1 rfl
  cases hCm

end DeterministicEngineering.Core.Order
