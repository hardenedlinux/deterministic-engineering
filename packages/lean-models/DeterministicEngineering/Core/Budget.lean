/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

/-!
# Reusable Unbounded Memory & Capacity Budget Core (`Core.Budget`)

Orthogonal to Quint (`BackpressureOwners.qnt` checks finite 4-job permit races &
4 guard-pruned countermodels): this module proves ∀-quantified algebraic memory
bounds, monotonicity, shrink-preservation, and an early-release counterexample
witness across arbitrary capacities and item sizes.
-/

namespace DeterministicEngineering.Core.Budget

/-- Algebraic memory retention model (pure Nat arithmetic, zero external axioms). -/
def retainedBytes (queued active itemBytes fixedBytes cacheBytes : Nat) : Nat :=
  (queued + active) * itemBytes + fixedBytes + cacheBytes

theorem retained_monotone_active (q a₁ a₂ item fixed cache : Nat) (h : a₁ ≤ a₂) :
    retainedBytes q a₁ item fixed cache ≤ retainedBytes q a₂ item fixed cache := by
  unfold retainedBytes
  exact Nat.add_le_add_right
    (Nat.add_le_add_right (Nat.mul_le_mul_right item (Nat.add_le_add_left h q)) fixed)
    cache

theorem retained_monotone_queued (q₁ q₂ a item fixed cache : Nat) (h : q₁ ≤ q₂) :
    retainedBytes q₁ a item fixed cache ≤ retainedBytes q₂ a item fixed cache := by
  unfold retainedBytes
  exact Nat.add_le_add_right
    (Nat.add_le_add_right (Nat.mul_le_mul_right item (Nat.add_le_add_right h a)) fixed)
    cache

theorem retained_monotone_cache (q a item fixed c₁ c₂ : Nat) (h : c₁ ≤ c₂) :
    retainedBytes q a item fixed c₁ ≤ retainedBytes q a item fixed c₂ := by
  unfold retainedBytes
  exact Nat.add_le_add_left h ((q + a) * item + fixed)

/-- Unbounded conservation law: for ANY concurrency limit and ANY item size,
if permit conservation keeps `queued + active ≤ limit`, retained bytes never
exceed `limit * itemBytes + fixedBytes + cacheBytes`. -/
theorem conservation_bounds_peak
    (queued active limit itemBytes fixedBytes cacheBytes : Nat)
    (hConserved : queued + active ≤ limit) :
    retainedBytes queued active itemBytes fixedBytes cacheBytes ≤
      limit * itemBytes + fixedBytes + cacheBytes := by
  unfold retainedBytes
  exact Nat.add_le_add_right
    (Nat.add_le_add_right (Nat.mul_le_mul_right itemBytes hConserved) fixedBytes)
    cacheBytes

/-- Monotonic budget reuse: tightening any upper bound preserves an already-discharged ceiling. -/
theorem budget_preserved_under_shrink (oldPeak newPeak ceiling : Nat)
    (hShrink : newPeak ≤ oldPeak) (hWithin : oldPeak ≤ ceiling) :
    newPeak ≤ ceiling :=
  Nat.le_trans hShrink hWithin

/-- Negative control witness: releasing a permit before payload disposal lets
`queued + active` exceed `limit` (e.g., `2 + 4 > 4` with cache `128`), breaching
a `512`-byte ceiling even when the configured permit limit stays bounded. -/
theorem earlyPermitRelease_can_exceed_budget :
    ¬ retainedBytes 2 4 64 128 128 ≤ 512 := by
  decide

end DeterministicEngineering.Core.Budget
