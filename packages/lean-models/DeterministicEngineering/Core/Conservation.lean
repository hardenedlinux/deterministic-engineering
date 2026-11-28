/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

/-!
# Reusable Single-Ownership Conservation & Idempotent Release Core (`Core.Conservation`)

Provides unbounded algebraic ownership conservation and idempotent release laws
reusable across process handles, semaphore permits, leases, and memory slots
without duplicating finite-state Quint interleavings.
-/

namespace DeterministicEngineering.Core.Conservation

/-- Abstract single-ownership pool tracking distinct active owners against an arbitrary capacity `cap`. -/
structure OwnerPool (α : Type) where
  cap : Nat
  owners : List α
  deriving Repr

def OwnerPool.count {α : Type} (p : OwnerPool α) : Nat :=
  p.owners.length

def OwnerPool.withinCap {α : Type} (p : OwnerPool α) : Prop :=
  p.count ≤ p.cap

def OwnerPool.admit {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α) : OwnerPool α :=
  if x ∈ p.owners then p
  else if p.owners.length < p.cap then { p with owners := x :: p.owners }
  else p

def OwnerPool.release {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α) : OwnerPool α :=
  { p with owners := p.owners.filter (fun y => y != x) }

/-- Admission preserves the arbitrary capacity ceiling `cap` for all `α` and all `p`. -/
theorem admit_preserves_withinCap {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α)
    (hCap : p.withinCap) : (p.admit x).withinCap := by
  unfold OwnerPool.admit OwnerPool.withinCap OwnerPool.count
  split
  · exact hCap
  · split
    · rename_i hLt
      simpa [List.length_cons] using Nat.succ_le_of_lt hLt
    · exact hCap

/-- Release never increases active owner count and therefore preserves `withinCap`. -/
theorem release_preserves_withinCap {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α)
    (hCap : p.withinCap) : (p.release x).withinCap := by
  unfold OwnerPool.release OwnerPool.withinCap OwnerPool.count
  exact Nat.le_trans (List.length_filter_le _ _) hCap

/-- Release is strictly idempotent: releasing the same handle twice is indistinguishable
from releasing it once (no double-release underflow or ghost permit creation). -/
theorem release_idempotent {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α) :
    (p.release x).release x = p.release x := by
  unfold OwnerPool.release
  congr 1
  induction p.owners with
  | nil => rfl
  | cons hd tl ih =>
    by_cases h : (hd != x) = true
    · simp [List.filter, h, ih]
    · simp [List.filter, h, ih]

/-- After releasing `x`, `x` is no longer present in the owner set. -/
theorem release_removes_owner {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α) :
    x ∉ (p.release x).owners := by
  unfold OwnerPool.release
  intro hMem
  have hPred := (List.mem_filter.mp hMem).2
  simp at hPred

/-- Negative control: unchecked admission without checking `length < cap` can violate `withinCap`. -/
def uncheckedAdmit {α : Type} (p : OwnerPool α) (x : α) : OwnerPool α :=
  { p with owners := x :: p.owners }

theorem uncheckedAdmit_violates_withinCap :
    let p : OwnerPool Nat := { cap := 1, owners := [10] }
    p.withinCap ∧ ¬ (uncheckedAdmit p 20).withinCap := by
  refine ⟨?_, ?_⟩
  · unfold OwnerPool.withinCap OwnerPool.count; decide
  · unfold uncheckedAdmit OwnerPool.withinCap OwnerPool.count; decide

end DeterministicEngineering.Core.Conservation
