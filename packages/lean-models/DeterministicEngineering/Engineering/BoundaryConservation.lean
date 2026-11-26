/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Conservation
import DeterministicEngineering.Core.Transport

/-!
# Deterministic C Trust-Boundary Conservation Refinement (`Engineering.BoundaryConservation`)

Refines `Core.Conservation` (unbounded single-ownership capacity conservation and
idempotent release) and `Core.Transport` (2-step contract refinement & 1-line proof
transport) for the 4th engineering subject `engineering.defense.c-boundary-conservation`
(10.154).

Orthogonal to CBMC (`deterministic_boundary.c` + `proof.c` discharges bit-precise
64-bit `size_t` pointer/bounds/unsigned-overflow UB and supplies the explicit premise
`NoCSourceOverflowOrPointerUB`): this module proves unbounded algebraic conservation
for arbitrary `Nat` capacities and cross-patch proof transport.
-/

namespace DeterministicEngineering.Engineering.BoundaryConservation

open DeterministicEngineering.Core.Conservation
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-- Unbounded reservation conservation across arbitrary owner types and capacities. -/
theorem boundaryAdmit_preserves_cap {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α)
    (hCap : p.withinCap) : (p.admit x).withinCap :=
  admit_preserves_withinCap p x hCap

/-- Idempotent release: double release never underflows or mints ghost capacity. -/
theorem boundaryRelease_idempotent {α : Type} [DecidableEq α] (p : OwnerPool α) (x : α) :
    (p.release x).release x = p.release x :=
  release_idempotent p x

/-! ## Two-Step LeanPoo `ObjectContract.refine` (via `Core.Transport`) -/

structure BoundaryConfig where
  rejectsNullAndDefect : Bool
  rejectsUnsignedOverflow : Bool
  rejectsOverCapacity : Bool
  deriving DecidableEq, Repr

inductive BoundaryConfigKey where
  | rejectsNullAndDefect
  | rejectsUnsignedOverflow
  | rejectsOverCapacity
  deriving DecidableEq, Repr

inductive BoundaryIssue where
  | silentNullFallback
  | silentWraparoundOverflow
  | silentCapacityClamp
  deriving DecidableEq, Repr

private def boundaryView : View BoundaryConfig BoundaryConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseBoundaryContract : Contract BoundaryConfig BoundaryConfigKey Unit BoundaryIssue where
  view := boundaryView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.rejectsNullAndDefect then [] else [.rejected path .silentNullFallback]
  validInventory := Or.inl rfl

def overflowGuardExt (cfg : BoundaryConfig) (path : List BoundaryConfigKey) :
    List (Issue BoundaryConfigKey BoundaryIssue) :=
  if cfg.rejectsUnsignedOverflow then [] else [.rejected path .silentWraparoundOverflow]

def capacityGuardExt (cfg : BoundaryConfig) (path : List BoundaryConfigKey) :
    List (Issue BoundaryConfigKey BoundaryIssue) :=
  if cfg.rejectsOverCapacity then [] else [.rejected path .silentCapacityClamp]

def strictBoundaryContract : Contract BoundaryConfig BoundaryConfigKey Unit BoundaryIssue :=
  refine (refine baseBoundaryContract overflowGuardExt) capacityGuardExt

/-- One-line 2-step monotonic refinement proof reusing `Core.Transport`. -/
theorem strictBoundaryContract_preserves_rejection
    (cfg : BoundaryConfig) (path : List BoundaryConfigKey)
    (hRej : diagnose baseBoundaryContract cfg path ≠ []) :
    diagnose strictBoundaryContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseBoundaryContract overflowGuardExt capacityGuardExt cfg path hRej

/-! ## One-Line Proof Transport via `Core.Transport` -/

inductive BoundaryProofKey where
  | overflowGuardEnabled
  | telemetrySampleRate
  deriving DecidableEq

abbrev BoundaryProofValue : BoundaryProofKey → Type
  | .overflowGuardEnabled => Bool
  | .telemetrySampleRate => Nat

def overflowGuardObligation : LeanPoo.Proof.Obligation BoundaryProofKey BoundaryProofValue where
  dependencies := [.overflowGuardEnabled]
  holds := fun s => s .overflowGuardEnabled = true
  stable := by
    intro before after same holds
    exact (same .overflowGuardEnabled (by simp)).symm.trans holds

def baselineBoundary : LeanPoo.Proof.ProofObject BoundaryProofKey BoundaryProofValue where
  state := fun
    | .overflowGuardEnabled => true
    | .telemetrySampleRate => 10
  obligations := [overflowGuardObligation]

theorem baselineBoundaryCertified : LeanPoo.Proof.Certificate baselineBoundary := by
  intro ob hMem
  have hEq : ob = overflowGuardObligation := by simpa [baselineBoundary] using hMem
  subst ob
  rfl

/-- One-line proof transport across telemetry tuning via `Core.Transport.close_single_set_untouched`. -/
theorem telemetryTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineBoundary
        (LeanPoo.Proof.Patch.set .telemetrySampleRate 100)) :=
  close_single_set_untouched baselineBoundary overflowGuardObligation
    .telemetrySampleRate 100 rfl baselineBoundaryCertified (by simp [overflowGuardObligation])

/-- Negative control: disabling `.overflowGuardEnabled` invalidates proof reuse. -/
theorem disableOverflowGuard_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected overflowGuardObligation
        (LeanPoo.Proof.Patch.set .overflowGuardEnabled false) :=
  set_dependency_invalidates_unaffected overflowGuardObligation
    .overflowGuardEnabled false (by simp [overflowGuardObligation])

end DeterministicEngineering.Engineering.BoundaryConservation
