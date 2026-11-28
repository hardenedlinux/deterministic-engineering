/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse

/-!
# Reusable LeanPoo Proof-Transport & Refinement Combinators (`Core.Transport`)

Factors out the recurring `LeanPoo.Proof.reuse` / `LeanPoo.Proof.close` and
`LeanPoo.Functional.ObjectContract.refine` proof transport lemmas so domain
modules (`Engineering.ProcessTree`, `Engineering.Backpressure`, and future
engineering subjects) reuse concise, one-line certificate transport combinators.
-/

namespace DeterministicEngineering.Core.Transport

open LeanPoo.Functional.ObjectContract
open LeanPoo.Proof

/-- Any single-obligation `ProofObject` whose obligation is unaffected by `patch`
transports its full `Certificate` across `append obj patch` with zero re-proof. -/
theorem close_single_unaffected
    {Key : Type} [DecidableEq Key] {Value : Key → Type}
    (obj : ProofObject Key Value)
    (obligation : Obligation Key Value)
    (patch : Patch Key Value)
    (hObls : obj.obligations = [obligation])
    (hNoNew : patch.obligations = [])
    (hCert : Certificate obj)
    (hUnaffected : unaffected obligation patch) :
    Certificate (append obj patch) := by
  apply close obj patch hCert
  · intro ob hMem hAffected
    have hEq : ob = obligation := by simpa [hObls] using hMem
    subst ob
    exact False.elim (hAffected hUnaffected)
  · intro ob hMem
    simp [hNoNew] at hMem

/-- Specialized certificate transport for `Patch.set key value` when `key ∉ obligation.dependencies`. -/
theorem close_single_set_untouched
    {Key : Type} [DecidableEq Key] {Value : Key → Type}
    (obj : ProofObject Key Value)
    (obligation : Obligation Key Value)
    (key : Key) (val : Value key)
    (hObls : obj.obligations = [obligation])
    (hCert : Certificate obj)
    (hNotDep : key ∉ obligation.dependencies) :
    Certificate (append obj (Patch.set key val)) := by
  apply close_single_unaffected obj obligation (Patch.set key val) hObls rfl hCert
  intro k hDep hTouched
  have hEq : k = key := by simpa [Patch.set] using hTouched
  subst k
  exact hNotDep hDep

/-- Universal negative control: setting any key `key ∈ obligation.dependencies`
always invalidates `unaffected`, blocking blind proof reuse. -/
theorem set_dependency_invalidates_unaffected
    {Key : Type} [DecidableEq Key] {Value : Key → Type}
    (obligation : Obligation Key Value)
    (key : Key) (val : Value key)
    (hDep : key ∈ obligation.dependencies) :
    ¬ unaffected obligation (Patch.set key val) := by
  intro hUnaffected
  exact hUnaffected key hDep (by simp [Patch.set])

/-- Two-step transitive contract refinement monotonically preserves every base rejection. -/
theorem refine_two_step_preserves_rejection
    {α Key Slot IssueDetail : Type} [DecidableEq Key]
    (base : Contract α Key Slot IssueDetail)
    (ext1 ext2 : α → List Key → List (Issue Key IssueDetail))
    (target : α) (path : List Key)
    (hRej : diagnose base target path ≠ []) :
    diagnose (refine (refine base ext1) ext2) target path ≠ [] :=
  refine_preserves_rejection (refine base ext1) ext2 target path
    (refine_preserves_rejection base ext1 target path hRej)

end DeterministicEngineering.Core.Transport
