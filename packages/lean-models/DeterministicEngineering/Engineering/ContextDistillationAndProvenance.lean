/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport
import DeterministicEngineering.Engineering.ToolSandboxAndRpcBoundary

/-!
# LeanPoo Unbounded Controlled Context Distillation & Epistemic Provenance Preservation (`B12`)

Built strictly on **Lean 4 core + `LeanPoo`** (ZERO Mathlib, ZERO Cedar dependency).
Transitively imports `ToolSandboxAndRpcBoundary` (all 10 prior modules, 116 theorems)
and adds 10 machine-checked theorems defending long-horizon AI Agent context compaction
and distillation against amnesia, citation fabrication, secrecy stripping, and integrity
laundering — bringing the pure `LeanPoo` library to **126 theorems across 11 modules**.

Machine-checked theorems (10 total -> **126 theorems across 11 modules**, zero `sorry`, zero custom axioms):
1. `dropping_pinned_m1_constraint_always_refused` — dropping ANY pinned M1 constraint/veto fails closed
2. `hallucinated_citation_always_refused` — fabricating ANY source hash absent from input DAG fails closed
3. `secrecy_tag_stripping_by_summarizer_refused` — paraphrasing cannot strip DIFC secrecy tags without M3 declass
4. `integrity_laundering_untrusted_to_trusted_refused` — untrusted source blocks trusted/agent-derived summary elevation
5. `distilled_context_exceeding_token_budget_refused` — distilled summary exceeding `maxTokens` fails closed
6. `empty_sources_with_zero_citations_and_budget_admitted` — sound base admissibility
7. `retained_pinned_subset_monotonic_under_append` — extending retained pinned hashes preserves retention
8. `distillationContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Data/Disclosure host)
9. `summaryPromptVersionTuning_preserves_distillation_certificate` — 1-line `Core.Transport` proof reuse
10. `disablingPinnedRetention_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.ContextDistillationAndProvenance

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Unbounded Context Distillation & Provenance Preservation (`B12`) -/

section ContextDistillation

inductive IntegrityRank where
  | untrustedExternal
  | agentDerived
  | trustedSystem
  deriving DecidableEq, Repr

def integrityLevel : IntegrityRank → Nat
  | .untrustedExternal => 0
  | .agentDerived => 1
  | .trustedSystem => 2

structure ContextItem (Hash Tag : Type) where
  itemHash : Hash
  isPinnedM1Constraint : Bool
  integrity : IntegrityRank
  secrecyTags : List Tag
  deriving DecidableEq, Repr

structure DistilledContext (Hash Tag : Type) where
  retainedPinnedHashes : List Hash
  citedSourceHashes : List Hash
  outputIntegrity : IntegrityRank
  outputSecrecyTags : List Tag
  tokenCount : Nat
  deriving DecidableEq, Repr

/-- Complete controlled context-distillation admissibility predicate matching
    `ControlledContextDistiller.admitDistillation`:
    1. Every pinned `M1` constraint in `sources` is retained in `out.retainedPinnedHashes`,
    2. Every citation in `out.citedSourceHashes` exists in `sources` (zero hallucinated citations),
    3. Every secrecy tag on any source item appears in `out.outputSecrecyTags`,
    4. Output integrity never exceeds any source item's integrity (monotonic meet),
    5. `out.tokenCount ≤ maxTokens`. -/
def distillationAdmitted [DecidableEq Hash] [DecidableEq Tag]
    (sources : List (ContextItem Hash Tag))
    (out : DistilledContext Hash Tag)
    (maxTokens : Nat) : Bool :=
  let sourceHashes := sources.map (·.itemHash)
  let pinnedRetained := sources.all (fun s =>
    !s.isPinnedM1Constraint || decide (s.itemHash ∈ out.retainedPinnedHashes))
  let citationsGrounded := out.citedSourceHashes.all (fun h => decide (h ∈ sourceHashes))
  let secrecyPreserved := sources.all (fun s =>
    s.secrecyTags.all (fun t => decide (t ∈ out.outputSecrecyTags)))
  let integrityBounded := sources.all (fun s =>
    decide (integrityLevel out.outputIntegrity ≤ integrityLevel s.integrity))
  pinnedRetained && citationsGrounded && secrecyPreserved &&
  integrityBounded && decide (out.tokenCount ≤ maxTokens)

/-- **Theorem 1 (Anti-Amnesia of Pinned `M1` Constraints)**: Dropping ANY pinned `M1`
    constraint or veto tombstone during summarization unconditionally causes refusal. -/
theorem dropping_pinned_m1_constraint_always_refused [DecidableEq Hash] [DecidableEq Tag]
    (sources : List (ContextItem Hash Tag))
    (out : DistilledContext Hash Tag)
    (maxTokens : Nat)
    (c : ContextItem Hash Tag)
    (hcMem : c ∈ sources)
    (hcPinned : c.isPinnedM1Constraint = true)
    (hcDropped : c.itemHash ∉ out.retainedPinnedHashes) :
    distillationAdmitted sources out maxTokens = false := by
  have hall : sources.all (fun s =>
      !s.isPinnedM1Constraint || decide (s.itemHash ∈ out.retainedPinnedHashes)) = false := by
    cases h : sources.all (fun s =>
        !s.isPinnedM1Constraint || decide (s.itemHash ∈ out.retainedPinnedHashes)) with
    | false => rfl
    | true =>
      have hc := List.all_eq_true.mp h c hcMem
      simp [hcPinned, hcDropped] at hc
  simp only [distillationAdmitted, hall, Bool.false_and]

/-- **Theorem 2 (Anti-Hallucinated Citation Refusal)**: Any cited hash `h` not present in
    `sources.map (·.itemHash)` unconditionally causes refusal. -/
theorem hallucinated_citation_always_refused [DecidableEq Hash] [DecidableEq Tag]
    (sources : List (ContextItem Hash Tag))
    (out : DistilledContext Hash Tag)
    (maxTokens : Nat)
    (hFake : Hash)
    (hCited : hFake ∈ out.citedSourceHashes)
    (hAbsent : hFake ∉ sources.map (·.itemHash)) :
    distillationAdmitted sources out maxTokens = false := by
  have hall : out.citedSourceHashes.all (fun h => decide (h ∈ sources.map (·.itemHash))) = false := by
    cases h : out.citedSourceHashes.all (fun h => decide (h ∈ sources.map (·.itemHash))) with
    | false => rfl
    | true =>
      have hf := List.all_eq_true.mp h hFake hCited
      exact False.elim (hAbsent (of_decide_eq_true hf))
  simp only [distillationAdmitted, hall, Bool.and_false, Bool.false_and]

/-- **Theorem 3 (Anti-Secrecy-Stripping by Summarization)**: If ANY source item carries a
    secrecy tag `t` missing from `out.outputSecrecyTags`, distillation is refused. -/
theorem secrecy_tag_stripping_by_summarizer_refused [DecidableEq Hash] [DecidableEq Tag]
    (sources : List (ContextItem Hash Tag))
    (out : DistilledContext Hash Tag)
    (maxTokens : Nat)
    (s : ContextItem Hash Tag)
    (t : Tag)
    (hsMem : s ∈ sources)
    (htIn : t ∈ s.secrecyTags)
    (htMissing : t ∉ out.outputSecrecyTags) :
    distillationAdmitted sources out maxTokens = false := by
  have hall : sources.all (fun x =>
      x.secrecyTags.all (fun y => decide (y ∈ out.outputSecrecyTags))) = false := by
    cases h : sources.all (fun x =>
        x.secrecyTags.all (fun y => decide (y ∈ out.outputSecrecyTags))) with
    | false => rfl
    | true =>
      have hs := List.all_eq_true.mp h s hsMem
      have ht := List.all_eq_true.mp hs t htIn
      exact False.elim (htMissing (of_decide_eq_true ht))
  simp only [distillationAdmitted, hall, Bool.and_false, Bool.false_and]

/-- **Theorem 4 (Anti-Integrity-Laundering)**: If ANY source item has `.untrustedExternal`
    integrity and `out.outputIntegrity ≠ .untrustedExternal`, distillation is refused. -/
theorem integrity_laundering_untrusted_to_trusted_refused [DecidableEq Hash] [DecidableEq Tag]
    (sources : List (ContextItem Hash Tag))
    (out : DistilledContext Hash Tag)
    (maxTokens : Nat)
    (s : ContextItem Hash Tag)
    (hsMem : s ∈ sources)
    (hsUntrusted : s.integrity = .untrustedExternal)
    (hElevated : out.outputIntegrity ≠ .untrustedExternal) :
    distillationAdmitted sources out maxTokens = false := by
  have hall : sources.all (fun x =>
      decide (integrityLevel out.outputIntegrity ≤ integrityLevel x.integrity)) = false := by
    cases h : sources.all (fun x =>
        decide (integrityLevel out.outputIntegrity ≤ integrityLevel x.integrity)) with
    | false => rfl
    | true =>
      have hs := of_decide_eq_true (List.all_eq_true.mp h s hsMem)
      rw [hsUntrusted] at hs
      cases ho : out.outputIntegrity with
      | untrustedExternal => exact False.elim (hElevated ho)
      | agentDerived => rw [ho] at hs; simp [integrityLevel] at hs
      | trustedSystem => rw [ho] at hs; simp [integrityLevel] at hs
  simp only [distillationAdmitted, hall, Bool.and_false, Bool.false_and]

/-- **Theorem 5 (Context Token-Budget Ceiling)**: Any distilled context exceeding
    `maxTokens` is unconditionally refused. -/
theorem distilled_context_exceeding_token_budget_refused [DecidableEq Hash] [DecidableEq Tag]
    (sources : List (ContextItem Hash Tag))
    (out : DistilledContext Hash Tag)
    (maxTokens : Nat)
    (hOver : out.tokenCount > maxTokens) :
    distillationAdmitted sources out maxTokens = false := by
  have hNotLe : ¬ (out.tokenCount ≤ maxTokens) := by omega
  simp [distillationAdmitted, hNotLe]

/-- **Theorem 6 (Sound Empty-DAG Base Admissibility)**: An empty source DAG with zero
    citations and `tokenCount ≤ maxTokens` is admitted cleanly. -/
theorem empty_sources_with_zero_citations_and_budget_admitted [DecidableEq Hash] [DecidableEq Tag]
    (out : DistilledContext Hash Tag)
    (maxTokens : Nat)
    (hNoCite : out.citedSourceHashes = [])
    (hBudget : out.tokenCount ≤ maxTokens) :
    distillationAdmitted ([] : List (ContextItem Hash Tag)) out maxTokens = true := by
  simp [distillationAdmitted, hNoCite, hBudget]

/-- **Theorem 7 (Monotonic Retention Under Appending Pinned Hashes)**: Appending additional
    pinned hashes `extra` to `retained` preserves membership of every previously retained item. -/
theorem retained_pinned_subset_monotonic_under_append {Hash : Type}
    (retained extra : List Hash) (h : Hash)
    (hIn : h ∈ retained) :
    h ∈ retained ++ extra :=
  List.mem_append_left extra hIn

end ContextDistillation

/-! ## Section 2: LeanPoo Two-Step Refinement (`Distillation -> Provenance -> cedar-poo-spec Data`) & `Core.Transport` -/

section LeanPooDistillationContract

structure DistillationConfig where
  pinnedM1RetentionEnforced : Bool
  secrecyAndIntegrityMeetEnforced : Bool
  groundedCitationsEnforced : Bool
  tokenBudgetCeilingEnforced : Bool
  deriving DecidableEq, Repr

inductive DistillationKey where
  | pinnedM1RetentionEnforced
  | secrecyAndIntegrityMeetEnforced
  | groundedCitationsEnforced
  | tokenBudgetCeilingEnforced
  deriving DecidableEq, Repr

inductive DistillationIssue where
  | pinnedM1AmnesiaAllowed
  | secrecyOrIntegrityLaundered
  | hallucinatedCitationAllowed
  | tokenBudgetOverflowAllowed
  deriving DecidableEq, Repr

private def distillationView : View DistillationConfig DistillationKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseDistillationContract :
    Contract DistillationConfig DistillationKey Unit DistillationIssue where
  view := distillationView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.pinnedM1RetentionEnforced then [] else [.rejected path .pinnedM1AmnesiaAllowed]) ++
    (if cfg.secrecyAndIntegrityMeetEnforced then [] else [.rejected path .secrecyOrIntegrityLaundered])
  validInventory := Or.inl rfl

def provenanceCitationExt (cfg : DistillationConfig) (path : List DistillationKey) :
    List (Issue DistillationKey DistillationIssue) :=
  (if cfg.groundedCitationsEnforced then [] else [.rejected path .hallucinatedCitationAllowed]) ++
  (if cfg.tokenBudgetCeilingEnforced then [] else [.rejected path .tokenBudgetOverflowAllowed])

/-- **Theorem 8 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Data/Disclosure Host)**:
    Layering citation-grounding/token-ceiling AND ANY downstream `cedar-poo-spec` data
    protection extension `hostDataExt` (e.g. `CedarPooSpec.Data.{ProtectionProfile,CumulativeDisclosure}`)
    onto `baseDistillationContract` monotonically preserves every distillation rejection. -/
theorem distillationContract_preserves_rejection
    (hostDataExt : DistillationConfig → List DistillationKey →
      List (Issue DistillationKey DistillationIssue))
    (cfg : DistillationConfig) (path : List DistillationKey)
    (hRej : diagnose baseDistillationContract cfg path ≠ []) :
    diagnose (refine (refine baseDistillationContract provenanceCitationExt) hostDataExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseDistillationContract provenanceCitationExt hostDataExt cfg path hRej

inductive DistillationProofKey where
  | pinnedM1RetentionEnforced
  | secrecyAndIntegrityMeetEnforced
  | groundedCitationsEnforced
  | tokenBudgetCeilingEnforced
  | summaryTemplateVersion
  deriving DecidableEq

abbrev DistillationProofValue : DistillationProofKey → Type
  | .pinnedM1RetentionEnforced => Bool
  | .secrecyAndIntegrityMeetEnforced => Bool
  | .groundedCitationsEnforced => Bool
  | .tokenBudgetCeilingEnforced => Bool
  | .summaryTemplateVersion => Nat

def distillationObligation :
    LeanPoo.Proof.Obligation DistillationProofKey DistillationProofValue where
  dependencies :=
    [ .pinnedM1RetentionEnforced
    , .secrecyAndIntegrityMeetEnforced
    , .groundedCitationsEnforced
    , .tokenBudgetCeilingEnforced
    ]
  holds := fun s =>
    s .pinnedM1RetentionEnforced = true ∧
    s .secrecyAndIntegrityMeetEnforced = true ∧
    s .groundedCitationsEnforced = true ∧
    s .tokenBudgetCeilingEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .pinnedM1RetentionEnforced (by simp)).symm.trans h1,
           (same .secrecyAndIntegrityMeetEnforced (by simp)).symm.trans h2,
           (same .groundedCitationsEnforced (by simp)).symm.trans h3,
           (same .tokenBudgetCeilingEnforced (by simp)).symm.trans h4⟩

def baselineDistillationSystem :
    LeanPoo.Proof.ProofObject DistillationProofKey DistillationProofValue where
  state := fun
    | .pinnedM1RetentionEnforced => true
    | .secrecyAndIntegrityMeetEnforced => true
    | .groundedCitationsEnforced => true
    | .tokenBudgetCeilingEnforced => true
    | .summaryTemplateVersion => 1
  obligations := [distillationObligation]

theorem baselineDistillationCertified :
    LeanPoo.Proof.Certificate baselineDistillationSystem := by
  intro ob hMem
  have hEq : ob = distillationObligation := by simpa [baselineDistillationSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 9**: Bumping `.summaryTemplateVersion` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem summaryPromptVersionTuning_preserves_distillation_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineDistillationSystem
        (LeanPoo.Proof.Patch.set .summaryTemplateVersion 2)) :=
  close_single_set_untouched baselineDistillationSystem distillationObligation
    .summaryTemplateVersion 2 rfl baselineDistillationCertified
    (by simp [distillationObligation])

/-- **Theorem 10 (Negative Control)**: Disabling `.pinnedM1RetentionEnforced` ALWAYS invalidates reuse. -/
theorem disablingPinnedRetention_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected distillationObligation
        (LeanPoo.Proof.Patch.set .pinnedM1RetentionEnforced false) :=
  set_dependency_invalidates_unaffected distillationObligation
    .pinnedM1RetentionEnforced false (by simp [distillationObligation])

end LeanPooDistillationContract

end DeterministicEngineering.Engineering.ContextDistillationAndProvenance
