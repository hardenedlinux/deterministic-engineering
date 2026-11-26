/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport

/-!
# LeanPoo Unbounded DIFC Non-Interference, CaMeL Integrity & ATMS Retraction (`B7`–`B8`)

Built strictly on **Lean 4 core + `LeanPoo`** (zero Mathlib, zero Cedar dependency).
Lifts the bounded Quint models `DifcExfiltrationFence.qnt` (`B7`, 10.164) and
`DurableMemoryTms.qnt` (`B8`, 10.165) to **unbounded arbitrary-depth machine-checked
theorems**, paired with `LeanPoo.Functional.ObjectContract.refine` (aligning with
consuming-host disclosure/pseudonymization policies in `cedar-poo-spec`) and
`LeanPoo.Proof.Reuse` / `Core.Transport` cross-patch certificate reuse.

Machine-checked theorems (11 total, zero `sorry`, zero custom axioms):
1. `difc_secrecy_monotonic_without_declass` — arbitrary-depth Bell-LaPadula taint preservation
2. `difc_no_write_down_blocks_exfiltration` — no-write-down exfiltration refusal
3. `difc_failed_declass_preserves_taint` — unauthorized or unsanitized declass never strips taint
4. `camel_integrity_meet_never_elevates` — arbitrary-depth Biba/CaMeL untrusted collapse
5. `camel_control_slot_blocks_untrusted` — untrusted leaf blocked from privileged control slot
6. `doyle_single_justification_retraction_cascades` — sole-support Doyle TMS retraction
7. `atms_clean_alternative_justification_survives` — de Kleer ATMS multi-justification survival
8. `poison_immunization_tombstone_blocks_reproposal` — monotonic immunization across sessions
9. `difcAtmsContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` host)
10. `retentionTuning_preserves_difc_atms_certificate` — 1-line `Core.Transport` proof reuse
11. `disablingCamelIntegrity_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.InformationFlowAndTms

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Unbounded DIFC Secrecy Join & CaMeL Control-Flow Integrity (`B7`) -/

section DifcAndCamel

inductive IntegrityLevel where
  | untrustedExternal
  | verifiedInternal
  | trustedSystem
  deriving DecidableEq, Repr

def integrityRank : IntegrityLevel → Nat
  | .untrustedExternal => 0
  | .verifiedInternal => 1
  | .trustedSystem => 2

def integrityMeet (a b : IntegrityLevel) : IntegrityLevel :=
  match a, b with
  | .untrustedExternal, _ => .untrustedExternal
  | _, .untrustedExternal => .untrustedExternal
  | .verifiedInternal, _ => .verifiedInternal
  | _, .verifiedInternal => .verifiedInternal
  | .trustedSystem, .trustedSystem => .trustedSystem

/-- Arbitrary-depth LLM synthesis / derivation expression DAG carrying DIFC secrecy
    tags and CaMeL/Biba control-flow integrity levels. -/
inductive FlowExpr (Tag : Type) where
  | leaf (tags : List Tag) (integrity : IntegrityLevel)
  | derive (left right : FlowExpr Tag)
  | declassify (inner : FlowExpr Tag) (removedTag : Tag) (capPermits : Bool) (sanitizerPassed : Bool)
  deriving DecidableEq, Repr

variable {Tag : Type}

def effectiveTags [DecidableEq Tag] : FlowExpr Tag → List Tag
  | .leaf tags _ => tags
  | .derive l r => effectiveTags l ++ effectiveTags r
  | .declassify inner removed capOk sanOk =>
    if capOk && sanOk then
      (effectiveTags inner).filter (fun t => decide (t ≠ removed))
    else
      effectiveTags inner

def effectiveIntegrity : FlowExpr Tag → IntegrityLevel
  | .leaf _ lvl => lvl
  | .derive l r => integrityMeet (effectiveIntegrity l) (effectiveIntegrity r)
  | .declassify inner _ _ _ => effectiveIntegrity inner

def hasLeafTag (tag : Tag) : FlowExpr Tag → Prop
  | .leaf tags _ => tag ∈ tags
  | .derive l r => hasLeafTag tag l ∨ hasLeafTag tag r
  | .declassify inner _ _ _ => hasLeafTag tag inner

def noValidDeclassFor (tag : Tag) : FlowExpr Tag → Prop
  | .leaf _ _ => True
  | .derive l r => noValidDeclassFor tag l ∧ noValidDeclassFor tag r
  | .declassify inner removed capOk sanOk =>
    noValidDeclassFor tag inner ∧ (capOk = true → sanOk = true → removed ≠ tag)

/--
**Theorem 1 (Unbounded Bell-LaPadula Secrecy Monotonicity)**:
Across an LLM derivation expression of ANY finite depth, if a confidential `tag`
enters at any leaf and no authorized + sanitized declassification removes `tag`,
then `tag` remains present in `effectiveTags e`.
-/
theorem difc_secrecy_monotonic_without_declass [DecidableEq Tag] (tag : Tag) :
    ∀ (e : FlowExpr Tag), hasLeafTag tag e → noValidDeclassFor tag e → tag ∈ effectiveTags e
  | .leaf _ _, hleaf, _ => hleaf
  | .derive l r, hleaf, ⟨hnoL, hnoR⟩ => by
    simp only [effectiveTags, List.mem_append]
    cases hleaf with
    | inl hl => exact Or.inl (difc_secrecy_monotonic_without_declass tag l hl hnoL)
    | inr hr => exact Or.inr (difc_secrecy_monotonic_without_declass tag r hr hnoR)
  | .declassify inner removed capOk sanOk, hleaf, ⟨hnoInner, hnotRemoved⟩ => by
    have ih := difc_secrecy_monotonic_without_declass tag inner hleaf hnoInner
    simp only [effectiveTags]
    cases hcap : capOk <;> cases hsan : sanOk
    · exact ih
    · exact ih
    · exact ih
    · simp only [Bool.and_self, ↓reduceIte, List.mem_filter, decide_eq_true_eq]
      exact ⟨ih, (hnotRemoved hcap hsan).symm⟩

/-- Tool-sink confidentiality gate: all effective secrecy tags must be allowed by the sink. -/
def sinkAllowsTags [DecidableEq Tag] (allowed : List Tag) (e : FlowExpr Tag) : Bool :=
  (effectiveTags e).all (fun t => decide (t ∈ allowed))

/--
**Theorem 2 (Unbounded No-Write-Down Exfiltration Refusal)**:
Any expression carrying an unallowed secrecy tag is deterministically blocked by `sinkAllowsTags`.
-/
theorem difc_no_write_down_blocks_exfiltration [DecidableEq Tag]
    (allowed : List Tag) (e : FlowExpr Tag) (tag : Tag)
    (htag : tag ∈ effectiveTags e) (hdisallowed : tag ∉ allowed) :
    sinkAllowsTags allowed e = false := by
  unfold sinkAllowsTags
  cases hall : (effectiveTags e).all (fun t => decide (t ∈ allowed)) with
  | false => rfl
  | true =>
    have hmem := List.all_eq_true.mp hall tag htag
    simp only [decide_eq_true_eq] at hmem
    exact False.elim (hdisallowed hmem)

/--
**Theorem 3 (Failed Sanitizer or Unauthorized Capability Preserves Taint)**:
If either `M3` capability authorization fails OR the deterministic sanitizer rejects
the payload, `declassify` NEVER strips any secrecy tag.
-/
theorem difc_failed_declass_preserves_taint [DecidableEq Tag]
    (inner : FlowExpr Tag) (removed tag : Tag) (capOk sanOk : Bool)
    (hfail : capOk = false ∨ sanOk = false)
    (htag : tag ∈ effectiveTags inner) :
    tag ∈ effectiveTags (.declassify inner removed capOk sanOk) := by
  simp only [effectiveTags]
  cases hfail with
  | inl hc => simp [hc, htag]
  | inr hs => simp [hs, htag]

def hasUntrustedLeaf : FlowExpr Tag → Prop
  | .leaf _ lvl => lvl = .untrustedExternal
  | .derive l r => hasUntrustedLeaf l ∨ hasUntrustedLeaf r
  | .declassify inner _ _ _ => hasUntrustedLeaf inner

/--
**Theorem 4 (Unbounded Biba / CaMeL Integrity Collapse)**:
If ANY leaf at arbitrary depth carries `untrustedExternal` integrity, the synthesized
expression's effective integrity is strictly `untrustedExternal` (never laundered upward).
-/
theorem camel_integrity_meet_never_elevates :
    ∀ (e : FlowExpr Tag), hasUntrustedLeaf e → effectiveIntegrity e = .untrustedExternal
  | .leaf _ _, hlvl => hlvl
  | .derive l r, h => by
    simp only [effectiveIntegrity]
    cases h with
    | inl hl =>
      rw [camel_integrity_meet_never_elevates l hl]
      rfl
    | inr hr =>
      rw [camel_integrity_meet_never_elevates r hr]
      cases effectiveIntegrity l <;> rfl
  | .declassify inner _ _ _, h =>
    camel_integrity_meet_never_elevates inner h

def admitControlArg (minRank : Nat) (ctrl : FlowExpr Tag) : Bool :=
  decide (integrityRank (effectiveIntegrity ctrl) ≥ minRank)

/--
**Theorem 5 (Unbounded CaMeL Control-Flow Integrity Fence)**:
Any control argument derived (at arbitrary depth) from an `untrustedExternal` leaf is
deterministically refused for any privileged tool sink requiring `minRank ≥ 1`.
-/
theorem camel_control_slot_blocks_untrusted
    (ctrl : FlowExpr Tag) (minRank : Nat)
    (huntrusted : hasUntrustedLeaf ctrl) (hpriv : minRank ≥ 1) :
    admitControlArg minRank ctrl = false := by
  unfold admitControlArg
  rw [camel_integrity_meet_never_elevates ctrl huntrusted]
  simp only [integrityRank]
  exact decide_eq_false (by omega)

end DifcAndCamel

/-! ## Section 2: Unbounded Doyle TMS Retraction & de Kleer ATMS Survival (`B8`) -/

section DoyleTmsAndAtms

variable {BeliefId Digest : Type}

def justificationSupported (active : BeliefId → Bool) (deps : List BeliefId) : Bool :=
  deps.all active

def beliefSupported (active : BeliefId → Bool) (justifications : List (List BeliefId)) : Bool :=
  justifications.any (justificationSupported active)

/--
**Theorem 6 (Unbounded Doyle TMS Sole-Support Causal Retraction)**:
If a derived belief depends on a single justification `deps` and ANY dependency `s ∈ deps`
is retracted (`active s = false`), the belief immediately loses support.
-/
theorem doyle_single_justification_retraction_cascades
    (active : BeliefId → Bool) (deps : List BeliefId) (s : BeliefId)
    (hmem : s ∈ deps) (hretracted : active s = false) :
    beliefSupported active [deps] = false := by
  simp only [beliefSupported, justificationSupported, List.any_cons, List.any_nil, Bool.or_false]
  cases hall : deps.all active with
  | false => rfl
  | true =>
    have hs := List.all_eq_true.mp hall s hmem
    rw [hretracted] at hs
    exact Bool.noConfusion hs

/--
**Theorem 7 (Unbounded de Kleer ATMS Multi-Justification Survival)**:
If a belief carries an arbitrary list of alternative justifications `justifications`
containing at least one clean justification `jClean` whose dependencies are all active,
the belief remains supported (`true`) even when all other poisoned justifications collapse.
-/
theorem atms_clean_alternative_justification_survives
    (active : BeliefId → Bool) (justifications : List (List BeliefId)) (jClean : List BeliefId)
    (hmem : jClean ∈ justifications)
    (hclean : ∀ u ∈ jClean, active u = true) :
    beliefSupported active justifications = true := by
  unfold beliefSupported
  apply List.any_eq_true.mpr
  refine ⟨jClean, hmem, ?_⟩
  unfold justificationSupported
  exact List.all_eq_true.mpr hclean

/--
**Theorem 8 (Unbounded Monotonic Poison Immunization Tombstone)**:
Once a poisoned claim digest `d` is pinned in `tombstones`, re-proposing `d` is refused
across ANY future monotonic tombstone expansion `tombstones ++ extra`.
-/
theorem poison_immunization_tombstone_blocks_reproposal
    [DecidableEq Digest] (tombstones extra : List Digest) (d : Digest)
    (htomb : d ∈ tombstones) :
    decide (d ∉ tombstones ++ extra) = false := by
  simp only [decide_eq_false_iff_not, Classical.not_not]
  exact List.mem_append_left extra htomb

end DoyleTmsAndAtms

/-! ## Section 3: LeanPoo Two-Step Refinement (`B7 -> B8 -> cedar-poo-spec`) & Proof Transport -/

section LeanPooInfoFlowContract

structure InfoFlowTmsConfig where
  difcTaintEnforced : Bool
  camelIntegrityEnforced : Bool
  atmsQuarantineEnforced : Bool
  hostDisclosurePolicyBound : Bool
  deriving DecidableEq, Repr

inductive InfoFlowTmsKey where
  | difcTaintEnforced
  | camelIntegrityEnforced
  | atmsQuarantineEnforced
  | hostDisclosurePolicyBound
  deriving DecidableEq, Repr

inductive InfoFlowTmsIssue where
  | secretExfiltrationAllowed
  | untrustedControlFlowAllowed
  | unverifiedMemoryPromoted
  | hostDisclosurePolicyBypassed
  deriving DecidableEq, Repr

private def infoFlowView : View InfoFlowTmsConfig InfoFlowTmsKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseDifcContract :
    Contract InfoFlowTmsConfig InfoFlowTmsKey Unit InfoFlowTmsIssue where
  view := infoFlowView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.difcTaintEnforced then [] else [.rejected path .secretExfiltrationAllowed]) ++
    (if cfg.camelIntegrityEnforced then [] else [.rejected path .untrustedControlFlowAllowed])
  validInventory := Or.inl rfl

def atmsQuarantineExt (cfg : InfoFlowTmsConfig) (path : List InfoFlowTmsKey) :
    List (Issue InfoFlowTmsKey InfoFlowTmsIssue) :=
  if cfg.atmsQuarantineEnforced then [] else [.rejected path .unverifiedMemoryPromoted]

/--
**Theorem 9 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Disclosure Host Preservation)**:
Layering `B8` ATMS quarantine AND ANY downstream `cedar-poo-spec` data-disclosure /
pseudonymization host extension `hostDisclosureExt` onto `baseDifcContract` strictly
preserves every `B7` DIFC / CaMeL safety rejection.
-/
theorem difcAtmsContract_preserves_rejection
    (hostDisclosureExt : InfoFlowTmsConfig → List InfoFlowTmsKey →
      List (Issue InfoFlowTmsKey InfoFlowTmsIssue))
    (cfg : InfoFlowTmsConfig) (path : List InfoFlowTmsKey)
    (hRej : diagnose baseDifcContract cfg path ≠ []) :
    diagnose (refine (refine baseDifcContract atmsQuarantineExt) hostDisclosureExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection
    baseDifcContract atmsQuarantineExt hostDisclosureExt cfg path hRej

inductive InfoFlowProofKey where
  | difcTaintEnforced
  | camelIntegrityEnforced
  | atmsQuarantineEnforced
  | memoryCacheTtlMs
  deriving DecidableEq

abbrev InfoFlowProofValue : InfoFlowProofKey → Type
  | .difcTaintEnforced => Bool
  | .camelIntegrityEnforced => Bool
  | .atmsQuarantineEnforced => Bool
  | .memoryCacheTtlMs => Nat

def infoFlowSafetyObligation : LeanPoo.Proof.Obligation InfoFlowProofKey InfoFlowProofValue where
  dependencies := [.difcTaintEnforced, .camelIntegrityEnforced, .atmsQuarantineEnforced]
  holds := fun s =>
    s .difcTaintEnforced = true ∧
    s .camelIntegrityEnforced = true ∧
    s .atmsQuarantineEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3⟩
    exact ⟨(same .difcTaintEnforced (by simp)).symm.trans h1,
           (same .camelIntegrityEnforced (by simp)).symm.trans h2,
           (same .atmsQuarantineEnforced (by simp)).symm.trans h3⟩

def baselineInfoFlowSystem : LeanPoo.Proof.ProofObject InfoFlowProofKey InfoFlowProofValue where
  state := fun
    | .difcTaintEnforced => true
    | .camelIntegrityEnforced => true
    | .atmsQuarantineEnforced => true
    | .memoryCacheTtlMs => 60000
  obligations := [infoFlowSafetyObligation]

theorem baselineInfoFlowCertified : LeanPoo.Proof.Certificate baselineInfoFlowSystem := by
  intro ob hMem
  have hEq : ob = infoFlowSafetyObligation := by simpa [baselineInfoFlowSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl⟩

/-- **Theorem 10**: Tuning `.memoryCacheTtlMs` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem retentionTuning_preserves_difc_atms_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineInfoFlowSystem
        (LeanPoo.Proof.Patch.set .memoryCacheTtlMs 120000)) :=
  close_single_set_untouched baselineInfoFlowSystem infoFlowSafetyObligation
    .memoryCacheTtlMs 120000 rfl baselineInfoFlowCertified (by simp [infoFlowSafetyObligation])

/-- **Theorem 11 (Negative Control)**: Disabling `.camelIntegrityEnforced` ALWAYS invalidates reuse. -/
theorem disablingCamelIntegrity_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected infoFlowSafetyObligation
        (LeanPoo.Proof.Patch.set .camelIntegrityEnforced false) :=
  set_dependency_invalidates_unaffected infoFlowSafetyObligation
    .camelIntegrityEnforced false (by simp [infoFlowSafetyObligation])

end LeanPooInfoFlowContract

end DeterministicEngineering.Engineering.InformationFlowAndTms
