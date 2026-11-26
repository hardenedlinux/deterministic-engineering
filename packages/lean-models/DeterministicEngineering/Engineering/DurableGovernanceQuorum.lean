/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Transport

/-!
# LeanPoo-Centric Unbounded Meta-Theorems for Durable AI Governance (`B1`–`B10b`)

Built strictly on **Lean 4 core + `LeanPoo`** (zero Mathlib dependency) and aligned
with our Library vs. Consuming Host boundary:
- This repository (`deterministic-engineering-qnt`) is the reusable **Library**:
  it proves unbounded algebraic laws, arbitrary-depth structural induction,
  `LeanPoo.Functional.ObjectContract.refine` monotonic contract refinements, and
  `LeanPoo.Proof.Reuse` / `Core.Transport` cross-patch certificate transport.
- Concrete authorization policy evaluation (Cedar policies, principals, roles,
  tenant permissions) lives in the consuming host (`cedar-poo-spec`), which
  instantiates and monotonically refines this library's `LeanPoo` contracts via
  `hostPolicyRefinement_preserves_library_rejection`.

Machine-checked theorems (zero `sorry`, zero custom axioms):
1. **Unbounded Byzantine Quorum Intersection & Safety (`B10`, 10.169)**:
   `∀ N, f, t` with `2 * t > N + f`, any two quorums share ≥ 1 honest witness.
2. **Unbounded Multi-Epoch Joint-Consensus Continuity (`B10b`, 10.171)**:
   Arbitrary `k`-step handover chain monotonically advances epoch & rejects all
   retired epochs `e_old < E₀ + k` against posterior corruption.
3. **Unbounded Stratified OP `R3` Non-Leakage (`M1/M2/M3`, 10.156)**:
   Arbitrary-depth recursive persistence guard forbids any reachable `M3` node.
4. **Unbounded Linear Multi-Agent Budget Conservation (`B6`, 10.163)**:
   Atomic split and bounded spend preserve `totalPoolBudget` across arbitrary trees.
5. **Unbounded Multi-Hop Capability Attenuation & Revocation (`B3`, 10.160)**:
   Arbitrary-hop expiry bound & cascading revocation (abstract over host policy).
6. **`LeanPoo` Monotonic Contract Refinement (`B10 -> B10b -> R3 -> cedar-poo-spec`)**:
   Two-step library refinement + generic downstream host-policy refinement
   monotonically preserve all base safety rejections (`floor-weakening` impossible).
7. **`LeanPoo.Proof.Reuse` / `Core.Transport` Cross-Patch Certificate Transport**:
   Operational tuning (`gossipIntervalMs`, `checkpointBatchSize`) transports the
   quorum certificate in 1 line; disabling `.externalPolicyHostBound` invalidates reuse.
-/

namespace DeterministicEngineering.Engineering.DurableGovernanceQuorum

open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Self-Contained Finite-List Pigeonhole & B10 Unbounded Quorum Intersection -/

section ByzantineQuorumIntersection

variable {α : Type} [DecidableEq α]

/-- Duplicate-free list predicate (self-contained, zero Mathlib dependency). -/
def isNodup : List α → Prop
  | [] => True
  | x :: xs => x ∉ xs ∧ isNodup xs

theorem mem_erase_of_ne {x y : α} : ∀ {ys : List α}, y ∈ ys → y ≠ x → y ∈ ys.erase x
  | [], h, _ => nomatch h
  | z :: zs, h, hne => by
    simp only [List.erase_cons]
    by_cases hzx : z == x
    · have hzx' : z = x := eq_of_beq hzx
      subst hzx'
      simp only [beq_self_eq_true, ↓reduceIte]
      cases List.mem_cons.mp h with
      | inl hyz => exact False.elim (hne hyz)
      | inr hyzs => exact hyzs
    · simp only [hzx, Bool.false_eq_true, ↓reduceIte]
      cases List.mem_cons.mp h with
      | inl hyz => subst hyz; exact List.mem_cons_self
      | inr hyzs => exact List.mem_cons_of_mem z (mem_erase_of_ne hyzs hne)

theorem length_erase_of_mem {x : α} : ∀ {ys : List α}, x ∈ ys → (ys.erase x).length + 1 = ys.length
  | [], h => nomatch h
  | z :: zs, h => by
    simp only [List.erase_cons]
    by_cases hzx : z == x
    · simp [hzx]
    · simp only [hzx, Bool.false_eq_true, ↓reduceIte, List.length_cons]
      have hzx' : z ≠ x := fun heq => hzx (by simp [heq])
      cases List.mem_cons.mp h with
      | inl hxz => exact False.elim (hzx' hxz.symm)
      | inr hxzs =>
        have ih := length_erase_of_mem hxzs
        omega

/-- Pigeonhole cardinality bound: any duplicate-free subset of `ys` has length `≤ ys.length`. -/
theorem length_le_of_subset :
    ∀ {xs ys : List α}, isNodup xs → (∀ x ∈ xs, x ∈ ys) → xs.length ≤ ys.length
  | [], _, _, _ => Nat.zero_le _
  | x :: xs, ys, ⟨hxNotIn, hndXs⟩, hsub => by
    have hxYs : x ∈ ys := hsub x List.mem_cons_self
    have hsubErase : ∀ y ∈ xs, y ∈ ys.erase x := by
      intro y hy
      have hyYs : y ∈ ys := hsub y (List.mem_cons_of_mem x hy)
      have hne : y ≠ x := fun heq => hxNotIn (heq ▸ hy)
      exact mem_erase_of_ne hyYs hne
    have ih := length_le_of_subset hndXs hsubErase
    have herase := length_erase_of_mem hxYs
    simp only [List.length_cons]
    omega

omit [DecidableEq α] in
theorem isNodup_filter (p : α → Bool) : ∀ {xs : List α}, isNodup xs → isNodup (xs.filter p)
  | [], _ => trivial
  | x :: xs, ⟨hxNotIn, hndXs⟩ => by
    simp only [List.filter_cons]
    cases hp : p x
    · exact isNodup_filter p hndXs
    · refine ⟨?_, isNodup_filter p hndXs⟩
      intro hmem
      exact hxNotIn (List.mem_filter.mp hmem).1

omit [DecidableEq α] in
theorem isNodup_append :
    ∀ {xs ys : List α}, isNodup xs → isNodup ys → (∀ x ∈ xs, x ∉ ys) → isNodup (xs ++ ys)
  | [], _, _, hndY, _ => hndY
  | x :: xs, ys, ⟨hxXs, hndXs⟩, hndY, hdisj => by
    simp only [List.cons_append]
    refine ⟨?_, isNodup_append hndXs hndY (fun z hz => hdisj z (List.mem_cons_of_mem x hz))⟩
    intro hmem
    cases List.mem_append.mp hmem with
    | inl h1 => exact hxXs h1
    | inr h2 => exact hdisj x List.mem_cons_self h2

omit [DecidableEq α] in
theorem length_filter_add_not (p : α → Bool) :
    ∀ (xs : List α), (xs.filter p).length + (xs.filter (fun x => !p x)).length = xs.length
  | [] => rfl
  | x :: xs => by
    have ih := length_filter_add_not p xs
    simp only [List.filter_cons, List.length_cons]
    cases p x <;> simp <;> omega

/-- Exact Finite-List Inclusion-Exclusion bound for any two quorums in `roster`. -/
theorem quorum_intersection_length_bound
    (roster q1 q2 : List α)
    (hnd1 : isNodup q1) (hnd2 : isNodup q2)
    (hsub1 : ∀ x ∈ q1, x ∈ roster) (hsub2 : ∀ x ∈ q2, x ∈ roster) :
    (q1.filter (fun x => decide (x ∈ q2))).length + roster.length ≥ q1.length + q2.length := by
  let p : α → Bool := fun x => decide (x ∈ q2)
  let only1 := q1.filter (fun x => !p x)
  have hpart : (q1.filter p).length + only1.length = q1.length := length_filter_add_not p q1
  have hndOnly1 : isNodup only1 := isNodup_filter (fun x => !p x) hnd1
  have hdisj : ∀ x ∈ only1, x ∉ q2 := by
    intro x hx
    have hfp := (List.mem_filter.mp hx).2
    simp only [p, Bool.not_eq_true', decide_eq_false_iff_not] at hfp
    exact hfp
  have hndUnion : isNodup (only1 ++ q2) := isNodup_append hndOnly1 hnd2 hdisj
  have hsubUnion : ∀ x ∈ only1 ++ q2, x ∈ roster := by
    intro x hx
    cases List.mem_append.mp hx with
    | inl h1 => exact hsub1 x (List.mem_filter.mp h1).1
    | inr h2 => exact hsub2 x h2
  have hcard : (only1 ++ q2).length ≤ roster.length := length_le_of_subset hndUnion hsubUnion
  rw [List.length_append] at hcard
  change (q1.filter p).length + roster.length ≥ q1.length + q2.length
  omega

/--
**Theorem 1a (Unbounded BFT Quorum Intersection, `∀ N, f, t`)**:
For any roster of size `N = roster.length`, any Byzantine fault budget `f`, and any
quorum threshold `t` with `2 * t > N + f`, any two duplicate-free quorums `q1, q2 ⊆ roster`
of size `≥ t` contain at least one **honest** witness `w ∈ q1 ∩ q2 \ byzantine`.
-/
theorem bft_quorum_intersection_honest_witness
    (roster q1 q2 byzantine : List α) (f t : Nat)
    (hnd1 : isNodup q1) (hnd2 : isNodup q2)
    (hsub1 : ∀ x ∈ q1, x ∈ roster) (hsub2 : ∀ x ∈ q2, x ∈ roster)
    (hq1 : q1.length ≥ t) (hq2 : q2.length ≥ t)
    (hbyz : byzantine.length ≤ f)
    (hbft : 2 * t > roster.length + f) :
    ∃ w : α, w ∈ q1 ∧ w ∈ q2 ∧ w ∉ byzantine := by
  let inter := q1.filter (fun x => decide (x ∈ q2))
  have hinterBound : inter.length + roster.length ≥ q1.length + q2.length :=
    quorum_intersection_length_bound roster q1 q2 hnd1 hnd2 hsub1 hsub2
  let isByz : α → Bool := fun x => decide (x ∈ byzantine)
  let byzInter := inter.filter isByz
  let honestInter := inter.filter (fun x => !isByz x)
  have hsplit : byzInter.length + honestInter.length = inter.length :=
    length_filter_add_not isByz inter
  have hndInter : isNodup inter := isNodup_filter (fun x => decide (x ∈ q2)) hnd1
  have hndByzInter : isNodup byzInter := isNodup_filter isByz hndInter
  have hsubByz : ∀ x ∈ byzInter, x ∈ byzantine := by
    intro x hx
    have hf := (List.mem_filter.mp hx).2
    simp only [isByz, decide_eq_true_eq] at hf
    exact hf
  have hbyzCard : byzInter.length ≤ byzantine.length := length_le_of_subset hndByzInter hsubByz
  have hhonestPos : honestInter.length ≥ 1 := by omega
  cases hlist : honestInter with
  | nil =>
    rw [hlist] at hhonestPos
    exact False.elim (Nat.not_succ_le_zero 0 hhonestPos)
  | cons w ws =>
    have hwMem : w ∈ honestInter := by rw [hlist]; exact List.mem_cons_self
    have ⟨hwInter, hwNotByzB⟩ := List.mem_filter.mp hwMem
    have ⟨hwQ1, hwQ2B⟩ := List.mem_filter.mp hwInter
    refine ⟨w, hwQ1, ?_, ?_⟩
    · simp only [decide_eq_true_eq] at hwQ2B
      exact hwQ2B
    · simp only [isByz, Bool.not_eq_true', decide_eq_false_iff_not] at hwNotByzB
      exact hwNotByzB

/--
**Theorem 1b (Unbounded BFT Finality Safety)**:
Under `2 * t > N + f` and at most `f` Byzantine witnesses, if honest witnesses never
sign two distinct roots `r1 ≠ r2`, then two conflicting roots can NEVER both achieve
quorum finality — for arbitrary committee size `N`!
-/
theorem bft_no_conflicting_finality
    {Root : Type}
    (roster q1 q2 byzantine : List α) (f t : Nat) (r1 r2 : Root)
    (signed : α → Root → Prop)
    (hnd1 : isNodup q1) (hnd2 : isNodup q2)
    (hsub1 : ∀ x ∈ q1, x ∈ roster) (hsub2 : ∀ x ∈ q2, x ∈ roster)
    (hq1 : q1.length ≥ t) (hq2 : q2.length ≥ t)
    (hbyz : byzantine.length ≤ f)
    (hbft : 2 * t > roster.length + f)
    (hsig1 : ∀ w ∈ q1, signed w r1)
    (hsig2 : ∀ w ∈ q2, signed w r2)
    (hhonest : ∀ w, w ∉ byzantine → signed w r1 → signed w r2 → r1 = r2) :
    r1 = r2 := by
  obtain ⟨w, hw1, hw2, hwHonest⟩ :=
    bft_quorum_intersection_honest_witness roster q1 q2 byzantine f t
      hnd1 hnd2 hsub1 hsub2 hq1 hq2 hbyz hbft
  exact hhonest w hwHonest (hsig1 w hw1) (hsig2 w hw2)

end ByzantineQuorumIntersection

/-! ## Section 2: Unbounded Multi-Epoch Joint-Consensus Handover Continuity (`B10b`) -/

section MultiEpochHandover

structure HandoverStep where
  fromEpoch : Nat
  toEpoch : Nat
  anchorTreeSize : Nat
  oldQuorumSigned : Bool
  newQuorumSigned : Bool
  deriving DecidableEq, Repr

structure EpochVerifierState where
  pinnedEpoch : Nat
  anchorTreeSize : Nat
  deriving DecidableEq, Repr

/-- A single Joint-Consensus handover step is valid iff it is strictly monotonic
    (`toEpoch = fromEpoch + 1`), backed by BOTH `Q_old` and `Q_new`, and preserves
    monotonic RFC 6962 tree-size continuity from the previous anchor. -/
def validHandoverStep (st : EpochVerifierState) (step : HandoverStep) : Prop :=
  step.fromEpoch = st.pinnedEpoch ∧
  step.toEpoch = st.pinnedEpoch + 1 ∧
  step.oldQuorumSigned = true ∧
  step.newQuorumSigned = true ∧
  step.anchorTreeSize ≥ st.anchorTreeSize

def applyHandoverStep (_st : EpochVerifierState) (step : HandoverStep) : EpochVerifierState :=
  { pinnedEpoch := step.toEpoch, anchorTreeSize := step.anchorTreeSize }

/-- Valid arbitrary-length handover chain starting from `st`. -/
def validHandoverChain : EpochVerifierState → List HandoverStep → Prop
  | _, [] => True
  | st, s :: rest => validHandoverStep st s ∧ validHandoverChain (applyHandoverStep st s) rest

def applyHandoverChain : EpochVerifierState → List HandoverStep → EpochVerifierState
  | st, [] => st
  | st, s :: rest => applyHandoverChain (applyHandoverStep st s) rest

/-- Weak-subjectivity epoch admission gate: only checkpoints in the exact pinned epoch are admitted. -/
def admitEpochCheckpoint (pinnedEpoch checkpointEpoch : Nat) : Bool :=
  decide (checkpointEpoch = pinnedEpoch)

/--
**Theorem 2a (Unbounded Monotonic Epoch & Anchor Continuity)**:
Across any valid chain of `k` Joint-Consensus handovers, `pinnedEpoch` advances
to `st.pinnedEpoch + k` without skipping any epoch, and `anchorTreeSize` never regresses.
-/
theorem handover_chain_monotonic :
    ∀ (chain : List HandoverStep) (st : EpochVerifierState),
      validHandoverChain st chain →
      (applyHandoverChain st chain).pinnedEpoch = st.pinnedEpoch + chain.length ∧
      (applyHandoverChain st chain).anchorTreeSize ≥ st.anchorTreeSize
  | [], st, _ => by
    simp [applyHandoverChain]
  | s :: rest, st, ⟨hstep, hrest⟩ => by
    rcases hstep with ⟨_, hto, _, _, htree⟩
    have ih := handover_chain_monotonic rest (applyHandoverStep st s) hrest
    simp only [applyHandoverChain, applyHandoverStep, List.length_cons] at ih ⊢
    omega

/--
**Theorem 2b (Unbounded Anti-Long-Range / Posterior-Corruption Safety)**:
After ANY valid chain of `k` handovers starting at `st`, EVERY retired epoch
`e_old < st.pinnedEpoch + k` is deterministically rejected by `admitEpochCheckpoint`,
even if an adversary compromises 100% of retired committee keys.
-/
theorem handover_chain_rejects_all_retired_epochs
    (st : EpochVerifierState) (chain : List HandoverStep) (retiredEpoch : Nat)
    (hvalid : validHandoverChain st chain)
    (hretired : retiredEpoch < st.pinnedEpoch + chain.length) :
    admitEpochCheckpoint (applyHandoverChain st chain).pinnedEpoch retiredEpoch = false := by
  have ⟨hepoch, _⟩ := handover_chain_monotonic chain st hvalid
  simp only [admitEpochCheckpoint, hepoch, decide_eq_false_iff_not]
  omega

end MultiEpochHandover

/-! ## Section 3: Unbounded Stratified OP `R3` Non-Leakage (`M1 / M2 / M3`) -/

section StratifiedOrthogonalPersistenceR3

/-- Arbitrary-depth object graph crossing the `M1` Merkle persistence boundary. -/
inductive PersistNode where
  | m1Immutable (digest : Nat)
  | m2Ephemeral (tag : Nat)
  | m3LiveCapability (capId : Nat)
  | pair (left right : PersistNode)
  deriving DecidableEq, Repr

/-- Recursive `R3` persistence boundary guard (mirrors `assert-m1-persistable!` / `putBlob`). -/
def isM1Persistable : PersistNode → Bool
  | .m1Immutable _ => true
  | .m2Ephemeral _ => true
  | .m3LiveCapability _ => false
  | .pair l r => isM1Persistable l && isM1Persistable r

/-- Reachability predicate: does any descendant at any depth carry a live `M3` capability? -/
def containsM3 : PersistNode → Prop
  | .m1Immutable _ => False
  | .m2Ephemeral _ => False
  | .m3LiveCapability _ => True
  | .pair l r => containsM3 l ∨ containsM3 r

/--
**Theorem 3a (Unbounded `R3` Reachability Non-Interference)**:
For an object graph of ANY finite depth, if `isM1Persistable root = true`, then
NO reachable descendant is a live `M3` capability.
-/
theorem m1_persistable_forbids_any_m3_descendant :
    ∀ (node : PersistNode), isM1Persistable node = true → ¬ containsM3 node
  | .m1Immutable _, _, h => h
  | .m2Ephemeral _, _, h => h
  | .m3LiveCapability _, hok, _ => by simp [isM1Persistable] at hok
  | .pair l r, hok, h => by
    simp only [isM1Persistable, Bool.and_eq_true] at hok
    cases h with
    | inl hl => exact m1_persistable_forbids_any_m3_descendant l hok.1 hl
    | inr hr => exact m1_persistable_forbids_any_m3_descendant r hok.2 hr

/--
**Theorem 3b (Completeness of `R3` Leak Refusal)**:
Conversely, ANY live `M3` capability buried at arbitrary depth forces `isM1Persistable = false`.
-/
theorem m3_leak_always_refused (node : PersistNode) (h : containsM3 node) :
    isM1Persistable node = false := by
  cases hok : isM1Persistable node with
  | false => rfl
  | true => exact False.elim (m1_persistable_forbids_any_m3_descendant node hok h)

end StratifiedOrthogonalPersistenceR3

/-! ## Section 4: Unbounded Linear Multi-Agent Budget Conservation (`B6`) -/

section LinearBudgetConservation

structure BudgetNode where
  remaining : Nat
  spent : Nat
  deriving DecidableEq, Repr

/-- Arbitrary-size pool of delegated linear sub-agent budget handles. -/
def totalPoolBudget : List BudgetNode → Nat
  | [] => 0
  | b :: bs => b.remaining + b.spent + totalPoolBudget bs

/-- Atomic linear budget transfer/split from parent handle into a new child handle. -/
def atomicSplitHead (amount : Nat) : List BudgetNode → List BudgetNode
  | [] => []
  | b :: bs =>
    if amount ≤ b.remaining then
      { remaining := b.remaining - amount, spent := b.spent } ::
      { remaining := amount, spent := 0 } :: bs
    else
      b :: bs

/-- Bounded step expenditure on the head budget handle (refuses overspend). -/
def boundedSpendHead (cost : Nat) : List BudgetNode → List BudgetNode
  | [] => []
  | b :: bs =>
    if cost ≤ b.remaining then
      { remaining := b.remaining - cost, spent := b.spent + cost } :: bs
    else
      b :: bs

/-- **Theorem 4a**: Atomic linear delegation split strictly conserves global budget for any pool size. -/
theorem split_preserves_total_budget (amount : Nat) (pool : List BudgetNode) :
    totalPoolBudget (atomicSplitHead amount pool) = totalPoolBudget pool := by
  cases pool with
  | nil => rfl
  | cons b bs =>
    simp only [atomicSplitHead]
    by_cases h : amount ≤ b.remaining
    · simp only [h, ↓reduceIte, totalPoolBudget]
      omega
    · simp [h]

/-- **Theorem 4b**: Bounded step expenditure strictly conserves global budget (`remaining + spent`). -/
theorem spend_preserves_total_budget (cost : Nat) (pool : List BudgetNode) :
    totalPoolBudget (boundedSpendHead cost pool) = totalPoolBudget pool := by
  cases pool with
  | nil => rfl
  | cons b bs =>
    simp only [boundedSpendHead]
    by_cases h : cost ≤ b.remaining
    · simp only [h, ↓reduceIte, totalPoolBudget]
      omega
    · simp [h]

end LinearBudgetConservation

/-! ## Section 5: Unbounded Multi-Hop Capability Attenuation & Cascading Revocation (`B3`) -/

section CapabilityAttenuation

structure CapHop where
  principalId : Nat
  expiresAtEpoch : Nat
  deriving DecidableEq, Repr

/-- Monotonic expiry narrowing across an arbitrary-length delegation chain `[root, ..., leaf]`. -/
def monotonicExpiryChain : List CapHop → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => b.expiresAtEpoch ≤ a.expiresAtEpoch ∧ monotonicExpiryChain (b :: rest)

def lastExpiry (head : CapHop) : List CapHop → Nat
  | [] => head.expiresAtEpoch
  | x :: xs => lastExpiry x xs

/--
**Theorem 5a (Unbounded Monotonic Attenuation Bound)**:
Across an arbitrary `k`-hop delegation chain, the leaf certificate's expiry epoch
can NEVER exceed the root authority's expiry epoch.
-/
theorem attenuation_chain_bounded_by_root :
    ∀ (root : CapHop) (rest : List CapHop),
      monotonicExpiryChain (root :: rest) →
      lastExpiry root rest ≤ root.expiresAtEpoch
  | _, [], _ => Nat.le_refl _
  | root, child :: rest, ⟨hstep, hrest⟩ => by
    have ih := attenuation_chain_bounded_by_root child rest hrest
    simp only [lastExpiry]
    omega

/-- Chain authorization predicate: every hop in the chain must be unrevoked. -/
def chainAuthorized (isRevoked : Nat → Bool) : List CapHop → Bool
  | [] => true
  | h :: rest => !isRevoked h.principalId && chainAuthorized isRevoked rest

/--
**Theorem 5b (Unbounded Cascading Ancestor Revocation Soundness)**:
If ANY ancestor hop `h` at arbitrary depth in the delegation chain is revoked,
the entire delegated chain immediately evaluates to `chainAuthorized = false`.
-/
theorem ancestor_revocation_invalidates_chain
    (isRevoked : Nat → Bool) :
    ∀ (chain : List CapHop) (h : CapHop),
      h ∈ chain → isRevoked h.principalId = true →
      chainAuthorized isRevoked chain = false
  | [], _, hmem, _ => nomatch hmem
  | x :: xs, h, hmem, hrev => by
    simp only [chainAuthorized]
    cases List.mem_cons.mp hmem with
    | inl heq =>
      subst heq
      simp [hrev]
    | inr htail =>
      have ih := ancestor_revocation_invalidates_chain isRevoked xs h htail hrev
      simp [ih]

end CapabilityAttenuation

/-! ## Section 6: LeanPoo Monotonic Contract Refinement (`B10 -> B10b -> R3 -> cedar-poo-spec`) -/

section LeanPooContractRefinement

/-- Library-owned quorum governance configuration; concrete authorization policy
    rules remain owned by the consuming host (e.g. `cedar-poo-spec`) and bound via
    `externalPolicyHostBound` + downstream `ObjectContract.refine`. -/
structure DurableQuorumConfig where
  bftIntersectionEnforced : Bool
  dualQuorumHandoverEnforced : Bool
  retiredKeyZeroizationEnforced : Bool
  externalPolicyHostBound : Bool
  deriving DecidableEq, Repr

inductive DurableQuorumKey where
  | bftIntersectionEnforced
  | dualQuorumHandoverEnforced
  | retiredKeyZeroizationEnforced
  | externalPolicyHostBound
  deriving DecidableEq, Repr

inductive DurableQuorumIssue where
  | unsafeNonIntersectingQuorum
  | missingExternalPolicyHostBinding
  | unilateralEpochHandoverAllowed
  | unzeroizedRetiredWitnessKey
  | hostAuthorizationDenied
  deriving DecidableEq, Repr

private def durableQuorumView : View DurableQuorumConfig DurableQuorumKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base library contract (`B10` + host-policy binding boundary): refuses unsafe BFT
    quorums or bypassing the consuming host's authorization boundary (`cedar-poo-spec`). -/
def baseQuorumContract :
    Contract DurableQuorumConfig DurableQuorumKey Unit DurableQuorumIssue where
  view := durableQuorumView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.bftIntersectionEnforced then [] else [.rejected path .unsafeNonIntersectingQuorum]) ++
    (if cfg.externalPolicyHostBound then [] else [.rejected path .missingExternalPolicyHostBinding])
  validInventory := Or.inl rfl

/-- Step 1 refinement (`B10b`): requires dual-quorum (`Q_old ∩ Q_new`) handover. -/
def reconfigHandoverExt (cfg : DurableQuorumConfig) (path : List DurableQuorumKey) :
    List (Issue DurableQuorumKey DurableQuorumIssue) :=
  if cfg.dualQuorumHandoverEnforced then [] else [.rejected path .unilateralEpochHandoverAllowed]

/-- Step 2 refinement (`R3`): requires irreversible zeroization of retired witness keys. -/
def forwardSecureZeroizeExt (cfg : DurableQuorumConfig) (path : List DurableQuorumKey) :
    List (Issue DurableQuorumKey DurableQuorumIssue) :=
  if cfg.retiredKeyZeroizationEnforced then [] else [.rejected path .unzeroizedRetiredWitnessKey]

/-- Full library contract composed via two-step `LeanPoo.Functional.ObjectContract.refine`. -/
def fullDurableQuorumContract :
    Contract DurableQuorumConfig DurableQuorumKey Unit DurableQuorumIssue :=
  refine (refine baseQuorumContract reconfigHandoverExt) forwardSecureZeroizeExt

/--
**Theorem 6a (Two-Step `LeanPoo` Monotonic Refinement)**:
Layering `B10b` handover and `R3` key-zeroization onto `baseQuorumContract`
strictly preserves every base rejection (mechanically prevents G2 floor weakening).
-/
theorem durableQuorumContract_preserves_rejection
    (cfg : DurableQuorumConfig) (path : List DurableQuorumKey)
    (hRej : diagnose baseQuorumContract cfg path ≠ []) :
    diagnose fullDurableQuorumContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection
    baseQuorumContract reconfigHandoverExt forwardSecureZeroizeExt cfg path hRej

/--
**Theorem 6b (Consuming Host `cedar-poo-spec` Refinement Preservation)**:
For ANY downstream consuming-host authorization extension `hostAuthExt` (such as
Cedar policy obligations in `cedar-poo-spec`), refining `fullDurableQuorumContract`
with `hostAuthExt` monotonically preserves every library-level safety rejection.
-/
theorem hostPolicyRefinement_preserves_library_rejection
    (hostAuthExt : DurableQuorumConfig → List DurableQuorumKey →
      List (Issue DurableQuorumKey DurableQuorumIssue))
    (cfg : DurableQuorumConfig) (path : List DurableQuorumKey)
    (hLibRej : diagnose fullDurableQuorumContract cfg path ≠ []) :
    diagnose (refine fullDurableQuorumContract hostAuthExt) cfg path ≠ [] :=
  refine_preserves_rejection fullDurableQuorumContract hostAuthExt cfg path hLibRej

end LeanPooContractRefinement

/-! ## Section 7: LeanPoo `Proof.Reuse` / `Core.Transport` Cross-Patch Certificate Transport -/

section LeanPooProofTransport

inductive QuorumProofKey where
  | bftQuorumEnforced
  | dualHandoverEnforced
  | externalPolicyHostBound
  | gossipIntervalMs
  | checkpointBatchSize
  deriving DecidableEq

abbrev QuorumProofValue : QuorumProofKey → Type
  | .bftQuorumEnforced => Bool
  | .dualHandoverEnforced => Bool
  | .externalPolicyHostBound => Bool
  | .gossipIntervalMs => Nat
  | .checkpointBatchSize => Nat

/-- Core security obligation depends ONLY on the three safety/boundary slots, never on
    operational tuning knobs (`gossipIntervalMs`, `checkpointBatchSize`). -/
def quorumSafetyObligation : LeanPoo.Proof.Obligation QuorumProofKey QuorumProofValue where
  dependencies := [.bftQuorumEnforced, .dualHandoverEnforced, .externalPolicyHostBound]
  holds := fun s =>
    s .bftQuorumEnforced = true ∧
    s .dualHandoverEnforced = true ∧
    s .externalPolicyHostBound = true
  stable := by
    intro before after same ⟨h1, h2, h3⟩
    exact ⟨(same .bftQuorumEnforced (by simp)).symm.trans h1,
           (same .dualHandoverEnforced (by simp)).symm.trans h2,
           (same .externalPolicyHostBound (by simp)).symm.trans h3⟩

def baselineQuorumDeployment : LeanPoo.Proof.ProofObject QuorumProofKey QuorumProofValue where
  state := fun
    | .bftQuorumEnforced => true
    | .dualHandoverEnforced => true
    | .externalPolicyHostBound => true
    | .gossipIntervalMs => 500
    | .checkpointBatchSize => 64
  obligations := [quorumSafetyObligation]

theorem baselineQuorumCertified : LeanPoo.Proof.Certificate baselineQuorumDeployment := by
  intro ob hMem
  have hEq : ob = quorumSafetyObligation := by simpa [baselineQuorumDeployment] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl⟩

/-- **Theorem 7a**: Tuning `.gossipIntervalMs` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem gossipTuning_preserves_quorum_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineQuorumDeployment
        (LeanPoo.Proof.Patch.set .gossipIntervalMs 1200)) :=
  close_single_set_untouched baselineQuorumDeployment quorumSafetyObligation
    .gossipIntervalMs 1200 rfl baselineQuorumCertified (by simp [quorumSafetyObligation])

/-- **Theorem 7b**: Tuning `.checkpointBatchSize` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem batchSizeTuning_preserves_quorum_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineQuorumDeployment
        (LeanPoo.Proof.Patch.set .checkpointBatchSize 256)) :=
  close_single_set_untouched baselineQuorumDeployment quorumSafetyObligation
    .checkpointBatchSize 256 rfl baselineQuorumCertified (by simp [quorumSafetyObligation])

/-- **Theorem 7c (Negative Control)**: Disabling `.externalPolicyHostBound` (bypassing
    consuming-host `cedar-poo-spec` authorization) ALWAYS invalidates proof reuse! -/
theorem droppingExternalPolicyHost_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected quorumSafetyObligation
        (LeanPoo.Proof.Patch.set .externalPolicyHostBound false) :=
  set_dependency_invalidates_unaffected quorumSafetyObligation
    .externalPolicyHostBound false (by simp [quorumSafetyObligation])

end LeanPooProofTransport

end DeterministicEngineering.Engineering.DurableGovernanceQuorum
