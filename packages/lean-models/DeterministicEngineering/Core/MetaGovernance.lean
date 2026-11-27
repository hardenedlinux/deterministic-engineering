/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

/-!
# Formal Meta-Soundness of ASCENT Governance, Admission & Incremental Reuse (`Core.MetaGovernance`)

Mechanizes the exact logical specification of our repository's 16 ASCENT Datalog rules
(`MR01`–`MR06`, `ER01`–`ER04`, `IR01`–`IR06` in `library/verification-flow/ascent-rules.ss`)
inside Lean 4's kernel, proving unbounded meta-soundness properties that finite unit tests
cannot exhaustively cover:

1. **Exact Partition (`IR01`–`IR06`)**: Every step is exclusively either `pending` or `reusable`.
2. **Arbitrary-Depth DAG Transitivity (`IR03`)**: Invalidation at any ancestor `u` propagates
   along arbitrary-length directed paths `u →* v` to every downstream consumer `v`.
3. **Signed Cryptographic Reuse Soundness (`IR01`–`IR06`)**: Under `requireSignedCache`,
   any `reusable` step is guaranteed to have a passing cache witness, exact bidirectional input
   closure match, exact toolchain fingerprint match, valid Ed25519 attestation, fresh-M3
   compliance, and all upstream DAG ancestors simultaneously reusable.
4. **Evidence Admission Soundness (`ER01`–`ER04`)**: Any `VerificationAdmitted` subject has
   every declared obligation discharged by passing authorized evidence, zero failed steps,
   and every required premise backed by a passing supporting step.
5. **Pre-Flight Governance Soundness (`MR01`–`MR02`)**: Any `RunnableAdmitted` subject has
   zero unauthorized `(method, claimKind)` routings and zero unbridged duplicate methods.
-/

namespace DeterministicEngineering.Core.MetaGovernance

/-! ## 1. Arbitrary-Length Directed DAG Reachability -/

inductive DagPath {Step : Type} (edge : Step → Step → Prop) : Step → Step → Prop where
  | refl (s : Step) : DagPath edge s s
  | step {a b c : Step} : edge a b → DagPath edge b c → DagPath edge a c

theorem DagPath.trans {Step : Type} {edge : Step → Step → Prop} {a b c : Step}
    (h1 : DagPath edge a b) (h2 : DagPath edge b c) : DagPath edge a c := by
  induction h1 with
  | refl _ => exact h2
  | step hab _ ih => exact DagPath.step hab (ih h2)

/-! ## 2. Exact Declarative Semantics of ASCENT `IR01`–`IR06` -/

structure ReuseSystem (Step Key Digest Toolchain : Type) where
  dagEdge : Step → Step → Prop
  premiseSupportEdge : Step → Step → Prop
  hasPassingCache : Step → Prop
  currentInput : Step → Key → Digest → Prop
  cachedInput : Step → Key → Digest → Prop
  currentToolchain : Step → Toolchain → Prop
  cachedToolchain : Step → Toolchain → Prop
  isM3Mutable : Step → Prop
  attested : Step → Prop
  witnessExpired : Step → Prop
  requireFreshM3 : Prop
  requireSignedCache : Prop
  strictPremiseRecheck : Prop

def inputMismatch {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) : Prop :=
  ∃ k d1 d2, sys.currentInput s k d1 ∧ sys.cachedInput s k d2 ∧ d1 ≠ d2

def inputMissingInCache {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) : Prop :=
  ∃ k d1, sys.currentInput s k d1 ∧ ∀ d2, ¬ sys.cachedInput s k d2

def inputExtraInCache {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) : Prop :=
  ∃ k d2, sys.cachedInput s k d2 ∧ ∀ d1, ¬ sys.currentInput s k d1

def inputDirty {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) : Prop :=
  inputMismatch sys s ∨ inputMissingInCache sys s ∨ inputExtraInCache sys s

def toolchainDirty {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) : Prop :=
  (∃ t1 t2, sys.currentToolchain s t1 ∧ sys.cachedToolchain s t2 ∧ t1 ≠ t2) ∨
  (∃ t1, sys.currentToolchain s t1 ∧ ∀ t2, ¬ sys.cachedToolchain s t2)

/-- Least fixed point of ASCENT `step_invalidated` rules (`IR01`–`IR07`). -/
inductive Invalidated {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) : Step → Prop where
  | ir01 (s : Step) : ¬ sys.hasPassingCache s → Invalidated sys s
  | ir02 (s : Step) : inputDirty sys s → Invalidated sys s
  | ir03 {u v : Step} : sys.dagEdge u v → Invalidated sys u → Invalidated sys v
  | ir04 (s : Step) : sys.isM3Mutable s → sys.requireFreshM3 → Invalidated sys s
  | ir05 (s : Step) : toolchainDirty sys s → Invalidated sys s
  | ir06 (s : Step) : sys.requireSignedCache → ¬ sys.attested s → Invalidated sys s
  | ir07 {sup req : Step} : sys.strictPremiseRecheck → sys.premiseSupportEdge sup req →
      Invalidated sys sup → Invalidated sys req
  | ir08 (s : Step) : sys.isM3Mutable s → sys.witnessExpired s → Invalidated sys s

def Pending {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) : Prop :=
  Invalidated sys s

def Reusable {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) : Prop :=
  ¬ Invalidated sys s

/-- Exclusive partition: no step can ever be both `Pending` and `Reusable`. -/
theorem ir_partition_exclusive {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) :
    ¬ (Pending sys s ∧ Reusable sys s) := by
  intro ⟨hPend, hReuse⟩
  exact hReuse hPend

/-- Exhaustive partition: every step is either `Pending` or `Reusable`. -/
theorem ir_partition_exhaustive {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step) :
    Pending sys s ∨ Reusable sys s :=
  Classical.em (Invalidated sys s)

/-- Unbounded `IR03` transitivity: any invalidation at `u` propagates along arbitrary-length DAG paths `u →* v`. -/
theorem ir03_transitive_path_invalidation {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {u v : Step}
    (hPath : DagPath sys.dagEdge u v) (hInv : Invalidated sys u) :
    Invalidated sys v := by
  induction hPath with
  | refl _ => exact hInv
  | step hab _ ih => exact ih (Invalidated.ir03 hab hInv)

/-- Contrapositive: if a downstream step `v` is `Reusable`, EVERY upstream ancestor `u` at arbitrary depth is also `Reusable`. -/
theorem reusable_implies_all_ancestors_reusable {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {u v : Step}
    (hPath : DagPath sys.dagEdge u v) (hReuseV : Reusable sys v) :
    Reusable sys u := by
  intro hInvU
  exact hReuseV (ir03_transitive_path_invalidation sys hPath hInvU)

/-- Complete soundness of `Reusable` under `IR01`–`IR06`:
no dirty input, no toolchain drift, no unattested witness (under `requireSignedCache`),
and no stale M3 step (under `requireFreshM3`) can ever be reused. -/
theorem reusable_sound {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step)
    (hReuse : Reusable sys s) :
    sys.hasPassingCache s ∧
    ¬ inputDirty sys s ∧
    ¬ toolchainDirty sys s ∧
    (sys.requireFreshM3 → ¬ sys.isM3Mutable s) ∧
    (sys.requireSignedCache → sys.attested s) := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · exact Classical.byContradiction fun hNo => hReuse (Invalidated.ir01 s hNo)
  · intro hDirty; exact hReuse (Invalidated.ir02 s hDirty)
  · intro hTc; exact hReuse (Invalidated.ir05 s hTc)
  · intro hFresh hM3; exact hReuse (Invalidated.ir04 s hM3 hFresh)
  · intro hSign
    exact Classical.byContradiction fun hNoAtt => hReuse (Invalidated.ir06 s hSign hNoAtt)

/-- Negative-control soundness theorem: any input digest change anywhere upstream invalidates downstream `v`. -/
theorem upstream_input_drift_prevents_downstream_reuse {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {u v : Step}
    (hPath : DagPath sys.dagEdge u v) (hDirty : inputDirty sys u) :
    ¬ Reusable sys v := by
  intro hReuseV
  exact hReuseV (ir03_transitive_path_invalidation sys hPath (Invalidated.ir02 u hDirty))

/-- Negative-control soundness theorem: any forged/unattested upstream witness prevents downstream reuse under signed policy. -/
theorem upstream_forged_cache_prevents_downstream_reuse {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {u v : Step}
    (hPath : DagPath sys.dagEdge u v)
    (hSign : sys.requireSignedCache) (hUnattested : ¬ sys.attested u) :
    ¬ Reusable sys v := by
  intro hReuseV
  exact hReuseV (ir03_transitive_path_invalidation sys hPath (Invalidated.ir06 u hSign hUnattested))

/-- Constructive zero-axiom `IR07` mixed-graph soundness: under `strictPremiseRecheck`,
any invalidation propagates along arbitrary mixed sequences of DAG artifact edges (`IR03`)
and premise-support edges (`IR07`), so no consumer can reuse a stale witness when any
upstream artifact producer OR premise supporter at arbitrary depth is invalidated. -/
theorem ir07_mixed_dag_and_premise_invalidation {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {u v : Step}
    (hStrict : sys.strictPremiseRecheck)
    (hPath : DagPath (fun a b => sys.dagEdge a b ∨ sys.premiseSupportEdge a b) u v)
    (hInv : Invalidated sys u) :
    Invalidated sys v := by
  induction hPath with
  | refl _ => exact hInv
  | step hab _ ih =>
    cases hab with
    | inl hDag => exact ih (Invalidated.ir03 hDag hInv)
    | inr hPrem => exact ih (Invalidated.ir07 hStrict hPrem hInv)

/-- Contrapositive (constructive, zero axioms): under `strictPremiseRecheck`, a `Reusable`
step guarantees every upstream DAG ancestor AND every premise supporter along mixed paths is `Reusable`. -/
theorem ir07_reusable_implies_premise_supporters_reusable {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {sup req : Step}
    (hStrict : sys.strictPremiseRecheck)
    (hPath : DagPath (fun a b => sys.dagEdge a b ∨ sys.premiseSupportEdge a b) sup req)
    (hReuseReq : Reusable sys req) :
    Reusable sys sup := by
  intro hInvSup
  exact hReuseReq (ir07_mixed_dag_and_premise_invalidation sys hStrict hPath hInvSup)

/-- Constructive zero-axiom `IR08` soundness: any expired `M3-mutable-root` witness is
strictly non-reusable, AND under `strictPremiseRecheck` cascades to block downstream reuse. -/
theorem ir08_expired_m3_prevents_reuse {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step)
    (hM3 : sys.isM3Mutable s) (hExp : sys.witnessExpired s) :
    ¬ Reusable sys s := by
  intro hReuse
  exact hReuse (Invalidated.ir08 s hM3 hExp)

theorem ir08_expired_m3_cascades_under_strict_premise {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {sup req : Step}
    (hStrict : sys.strictPremiseRecheck)
    (hPath : DagPath (fun a b => sys.dagEdge a b ∨ sys.premiseSupportEdge a b) sup req)
    (hM3 : sys.isM3Mutable sup) (hExp : sys.witnessExpired sup) :
    ¬ Reusable sys req := by
  intro hReuseReq
  exact ir08_expired_m3_prevents_reuse sys sup hM3 hExp
    (ir07_reusable_implies_premise_supporters_reusable sys hStrict hPath hReuseReq)

/-! ## 3. Exact Declarative Semantics of ASCENT `MR01`–`MR02` & `ER01`–`ER04` -/

structure GovernanceSystem (Subject Step Obligation Method ClaimKind Premise : Type) where
  subjectObligation : Subject → Obligation → ClaimKind → Prop
  methodAllowsClaim : Method → ClaimKind → Prop
  flowStep : Step → Subject → Obligation → Method → ClaimKind → Prop
  correspondenceBridge : Obligation → Method → Method → Prop
  requiresPremise : Step → Premise → Prop
  supportsPremise : Step → Premise → Prop
  stepEvidencePass : Step → Obligation → Method → ClaimKind → Prop
  stepEvidenceFail : Step → Obligation → Method → ClaimKind → Prop

def ObligationPassed {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) (o : Obl) (k : CK) : Prop :=
  g.subjectObligation s o k ∧
  ∃ st m, g.flowStep st s o m k ∧ g.stepEvidencePass st o m k

def PremiseVerified {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (p : Prem) : Prop :=
  ∃ sup o m k, g.supportsPremise sup p ∧ g.stepEvidencePass sup o m k

def Er01MissingEvidence {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  ∃ o k, g.subjectObligation s o k ∧ ¬ ObligationPassed g s o k

def Er02FailedStep {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  ∃ st o m k o' m' k', g.flowStep st s o m k ∧ g.stepEvidenceFail st o' m' k'

def Er03UnverifiedPremise {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  ∃ st o m k p, g.flowStep st s o m k ∧ g.requiresPremise st p ∧ ¬ PremiseVerified g p

def Er04MethodMismatch {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) : Prop :=
  ∃ st o m k, (g.stepEvidencePass st o m k ∨ g.stepEvidenceFail st o m k) ∧ ¬ g.methodAllowsClaim m k

def VerificationAdmitted {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  (∃ o k, g.subjectObligation s o k) ∧
  ¬ Er01MissingEvidence g s ∧
  ¬ Er02FailedStep g s ∧
  ¬ Er03UnverifiedPremise g s ∧
  ¬ Er04MethodMismatch g

/-- Complete soundness of `ER01`–`ER04`: any admitted subject has every obligation passed,
zero failed steps, every required premise verified at runtime, and zero unauthorized claims. -/
theorem er_admitted_sound {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub)
    (hAdm : VerificationAdmitted g s) :
    (∀ o k, g.subjectObligation s o k → ObligationPassed g s o k) ∧
    (∀ st o m k p, g.flowStep st s o m k → g.requiresPremise st p → PremiseVerified g p) ∧
    (∀ st o m k, g.stepEvidencePass st o m k → g.methodAllowsClaim m k) := by
  rcases hAdm with ⟨_, hNo1, _, hNo3, hNo4⟩
  refine ⟨?_, ?_, ?_⟩
  · intro o k hObl
    exact Classical.byContradiction fun hNot => hNo1 ⟨o, k, hObl, hNot⟩
  · intro st o m k p hStep hReq
    exact Classical.byContradiction fun hNot => hNo3 ⟨st, o, m, k, p, hStep, hReq, hNot⟩
  · intro st o m k hPass
    exact Classical.byContradiction fun hDis => hNo4 ⟨st, o, m, k, Or.inl hPass, hDis⟩

def Mr01Unauthorized {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  ∃ st o m k, g.flowStep st s o m k ∧ ¬ g.methodAllowsClaim m k

def Mr02DuplicateWithoutBridge {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  ∃ st1 st2 o m1 m2 k,
    g.flowStep st1 s o m1 k ∧
    g.flowStep st2 s o m2 k ∧
    m1 ≠ m2 ∧
    ¬ g.correspondenceBridge o m1 m2 ∧
    ¬ g.correspondenceBridge o m2 m1

def RunnableAdmitted {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  (∃ o k, g.subjectObligation s o k) ∧
  ¬ Mr01Unauthorized g s ∧
  ¬ Mr02DuplicateWithoutBridge g s

/-- Complete soundness of `MR01`–`MR02`: any runnable-admitted subject has strictly authorized
method routing and zero unbridged cross-method duplication. -/
theorem mr_admitted_sound {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub)
    (hAdm : RunnableAdmitted g s) :
    (∀ st o m k, g.flowStep st s o m k → g.methodAllowsClaim m k) ∧
    (∀ st1 st2 o m1 m2 k,
      g.flowStep st1 s o m1 k → g.flowStep st2 s o m2 k → m1 ≠ m2 →
      g.correspondenceBridge o m1 m2 ∨ g.correspondenceBridge o m2 m1) := by
  rcases hAdm with ⟨_, hNo1, hNo2⟩
  refine ⟨?_, ?_⟩
  · intro st o m k hStep
    exact Classical.byContradiction fun hDis => hNo1 ⟨st, o, m, k, hStep, hDis⟩
  · intro st1 st2 o m1 m2 k h1 h2 hNe
    exact Classical.byContradiction fun hNoBr =>
      hNo2 ⟨st1, st2, o, m1, m2, k, h1, h2, hNe,
            fun hb => hNoBr (Or.inl hb), fun hb => hNoBr (Or.inr hb)⟩

/-! ## 4. Full `MR03`–`MR06` Pre-Flight Governance Soundness -/

structure ExtendedGovernance (Subject Step Obligation Method ClaimKind Premise Artifact Factor Platform Guard : Type)
    extends GovernanceSystem Subject Step Obligation Method ClaimKind Premise where
  dagEdge : Step → Step → Prop
  produces : Step → Artifact → Prop
  consumes : Step → Artifact → Prop
  statefulQuint : Step → Prop
  countermodel : Step → Guard → Prop
  subjectFactor : Subject → Factor → Prop
  ownsSubprocessTree : Factor
  osSigkillClaim : ClaimKind
  osContainment : Subject → Platform → Prop

def ArtifactEdgeSatisfied {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (st : St) (a : Art) : Prop :=
  ∃ u, g.dagEdge u st ∧ g.produces u a ∧ g.consumes st a

def Mr03OpenPremise {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (s : Sub) : Prop :=
  ∃ st o m k p, g.flowStep st s o m k ∧ g.requiresPremise st p ∧ ∀ sup, ¬ g.supportsPremise sup p

def Mr04MissingArtifactEdge {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (s : Sub) : Prop :=
  ∃ st o m k a, g.flowStep st s o m k ∧ g.consumes st a ∧ ¬ ArtifactEdgeSatisfied g st a

def Mr05MissingCountermodel {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (s : Sub) : Prop :=
  ∃ st o m k, g.flowStep st s o m k ∧ g.statefulQuint st ∧ ∀ grd, ¬ g.countermodel st grd

def Mr06MissingContainmentOrOracle {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (s : Sub) : Prop :=
  g.subjectFactor s g.ownsSubprocessTree ∧
  ((∀ plat, ¬ g.osContainment s plat) ∨
   (∀ st o m, ¬ g.flowStep st s o m g.osSigkillClaim))

/-- Complete `MR03`–`MR06` soundness: zero findings guarantee closed premises,
satisfied DAG artifact edges, mandatory stateful-Quint countermodels, and OS containment + SIGKILL oracle. -/
theorem mr03_06_full_sound {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (s : Sub)
    (hNo3 : ¬ Mr03OpenPremise g s)
    (hNo4 : ¬ Mr04MissingArtifactEdge g s)
    (hNo5 : ¬ Mr05MissingCountermodel g s)
    (hNo6 : ¬ Mr06MissingContainmentOrOracle g s) :
    (∀ st o m k p, g.flowStep st s o m k → g.requiresPremise st p → ∃ sup, g.supportsPremise sup p) ∧
    (∀ st o m k a, g.flowStep st s o m k → g.consumes st a → ArtifactEdgeSatisfied g st a) ∧
    (∀ st o m k, g.flowStep st s o m k → g.statefulQuint st → ∃ grd, g.countermodel st grd) ∧
    (g.subjectFactor s g.ownsSubprocessTree →
      (∃ plat, g.osContainment s plat) ∧ (∃ st o m, g.flowStep st s o m g.osSigkillClaim)) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro st o m k p hSt hReq
    exact Classical.byContradiction fun hNo =>
      hNo3 ⟨st, o, m, k, p, hSt, hReq, fun sup hSup => hNo ⟨sup, hSup⟩⟩
  · intro st o m k a hSt hCons
    exact Classical.byContradiction fun hNo =>
      hNo4 ⟨st, o, m, k, a, hSt, hCons, hNo⟩
  · intro st o m k hSt hQ
    exact Classical.byContradiction fun hNo =>
      hNo5 ⟨st, o, m, k, hSt, hQ, fun grd hCm => hNo ⟨grd, hCm⟩⟩
  · intro hFac
    refine ⟨?_, ?_⟩
    · exact Classical.byContradiction fun hNo =>
        hNo6 ⟨hFac, Or.inl (fun plat hP => hNo ⟨plat, hP⟩)⟩
    · exact Classical.byContradiction fun hNo =>
        hNo6 ⟨hFac, Or.inr (fun st o m hF => hNo ⟨st, o, m, hF⟩)⟩

/-! ## 5. Parallel Frontier Wave Scheduling Soundness (Zero-Race Confluence) -/

inductive NonEmptyDagPath {Step : Type} (edge : Step → Step → Prop) : Step → Step → Prop where
  | single {a b : Step} : edge a b → NonEmptyDagPath edge a b
  | cons {a b c : Step} : edge a b → NonEmptyDagPath edge b c → NonEmptyDagPath edge a c

/-- A wave assignment `waveOf : Step → Nat` is valid iff every DAG edge strictly increases
wave index and no resource-exclusive pair shares the same wave. -/
structure ValidWaveSchedule {Step : Type}
    (dagEdge : Step → Step → Prop)
    (resourceConflict : Step → Step → Prop)
    (waveOf : Step → Nat) : Prop where
  respectsDag : ∀ u v, dagEdge u v → waveOf u < waveOf v
  respectsConflict : ∀ u v, resourceConflict u v → waveOf u ≠ waveOf v

/-- Arbitrary-depth topological ordering: any non-empty directed path `u →+ v` strictly increases wave index. -/
theorem valid_wave_strictly_increasing_along_path {Step : Type}
    {edge conflict : Step → Step → Prop} {waveOf : Step → Nat}
    (hValid : ValidWaveSchedule edge conflict waveOf)
    {u v : Step} (hPath : NonEmptyDagPath edge u v) :
    waveOf u < waveOf v := by
  induction hPath with
  | single hab => exact hValid.respectsDag _ _ hab
  | cons hab _ ih => exact Nat.lt_trans (hValid.respectsDag _ _ hab) ih

/-- Parallel wave confluence / zero-race theorem (constructive, zero axioms!):
Any two steps assigned to the SAME parallel wave have NO directed DAG dependency path
in either direction and NO shared resource conflict (e.g., Cargo target lock). -/
theorem same_wave_implies_independent {Step : Type}
    {edge conflict : Step → Step → Prop} {waveOf : Step → Nat}
    (hValid : ValidWaveSchedule edge conflict waveOf)
    {a b : Step} (hSameWave : waveOf a = waveOf b) :
    ¬ NonEmptyDagPath edge a b ∧ ¬ NonEmptyDagPath edge b a ∧ ¬ conflict a b := by
  refine ⟨?_, ?_, ?_⟩
  · intro hPath
    have hLt := valid_wave_strictly_increasing_along_path hValid hPath
    rw [hSameWave] at hLt
    exact Nat.lt_irrefl _ hLt
  · intro hPath
    have hLt := valid_wave_strictly_increasing_along_path hValid hPath
    rw [hSameWave] at hLt
    exact Nat.lt_irrefl _ hLt
  · intro hConf
    exact hValid.respectsConflict a b hConf hSameWave

/-! ## 6. Acyclicity Meta-Soundness (`MR07` Premise Acyclicity & `MR08` DAG Acyclicity) -/

def PremiseDepEdge {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (req sup : St) : Prop :=
  ∃ p, g.requiresPremise req p ∧ g.supportsPremise sup p

def Mr07CyclicPremise {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub) : Prop :=
  ∃ st o m k, g.flowStep st s o m k ∧ NonEmptyDagPath (PremiseDepEdge g) st st

def Mr08CyclicDag {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (s : Sub) : Prop :=
  ∃ st o m k, g.flowStep st s o m k ∧ NonEmptyDagPath g.dagEdge st st

/-- Constructive zero-axiom `MR07` soundness: zero `Mr07CyclicPremise` findings rule out
both self-justification (`A` proves its own premise) and arbitrary-length circular justification cycles! -/
theorem mr07_acyclic_premise_sound {Sub St Obl Meth CK Prem : Type}
    (g : GovernanceSystem Sub St Obl Meth CK Prem) (s : Sub)
    (hNo7 : ¬ Mr07CyclicPremise g s) :
    ∀ st o m k, g.flowStep st s o m k → ¬ NonEmptyDagPath (PremiseDepEdge g) st st := by
  intro st o m k hStep hCycle
  exact hNo7 ⟨st, o, m, k, hStep, hCycle⟩

/-- Constructive zero-axiom `MR08` soundness: zero `Mr08CyclicDag` findings guarantee
that no step of `s` lies on a directed `flow_dag_edge` cycle of any length. -/
theorem mr08_acyclic_dag_sound {Sub St Obl Meth CK Prem Art Fac Plat Grd : Type}
    (g : ExtendedGovernance Sub St Obl Meth CK Prem Art Fac Plat Grd) (s : Sub)
    (hNo8 : ¬ Mr08CyclicDag g s) :
    ∀ st o m k, g.flowStep st s o m k → ¬ NonEmptyDagPath g.dagEdge st st := by
  intro st o m k hStep hCycle
  exact hNo8 ⟨st, o, m, k, hStep, hCycle⟩

/-! ## 7. Two-Level Fleet Merkle Attestation & Pinned-Key Soundness -/

structure FleetMerkleModel (PubKey Payload Digest Sig : Type) where
  digestOf : Payload → Digest
  verify : PubKey → Payload → Sig → Prop
  hashCollisionResistant : ∀ p1 p2, digestOf p1 = digestOf p2 → p1 = p2
  sigUnforgeable : ∀ pk1 pk2 p1 p2 sig,
    verify pk1 p1 sig → verify pk2 p2 sig → pk1 = pk2 ∧ p1 = p2

/-- Constructive zero-axiom tamper-resistance theorem: under collision resistance and
pinned-key unforgeability, ANY change to the canonical Fleet payload (e.g. changing
`sysmlSha256` or any child subject's `reportPayloadSha256`) invalidates the Fleet signature,
and substituting a different public key `pk' ≠ pk` is strictly rejected. -/
theorem fleet_merkle_pinned_key_tamper_resistant {PubKey Payload Digest Sig : Type}
    (m : FleetMerkleModel PubKey Payload Digest Sig)
    {pk pk' : PubKey} {p p' : Payload} {sig : Sig}
    (hValid : m.verify pk p sig) :
    (p ≠ p' → ¬ m.verify pk p' sig) ∧
    (pk ≠ pk' → ¬ m.verify pk' p sig) ∧
    (m.digestOf p ≠ m.digestOf p' → ¬ m.verify pk p' sig) := by
  refine ⟨?_, ?_, ?_⟩
  · intro hNe hV'
    exact hNe (m.sigUnforgeable pk pk p p' sig hValid hV').2
  · intro hNePk hV'
    exact hNePk (m.sigUnforgeable pk pk' p p sig hValid hV').1
  · intro hNeDig hV'
    have hEq := (m.sigUnforgeable pk pk p p' sig hValid hV').2
    exact hNeDig (congrArg m.digestOf hEq)

/-! ## 8. Multi-Key Trust Store, Zero-Downtime Key Rotation & Compromise Revocation -/

structure KeyTrustPolicy (PubKey : Type) where
  trusted : PubKey → Prop
  revoked : PubKey → Prop

def KeyAdmitted {PubKey : Type} (pol : KeyTrustPolicy PubKey) (pk : PubKey) : Prop :=
  pol.trusted pk ∧ ¬ pol.revoked pk

/-- Constructive zero-axiom revocation soundness: a revoked key is NEVER admitted,
even if it remains present in the historical `trusted` set. -/
theorem revoked_key_never_admitted {PubKey : Type} (pol : KeyTrustPolicy PubKey) (pk : PubKey)
    (hRev : pol.revoked pk) : ¬ KeyAdmitted pol pk :=
  fun hAdm => hAdm.2 hRev

/-- Constructive zero-axiom untrusted key rejection. -/
theorem untrusted_key_never_admitted {PubKey : Type} (pol : KeyTrustPolicy PubKey) (pk : PubKey)
    (hNotTrusted : ¬ pol.trusted pk) : ¬ KeyAdmitted pol pk :=
  fun hAdm => hNotTrusted hAdm.1

/-- Constructive zero-axiom zero-downtime key rotation: adding a fresh unrevoked key `pkNew`
preserves admission of existing unrevoked key `pkOld` while admitting `pkNew`. -/
theorem rotation_preserves_unrevoked_trust {PubKey : Type}
    (pol : KeyTrustPolicy PubKey) (pkOld pkNew : PubKey)
    (hOld : KeyAdmitted pol pkOld) (hNewNotRev : ¬ pol.revoked pkNew) :
    let rotated : KeyTrustPolicy PubKey :=
      { trusted := fun k => pol.trusted k ∨ k = pkNew, revoked := pol.revoked }
    KeyAdmitted rotated pkOld ∧ KeyAdmitted rotated pkNew :=
  ⟨⟨Or.inl hOld.1, hOld.2⟩, ⟨Or.inr rfl, hNewNotRev⟩⟩

/-- Constructive zero-axiom end-to-end key revocation invalidation: when attestation requires
`KeyAdmitted pol (signerOf s)`, revoking `signerOf u` blocks reuse of `u` AND cascades across
arbitrary mixed DAG + strict-premise paths `u →* v` to block every downstream consumer `v`. -/
theorem revoked_key_blocks_reuse_and_downstream {Step Key Digest Toolchain PubKey : Type}
    (sys : ReuseSystem Step Key Digest Toolchain)
    (pol : KeyTrustPolicy PubKey) (signerOf : Step → PubKey)
    (hAttBound : ∀ s, sys.attested s → KeyAdmitted pol (signerOf s))
    (hSign : sys.requireSignedCache)
    (hStrict : sys.strictPremiseRecheck)
    {u v : Step}
    (hPath : DagPath (fun a b => sys.dagEdge a b ∨ sys.premiseSupportEdge a b) u v)
    (hRev : pol.revoked (signerOf u)) :
    ¬ Reusable sys u ∧ ¬ Reusable sys v := by
  have hNotAttU : ¬ sys.attested u := fun hAtt => (hAttBound u hAtt).2 hRev
  have hInvU : Invalidated sys u := Invalidated.ir06 u hSign hNotAttU
  refine ⟨fun hRu => hRu hInvU, fun hRv => hRv (ir07_mixed_dag_and_premise_invalidation sys hStrict hPath hInvU)⟩

/-! ## 9. Mixed-Key 2-Level Merkle Fleet Verification & Sub-Report Revocation Cascade -/

structure SignedChildReport (PubKey Payload Digest Sig : Type) where
  key : PubKey
  payload : Payload
  claimedDigest : Digest
  sig : Sig

structure SignedFleetBundle (Subject PubKey Payload Digest Sig : Type) where
  rootKey : PubKey
  rootPayload : Payload
  rootSig : Sig
  childOf : Subject → SignedChildReport PubKey Payload Digest Sig
  boundDigestOf : Subject → Digest

/-- Exact formal model of `offline-attestation-verifier.ss --verify-fleet`:
both the top-level Fleet root AND every child subject report must be signed by an
admitted (trusted & unrevoked) key in `pol`, with matching 2-level Merkle digests. -/
def FleetTrustStoreVerified {Subject PubKey Payload Digest Sig : Type}
    (m : FleetMerkleModel PubKey Payload Digest Sig)
    (pol : KeyTrustPolicy PubKey)
    (fleet : SignedFleetBundle Subject PubKey Payload Digest Sig) : Prop :=
  KeyAdmitted pol fleet.rootKey ∧
  m.verify fleet.rootKey fleet.rootPayload fleet.rootSig ∧
  ∀ s : Subject,
    let c := fleet.childOf s
    KeyAdmitted pol c.key ∧
    m.verify c.key c.payload c.sig ∧
    m.digestOf c.payload = c.claimedDigest ∧
    c.claimedDigest = fleet.boundDigestOf s

/-- Constructive zero-axiom proof: adding a rotated key `pkNew` to a Trust Store preserves
offline verification of any valid Mixed-Key Fleet without re-signing existing child reports. -/
theorem mixedKeyFleet_rotation_preserves_verification {Subject PubKey Payload Digest Sig : Type}
    (m : FleetMerkleModel PubKey Payload Digest Sig)
    (pol : KeyTrustPolicy PubKey) (pkNew : PubKey)
    (fleet : SignedFleetBundle Subject PubKey Payload Digest Sig)
    (hVer : FleetTrustStoreVerified m pol fleet) :
    let rotated : KeyTrustPolicy PubKey :=
      { trusted := fun k => pol.trusted k ∨ k = pkNew, revoked := pol.revoked }
    FleetTrustStoreVerified m rotated fleet := by
  rcases hVer with ⟨hRootAdm, hRootSig, hChildren⟩
  refine ⟨⟨Or.inl hRootAdm.1, hRootAdm.2⟩, hRootSig, ?_⟩
  intro s
  rcases hChildren s with ⟨hChildAdm, hChildSig, hDig1, hDig2⟩
  exact ⟨⟨Or.inl hChildAdm.1, hChildAdm.2⟩, hChildSig, hDig1, hDig2⟩

/-- Constructive zero-axiom sub-report revocation cascade: revoking ANY child subject's signing key
immediately invalidates the entire 2-level Merkle Fleet, even if the top-level Fleet root key
remains trusted, unrevoked, and cryptographically valid. -/
theorem mixedKeyFleet_rejects_revoked_child_even_with_valid_root_key
    {Subject PubKey Payload Digest Sig : Type}
    (m : FleetMerkleModel PubKey Payload Digest Sig)
    (pol : KeyTrustPolicy PubKey)
    (fleet : SignedFleetBundle Subject PubKey Payload Digest Sig)
    (s : Subject)
    (hChildRevoked : pol.revoked (fleet.childOf s).key) :
    ¬ FleetTrustStoreVerified m pol fleet := by
  intro hVer
  rcases hVer with ⟨_, _, hChildren⟩
  exact (hChildren s).1.2 hChildRevoked

/-- Constructive zero-axiom 2-level Merkle binding rejection: if any child subject's payload
digest diverges from the root-bound Merkle digest, offline Fleet verification fails unconditionally
(even if an attacker re-signs the forged child report with a valid trusted key). -/
theorem mixedKeyFleet_rejects_tampered_child_digest
    {Subject PubKey Payload Digest Sig : Type}
    (m : FleetMerkleModel PubKey Payload Digest Sig)
    (pol : KeyTrustPolicy PubKey)
    (fleet : SignedFleetBundle Subject PubKey Payload Digest Sig)
    (s : Subject)
    (hMismatch : m.digestOf (fleet.childOf s).payload ≠ fleet.boundDigestOf s) :
    ¬ FleetTrustStoreVerified m pol fleet := by
  intro hVer
  rcases hVer with ⟨_, _, hChildren⟩
  rcases hChildren s with ⟨_, _, hDig1, hDig2⟩
  exact hMismatch (hDig1.trans hDig2)

/-! ## 10. Fleet Child-Report Path-Traversal Containment (`safe-relative-child-path?`) -/

inductive PathSegment where
  | normal (name : String)
  | dot
  | dotdot
  | empty

structure RelativeChildPath where
  isAbsolute : Bool
  segments : List PathSegment

def allNormalSegments : List PathSegment → Prop
  | [] => True
  | .normal _ :: rest => allNormalSegments rest
  | .dot :: _ => False
  | .dotdot :: _ => False
  | .empty :: _ => False

def containsSegment (target : PathSegment) : List PathSegment → Prop
  | [] => False
  | x :: rest => x = target ∨ containsSegment target rest

def SafeRelativeChildPath (p : RelativeChildPath) : Prop :=
  p.isAbsolute = false ∧
  p.segments ≠ [] ∧
  allNormalSegments p.segments

/-- Constructive zero-axiom proof: an absolute child path is never safe. -/
theorem absolute_path_never_safe (p : RelativeChildPath) (hAbs : p.isAbsolute = true) :
    ¬ SafeRelativeChildPath p := by
  intro hSafe
  exact Bool.noConfusion (hAbs.symm.trans hSafe.1)

/-- Constructive zero-axiom proof: an empty child path is never safe. -/
theorem empty_path_never_safe (p : RelativeChildPath) (hEmpty : p.segments = []) :
    ¬ SafeRelativeChildPath p := by
  intro hSafe
  exact hSafe.2.1 hEmpty

private theorem dotdot_contradicts_allNormal :
    ∀ segs : List PathSegment, containsSegment PathSegment.dotdot segs → allNormalSegments segs → False
  | [], hIn, _ => hIn
  | .normal _ :: rest, Or.inl hEq, _ => nomatch hEq
  | .normal _ :: rest, Or.inr hRest, hAll => dotdot_contradicts_allNormal rest hRest hAll
  | .dot :: _, _, hAll => hAll
  | .dotdot :: _, _, hAll => hAll
  | .empty :: _, _, hAll => hAll

/-- Constructive zero-axiom proof: any `..` parent-traversal segment renders the path unsafe. -/
theorem dotdot_segment_never_safe (p : RelativeChildPath)
    (hDotDot : containsSegment PathSegment.dotdot p.segments) :
    ¬ SafeRelativeChildPath p := by
  intro hSafe
  exact dotdot_contradicts_allNormal p.segments hDotDot hSafe.2.2

/-! ## 11. Single-File Inline-PEM Trust Bundle Export Safety (`--export-trust-bundle`) -/

inductive PemKind where
  | publicKey
  | privateKey
  | malformed

structure ExportKeyCandidate where
  isRegularNonSymlink : Bool
  pemKind : PemKind
  isRevoked : Bool

def candidateSafe (c : ExportKeyCandidate) : Prop :=
  c.isRegularNonSymlink = true ∧ c.pemKind = PemKind.publicKey

def allCandidatesSafe : List ExportKeyCandidate → Prop
  | [] => True
  | c :: rest => candidateSafe c ∧ allCandidatesSafe rest

def hasActiveCandidate : List ExportKeyCandidate → Prop
  | [] => False
  | c :: rest => c.isRevoked = false ∨ hasActiveCandidate rest

def containsCandidateWith (P : ExportKeyCandidate → Prop) : List ExportKeyCandidate → Prop
  | [] => False
  | c :: rest => P c ∨ containsCandidateWith P rest

def allCandidatesRevoked : List ExportKeyCandidate → Prop
  | [] => True
  | c :: rest => c.isRevoked = true ∧ allCandidatesRevoked rest

/-- Constructive zero-axiom safety predicate for `--export-trust-bundle`:
every input PEM must be a POSIX `lstat` regular non-symlink public-key PEM, and at least one
exported key must remain active (unrevoked). -/
def SafeTrustBundleExport (cs : List ExportKeyCandidate) : Prop :=
  allCandidatesSafe cs ∧ hasActiveCandidate cs

private theorem privateKey_contradicts_allSafe :
    ∀ cs : List ExportKeyCandidate,
      containsCandidateWith (fun c => c.pemKind = PemKind.privateKey) cs →
      allCandidatesSafe cs → False
  | [], hIn, _ => hIn
  | _ :: _, Or.inl hPriv, ⟨⟨_, hPub⟩, _⟩ => nomatch (hPriv.symm.trans hPub)
  | _ :: rest, Or.inr hRest, ⟨_, hAll⟩ => privateKey_contradicts_allSafe rest hRest hAll

/-- Constructive zero-axiom proof: private-key PEM inputs are unconditionally rejected from export. -/
theorem exportBundle_rejects_privateKey_pem (cs : List ExportKeyCandidate)
    (hPriv : containsCandidateWith (fun c => c.pemKind = PemKind.privateKey) cs) :
    ¬ SafeTrustBundleExport cs := by
  intro hSafe
  exact privateKey_contradicts_allSafe cs hPriv hSafe.1

private theorem nonRegular_contradicts_allSafe :
    ∀ cs : List ExportKeyCandidate,
      containsCandidateWith (fun c => c.isRegularNonSymlink = false) cs →
      allCandidatesSafe cs → False
  | [], hIn, _ => hIn
  | _ :: _, Or.inl hBad, ⟨⟨hReg, _⟩, _⟩ => Bool.noConfusion (hBad.symm.trans hReg)
  | _ :: rest, Or.inr hRest, ⟨_, hAll⟩ => nonRegular_contradicts_allSafe rest hRest hAll

/-- Constructive zero-axiom proof: symlink or non-regular PEM inputs are unconditionally rejected. -/
theorem exportBundle_rejects_symlink_or_nonRegular (cs : List ExportKeyCandidate)
    (hNonReg : containsCandidateWith (fun c => c.isRegularNonSymlink = false) cs) :
    ¬ SafeTrustBundleExport cs := by
  intro hSafe
  exact nonRegular_contradicts_allSafe cs hNonReg hSafe.1

private theorem allRevoked_contradicts_hasActive :
    ∀ cs : List ExportKeyCandidate,
      allCandidatesRevoked cs → hasActiveCandidate cs → False
  | [], _, hAct => hAct
  | _ :: _, ⟨hRev, _⟩, Or.inl hNotRev => Bool.noConfusion (hRev.symm.trans hNotRev)
  | _ :: rest, ⟨_, hAllRev⟩, Or.inr hRest => allRevoked_contradicts_hasActive rest hAllRev hRest

/-- Constructive zero-axiom proof: exporting a trust bundle with zero active keys is rejected
(preventing total offline-verification lockout). -/
theorem exportBundle_rejects_zeroActiveLockout (cs : List ExportKeyCandidate)
    (hAllRev : allCandidatesRevoked cs) :
    ¬ SafeTrustBundleExport cs := by
  intro hSafe
  exact allRevoked_contradicts_hasActive cs hAllRev hSafe.2

/-! ## 12. Self-Contained Single-File Fleet Evidence Bundle Integrity (`--verify-fleet-bundle`) -/

structure FleetBundleChildEntry where
  pathSafe : Bool
  present : Bool
  signatureValid : Bool
  keyUnrevoked : Bool
  merkleDigestMatches : Bool

structure FleetEvidenceBundleModel where
  rootValid : Bool
  declaredCount : Nat
  embeddedCount : Nat
  children : List FleetBundleChildEntry

def bundleChildAdmitted (c : FleetBundleChildEntry) : Prop :=
  c.pathSafe = true ∧
  c.present = true ∧
  c.signatureValid = true ∧
  c.keyUnrevoked = true ∧
  c.merkleDigestMatches = true

def allBundleChildrenAdmitted : List FleetBundleChildEntry → Prop
  | [] => True
  | c :: rest => bundleChildAdmitted c ∧ allBundleChildrenAdmitted rest

def containsBundleChildWith (P : FleetBundleChildEntry → Prop) : List FleetBundleChildEntry → Prop
  | [] => False
  | c :: rest => P c ∨ containsBundleChildWith P rest

/-- Constructive zero-axiom verification predicate for `de.attestation.fleet-evidence-bundle.v1`:
requires valid root Ed25519 signature, non-empty subject set, exact 1-to-1 cardinality bijection
(`declaredCount = embeddedCount`, blocking smuggled extra entries), and full cryptographic +
Merkle-binding admission of every embedded child report. -/
def SafeFleetEvidenceBundle (b : FleetEvidenceBundleModel) : Prop :=
  b.rootValid = true ∧
  b.declaredCount > 0 ∧
  b.declaredCount = b.embeddedCount ∧
  allBundleChildrenAdmitted b.children

private theorem badChild_contradicts_allBundleAdmitted
    {P : FleetBundleChildEntry → Prop}
    (hContra : ∀ c, P c → bundleChildAdmitted c → False) :
    ∀ cs : List FleetBundleChildEntry,
      containsBundleChildWith P cs → allBundleChildrenAdmitted cs → False
  | [], hIn, _ => hIn
  | c :: _, Or.inl hP, ⟨hAdm, _⟩ => hContra c hP hAdm
  | _ :: rest, Or.inr hRest, ⟨_, hAll⟩ =>
      badChild_contradicts_allBundleAdmitted hContra rest hRest hAll

/-- Constructive zero-axiom proof: a Fleet evidence bundle missing ANY declared child report
is unconditionally rejected. -/
theorem bundle_rejects_missing_child_entry (b : FleetEvidenceBundleModel)
    (hMissing : containsBundleChildWith (fun c => c.present = false) b.children) :
    ¬ SafeFleetEvidenceBundle b := by
  intro hSafe
  exact badChild_contradicts_allBundleAdmitted
    (fun _ hM hAdm => Bool.noConfusion (hM.symm.trans hAdm.2.1))
    b.children hMissing hSafe.2.2.2

/-- Constructive zero-axiom proof: injecting smuggled/unreferenced extra child reports
(breaking exact 1-to-1 bijection `declaredCount = embeddedCount`) is unconditionally rejected. -/
theorem bundle_rejects_smuggled_extra_child (b : FleetEvidenceBundleModel)
    (hMismatch : b.declaredCount ≠ b.embeddedCount) :
    ¬ SafeFleetEvidenceBundle b := by
  intro hSafe
  exact hMismatch hSafe.2.2.1

/-- Constructive zero-axiom proof: any embedded child report with a revoked key or tampered
Merkle digest invalidates the entire self-contained Fleet bundle. -/
theorem bundle_rejects_revoked_or_tampered_embedded_child (b : FleetEvidenceBundleModel)
    (hBad : containsBundleChildWith
              (fun c => c.keyUnrevoked = false ∨ c.merkleDigestMatches = false) b.children) :
    ¬ SafeFleetEvidenceBundle b := by
  intro hSafe
  exact badChild_contradicts_allBundleAdmitted
    (fun _ hOr hAdm =>
      match hOr with
      | Or.inl hRev => Bool.noConfusion (hRev.symm.trans hAdm.2.2.2.1)
      | Or.inr hDig => Bool.noConfusion (hDig.symm.trans hAdm.2.2.2.2))
    b.children hBad hSafe.2.2.2

/-! ## 13. Deterministic Anti-Replay Freshness Window (`--max-age-seconds` / `--now-epoch`) -/

/-- Constructive zero-axiom anti-replay freshness window over `Nat` Unix epochs:
enforces BOTH lower-bound TTL (`nowEpoch ≤ issuedEpoch + maxAge`) AND upper-bound
future-skew guard (`issuedEpoch ≤ nowEpoch + maxFutureSkew`). -/
def WitnessFreshnessWindow (issuedEpoch nowEpoch maxAge maxFutureSkew : Nat) : Prop :=
  nowEpoch ≤ issuedEpoch + maxAge ∧ issuedEpoch ≤ nowEpoch + maxFutureSkew

/-- Constructive zero-axiom proof: any witness older than `maxAge` (stale replay) is rejected. -/
theorem freshnessWindow_rejects_expired_replay
    (issuedEpoch nowEpoch maxAge maxFutureSkew : Nat)
    (hExpired : issuedEpoch + maxAge < nowEpoch) :
    ¬ WitnessFreshnessWindow issuedEpoch nowEpoch maxAge maxFutureSkew := by
  intro hFresh
  exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le hExpired hFresh.1)

/-- Constructive zero-axiom proof: any witness dated beyond `nowEpoch + maxFutureSkew`
(future clock forgery attempting to bypass `IR08` expiry) is unconditionally rejected. -/
theorem freshnessWindow_rejects_future_clock_forgery
    (issuedEpoch nowEpoch maxAge maxFutureSkew : Nat)
    (hFuture : nowEpoch + maxFutureSkew < issuedEpoch) :
    ¬ WitnessFreshnessWindow issuedEpoch nowEpoch maxAge maxFutureSkew := by
  intro hFresh
  exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le hFuture hFresh.2)

/-! ## 14. Anti-Downgrade SysML Specification Pinning (`--expected-sysml-sha256`) -/

/-- Constructive zero-axiom specification-pinned Fleet Evidence Bundle predicate:
requires both complete cryptographic/Merkle bundle integrity AND exact binding of the
signed `sysmlSha256` digest to the auditor's pinned SysML v2 specification digest. -/
def SysmlPinnedFleetBundle {Digest : Type}
    (b : FleetEvidenceBundleModel) (actualSpecDigest expectedSpecDigest : Digest) : Prop :=
  SafeFleetEvidenceBundle b ∧ actualSpecDigest = expectedSpecDigest

/-- Constructive zero-axiom proof: replaying a cryptographically valid Fleet bundle produced
under an older/different SysML v2 specification (spec downgrade attack) is unconditionally rejected. -/
theorem sysmlPinnedBundle_rejects_spec_downgrade {Digest : Type}
    (b : FleetEvidenceBundleModel) {actualSpecDigest expectedSpecDigest : Digest}
    (hMismatch : actualSpecDigest ≠ expectedSpecDigest) :
    ¬ SysmlPinnedFleetBundle b actualSpecDigest expectedSpecDigest := by
  intro hPinned
  exact hMismatch hPinned.2

/-! ## 15. Fleet Subject-Coverage Completeness (`--expected-subject-count` / `--require-subject`) -/

def containsKey {Key : Type} (target : Key) : List Key → Prop
  | [] => False
  | x :: rest => x = target ∨ containsKey target rest

def allRequiredKeysPresent {Key : Type} (actual : List Key) : List Key → Prop
  | [] => True
  | r :: rest => containsKey r actual ∧ allRequiredKeysPresent actual rest

/-- Constructive zero-axiom subject-coverage completeness predicate for offline Fleet verification:
requires cryptographic bundle soundness, exact subject count (`declaredCount = expectedCount`),
and presence of every auditor-required `subjectKey`. -/
def FleetCoverageComplete {Key : Type}
    (b : FleetEvidenceBundleModel) (actualKeys requiredKeys : List Key) (expectedCount : Nat) : Prop :=
  SafeFleetEvidenceBundle b ∧
  b.declaredCount = expectedCount ∧
  allRequiredKeysPresent actualKeys requiredKeys

private theorem missingRequiredKey_contradicts_allPresent {Key : Type}
    (actual : List Key) (req : Key) (hMissing : ¬ containsKey req actual) :
    ∀ reqs : List Key, containsKey req reqs → allRequiredKeysPresent actual reqs → False
  | [], hIn, _ => hIn
  | _ :: _, Or.inl hEq, ⟨hPres, _⟩ => hMissing (hEq ▸ hPres)
  | _ :: rest, Or.inr hRest, ⟨_, hAll⟩ =>
      missingRequiredKey_contradicts_allPresent actual req hMissing rest hRest hAll

/-- Constructive zero-axiom proof: a partial Fleet whose subject count diverges from
`expectedCount` is unconditionally rejected. -/
theorem fleetCoverage_rejects_omitted_subject_count {Key : Type}
    (b : FleetEvidenceBundleModel) (actualKeys requiredKeys : List Key) {expectedCount : Nat}
    (hCountNe : b.declaredCount ≠ expectedCount) :
    ¬ FleetCoverageComplete b actualKeys requiredKeys expectedCount := by
  intro hComp
  exact hCountNe hComp.2.1

/-- Constructive zero-axiom proof: omitting ANY auditor-required subject key invalidates
the entire Fleet even when all included subjects have valid Ed25519 signatures. -/
theorem fleetCoverage_rejects_missing_required_subject {Key : Type}
    (b : FleetEvidenceBundleModel) (actualKeys requiredKeys : List Key)
    (expectedCount : Nat) {req : Key}
    (hReq : containsKey req requiredKeys)
    (hAbsent : ¬ containsKey req actualKeys) :
    ¬ FleetCoverageComplete b actualKeys requiredKeys expectedCount := by
  intro hComp
  exact missingRequiredKey_contradicts_allPresent actualKeys req hAbsent requiredKeys hReq hComp.2.2

/-! ## 16. Authenticated in-toto v1 Statement Export (`--emit-statement`) -/

structure IntotoSummaryStatement (Digest Key : Type) where
  sysmlDigest : Digest
  rootKey : Key
  subjectCount : Nat
  verifiedSubjects : List Key

/-- Constructive zero-axiom emission decision for `--emit-statement <out.json>`:
produces `some stmt` ONLY when `fleetVerified = true` AND `outputTargetSafe = true`
(non-symlink output path); otherwise emits `none` (fail-closed zero-leakage). -/
def emitIntotoStatement {Digest Key : Type}
    (fleetVerified outputTargetSafe : Bool)
    (sysmlDigest : Digest) (rootKey : Key)
    (subjectCount : Nat) (verifiedSubjects : List Key) :
    Option (IntotoSummaryStatement Digest Key) :=
  match fleetVerified with
  | false => none
  | true =>
    match outputTargetSafe with
    | false => none
    | true =>
      some {
        sysmlDigest := sysmlDigest
        rootKey := rootKey
        subjectCount := subjectCount
        verifiedSubjects := verifiedSubjects
      }

/-- Constructive zero-axiom proof: unverified fleets NEVER emit an in-toto statement
(fail-closed zero-leakage). -/
theorem intotoStatement_zeroLeak_on_unverified {Digest Key : Type}
    (outputTargetSafe : Bool) (sysmlDigest : Digest) (rootKey : Key)
    (subjectCount : Nat) (verifiedSubjects : List Key) :
    emitIntotoStatement false outputTargetSafe sysmlDigest rootKey subjectCount verifiedSubjects = none :=
  rfl

/-- Constructive zero-axiom proof: unsafe/symlink output destinations NEVER emit a statement,
even when the underlying fleet bundle is cryptographically valid. -/
theorem intotoStatement_rejects_unsafe_symlink_target {Digest Key : Type}
    (fleetVerified : Bool) (sysmlDigest : Digest) (rootKey : Key)
    (subjectCount : Nat) (verifiedSubjects : List Key) :
    emitIntotoStatement fleetVerified false sysmlDigest rootKey subjectCount verifiedSubjects = none := by
  cases fleetVerified <;> rfl

/-- Constructive zero-axiom soundness proof: whenever `--emit-statement` produces `some stmt`,
BOTH full fleet verification AND safe non-symlink target hold, and the emitted statement preserves
exact authenticated `sysmlDigest`, `rootKey`, `subjectCount`, and `verifiedSubjects`. -/
theorem intotoStatement_some_implies_verified_and_faithful {Digest Key : Type}
    {fleetVerified outputTargetSafe : Bool}
    {sysmlDigest : Digest} {rootKey : Key}
    {subjectCount : Nat} {verifiedSubjects : List Key}
    {stmt : IntotoSummaryStatement Digest Key}
    (hEmit : emitIntotoStatement fleetVerified outputTargetSafe
               sysmlDigest rootKey subjectCount verifiedSubjects = some stmt) :
    fleetVerified = true ∧
    outputTargetSafe = true ∧
    stmt.sysmlDigest = sysmlDigest ∧
    stmt.rootKey = rootKey ∧
    stmt.subjectCount = subjectCount ∧
    stmt.verifiedSubjects = verifiedSubjects := by
  cases fleetVerified with
  | false => cases hEmit
  | true =>
    cases outputTargetSafe with
    | false => cases hEmit
    | true =>
      cases hEmit
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-! ## 17. Standard DSSE v1 Signed in-toto Statement Envelope (`--verify-dsse-statement`) -/

structure DsseSignatureCheck where
  keyAdmitted : Bool
  paeSignatureValid : Bool

def dsseSigVerified (s : DsseSignatureCheck) : Prop :=
  s.keyAdmitted = true ∧ s.paeSignatureValid = true

def hasVerifiedDsseSig : List DsseSignatureCheck → Prop
  | [] => False
  | s :: rest => dsseSigVerified s ∨ hasVerifiedDsseSig rest

def allDsseSigsRejected : List DsseSignatureCheck → Prop
  | [] => True
  | s :: rest => (s.keyAdmitted = false ∨ s.paeSignatureValid = false) ∧ allDsseSigsRejected rest

structure DsseStatementEnvelopeModel (Digest : Type) where
  payloadTypeMatchesIntoto : Bool
  statementSchemaValid : Bool
  subjectSysmlDigest : Digest
  predicateSysmlDigest : Digest
  subjectFleetDigest : Digest
  predicateFleetDigest : Digest
  signatures : List DsseSignatureCheck

/-- Constructive zero-axiom verification predicate for standard DSSE v1 signed in-toto statements:
requires exact `application/vnd.in-toto+json` payloadType (blocking type confusion), valid in-toto v1
statement schema, exact digest agreement between `subject` and `predicate`, at least one admitted
unrevoked Ed25519 PAE signature, and exact pinning to `expectedSysmlDigest`. -/
def SafeDsseStatementEnvelope {Digest : Type}
    (env : DsseStatementEnvelopeModel Digest) (expectedSysmlDigest : Digest) : Prop :=
  env.payloadTypeMatchesIntoto = true ∧
  env.statementSchemaValid = true ∧
  env.subjectSysmlDigest = env.predicateSysmlDigest ∧
  env.subjectFleetDigest = env.predicateFleetDigest ∧
  env.predicateSysmlDigest = expectedSysmlDigest ∧
  hasVerifiedDsseSig env.signatures

/-- Constructive zero-axiom proof: DSSE payload-type confusion (e.g. non-in-toto `payloadType`)
is unconditionally rejected even when Ed25519 signatures are valid. -/
theorem dsseEnvelope_rejects_payloadType_confusion {Digest : Type}
    (env : DsseStatementEnvelopeModel Digest) (expectedSysmlDigest : Digest)
    (hBadType : env.payloadTypeMatchesIntoto = false) :
    ¬ SafeDsseStatementEnvelope env expectedSysmlDigest := by
  intro hSafe
  exact Bool.noConfusion (hBadType.symm.trans hSafe.1)

private theorem allRejected_contradicts_hasVerified :
    ∀ sigs : List DsseSignatureCheck, allDsseSigsRejected sigs → hasVerifiedDsseSig sigs → False
  | [], _, hHas => hHas
  | _ :: _, ⟨Or.inl hRev, _⟩, Or.inl ⟨hAdm, _⟩ => Bool.noConfusion (hRev.symm.trans hAdm)
  | _ :: _, ⟨Or.inr hBadSig, _⟩, Or.inl ⟨_, hVal⟩ => Bool.noConfusion (hBadSig.symm.trans hVal)
  | _ :: rest, ⟨_, hAll⟩, Or.inr hRest => allRejected_contradicts_hasVerified rest hAll hRest

/-- Constructive zero-axiom proof: a DSSE envelope whose signatures are all revoked, untrusted,
or cryptographically invalid is unconditionally rejected. -/
theorem dsseEnvelope_rejects_when_all_signatures_revoked_or_invalid {Digest : Type}
    (env : DsseStatementEnvelopeModel Digest) (expectedSysmlDigest : Digest)
    (hAllRej : allDsseSigsRejected env.signatures) :
    ¬ SafeDsseStatementEnvelope env expectedSysmlDigest := by
  intro hSafe
  exact allRejected_contradicts_hasVerified env.signatures hAllRej hSafe.2.2.2.2.2

/-- Constructive zero-axiom proof: any digest divergence between the in-toto `subject` bindings
and `predicate` fields invalidates the DSSE statement even under a valid Ed25519 signature. -/
theorem dsseEnvelope_rejects_subject_predicate_digest_mismatch {Digest : Type}
    (env : DsseStatementEnvelopeModel Digest) (expectedSysmlDigest : Digest)
    (hMismatch : env.subjectSysmlDigest ≠ env.predicateSysmlDigest ∨
                 env.subjectFleetDigest ≠ env.predicateFleetDigest) :
    ¬ SafeDsseStatementEnvelope env expectedSysmlDigest := by
  intro hSafe
  match hMismatch with
  | Or.inl hSys => exact hSys hSafe.2.2.1
  | Or.inr hFlt => exact hFlt hSafe.2.2.2.1

/-! ## 18. M-of-N Threshold Quorum Attestation (`--min-signatures` & `--cosign-dsse-statement`) -/

/-- Pure structural pairwise-distinctness predicate over signer key lists (zero axioms, no `List.Mem`). -/
def pairwiseDistinct {Key : Type} : List Key → Prop
  | [] => True
  | k :: rest => ¬ containsKey k rest ∧ pairwiseDistinct rest

/-- Constructive zero-axiom M-of-N threshold quorum predicate:
requires `requiredQuorum ≥ 1`, all verified signer keys are pairwise distinct (defeating
duplicate-keyId signature padding attacks), and at least `requiredQuorum` distinct keys verified. -/
def DsseQuorumSatisfied {Key : Type}
    (distinctVerifiedKeys : List Key) (requiredQuorum : Nat) : Prop :=
  1 ≤ requiredQuorum ∧
  pairwiseDistinct distinctVerifiedKeys ∧
  requiredQuorum ≤ distinctVerifiedKeys.length

/-- Constructive zero-axiom proof: fewer than `requiredQuorum` distinct verified keys NEVER satisfy
the M-of-N threshold quorum. -/
theorem dsseQuorum_rejects_below_threshold {Key : Type}
    (distinctVerifiedKeys : List Key) (requiredQuorum : Nat)
    (hBelow : distinctVerifiedKeys.length < requiredQuorum) :
    ¬ DsseQuorumSatisfied distinctVerifiedKeys requiredQuorum := by
  intro hQ
  exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le hBelow hQ.2.2)

/-- Constructive zero-axiom proof: padding a signature list with a duplicate keyId (`containsKey k rest`)
is unconditionally rejected by `DsseQuorumSatisfied` regardless of raw list length. -/
theorem dsseQuorum_rejects_duplicate_key_padding {Key : Type}
    (k : Key) (rest : List Key) (requiredQuorum : Nat)
    (hDup : containsKey k rest) :
    ¬ DsseQuorumSatisfied (k :: rest) requiredQuorum := by
  intro hQ
  exact hQ.2.1.1 hDup

/-- Constructive zero-axiom proof: offline counter-signing (`--cosign-dsse-statement`) by a fresh
distinct admitted key strictly advances M-of-N quorum capacity from `q` to `q + 1`. -/
theorem dsseQuorum_monotonic_under_fresh_cosigner {Key : Type}
    (newKey : Key) (existing : List Key) (q : Nat)
    (hFresh : ¬ containsKey newKey existing)
    (hQ : DsseQuorumSatisfied existing q) :
    DsseQuorumSatisfied (newKey :: existing) (q + 1) :=
  ⟨Nat.le_trans hQ.1 (Nat.le_succ q),
   ⟨hFresh, hQ.2.1⟩,
   Nat.succ_le_succ hQ.2.2⟩

/-! ## 19. Separation of Duties: Named-Approver Policy Pinning (`--require-signer`) -/

/-- Constructive zero-axiom Separation-of-Duties predicate: requires BOTH M-of-N distinct
threshold quorum (`DsseQuorumSatisfied`) AND presence of every auditor-mandated named signer
keyId in `distinctVerifiedKeys` (preventing same-role keys from bypassing distinct authorities). -/
def DsseSeparationOfDutiesSatisfied {Key : Type}
    (distinctVerifiedKeys requiredSigners : List Key) (requiredQuorum : Nat) : Prop :=
  DsseQuorumSatisfied distinctVerifiedKeys requiredQuorum ∧
  allRequiredKeysPresent distinctVerifiedKeys requiredSigners

/-- Constructive zero-axiom proof: omitting ANY required named approver keyId invalidates
the DSSE envelope even when the M-of-N threshold quorum count is met by other active keys. -/
theorem dsseSoD_rejects_missing_required_signer {Key : Type}
    (distinctVerifiedKeys requiredSigners : List Key) (requiredQuorum : Nat) {req : Key}
    (hReq : containsKey req requiredSigners)
    (hAbsent : ¬ containsKey req distinctVerifiedKeys) :
    ¬ DsseSeparationOfDutiesSatisfied distinctVerifiedKeys requiredSigners requiredQuorum := by
  intro hSoD
  exact missingRequiredKey_contradicts_allPresent distinctVerifiedKeys req hAbsent requiredSigners hReq hSoD.2

/-- Constructive zero-axiom proof: even when all named signers are present, failing to reach
`requiredQuorum` distinct verified keys still rejects the DSSE envelope. -/
theorem dsseSoD_rejects_below_threshold {Key : Type}
    (distinctVerifiedKeys requiredSigners : List Key) (requiredQuorum : Nat)
    (hBelow : distinctVerifiedKeys.length < requiredQuorum) :
    ¬ DsseSeparationOfDutiesSatisfied distinctVerifiedKeys requiredSigners requiredQuorum := by
  intro hSoD
  exact dsseQuorum_rejects_below_threshold distinctVerifiedKeys requiredQuorum hBelow hSoD.1

/-! ## 20. Role-Based Separation of Duties (`--require-role` & Trust Store `keyRoles`) -/

/-- Pure structural predicate: at least one active verified signer key in `verifiedKeys`
holds `role` under the trust-store mapping `keyHasRole`. -/
def roleSatisfiedByKeys {Key Role : Type}
    (keyHasRole : Key → Role → Prop) (role : Role) : List Key → Prop
  | [] => False
  | k :: rest => keyHasRole k role ∨ roleSatisfiedByKeys keyHasRole role rest

def allRequiredRolesSatisfied {Key Role : Type}
    (keyHasRole : Key → Role → Prop) (verifiedKeys : List Key) : List Role → Prop
  | [] => True
  | r :: rest => roleSatisfiedByKeys keyHasRole r verifiedKeys ∧
                 allRequiredRolesSatisfied keyHasRole verifiedKeys rest

/-- Constructive zero-axiom Role-Based Separation-of-Duties predicate:
requires BOTH M-of-N distinct verified key quorum (`DsseQuorumSatisfied`) AND satisfaction
of every required operational role (e.g. `ci-builder`, `security-auditor`) by active verified keys. -/
def DsseRoleSoDSatisfied {Key Role : Type}
    (keyHasRole : Key → Role → Prop)
    (distinctVerifiedKeys : List Key) (requiredRoles : List Role) (requiredQuorum : Nat) : Prop :=
  DsseQuorumSatisfied distinctVerifiedKeys requiredQuorum ∧
  allRequiredRolesSatisfied keyHasRole distinctVerifiedKeys requiredRoles

private theorem missingRole_contradicts_allRoles {Key Role : Type}
    (keyHasRole : Key → Role → Prop) (verifiedKeys : List Key) (req : Role)
    (hMissing : ¬ roleSatisfiedByKeys keyHasRole req verifiedKeys) :
    ∀ reqs : List Role, containsKey req reqs →
      allRequiredRolesSatisfied keyHasRole verifiedKeys reqs → False
  | [], hIn, _ => hIn
  | _ :: _, Or.inl hEq, ⟨hSat, _⟩ => hMissing (hEq ▸ hSat)
  | _ :: rest, Or.inr hRest, ⟨_, hAll⟩ =>
      missingRole_contradicts_allRoles keyHasRole verifiedKeys req hMissing rest hRest hAll

/-- Constructive zero-axiom proof: omitting ANY required operational role (e.g. two `ci-builder`
keys signing without a `security-auditor` key) is unconditionally rejected even when the M-of-N
signature threshold is satisfied. -/
theorem dsseRoleSoD_rejects_missing_required_role {Key Role : Type}
    (keyHasRole : Key → Role → Prop)
    (distinctVerifiedKeys : List Key) (requiredRoles : List Role) (requiredQuorum : Nat)
    {req : Role}
    (hReq : containsKey req requiredRoles)
    (hNoHolder : ¬ roleSatisfiedByKeys keyHasRole req distinctVerifiedKeys) :
    ¬ DsseRoleSoDSatisfied keyHasRole distinctVerifiedKeys requiredRoles requiredQuorum := by
  intro hSoD
  exact missingRole_contradicts_allRoles keyHasRole distinctVerifiedKeys req hNoHolder
    requiredRoles hReq hSoD.2

private theorem roleSatisfied_preserved_by_rotation {Key Role : Type}
    (keyHasRole : Key → Role → Prop) (kOld kNew : Key) (role : Role)
    (hRolesSub : keyHasRole kOld role → keyHasRole kNew role) :
    ∀ rest : List Key,
      roleSatisfiedByKeys keyHasRole role (kOld :: rest) →
      roleSatisfiedByKeys keyHasRole role (kNew :: rest)
  | _, Or.inl hOld => Or.inl (hRolesSub hOld)
  | _, Or.inr hRest => Or.inr hRest

/-- Constructive zero-axiom proof: rotating a role's signing key from `kOld` to a fresh key `kNew`
carrying at least the same roles preserves `allRequiredRolesSatisfied` with zero policy changes. -/
theorem dsseRoleSoD_preserved_under_role_key_rotation {Key Role : Type}
    (keyHasRole : Key → Role → Prop) (kOld kNew : Key) (rest : List Key)
    (hRolesSub : ∀ r, keyHasRole kOld r → keyHasRole kNew r) :
    ∀ requiredRoles : List Role,
      allRequiredRolesSatisfied keyHasRole (kOld :: rest) requiredRoles →
      allRequiredRolesSatisfied keyHasRole (kNew :: rest) requiredRoles
  | [], _ => trivial
  | r :: rRest, ⟨hHead, hTail⟩ =>
      ⟨roleSatisfied_preserved_by_rotation keyHasRole kOld kNew r (hRolesSub r) rest hHead,
       dsseRoleSoD_preserved_under_role_key_rotation keyHasRole kOld kNew rest hRolesSub rRest hTail⟩

/-! ## 21. Declarative Audit Policy Manifest & Monotonic Tightening (`--policy`) -/

/-- Constructive zero-axiom monotonic policy tightening relation between a baseline
versioned audit policy (`pMinSigs`, `pReqSubjects`, `pReqSigners`, `pReqRoles`) and an
effective merged policy (`eMinSigs`, `eReqSubjects`, `eReqSigners`, `eReqRoles`):
CLI flags may ONLY tighten (never weaken) quorum thresholds or drop required subjects,
signers, or operational roles. -/
def PolicyMonotonicallyTighter {Subject Key Role : Type}
    (pMinSigs eMinSigs : Nat)
    (pReqSubjects eReqSubjects : List Subject)
    (pReqSigners eReqSigners : List Key)
    (pReqRoles eReqRoles : List Role) : Prop :=
  pMinSigs ≤ eMinSigs ∧
  (∀ s, containsKey s pReqSubjects → containsKey s eReqSubjects) ∧
  (∀ k, containsKey k pReqSigners → containsKey k eReqSigners) ∧
  (∀ r, containsKey r pReqRoles → containsKey r eReqRoles)

private theorem allRequiredKeys_subset_mono {Key : Type}
    (actual : List Key) (eReqs : List Key)
    (hE : allRequiredKeysPresent actual eReqs) :
    ∀ pReqs : List Key,
      (∀ x, containsKey x pReqs → containsKey x eReqs) →
      allRequiredKeysPresent actual pReqs
  | [], _ => trivial
  | x :: rest, hSub =>
      have hInE : containsKey x eReqs := hSub x (Or.inl rfl)
      have hPres : containsKey x actual :=
        let rec extract : ∀ ys : List Key, containsKey x ys → allRequiredKeysPresent actual ys → containsKey x actual
          | [], hIn, _ => False.elim hIn
          | _ :: _, Or.inl hEq, ⟨hP, _⟩ => hEq ▸ hP
          | _ :: ysRest, Or.inr hR, ⟨_, hAll⟩ => extract ysRest hR hAll
        extract eReqs hInE hE
      ⟨hPres, allRequiredKeys_subset_mono actual eReqs hE rest (fun y hy => hSub y (Or.inr hy))⟩

private theorem allRequiredRoles_subset_mono {Key Role : Type}
    (keyHasRole : Key → Role → Prop) (verifiedKeys : List Key) (eRoles : List Role)
    (hE : allRequiredRolesSatisfied keyHasRole verifiedKeys eRoles) :
    ∀ pRoles : List Role,
      (∀ r, containsKey r pRoles → containsKey r eRoles) →
      allRequiredRolesSatisfied keyHasRole verifiedKeys pRoles
  | [], _ => trivial
  | r :: rest, hSub =>
      have hInE : containsKey r eRoles := hSub r (Or.inl rfl)
      have hSat : roleSatisfiedByKeys keyHasRole r verifiedKeys :=
        let rec extract : ∀ ys : List Role, containsKey r ys → allRequiredRolesSatisfied keyHasRole verifiedKeys ys → roleSatisfiedByKeys keyHasRole r verifiedKeys
          | [], hIn, _ => False.elim hIn
          | _ :: _, Or.inl hEq, ⟨hS, _⟩ => hEq ▸ hS
          | _ :: ysRest, Or.inr hR, ⟨_, hAll⟩ => extract ysRest hR hAll
        extract eRoles hInE hE
      ⟨hSat, allRequiredRoles_subset_mono keyHasRole verifiedKeys eRoles hE rest (fun y hy => hSub y (Or.inr hy))⟩

/-- Constructive zero-axiom monotonic policy soundness proof: any attestation admitted under
a monotonically tightened effective policy unconditionally satisfies the entire baseline
policy manifest (CLI overrides can NEVER weaken a declarative audit policy). -/
theorem monotonicPolicyTightening_implies_baseline_satisfied {Subject Key Role : Type}
    (keyHasRole : Key → Role → Prop)
    (actualSubjects : List Subject) (verifiedKeys : List Key)
    (pMinSigs eMinSigs : Nat) (hPPos : 1 ≤ pMinSigs)
    (pReqSubjects eReqSubjects : List Subject)
    (pReqSigners eReqSigners : List Key)
    (pReqRoles eReqRoles : List Role)
    (hTighter : PolicyMonotonicallyTighter pMinSigs eMinSigs
                  pReqSubjects eReqSubjects pReqSigners eReqSigners pReqRoles eReqRoles)
    (hEffRoleSoD : DsseRoleSoDSatisfied keyHasRole verifiedKeys eReqRoles eMinSigs)
    (hEffSub : allRequiredKeysPresent actualSubjects eReqSubjects)
    (hEffSig : allRequiredKeysPresent verifiedKeys eReqSigners) :
    DsseRoleSoDSatisfied keyHasRole verifiedKeys pReqRoles pMinSigs ∧
    allRequiredKeysPresent actualSubjects pReqSubjects ∧
    allRequiredKeysPresent verifiedKeys pReqSigners :=
  ⟨⟨⟨hPPos, hEffRoleSoD.1.2.1, Nat.le_trans hTighter.1 hEffRoleSoD.1.2.2⟩,
    allRequiredRoles_subset_mono keyHasRole verifiedKeys eReqRoles hEffRoleSoD.2 pReqRoles hTighter.2.2.2⟩,
   allRequiredKeys_subset_mono actualSubjects eReqSubjects hEffSub pReqSubjects hTighter.2.1,
   allRequiredKeys_subset_mono verifiedKeys eReqSigners hEffSig pReqSigners hTighter.2.2.1⟩

/-! ## 22. Cryptographically Signed DSSE v1 Audit Policy Envelopes (`--signed-policy`) -/

/-- Constructive zero-axiom authenticity predicate for a DSSE v1 signed audit policy envelope
(`payloadType = application/vnd.de.attestation-policy+json`): requires distinct policy
payloadType (preventing in-toto statement confusion), valid `de.attestation.policy.v1` schema,
at least one admitted unrevoked Ed25519 PAE signature, and satisfaction of every auditor-mandated
policy-authority role (e.g. `policy-admin`). -/
def SafeSignedAuditPolicy {Key Role : Type}
    (keyHasRole : Key → Role → Prop)
    (payloadTypeMatchesPolicy policySchemaValid : Bool)
    (signatures : List DsseSignatureCheck)
    (verifiedPolicyKeys : List Key)
    (requiredPolicyRoles : List Role) : Prop :=
  payloadTypeMatchesPolicy = true ∧
  policySchemaValid = true ∧
  hasVerifiedDsseSig signatures ∧
  allRequiredRolesSatisfied keyHasRole verifiedPolicyKeys requiredPolicyRoles

/-- Constructive zero-axiom proof: signed policy verification unconditionally rejects
DSSE payloadType confusion, revoked/invalid signatures, and unprivileged signer roles
(e.g. `ci-builder` attempting to forge a policy when `policy-admin` is required). -/
theorem signedPolicy_rejects_typeConfusion_revoked_and_unprivilegedRole {Key Role : Type}
    (keyHasRole : Key → Role → Prop)
    (payloadTypeMatchesPolicy policySchemaValid : Bool)
    (signatures : List DsseSignatureCheck)
    (verifiedPolicyKeys : List Key)
    (requiredPolicyRoles : List Role) :
    (payloadTypeMatchesPolicy = false →
      ¬ SafeSignedAuditPolicy keyHasRole payloadTypeMatchesPolicy policySchemaValid
          signatures verifiedPolicyKeys requiredPolicyRoles) ∧
    (allDsseSigsRejected signatures →
      ¬ SafeSignedAuditPolicy keyHasRole payloadTypeMatchesPolicy policySchemaValid
          signatures verifiedPolicyKeys requiredPolicyRoles) ∧
    (∀ reqRole, containsKey reqRole requiredPolicyRoles →
      ¬ roleSatisfiedByKeys keyHasRole reqRole verifiedPolicyKeys →
      ¬ SafeSignedAuditPolicy keyHasRole payloadTypeMatchesPolicy policySchemaValid
          signatures verifiedPolicyKeys requiredPolicyRoles) :=
  ⟨fun hBadType hSafe => Bool.noConfusion (hBadType.symm.trans hSafe.1),
   fun hAllRej hSafe => allRejected_contradicts_hasVerified signatures hAllRej hSafe.2.2.1,
   fun _ hReq hNo hSafe =>
     missingRole_contradicts_allRoles keyHasRole verifiedPolicyKeys _ hNo requiredPolicyRoles hReq hSafe.2.2.2⟩

end DeterministicEngineering.Core.MetaGovernance
