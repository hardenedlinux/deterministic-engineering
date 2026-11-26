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
  hasPassingCache : Step → Prop
  currentInput : Step → Key → Digest → Prop
  cachedInput : Step → Key → Digest → Prop
  currentToolchain : Step → Toolchain → Prop
  cachedToolchain : Step → Toolchain → Prop
  isM3Mutable : Step → Prop
  attested : Step → Prop
  requireFreshM3 : Prop
  requireSignedCache : Prop

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

/-- Least fixed point of ASCENT `step_invalidated` rules (`IR01`–`IR06`). -/
inductive Invalidated {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) : Step → Prop where
  | ir01 (s : Step) : ¬ sys.hasPassingCache s → Invalidated sys s
  | ir02 (s : Step) : inputDirty sys s → Invalidated sys s
  | ir03 {u v : Step} : sys.dagEdge u v → Invalidated sys u → Invalidated sys v
  | ir04 (s : Step) : sys.isM3Mutable s → sys.requireFreshM3 → Invalidated sys s
  | ir05 (s : Step) : toolchainDirty sys s → Invalidated sys s
  | ir06 (s : Step) : sys.requireSignedCache → ¬ sys.attested s → Invalidated sys s

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

end DeterministicEngineering.Core.MetaGovernance
