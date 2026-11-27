/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

/-!
# Formal Soundness of AI Security & AI-SE Governance (`Core.AiGovernance`)

Mechanizes the exact declarative semantics of our repository's Phase 4 ASCENT
AI Security & AI Software Engineering governance rules (`AR01`–`AR05` in
`library/verification-flow/ascent-rules.ss`) inside Lean 4's kernel with
**strictly zero axioms** (every theorem verified via `#print axioms` to report
`does not depend on any axioms`).

## Proved AI Security & AI-SE Laws

1. **AR01 — No AI Self-Certification / Reject LLM-as-a-Judge**:
   Only the 4 deterministic formal/source/oracle families (`quint`, `leanPoo`,
   `sourceContract`, `nativeOracle`) can discharge verification obligations;
   `llmJudge` and `aiSelfReview` are never deterministic, and any AI-authored
   change lacking a deterministic verifier or routing any step to an LLM judge
   is unconditionally rejected.
2. **AR01 (AI-SE) — Invalid Proof-Reuse Refusal**:
   When an AI-authored patch mutates any key inside an obligation's security
   dependency set, silent proof reuse is unconditionally rejected; conversely,
   parameter tuning strictly disjoint from security dependencies preserves safe
   proof reuse.
3. **AR02 — AI Tool Execution Confinement**:
   Any AI agent executing tools (`aiExecutesTools`) must declare tool confinement
   and at least one executable attack countermodel; omitting either blocks admission.
4. **AR03 — Multi-Agent Authority Delegation**:
   Any AI agent delegating authority (`aiDelegatesAuthority`) must declare both
   monotonic scope attenuation and revocation currentness.
5. **AR04 — Untrusted Context / Prompt Injection Isolation**:
   Any AI agent ingesting untrusted context (`aiIngestsUntrustedContext`) must
   declare context integrity (recomputed prefix digest) or IFC taint confinement.
6. **AR05 — Human-in-the-Loop Role Separation of Duties (SoD)**:
   Any AI agent mutating host or governance state (`aiMutatesHostOrGovernance`)
   must declare human Step-Up + E-Stop AND bind a genuine `humanApprover`; an
   `aiAgent` identity can never satisfy `humanApprover` or `policyAdmin`
   authority (blocking AI self-approval fail-closed).
7. **Master Soundness Theorem**:
   `aiGovernanceAdmitted p = true` simultaneously guarantees all five `AR01`–`AR05`
   security invariants and sound AI-SE proof-reuse discipline.
-/

namespace DeterministicEngineering.Core.AiGovernance

/-! ## 1. Verifier Taxonomy & Deterministic Floor (`AR01`) -/

inductive VerifierKind where
  | quint
  | leanPoo
  | sourceContract
  | nativeOracle
  | llmJudge
  | aiSelfReview
  deriving DecidableEq, Repr

/-- Only the 4 deterministic formal/source/oracle engines qualify as verifiers. -/
def VerifierKind.isDeterministic : VerifierKind → Bool
  | .quint => true
  | .leanPoo => true
  | .sourceContract => true
  | .nativeOracle => true
  | .llmJudge => false
  | .aiSelfReview => false

/-- Every step in a list uses a deterministic verifier. -/
def allStepsDeterministic : List VerifierKind → Bool
  | [] => true
  | v :: rest =>
    match v.isDeterministic with
    | true => allStepsDeterministic rest
    | false => false

/-- At least one step in a list uses a deterministic verifier. -/
def hasDeterministicVerifier : List VerifierKind → Bool
  | [] => false
  | v :: rest =>
    match v.isDeterministic with
    | true => true
    | false => hasDeterministicVerifier rest

/-! ## 2. Role-Based Separation of Duties for AI vs Human Authority (`AR05`) -/

inductive ActorRole where
  | aiAgent
  | humanApprover
  | policyAdmin
  | ciRunner
  deriving DecidableEq, Repr

inductive AuthorityKind where
  | aiProposer
  | humanApprover
  | policyAdmin
  deriving DecidableEq, Repr

structure RoleBinding where
  actor : ActorRole
  authority : AuthorityKind
  deriving DecidableEq, Repr

/-- Whether an actor role is allowed to hold a given approval authority.
    Crucially, `aiAgent` is strictly forbidden from holding `humanApprover` or `policyAdmin`. -/
def roleAllowedForAuthority (actor : ActorRole) (auth : AuthorityKind) : Bool :=
  match actor with
  | .aiAgent =>
    match auth with
    | .aiProposer => true
    | .humanApprover => false
    | .policyAdmin => false
  | .humanApprover =>
    match auth with
    | .humanApprover => true
    | .aiProposer => false
    | .policyAdmin => false
  | .policyAdmin =>
    match auth with
    | .policyAdmin => true
    | .aiProposer => false
    | .humanApprover => false
  | .ciRunner => false

/-- Detects any illegal `aiAgent` self-approval for `humanApprover` or `policyAdmin`. -/
def hasAiSelfApprovalBinding : List RoleBinding → Bool
  | [] => false
  | b :: rest =>
    match b.actor with
    | .aiAgent =>
      match b.authority with
      | .humanApprover => true
      | .policyAdmin => true
      | .aiProposer => hasAiSelfApprovalBinding rest
    | .humanApprover => hasAiSelfApprovalBinding rest
    | .policyAdmin => hasAiSelfApprovalBinding rest
    | .ciRunner => hasAiSelfApprovalBinding rest

/-- Checks whether a genuine `humanApprover` binding is present. -/
def hasGenuineHumanApprover : List RoleBinding → Bool
  | [] => false
  | b :: rest =>
    match b.actor with
    | .humanApprover =>
      match b.authority with
      | .humanApprover => true
      | .aiProposer => hasGenuineHumanApprover rest
      | .policyAdmin => hasGenuineHumanApprover rest
    | .aiAgent => hasGenuineHumanApprover rest
    | .policyAdmin => hasGenuineHumanApprover rest
    | .ciRunner => hasGenuineHumanApprover rest

/-! ## 3. AI-SE Proof-Reuse Dependency Overlap Guard (`AR01` / LeanPoo Transport) -/

/-- Pure structural membership check over `Nat` dependency key IDs (zero axioms). -/
def natKeyIn : Nat → List Nat → Bool
  | _, [] => false
  | k, x :: xs =>
    match Nat.beq k x with
    | true => true
    | false => natKeyIn k xs

/-- True iff an AI patch touches at least one security dependency key of a proof obligation. -/
def patchTouchesSecurityDep (touchedKeys securityDeps : List Nat) : Bool :=
  match touchedKeys with
  | [] => false
  | k :: rest =>
    match natKeyIn k securityDeps with
    | true => true
    | false => patchTouchesSecurityDep rest securityDeps

/-- AI-SE proof reuse admission: allowed iff either no reuse is claimed OR the AI patch
    is strictly disjoint from every security dependency key. -/
def aiProofReuseAdmitted (claimedReuse : Bool) (touchedKeys securityDeps : List Nat) : Bool :=
  match claimedReuse with
  | false => true
  | true =>
    match patchTouchesSecurityDep touchedKeys securityDeps with
    | true => false
    | false => true

/-! ## 4. Unified AI Security Governance Posture (`AR01`–`AR05`) -/

structure AiGovernancePosture where
  aiAuthoredChange : Bool
  aiExecutesTools : Bool
  aiDelegatesAuthority : Bool
  aiIngestsUntrustedContext : Bool
  aiMutatesHostOrGovernance : Bool
  verifiers : List VerifierKind
  hasAttackCountermodel : Bool
  hasToolConfinement : Bool
  hasMonotonicAttenuation : Bool
  hasRevocationCurrentness : Bool
  hasContextIntegrityOrIfc : Bool
  hasHumanStepUpAndEstop : Bool
  roleBindings : List RoleBinding
  claimedProofReuse : Bool
  patchTouchedDeps : List Nat
  obligationSecurityDeps : List Nat
  deriving DecidableEq, Repr

/-- AR01: All verifiers deterministic, AI-authored changes have >= 1 deterministic verifier,
    and AI-SE proof reuse never survives a mutation touching a security dependency. -/
def ar01Satisfied (p : AiGovernancePosture) : Bool :=
  match allStepsDeterministic p.verifiers with
  | false => false
  | true =>
    match p.aiAuthoredChange with
    | true =>
      match hasDeterministicVerifier p.verifiers with
      | false => false
      | true => aiProofReuseAdmitted p.claimedProofReuse p.patchTouchedDeps p.obligationSecurityDeps
    | false =>
      aiProofReuseAdmitted p.claimedProofReuse p.patchTouchedDeps p.obligationSecurityDeps

/-- AR02: Tool-executing AI agents require tool confinement AND attack countermodels. -/
def ar02Satisfied (p : AiGovernancePosture) : Bool :=
  match p.aiExecutesTools with
  | false => true
  | true =>
    match p.hasToolConfinement with
    | false => false
    | true => p.hasAttackCountermodel

/-- AR03: Authority-delegating AI agents require monotonic attenuation AND revocation currentness. -/
def ar03Satisfied (p : AiGovernancePosture) : Bool :=
  match p.aiDelegatesAuthority with
  | false => true
  | true =>
    match p.hasMonotonicAttenuation with
    | false => false
    | true => p.hasRevocationCurrentness

/-- AR04: Untrusted-context AI agents require context integrity or IFC taint confinement. -/
def ar04Satisfied (p : AiGovernancePosture) : Bool :=
  match p.aiIngestsUntrustedContext with
  | false => true
  | true => p.hasContextIntegrityOrIfc

/-- AR05: Host/governance-mutating AI agents require human Step-Up + E-Stop, a genuine
    `humanApprover` binding, and zero `aiAgent` self-approval bindings anywhere. -/
def ar05Satisfied (p : AiGovernancePosture) : Bool :=
  match hasAiSelfApprovalBinding p.roleBindings with
  | true => false
  | false =>
    match p.aiMutatesHostOrGovernance with
    | false => true
    | true =>
      match p.hasHumanStepUpAndEstop with
      | false => false
      | true => hasGenuineHumanApprover p.roleBindings

/-- Combined fail-closed AI Security & AI-SE governance admission gate (`AR01`–`AR05`). -/
def aiGovernanceAdmitted (p : AiGovernancePosture) : Bool :=
  match ar01Satisfied p with
  | false => false
  | true =>
    match ar02Satisfied p with
    | false => false
    | true =>
      match ar03Satisfied p with
      | false => false
      | true =>
        match ar04Satisfied p with
        | false => false
        | true => ar05Satisfied p

/-! ## 5. Strictly Zero-Axiom Meta-Theorems (`#print axioms` = zero axioms) -/

/-- Theorem 1 (AR01): `llmJudge` and `aiSelfReview` are never deterministic verifiers. -/
theorem llmJudge_never_deterministic :
    VerifierKind.llmJudge.isDeterministic = false ∧
    VerifierKind.aiSelfReview.isDeterministic = false :=
  ⟨rfl, rfl⟩

/-- Theorem 2 (AR01): Any step list containing `llmJudge` or `aiSelfReview` fails
    `allStepsDeterministic`, unconditionally blocking `ar01Satisfied` and `aiGovernanceAdmitted`. -/
theorem nonDeterministicStep_rejects_admission
    (p : AiGovernancePosture) (v : VerifierKind) (rest : List VerifierKind)
    (hHead : p.verifiers = v :: rest)
    (hNonDet : v.isDeterministic = false) :
    aiGovernanceAdmitted p = false := by
  have hAll : allStepsDeterministic p.verifiers = false := by
    rw [hHead]
    unfold allStepsDeterministic
    rw [hNonDet]
  unfold aiGovernanceAdmitted ar01Satisfied
  rw [hAll]

/-- Theorem 3 (AR01): An AI-authored change with zero deterministic verifiers (empty or LLM-only)
    can never self-certify. -/
theorem aiAuthoredChange_without_deterministicVerifier_rejected
    (p : AiGovernancePosture)
    (hAi : p.aiAuthoredChange = true)
    (hNoDet : hasDeterministicVerifier p.verifiers = false) :
    aiGovernanceAdmitted p = false := by
  unfold aiGovernanceAdmitted ar01Satisfied
  cases hAll : allStepsDeterministic p.verifiers
  · rfl
  · rw [hAi, hNoDet]

/-- Theorem 4 (AR01 / AI-SE): Claiming proof reuse when an AI patch touches any key in the
    obligation's security dependency set is unconditionally rejected. -/
theorem aiPatch_touching_securityDep_invalidates_proofReuse
    (p : AiGovernancePosture)
    (hReuse : p.claimedProofReuse = true)
    (hTouch : patchTouchesSecurityDep p.patchTouchedDeps p.obligationSecurityDeps = true) :
    aiGovernanceAdmitted p = false := by
  have hPr : aiProofReuseAdmitted p.claimedProofReuse p.patchTouchedDeps p.obligationSecurityDeps = false := by
    unfold aiProofReuseAdmitted
    rw [hReuse, hTouch]
  unfold aiGovernanceAdmitted ar01Satisfied
  cases hAll : allStepsDeterministic p.verifiers
  · rfl
  · cases hAi : p.aiAuthoredChange
    · rw [hPr]
    · cases hHas : hasDeterministicVerifier p.verifiers
      · rfl
      · rw [hPr]

/-- Theorem 5 (AR01 / AI-SE): An AI patch touching ONLY keys disjoint from security dependencies
    preserves `aiProofReuseAdmitted = true` (formal basis for safe parameter-tuning reuse). -/
theorem aiPatch_disjoint_from_securityDeps_preserves_proofReuse
    (touchedKeys securityDeps : List Nat)
    (hDisjoint : patchTouchesSecurityDep touchedKeys securityDeps = false) :
    aiProofReuseAdmitted true touchedKeys securityDeps = true := by
  unfold aiProofReuseAdmitted
  rw [hDisjoint]

/-- Theorem 6 (AR02): Tool-executing AI agents lacking tool confinement OR attack countermodels
    are unconditionally rejected. -/
theorem aiToolExecution_missing_confinement_or_countermodel_rejected
    (p : AiGovernancePosture)
    (hTools : p.aiExecutesTools = true)
    (hDefect : p.hasToolConfinement = false ∨ p.hasAttackCountermodel = false) :
    aiGovernanceAdmitted p = false := by
  have hAr02 : ar02Satisfied p = false := by
    unfold ar02Satisfied
    rw [hTools]
    cases hDefect with
    | inl hNoConf => rw [hNoConf]
    | inr hNoCm =>
      cases p.hasToolConfinement
      · rfl
      · exact hNoCm
  unfold aiGovernanceAdmitted
  cases ar01Satisfied p
  · rfl
  · rw [hAr02]

/-- Theorem 7 (AR03): Authority-delegating AI agents lacking monotonic attenuation OR
    revocation currentness are unconditionally rejected. -/
theorem aiDelegation_missing_attenuation_or_currentness_rejected
    (p : AiGovernancePosture)
    (hDel : p.aiDelegatesAuthority = true)
    (hDefect : p.hasMonotonicAttenuation = false ∨ p.hasRevocationCurrentness = false) :
    aiGovernanceAdmitted p = false := by
  have hAr03 : ar03Satisfied p = false := by
    unfold ar03Satisfied
    rw [hDel]
    cases hDefect with
    | inl hNoAtt => rw [hNoAtt]
    | inr hNoCur =>
      cases p.hasMonotonicAttenuation
      · rfl
      · exact hNoCur
  unfold aiGovernanceAdmitted
  cases ar01Satisfied p
  · rfl
  · cases ar02Satisfied p
    · rfl
    · rw [hAr03]

/-- Theorem 8 (AR04): Untrusted-context AI agents lacking context integrity / IFC confinement
    are unconditionally rejected. -/
theorem aiUntrustedContext_missing_integrity_rejected
    (p : AiGovernancePosture)
    (hCtx : p.aiIngestsUntrustedContext = true)
    (hNoIfc : p.hasContextIntegrityOrIfc = false) :
    aiGovernanceAdmitted p = false := by
  have hAr04 : ar04Satisfied p = false := by
    unfold ar04Satisfied
    rw [hCtx, hNoIfc]
  unfold aiGovernanceAdmitted
  cases ar01Satisfied p
  · rfl
  · cases ar02Satisfied p
    · rfl
    · cases ar03Satisfied p
      · rfl
      · rw [hAr04]

/-- Theorem 9 (AR05 — Human-in-the-Loop SoD): `aiAgent` is strictly forbidden from holding
    `humanApprover` or `policyAdmin` authority, and any posture with an `aiAgent` self-approval
    binding OR a host-mutating AI lacking human Step-Up/E-Stop or genuine human approver is rejected. -/
theorem aiAgent_selfApproval_and_missing_humanStepUp_rejected
    (p : AiGovernancePosture) :
    roleAllowedForAuthority .aiAgent .humanApprover = false ∧
    roleAllowedForAuthority .aiAgent .policyAdmin = false ∧
    (hasAiSelfApprovalBinding p.roleBindings = true → aiGovernanceAdmitted p = false) ∧
    (p.aiMutatesHostOrGovernance = true →
      (p.hasHumanStepUpAndEstop = false ∨ hasGenuineHumanApprover p.roleBindings = false) →
      aiGovernanceAdmitted p = false) := by
  refine ⟨rfl, rfl, ?_, ?_⟩
  · intro hSelf
    have hAr05 : ar05Satisfied p = false := by
      unfold ar05Satisfied
      rw [hSelf]
    unfold aiGovernanceAdmitted
    cases ar01Satisfied p
    · rfl
    · cases ar02Satisfied p
      · rfl
      · cases ar03Satisfied p
        · rfl
        · cases ar04Satisfied p
          · rfl
          · exact hAr05
  · intro hMut hDef
    have hAr05 : ar05Satisfied p = false := by
      unfold ar05Satisfied
      cases hasAiSelfApprovalBinding p.roleBindings
      · rw [hMut]
        cases hDef with
        | inl hNoEstop => rw [hNoEstop]
        | inr hNoHuman =>
          cases p.hasHumanStepUpAndEstop
          · rfl
          · exact hNoHuman
      · rfl
    unfold aiGovernanceAdmitted
    cases ar01Satisfied p
    · rfl
    · cases ar02Satisfied p
      · rfl
      · cases ar03Satisfied p
        · rfl
        · cases ar04Satisfied p
          · rfl
          · exact hAr05

/-- Theorem 10 (Master Soundness Contract — AR01..AR05):
    Whenever `aiGovernanceAdmitted p = true`, ALL five AI security & AI-SE invariants hold
    simultaneously with zero gaps. -/
theorem aiGovernanceAdmitted_sound
    (p : AiGovernancePosture)
    (hAdmit : aiGovernanceAdmitted p = true) :
    allStepsDeterministic p.verifiers = true ∧
    (p.aiAuthoredChange = true → hasDeterministicVerifier p.verifiers = true) ∧
    (p.claimedProofReuse = true →
      patchTouchesSecurityDep p.patchTouchedDeps p.obligationSecurityDeps = false) ∧
    (p.aiExecutesTools = true →
      p.hasToolConfinement = true ∧ p.hasAttackCountermodel = true) ∧
    (p.aiDelegatesAuthority = true →
      p.hasMonotonicAttenuation = true ∧ p.hasRevocationCurrentness = true) ∧
    (p.aiIngestsUntrustedContext = true → p.hasContextIntegrityOrIfc = true) ∧
    hasAiSelfApprovalBinding p.roleBindings = false ∧
    (p.aiMutatesHostOrGovernance = true →
      p.hasHumanStepUpAndEstop = true ∧ hasGenuineHumanApprover p.roleBindings = true) := by
  have hSplit :
      ar01Satisfied p = true ∧
      ar02Satisfied p = true ∧
      ar03Satisfied p = true ∧
      ar04Satisfied p = true ∧
      ar05Satisfied p = true := by
    unfold aiGovernanceAdmitted at hAdmit
    cases h1 : ar01Satisfied p <;> rw [h1] at hAdmit
    · cases hAdmit
    · cases h2 : ar02Satisfied p <;> rw [h2] at hAdmit
      · cases hAdmit
      · cases h3 : ar03Satisfied p <;> rw [h3] at hAdmit
        · cases hAdmit
        · cases h4 : ar04Satisfied p <;> rw [h4] at hAdmit
          · cases hAdmit
          · exact ⟨rfl, rfl, rfl, rfl, hAdmit⟩
  rcases hSplit with ⟨h1, h2, h3, h4, h5⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · unfold ar01Satisfied at h1
    cases hDet : allStepsDeterministic p.verifiers
    · rw [hDet] at h1; cases h1
    · rfl
  · intro hAi
    unfold ar01Satisfied at h1
    cases hDet : allStepsDeterministic p.verifiers
    · rw [hDet] at h1; cases h1
    · rw [hDet, hAi] at h1
      cases hHas : hasDeterministicVerifier p.verifiers
      · rw [hHas] at h1; cases h1
      · rfl
  · intro hReuse
    unfold ar01Satisfied at h1
    cases hDet : allStepsDeterministic p.verifiers
    · rw [hDet] at h1; cases h1
    · rw [hDet] at h1
      cases hAi : p.aiAuthoredChange
      · rw [hAi] at h1
        unfold aiProofReuseAdmitted at h1
        rw [hReuse] at h1
        cases hT : patchTouchesSecurityDep p.patchTouchedDeps p.obligationSecurityDeps
        · rfl
        · rw [hT] at h1; cases h1
      · rw [hAi] at h1
        cases hHas : hasDeterministicVerifier p.verifiers
        · rw [hHas] at h1; cases h1
        · rw [hHas] at h1
          unfold aiProofReuseAdmitted at h1
          rw [hReuse] at h1
          cases hT : patchTouchesSecurityDep p.patchTouchedDeps p.obligationSecurityDeps
          · rfl
          · rw [hT] at h1; cases h1
  · intro hTools
    unfold ar02Satisfied at h2
    rw [hTools] at h2
    cases hConf : p.hasToolConfinement
    · rw [hConf] at h2; cases h2
    · rw [hConf] at h2; exact ⟨rfl, h2⟩
  · intro hDel
    unfold ar03Satisfied at h3
    rw [hDel] at h3
    cases hAtt : p.hasMonotonicAttenuation
    · rw [hAtt] at h3; cases h3
    · rw [hAtt] at h3; exact ⟨rfl, h3⟩
  · intro hCtx
    unfold ar04Satisfied at h4
    rw [hCtx] at h4
    exact h4
  · unfold ar05Satisfied at h5
    cases hSelf : hasAiSelfApprovalBinding p.roleBindings
    · rfl
    · rw [hSelf] at h5; cases h5
  · intro hMut
    unfold ar05Satisfied at h5
    cases hSelf : hasAiSelfApprovalBinding p.roleBindings
    · rw [hSelf, hMut] at h5
      cases hEstop : p.hasHumanStepUpAndEstop
      · rw [hEstop] at h5; cases h5
      · rw [hEstop] at h5; exact ⟨rfl, h5⟩
    · rw [hSelf] at h5; cases h5

end DeterministicEngineering.Core.AiGovernance
