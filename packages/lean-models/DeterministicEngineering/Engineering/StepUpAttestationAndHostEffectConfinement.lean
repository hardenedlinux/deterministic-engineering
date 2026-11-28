/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM30: Adversarial (`ADV-L4`) Step-Up MFA Attestation Integrity, Scheme Effect E-Stop/CAS Isolation & Bounded Host Resilience

Standalone objectified `LeanPoo` module (48th Lean module, zero edits to
`Core/Stability.lean`) formalizing five real `ADV-L4` host-controller & effect-worker
bypass vulnerabilities discovered in `marlin-gerbil-scheme`:

1. **Step-Up MFA Attestation Integrity**: Accepting non-human `worker-*`/`scheme-sandbox-*`
   prefixes, weak/arbitrary `acr=` strings (`acr=none`/`password`/`fake`), or duplicate
   `actor=` parameter smuggling allows unauthorized circuit-breaker re-arm.
2. **Scheme Effect E-Stop & Reserved Governance CAS Confinement**: Leaving `LlmComplete`
   ungated under E-Stop leaks live external AI inference; leaving `CasPut` open on reserved
   governance checkpoint keys (`checkpoint:governance*` / `*:facts`) lets untrusted Scheme
   effects overwrite durable `MGV1`/`MGF1` E-Stop latches.
3. **Broadcast-Lag Watcher Survival**: Matching `Err(_) => break` on broadcast receivers
   permanently kills `gate_watcher` and `ui_cmd_watcher` on `RecvError::Lagged(_)`.
4. **Fact-Graph Write/Read Capacity Parity & Constant-Time `MGF1` Verification**: Inserting
   beyond `from_canonical_bytes`'s `MAX_FACT_STORE_ENTRIES` creates a self-inflicted restart
   deserialization bomb; comparing `MGF1` SHA-256 digests with `!=` leaks timing.
5. **Fail-Closed Durable Re-Arm Persistence**: Swallowing `persist_to_cas` errors with `let _ =`
   desynchronizes live armed state from durable Turso CAS WAL.
-/

namespace DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Verified Step-Up MFA attestation admission judgment. -/
def stepUpAttestationAdmitted
    (isHumanNonAgentPrefix : Bool)
    (isAllowlistedMfaAcr : Bool)
    (noDuplicateParams : Bool) : Bool :=
  isHumanNonAgentPrefix && isAllowlistedMfaAcr && noDuplicateParams

/-- Atomic effect worker admission law for `LlmComplete` and `CasPut`. -/
def schemeEffectAdmitted
    (isLlm : Bool) (isCasPut : Bool)
    (estopTripped : Bool) (targetsReservedGovCasKey : Bool) : Bool :=
  if isLlm && estopTripped then false
  else if isCasPut && targetsReservedGovCasKey then false
  else true

/-- Fact-store insertion guard preserving write/read deserialization capacity parity. -/
def factInsertAdmitted (currentLen maxCap : Nat) (alreadyPresent : Bool) : Bool :=
  alreadyPresent || (currentLen < maxCap)

/-- Security posture of a Scheme governance host controller & atomic-effect worker. -/
structure SchemeHostSecurityConfig where
  enforcesStrictStepUpMfaAttestation : Bool
  mediatesLlmAndConfinesReservedCas : Bool
  survivesBroadcastLagAndBoundsFanout : Bool
  enforcesFactCapAndConstantTimeMgf1 : Bool
  failsClosedOnRearmCasPersistError : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a host configuration satisfies strict SM30 confinement. -/
def strictSm30Admitted (c : SchemeHostSecurityConfig) : Bool :=
  c.enforcesStrictStepUpMfaAttestation &&
  c.mediatesLlmAndConfinesReservedCas &&
  c.survivesBroadcastLagAndBoundsFanout &&
  c.enforcesFactCapAndConstantTimeMgf1 &&
  c.failsClosedOnRearmCasPersistError &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM30 hostile exploit classes remain reachable. -/
def anySm30ExploitReachable (c : SchemeHostSecurityConfig) : Bool :=
  !c.enforcesStrictStepUpMfaAttestation ||
  !c.mediatesLlmAndConfinesReservedCas ||
  !c.survivesBroadcastLagAndBoundsFanout ||
  !c.enforcesFactCapAndConstantTimeMgf1 ||
  !c.failsClosedOnRearmCasPersistError

/-- Canonical hardened SM30 Marlin Scheme host posture. -/
def hardenedSm30Config : SchemeHostSecurityConfig :=
  { enforcesStrictStepUpMfaAttestation := true
    mediatesLlmAndConfinesReservedCas := true
    survivesBroadcastLagAndBoundsFanout := true
    enforcesFactCapAndConstantTimeMgf1 := true
    failsClosedOnRearmCasPersistError := true
    pressureTier := .l4HostileAttack }

def defectiveStepUpConfig : SchemeHostSecurityConfig :=
  { hardenedSm30Config with enforcesStrictStepUpMfaAttestation := false }

def defectiveEffectCasConfig : SchemeHostSecurityConfig :=
  { hardenedSm30Config with mediatesLlmAndConfinesReservedCas := false }

def defectiveWatcherLagConfig : SchemeHostSecurityConfig :=
  { hardenedSm30Config with survivesBroadcastLagAndBoundsFanout := false }

def defectiveFactCapConfig : SchemeHostSecurityConfig :=
  { hardenedSm30Config with enforcesFactCapAndConstantTimeMgf1 := false }

def defectivePersistSwallowConfig : SchemeHostSecurityConfig :=
  { hardenedSm30Config with failsClosedOnRearmCasPersistError := false }

def defectiveGentleTierConfig : SchemeHostSecurityConfig :=
  { hardenedSm30Config with pressureTier := .l1Gentle }

/-- Theorem 1: Non-human prefixes (`worker-*`, `scheme-sandbox-*`), weak ACR values,
    and duplicate-parameter smuggling are all unconditionally refused by Step-Up admission. -/
theorem sm30_stepup_spoof_weak_acr_and_duplicate_params_refused
    (h1 h2 h3 : Bool) :
    stepUpAttestationAdmitted false h2 h3 = false ∧
    stepUpAttestationAdmitted h1 false h3 = false ∧
    stepUpAttestationAdmitted h1 h2 false = false ∧
    stepUpAttestationAdmitted true true true = true := by
  cases h1 <;> cases h2 <;> cases h3 <;> decide

/-- Theorem 2: Active E-Stop unconditionally blocks `LlmComplete` effects. -/
theorem sm30_estop_blocks_llm_complete (isCasPut reserved : Bool) :
    schemeEffectAdmitted true isCasPut true reserved = false := by
  simp [schemeEffectAdmitted]

/-- Theorem 3: `CasPut` targeting a reserved governance checkpoint key is unconditionally refused. -/
theorem sm30_reserved_governance_cas_overwrite_refused (isLlm estop : Bool) :
    schemeEffectAdmitted isLlm true estop true = false := by
  cases isLlm <;> cases estop <;> simp [schemeEffectAdmitted]

/-- Theorem 4: Inserting a new fact at or above `maxCap` is refused, preserving MGF1 deserialization parity. -/
theorem sm30_fact_insert_at_cap_refused (cur cap : Nat) (hge : cap ≤ cur) :
    factInsertAdmitted cur cap false = false := by
  have hnotlt : (cur < cap) = false := by
    simp [Nat.not_lt_of_ge hge]
  simp [factInsertAdmitted, hnotlt]

/-- Theorem 5: Strict SM30 admission eliminates all 5 Scheme host exploit classes. -/
theorem sm30_strict_admission_eliminates_all_exploits (c : SchemeHostSecurityConfig)
    (h : strictSm30Admitted c = true) :
    anySm30ExploitReachable c = false := by
  cases c with
  | mk s e w f p tier =>
    simp [strictSm30Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨hs, he⟩, hw⟩, hf⟩, hp⟩, _⟩
    subst hs; subst he; subst hw; subst hf; subst hp
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 tiers fail mandatory SM30 admission. -/
theorem sm30_gentle_pressure_rejected (c : SchemeHostSecurityConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm30Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm30Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm30Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm30_defective_configs_expose_live_exploits :
    anySm30ExploitReachable defectiveStepUpConfig = true ∧
    anySm30ExploitReachable defectiveEffectCasConfig = true ∧
    anySm30ExploitReachable defectiveWatcherLagConfig = true ∧
    anySm30ExploitReachable defectiveFactCapConfig = true ∧
    anySm30ExploitReachable defectivePersistSwallowConfig = true ∧
    strictSm30Admitted defectiveGentleTierConfig = false ∧
    strictSm30Admitted hardenedSm30Config = true ∧
    anySm30ExploitReachable hardenedSm30Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive SchemeHostConfigKey where
  | strictStepUpMfa
  | llmAndReservedCasConfinement
  | watcherLagAndFanoutBound
  | factCapAndConstantTimeMgf1
  | failClosedRearmPersist
  | pressureTier
  deriving DecidableEq, Repr

inductive SchemeHostIssue where
  | stepUpAttestationSpoof
  | estopLlmOrReservedCasBypass
  | watcherLagSuicideOrUnboundedFanout
  | factDeserBombOrTimingTag
  | silentRearmPersistSwallow
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def schemeHostView : View SchemeHostSecurityConfig SchemeHostConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseSchemeHostContract :
    Contract SchemeHostSecurityConfig SchemeHostConfigKey Unit SchemeHostIssue where
  view := schemeHostView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesStrictStepUpMfaAttestation then [] else [.rejected path .stepUpAttestationSpoof]) ++
    (if cfg.mediatesLlmAndConfinesReservedCas then [] else [.rejected path .estopLlmOrReservedCasBypass]) ++
    (if cfg.survivesBroadcastLagAndBoundsFanout then [] else [.rejected path .watcherLagSuicideOrUnboundedFanout]) ++
    (if cfg.enforcesFactCapAndConstantTimeMgf1 then [] else [.rejected path .factDeserBombOrTimingTag]) ++
    (if cfg.failsClosedOnRearmCasPersistError then [] else [.rejected path .silentRearmPersistSwallow])
  validInventory := Or.inl rfl

def marlinSchemeHostContract :
    Contract SchemeHostSecurityConfig SchemeHostConfigKey Unit SchemeHostIssue :=
  refine baseSchemeHostContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin Scheme host contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm30_marlin_contract_refinement_laws
    (cfg : SchemeHostSecurityConfig) (path : List SchemeHostConfigKey) :
    (diagnose baseSchemeHostContract cfg path ≠ [] →
      diagnose marlinSchemeHostContract cfg path ≠ []) ∧
    (diagnose marlinSchemeHostContract cfg path = [] ↔
      diagnose baseSchemeHostContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path SchemeHostIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseSchemeHostContract _ cfg path,
   refine_accepts_iff baseSchemeHostContract _ cfg path⟩

inductive SchemeHostProofKey where
  | strictStepUpMfa
  | llmAndReservedCasConfinement
  | watcherLagAndFanoutBound
  | factCapAndConstantTimeMgf1
  | failClosedRearmPersist
  | pressureTier
  | maxConcurrentEffects
  deriving DecidableEq

abbrev SchemeHostProofValue : SchemeHostProofKey → Type
  | .strictStepUpMfa => Bool
  | .llmAndReservedCasConfinement => Bool
  | .watcherLagAndFanoutBound => Bool
  | .factCapAndConstantTimeMgf1 => Bool
  | .failClosedRearmPersist => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxConcurrentEffects => Nat

def schemeHostObligation :
    LeanPoo.Proof.Obligation SchemeHostProofKey SchemeHostProofValue where
  dependencies := [
    .strictStepUpMfa,
    .llmAndReservedCasConfinement,
    .watcherLagAndFanoutBound,
    .factCapAndConstantTimeMgf1,
    .failClosedRearmPersist,
    .pressureTier
  ]
  holds := fun s =>
    s .strictStepUpMfa = true ∧
    s .llmAndReservedCasConfinement = true ∧
    s .watcherLagAndFanoutBound = true ∧
    s .factCapAndConstantTimeMgf1 = true ∧
    s .failClosedRearmPersist = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .strictStepUpMfa = after .strictStepUpMfa :=
      same .strictStepUpMfa (by simp)
    have h2 : before .llmAndReservedCasConfinement = after .llmAndReservedCasConfinement :=
      same .llmAndReservedCasConfinement (by simp)
    have h3 : before .watcherLagAndFanoutBound = after .watcherLagAndFanoutBound :=
      same .watcherLagAndFanoutBound (by simp)
    have h4 : before .factCapAndConstantTimeMgf1 = after .factCapAndConstantTimeMgf1 :=
      same .factCapAndConstantTimeMgf1 (by simp)
    have h5 : before .failClosedRearmPersist = after .failClosedRearmPersist :=
      same .failClosedRearmPersist (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineSchemeHostProof :
    LeanPoo.Proof.ProofObject SchemeHostProofKey SchemeHostProofValue where
  state := fun
    | .strictStepUpMfa => true
    | .llmAndReservedCasConfinement => true
    | .watcherLagAndFanoutBound => true
    | .factCapAndConstantTimeMgf1 => true
    | .failClosedRearmPersist => true
    | .pressureTier => .l4HostileAttack
    | .maxConcurrentEffects => 16
  obligations := [schemeHostObligation]

/-- Theorem 9: Baseline ADV-L4 SM30 proof is certified. -/
theorem sm30_baseline_certified :
    LeanPoo.Proof.Certificate baselineSchemeHostProof := by
  intro obligation member
  have hEq : obligation = schemeHostObligation := by
    simpa [baselineSchemeHostProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def effectConcurrencyTuningPatch :
    LeanPoo.Proof.Patch SchemeHostProofKey SchemeHostProofValue :=
  LeanPoo.Proof.Patch.set .maxConcurrentEffects 32

theorem sm30_obligation_untouched_by_concurrency_tuning :
    LeanPoo.Proof.unaffected schemeHostObligation effectConcurrencyTuningPatch := by
  intro key dep touched
  have hKey : key = .maxConcurrentEffects := by
    simpa [effectConcurrencyTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [schemeHostObligation] at dep

/-- Theorem 10: Tuning bounded concurrency cleanly reuses and closes the LeanPoo certificate. -/
theorem sm30_concurrency_tuning_reuses_and_closes_certificate :
    schemeHostObligation.holds
      (LeanPoo.Proof.append baselineSchemeHostProof effectConcurrencyTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineSchemeHostProof effectConcurrencyTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineSchemeHostProof effectConcurrencyTuningPatch
      sm30_baseline_certified schemeHostObligation
      (by simp [baselineSchemeHostProof]) sm30_obligation_untouched_by_concurrency_tuning
  · apply LeanPoo.Proof.close baselineSchemeHostProof effectConcurrencyTuningPatch
      sm30_baseline_certified
    · intro obligation member affected
      have hEq : obligation = schemeHostObligation := by
        simpa [baselineSchemeHostProof] using member
      subst obligation
      exact False.elim (affected sm30_obligation_untouched_by_concurrency_tuning)
    · intro obligation member
      simp [effectConcurrencyTuningPatch, LeanPoo.Proof.Patch.set] at member

def stepUpRegressionPatch :
    LeanPoo.Proof.Patch SchemeHostProofKey SchemeHostProofValue :=
  LeanPoo.Proof.Patch.set .strictStepUpMfa false

def effectCasRegressionPatch :
    LeanPoo.Proof.Patch SchemeHostProofKey SchemeHostProofValue :=
  LeanPoo.Proof.Patch.set .llmAndReservedCasConfinement false

def watcherLagRegressionPatch :
    LeanPoo.Proof.Patch SchemeHostProofKey SchemeHostProofValue :=
  LeanPoo.Proof.Patch.set .watcherLagAndFanoutBound false

def factCapRegressionPatch :
    LeanPoo.Proof.Patch SchemeHostProofKey SchemeHostProofValue :=
  LeanPoo.Proof.Patch.set .factCapAndConstantTimeMgf1 false

def persistSwallowRegressionPatch :
    LeanPoo.Proof.Patch SchemeHostProofKey SchemeHostProofValue :=
  LeanPoo.Proof.Patch.set .failClosedRearmPersist false

/-- Theorem 11: Regressing any of the 5 SM30 defenses invalidates LeanPoo certificate reuse. -/
theorem sm30_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected schemeHostObligation stepUpRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected schemeHostObligation effectCasRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected schemeHostObligation watcherLagRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected schemeHostObligation factCapRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected schemeHostObligation persistSwallowRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .strictStepUpMfa (by simp [schemeHostObligation])
      (by simp [stepUpRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .llmAndReservedCasConfinement (by simp [schemeHostObligation])
      (by simp [effectCasRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .watcherLagAndFanoutBound (by simp [schemeHostObligation])
      (by simp [watcherLagRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .factCapAndConstantTimeMgf1 (by simp [schemeHostObligation])
      (by simp [factCapRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .failClosedRearmPersist (by simp [schemeHostObligation])
      (by simp [persistSwallowRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.StepUpAttestationAndHostEffectConfinement
