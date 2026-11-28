/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM36: Adversarial (`ADV-L4`) Telemetry/Watchdog & Deck Single-VM Confinement

Standalone objectified `LeanPoo` module (54th Lean module, zero edits to
`Core/Stability.lean`) formalizing four real `ADV-L4` boundary defects
discovered in `marlin-agent-telemetry` and `marlin-deck-runtime`:

1. **OTLP Remote TLS Mandatory & Clean Endpoint/Label Confinement**:
   `OpenTelemetry::otlp_http` admitted remote cleartext `http://` collectors,
   empty hosts, `%40` userinfo/query/fragment smuggling, and blank or
   control-character `TelemetryServiceName` / `TraceTarget` labels.
2. **Host Observer Sidecar Environment Scrubbing & Symlink-Free Report Path**:
   `start_host_observer` spawned detached sidecars without `env_clear()`,
   inheriting ambient host secrets and loader variables (`OPENAI_API_KEY`,
   `MARLIN_BRIDGE_TOKEN`, `DYLD_*`), without parent-symlink checks, and
   `run_host_observer_if_requested` accepted extra args or invalid PIDs (`<= 1`).
3. **Watchdog Future-Timestamp Anti-Blinding & Non-Zero PID/Timeout Enforcement**:
   `HostObserver::drain_pulses` trusted sender-supplied `u64::MAX` timestamps
   permanently blinding `HeartbeatMissed` detection, and `HostObserver::attach`
   accepted `pid == 0` or `Duration::ZERO`.
4. **Deck Single-VM Module/Timer Capacity & Delay Confinement**:
   `Controls.modules` and `Controls.timers` lacked capacity ceilings under
   repeated activation/timer requests, and `DeckContextModule::timer` accepted
   unbounded `u64` microsecond delays pinning native VM slots indefinitely.
-/

namespace DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- OTLP endpoint and label admission predicate. -/
def otlpExportAdmitted
    (tlsOrLoopbackHttp : Bool)
    (cleanHostNoUserinfoQuery : Bool)
    (nonBlankCleanLabels : Bool) : Bool :=
  tlsOrLoopbackHttp && cleanHostNoUserinfoQuery && nonBlankCleanLabels

/-- Host observer sidecar spawn admission predicate. -/
def hostObserverSpawnAdmitted
    (envCleared : Bool)
    (symlinkFreeParent : Bool)
    (validHostPidAndArgs : Bool) : Bool :=
  envCleared && symlinkFreeParent && validHostPidAndArgs

/-- Watchdog heartbeat admission predicate preventing future-timestamp blinding and zero attach params. -/
def watchdogSampleAdmitted
    (pulseTs : Nat) (nowNs : Nat)
    (hostPid : Nat) (timeoutNs : Nat) : Bool :=
  (0 < pulseTs) && (pulseTs ≤ nowNs) && (0 < hostPid) && (0 < timeoutNs)

/-- Deck single-VM active module/timer capacity and finite timer delay admission predicate. -/
def deckVmControlAdmitted
    (activeModules : Nat) (maxModules : Nat)
    (activeTimers : Nat) (maxTimers : Nat)
    (delayUs : Nat) (maxDelayUs : Nat) : Bool :=
  (activeModules < maxModules) &&
  (activeTimers < maxTimers) &&
  (0 < delayUs) &&
  (delayUs ≤ maxDelayUs)

/-- Security and steady-state posture of Marlin telemetry and Deck single-VM boundaries. -/
structure TelemetryDeckVmConfig where
  enforcesOtlpTlsAndCleanLabels : Bool
  enforcesObserverEnvScrubAndPathConfinement : Bool
  enforcesWatchdogClockAndAttachBounds : Bool
  enforcesDeckVmModuleTimerAndDelayBounds : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a configuration satisfies strict SM36 confinement. -/
def strictSm36Admitted (c : TelemetryDeckVmConfig) : Bool :=
  c.enforcesOtlpTlsAndCleanLabels &&
  c.enforcesObserverEnvScrubAndPathConfinement &&
  c.enforcesWatchdogClockAndAttachBounds &&
  c.enforcesDeckVmModuleTimerAndDelayBounds &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 4 SM36 hostile exploit classes remain reachable. -/
def anySm36ExploitReachable (c : TelemetryDeckVmConfig) : Bool :=
  !c.enforcesOtlpTlsAndCleanLabels ||
  !c.enforcesObserverEnvScrubAndPathConfinement ||
  !c.enforcesWatchdogClockAndAttachBounds ||
  !c.enforcesDeckVmModuleTimerAndDelayBounds

/-- Canonical hardened SM36 posture. -/
def hardenedSm36Config : TelemetryDeckVmConfig :=
  { enforcesOtlpTlsAndCleanLabels := true
    enforcesObserverEnvScrubAndPathConfinement := true
    enforcesWatchdogClockAndAttachBounds := true
    enforcesDeckVmModuleTimerAndDelayBounds := true
    pressureTier := .l4HostileAttack }

def defectiveOtlpConfig : TelemetryDeckVmConfig :=
  { hardenedSm36Config with enforcesOtlpTlsAndCleanLabels := false }

def defectiveObserverConfig : TelemetryDeckVmConfig :=
  { hardenedSm36Config with enforcesObserverEnvScrubAndPathConfinement := false }

def defectiveWatchdogConfig : TelemetryDeckVmConfig :=
  { hardenedSm36Config with enforcesWatchdogClockAndAttachBounds := false }

def defectiveDeckVmConfig : TelemetryDeckVmConfig :=
  { hardenedSm36Config with enforcesDeckVmModuleTimerAndDelayBounds := false }

def defectiveGentleTierConfig : TelemetryDeckVmConfig :=
  { hardenedSm36Config with pressureTier := .l1Gentle }

/-- Theorem 1: Cleartext remote OTLP, smuggled host/query/userinfo, or blank/control labels fail closed. -/
theorem sm36_otlp_export_fail_closed (a b c : Bool) :
    otlpExportAdmitted false b c = false ∧
    otlpExportAdmitted a false c = false ∧
    otlpExportAdmitted a b false = false ∧
    otlpExportAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 2: Unscrubbed observer env, symlinked parent report path, or bad PID/args fail closed. -/
theorem sm36_host_observer_spawn_fail_closed (a b c : Bool) :
    hostObserverSpawnAdmitted false b c = false ∧
    hostObserverSpawnAdmitted a false c = false ∧
    hostObserverSpawnAdmitted a b false = false ∧
    hostObserverSpawnAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 3: Zero or future (> nowNs) watchdog timestamps and zero PID/timeout fail closed. -/
theorem sm36_watchdog_future_timestamp_and_zero_attach_fail_closed
    (pulseTs nowNs hostPid timeoutNs : Nat) :
    watchdogSampleAdmitted 0 nowNs hostPid timeoutNs = false ∧
    watchdogSampleAdmitted (nowNs + 1) nowNs hostPid timeoutNs = false ∧
    watchdogSampleAdmitted pulseTs nowNs 0 timeoutNs = false ∧
    watchdogSampleAdmitted pulseTs nowNs hostPid 0 = false := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · simp [watchdogSampleAdmitted]
  · simp [watchdogSampleAdmitted]; omega
  · simp [watchdogSampleAdmitted]
  · simp [watchdogSampleAdmitted]

/-- Theorem 4: Deck VM module/timer capacity saturation and zero/oversize timer delays fail closed. -/
theorem sm36_deck_vm_bounds_fail_closed (m maxM t maxT d maxD : Nat) :
    deckVmControlAdmitted maxM maxM t maxT d maxD = false ∧
    deckVmControlAdmitted m maxM maxT maxT d maxD = false ∧
    deckVmControlAdmitted m maxM t maxT 0 maxD = false ∧
    deckVmControlAdmitted m maxM t maxT (maxD + 1) maxD = false := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · simp [deckVmControlAdmitted]
  · simp [deckVmControlAdmitted]
  · simp [deckVmControlAdmitted]
  · simp [deckVmControlAdmitted]

/-- Theorem 5: Strict SM36 admission eliminates all 4 Telemetry/Watchdog & Deck VM exploit classes. -/
theorem sm36_strict_admission_eliminates_all_exploits (c : TelemetryDeckVmConfig)
    (h : strictSm36Admitted c = true) :
    anySm36ExploitReachable c = false := by
  cases c with
  | mk o s w d tier =>
    simp [strictSm36Admitted] at h
    rcases h with ⟨⟨⟨⟨ho, hs⟩, hw⟩, hd⟩, _⟩
    subst ho; subst hs; subst hw; subst hd
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 pressure tiers fail mandatory SM36 admission. -/
theorem sm36_gentle_pressure_rejected (c : TelemetryDeckVmConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm36Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm36Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm36Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm36_defective_configs_expose_live_exploits :
    anySm36ExploitReachable defectiveOtlpConfig = true ∧
    anySm36ExploitReachable defectiveObserverConfig = true ∧
    anySm36ExploitReachable defectiveWatchdogConfig = true ∧
    anySm36ExploitReachable defectiveDeckVmConfig = true ∧
    strictSm36Admitted defectiveGentleTierConfig = false ∧
    strictSm36Admitted hardenedSm36Config = true ∧
    anySm36ExploitReachable hardenedSm36Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive TelemetryDeckVmConfigKey where
  | otlpTlsAndLabels
  | observerEnvScrubAndPath
  | watchdogClockAndAttach
  | deckVmModuleTimerBounds
  | pressureTier
  deriving DecidableEq, Repr

inductive TelemetryDeckVmIssue where
  | cleartextRemoteOtlpOrDirtyLabel
  | unscrubbedHostObserverEnvOrSymlink
  | watchdogFutureTimestampBlindingOrZeroAttach
  | deckVmUnboundedControlsOrTimerPinning
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def telemetryDeckVmView :
    View TelemetryDeckVmConfig TelemetryDeckVmConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseTelemetryDeckVmContract :
    Contract TelemetryDeckVmConfig TelemetryDeckVmConfigKey Unit TelemetryDeckVmIssue where
  view := telemetryDeckVmView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesOtlpTlsAndCleanLabels then [] else [.rejected path .cleartextRemoteOtlpOrDirtyLabel]) ++
    (if cfg.enforcesObserverEnvScrubAndPathConfinement then [] else [.rejected path .unscrubbedHostObserverEnvOrSymlink]) ++
    (if cfg.enforcesWatchdogClockAndAttachBounds then [] else [.rejected path .watchdogFutureTimestampBlindingOrZeroAttach]) ++
    (if cfg.enforcesDeckVmModuleTimerAndDelayBounds then [] else [.rejected path .deckVmUnboundedControlsOrTimerPinning])
  validInventory := Or.inl rfl

def marlinTelemetryDeckVmContract :
    Contract TelemetryDeckVmConfig TelemetryDeckVmConfigKey Unit TelemetryDeckVmIssue :=
  refine baseTelemetryDeckVmContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin Telemetry/Deck VM contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm36_marlin_contract_refinement_laws
    (cfg : TelemetryDeckVmConfig) (path : List TelemetryDeckVmConfigKey) :
    (diagnose baseTelemetryDeckVmContract cfg path ≠ [] →
      diagnose marlinTelemetryDeckVmContract cfg path ≠ []) ∧
    (diagnose marlinTelemetryDeckVmContract cfg path = [] ↔
      diagnose baseTelemetryDeckVmContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path TelemetryDeckVmIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseTelemetryDeckVmContract _ cfg path,
   refine_accepts_iff baseTelemetryDeckVmContract _ cfg path⟩

inductive TelemetryDeckVmProofKey where
  | otlpTlsAndLabels
  | observerEnvScrubAndPath
  | watchdogClockAndAttach
  | deckVmModuleTimerBounds
  | pressureTier
  | defaultMaxActiveTimers
  deriving DecidableEq

abbrev TelemetryDeckVmProofValue : TelemetryDeckVmProofKey → Type
  | .otlpTlsAndLabels => Bool
  | .observerEnvScrubAndPath => Bool
  | .watchdogClockAndAttach => Bool
  | .deckVmModuleTimerBounds => Bool
  | .pressureTier => AdversarialPressureTier
  | .defaultMaxActiveTimers => Nat

def telemetryDeckVmObligation :
    LeanPoo.Proof.Obligation TelemetryDeckVmProofKey TelemetryDeckVmProofValue where
  dependencies := [
    .otlpTlsAndLabels,
    .observerEnvScrubAndPath,
    .watchdogClockAndAttach,
    .deckVmModuleTimerBounds,
    .pressureTier
  ]
  holds := fun s =>
    s .otlpTlsAndLabels = true ∧
    s .observerEnvScrubAndPath = true ∧
    s .watchdogClockAndAttach = true ∧
    s .deckVmModuleTimerBounds = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .otlpTlsAndLabels = after .otlpTlsAndLabels :=
      same .otlpTlsAndLabels (by simp)
    have h2 : before .observerEnvScrubAndPath = after .observerEnvScrubAndPath :=
      same .observerEnvScrubAndPath (by simp)
    have h3 : before .watchdogClockAndAttach = after .watchdogClockAndAttach :=
      same .watchdogClockAndAttach (by simp)
    have h4 : before .deckVmModuleTimerBounds = after .deckVmModuleTimerBounds :=
      same .deckVmModuleTimerBounds (by simp)
    have h5 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5] using holds

def baselineTelemetryDeckVmProof :
    LeanPoo.Proof.ProofObject TelemetryDeckVmProofKey TelemetryDeckVmProofValue where
  state := fun
    | .otlpTlsAndLabels => true
    | .observerEnvScrubAndPath => true
    | .watchdogClockAndAttach => true
    | .deckVmModuleTimerBounds => true
    | .pressureTier => .l4HostileAttack
    | .defaultMaxActiveTimers => 1024
  obligations := [telemetryDeckVmObligation]

/-- Theorem 9: Baseline ADV-L4 SM36 proof is certified. -/
theorem sm36_baseline_certified :
    LeanPoo.Proof.Certificate baselineTelemetryDeckVmProof := by
  intro obligation member
  have hEq : obligation = telemetryDeckVmObligation := by
    simpa [baselineTelemetryDeckVmProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

def deckTimerBudgetTuningPatch :
    LeanPoo.Proof.Patch TelemetryDeckVmProofKey TelemetryDeckVmProofValue :=
  LeanPoo.Proof.Patch.set .defaultMaxActiveTimers 512

/-- Theorem 10: Tuning bounded Deck timer capacity leaves SM36 security obligations untouched. -/
theorem sm36_obligation_untouched_by_timer_budget_tuning :
    LeanPoo.Proof.unaffected telemetryDeckVmObligation deckTimerBudgetTuningPatch := by
  intro key dep touched
  have hKey : key = .defaultMaxActiveTimers := by
    simpa [deckTimerBudgetTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [telemetryDeckVmObligation] at dep

/-- Theorem 11: Timer budget tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm36_timer_budget_tuning_reuses_and_closes_certificate :
    telemetryDeckVmObligation.holds
      (LeanPoo.Proof.append baselineTelemetryDeckVmProof deckTimerBudgetTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineTelemetryDeckVmProof deckTimerBudgetTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineTelemetryDeckVmProof deckTimerBudgetTuningPatch
      sm36_baseline_certified telemetryDeckVmObligation
      (by simp [baselineTelemetryDeckVmProof]) sm36_obligation_untouched_by_timer_budget_tuning
  · apply LeanPoo.Proof.close baselineTelemetryDeckVmProof deckTimerBudgetTuningPatch
      sm36_baseline_certified
    · intro obligation member affected
      have hEq : obligation = telemetryDeckVmObligation := by
        simpa [baselineTelemetryDeckVmProof] using member
      subst obligation
      exact False.elim (affected sm36_obligation_untouched_by_timer_budget_tuning)
    · intro obligation member
      simp [deckTimerBudgetTuningPatch, LeanPoo.Proof.Patch.set] at member

def otlpTlsRegressionPatch :
    LeanPoo.Proof.Patch TelemetryDeckVmProofKey TelemetryDeckVmProofValue :=
  LeanPoo.Proof.Patch.set .otlpTlsAndLabels false

def observerEnvRegressionPatch :
    LeanPoo.Proof.Patch TelemetryDeckVmProofKey TelemetryDeckVmProofValue :=
  LeanPoo.Proof.Patch.set .observerEnvScrubAndPath false

def watchdogClockRegressionPatch :
    LeanPoo.Proof.Patch TelemetryDeckVmProofKey TelemetryDeckVmProofValue :=
  LeanPoo.Proof.Patch.set .watchdogClockAndAttach false

def deckVmBoundsRegressionPatch :
    LeanPoo.Proof.Patch TelemetryDeckVmProofKey TelemetryDeckVmProofValue :=
  LeanPoo.Proof.Patch.set .deckVmModuleTimerBounds false

/-- Theorem 12: Regressing any of the 4 SM36 defenses invalidates LeanPoo certificate reuse. -/
theorem sm36_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected telemetryDeckVmObligation otlpTlsRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected telemetryDeckVmObligation observerEnvRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected telemetryDeckVmObligation watchdogClockRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected telemetryDeckVmObligation deckVmBoundsRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    exact h .otlpTlsAndLabels (by simp [telemetryDeckVmObligation])
      (by simp [otlpTlsRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .observerEnvScrubAndPath (by simp [telemetryDeckVmObligation])
      (by simp [observerEnvRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .watchdogClockAndAttach (by simp [telemetryDeckVmObligation])
      (by simp [watchdogClockRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .deckVmModuleTimerBounds (by simp [telemetryDeckVmObligation])
      (by simp [deckVmBoundsRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.TelemetryWatchdogAndDeckVmConfinement
