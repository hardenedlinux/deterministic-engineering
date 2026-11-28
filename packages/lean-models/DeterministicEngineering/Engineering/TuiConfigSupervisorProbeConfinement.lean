/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM39: Adversarial (`ADV-L4`) TUI Config, ASP Supervisor, Diagnostic Probe & Bootstrap Confinement

Standalone objectified `LeanPoo` module (57th committed Lean module, zero edits to
`Core/Stability.lean`) formalizing four real `ADV-L4` boundary defects discovered
in `marlin-agent-tui`:

1. **TUI TOML Config Confinement (`config.rs`)**:
   `Config::load` performed unbounded `fs::read_to_string` following symlinks;
   `ModelProfile::route` read ambient OS/loader `credential_env` variables
   (`PATH`/`HOME`/`LD_PRELOAD`/`SSH_AUTH_SOCK`); `catalog_with` accepted
   `timeout_seconds == 0` or multi-year timeouts; `tui_ui_package` omitted
   path/module validation.
2. **ASP Gateway Supervisor Isolation (`app/asp_supervisor.rs`)**:
   `spawn_managed_asp_gateway` inherited ambient host secrets without `.env_clear()`,
   blocked indefinitely on silent child stdout without a boot timeout, accepted
   `@-userinfo`/control-char spoofed endpoints, and `discover_asp_gateway_binary`
   searched relative `PATH` segments (`.`).
3. **Runtime Diagnostic Probe File Confinement (`app/runtime_probe.rs`)**:
   `RuntimeProbe::start` opened `MARLIN_TUI_RUNTIME_METRICS_FILE` via `File::create`
   following leaf/parent symlinks and appended CSV rows every 250ms indefinitely
   without a cumulative byte cap.
4. **Local Scheme Bootstrap Trust Ordering (`bootstrap.rs`)**:
   `resolve_local_scheme_prefix` checked untrusted `cwd/scheme` before the
   compiled binary's own repository root and followed symlinks, enabling CWD
   Scheme hijacking.
-/

namespace DeterministicEngineering.Engineering.TuiConfigSupervisorProbeConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- TUI TOML config admission predicate: non-symlink, byte-bounded, finite timeout (`1..=maxTimeout`), and safe non-ambient `credential_env`. -/
def tuiConfigAdmitted
    (symlinkFree : Bool)
    (fileBytes maxBytes : Nat)
    (timeoutSecs maxTimeout : Nat)
    (credEnvSafe : Bool) : Bool :=
  symlinkFree &&
  (fileBytes ≤ maxBytes) &&
  (0 < timeoutSecs) &&
  (timeoutSecs ≤ maxTimeout) &&
  credEnvSafe

/-- ASP gateway supervisor admission predicate: env-cleared allowlist, bounded boot timeout, strict loopback host:port without `@`/controls, and absolute binary path. -/
def aspSupervisorAdmitted
    (envCleared : Bool)
    (bootElapsedMs bootTimeoutMs : Nat)
    (strictLoopbackEndpoint : Bool)
    (pathAbsolute : Bool) : Bool :=
  envCleared &&
  (bootElapsedMs ≤ bootTimeoutMs) &&
  strictLoopbackEndpoint &&
  pathAbsolute

/-- Runtime diagnostic probe write admission predicate: `O_NOFOLLOW` non-symlink file and cumulative byte ceiling. -/
def runtimeProbeWriteAdmitted
    (symlinkFree : Bool)
    (writtenBytes rowBytes maxBytes : Nat) : Bool :=
  symlinkFree && (writtenBytes + rowBytes ≤ maxBytes)

/-- Local Scheme bootstrap selection predicate: trusted exe-owned repository precedes CWD and rejects symlinks. -/
def bootstrapPrefixAdmitted
    (exeRepoPresent : Bool)
    (selectedIsExeRepo : Bool)
    (symlinkFree : Bool) : Bool :=
  symlinkFree && ((!exeRepoPresent) || selectedIsExeRepo)

/-- Security and steady-state posture of terminal client config, supervisor, probe, and bootstrap boundaries. -/
structure TuiConfinementConfig where
  enforcesConfigSymlinkCapTimeoutCredEnv : Bool
  enforcesAspSupervisorScrubTimeoutEndpointPath : Bool
  enforcesProbeNoFollowByteCap : Bool
  enforcesBootstrapExeFirstNoSymlink : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a configuration satisfies strict SM39 confinement. -/
def strictSm39Admitted (c : TuiConfinementConfig) : Bool :=
  c.enforcesConfigSymlinkCapTimeoutCredEnv &&
  c.enforcesAspSupervisorScrubTimeoutEndpointPath &&
  c.enforcesProbeNoFollowByteCap &&
  c.enforcesBootstrapExeFirstNoSymlink &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 4 SM39 hostile exploit classes remain reachable. -/
def anySm39ExploitReachable (c : TuiConfinementConfig) : Bool :=
  !c.enforcesConfigSymlinkCapTimeoutCredEnv ||
  !c.enforcesAspSupervisorScrubTimeoutEndpointPath ||
  !c.enforcesProbeNoFollowByteCap ||
  !c.enforcesBootstrapExeFirstNoSymlink

/-- Canonical hardened SM39 posture. -/
def hardenedSm39Config : TuiConfinementConfig :=
  { enforcesConfigSymlinkCapTimeoutCredEnv := true
    enforcesAspSupervisorScrubTimeoutEndpointPath := true
    enforcesProbeNoFollowByteCap := true
    enforcesBootstrapExeFirstNoSymlink := true
    pressureTier := .l4HostileAttack }

def defectiveConfigPosture : TuiConfinementConfig :=
  { hardenedSm39Config with enforcesConfigSymlinkCapTimeoutCredEnv := false }

def defectiveSupervisorPosture : TuiConfinementConfig :=
  { hardenedSm39Config with enforcesAspSupervisorScrubTimeoutEndpointPath := false }

def defectiveProbePosture : TuiConfinementConfig :=
  { hardenedSm39Config with enforcesProbeNoFollowByteCap := false }

def defectiveBootstrapPosture : TuiConfinementConfig :=
  { hardenedSm39Config with enforcesBootstrapExeFirstNoSymlink := false }

def defectiveGentleTierPosture : TuiConfinementConfig :=
  { hardenedSm39Config with pressureTier := .l1Gentle }

/-- Theorem 1: Symlinked/oversize configs, zero/oversize timeouts, and ambient credential_env names fail closed. -/
theorem sm39_tui_config_bounds_fail_closed (bytes maxBytes maxTimeout : Nat) :
    tuiConfigAdmitted false bytes maxBytes 30 600 true = false ∧
    tuiConfigAdmitted true (maxBytes + 1) maxBytes 30 600 true = false ∧
    tuiConfigAdmitted true 128 262144 0 maxTimeout true = false ∧
    tuiConfigAdmitted true 128 262144 (maxTimeout + 1) maxTimeout true = false ∧
    tuiConfigAdmitted true 128 262144 30 600 false = false ∧
    tuiConfigAdmitted true 128 262144 30 600 true = true := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [tuiConfigAdmitted]
  · simp [tuiConfigAdmitted]
  · simp [tuiConfigAdmitted]
  · simp [tuiConfigAdmitted]
  · simp [tuiConfigAdmitted]
  · decide

/-- Theorem 2: Unscrubbed env, boot-timeout hang, spoofed non-loopback/@ endpoint, and relative PATH fail closed. -/
theorem sm39_asp_supervisor_isolation_fail_closed (elapsed timeout : Nat) :
    aspSupervisorAdmitted false elapsed timeout true true = false ∧
    aspSupervisorAdmitted true (timeout + 1) timeout true true = false ∧
    aspSupervisorAdmitted true elapsed timeout false true = false ∧
    aspSupervisorAdmitted true elapsed timeout true false = false ∧
    aspSupervisorAdmitted true 100 5000 true true = true := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · simp [aspSupervisorAdmitted]
  · simp [aspSupervisorAdmitted]
  · simp [aspSupervisorAdmitted]
  · simp [aspSupervisorAdmitted]
  · decide

/-- Theorem 3: Symlinked runtime probe targets and cumulative byte-ceiling overflows fail closed. -/
theorem sm39_runtime_probe_bounds_fail_closed (written row maxBytes : Nat) :
    runtimeProbeWriteAdmitted false written row maxBytes = false ∧
    runtimeProbeWriteAdmitted true maxBytes (row + 1) maxBytes = false ∧
    runtimeProbeWriteAdmitted true 0 32 4194304 = true := by
  refine ⟨?_, ?_, ?_⟩
  · simp [runtimeProbeWriteAdmitted]
  · simp [runtimeProbeWriteAdmitted]
  · decide

/-- Theorem 4: CWD hijack over an existing binary-owned repository or symlinked Scheme prefix fails closed. -/
theorem sm39_bootstrap_trust_order_fail_closed (exePresent selectedExe : Bool) :
    bootstrapPrefixAdmitted true false true = false ∧
    bootstrapPrefixAdmitted exePresent selectedExe false = false ∧
    bootstrapPrefixAdmitted true true true = true ∧
    bootstrapPrefixAdmitted false false true = true := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · decide
  · simp [bootstrapPrefixAdmitted]
  · decide
  · decide

/-- Theorem 5: Strict SM39 admission eliminates all 4 TUI confinement exploit classes. -/
theorem sm39_strict_admission_eliminates_all_exploits (c : TuiConfinementConfig)
    (h : strictSm39Admitted c = true) :
    anySm39ExploitReachable c = false := by
  cases c with
  | mk cfg sup prb boot tier =>
    simp [strictSm39Admitted] at h
    rcases h with ⟨⟨⟨⟨hc, hs⟩, hp⟩, hb⟩, _⟩
    subst hc; subst hs; subst hp; subst hb
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 pressure tiers fail mandatory SM39 admission. -/
theorem sm39_gentle_pressure_rejected (c : TuiConfinementConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm39Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm39Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm39Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm39_defective_configs_expose_live_exploits :
    anySm39ExploitReachable defectiveConfigPosture = true ∧
    anySm39ExploitReachable defectiveSupervisorPosture = true ∧
    anySm39ExploitReachable defectiveProbePosture = true ∧
    anySm39ExploitReachable defectiveBootstrapPosture = true ∧
    strictSm39Admitted defectiveGentleTierPosture = false ∧
    strictSm39Admitted hardenedSm39Config = true ∧
    anySm39ExploitReachable hardenedSm39Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive TuiConfinementKey where
  | configConfinement
  | aspSupervisorIsolation
  | probeFileConfinement
  | bootstrapTrustOrder
  | pressureTier
  deriving DecidableEq, Repr

inductive TuiConfinementIssue where
  | tuiConfigSymlinkOrAmbientCredEnv
  | aspSupervisorLeakHangOrSsrf
  | runtimeProbeSymlinkOrDiskFlood
  | bootstrapCwdOrSymlinkHijack
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def tuiConfinementView :
    View TuiConfinementConfig TuiConfinementKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseTuiConfinementContract :
    Contract TuiConfinementConfig TuiConfinementKey Unit TuiConfinementIssue where
  view := tuiConfinementView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesConfigSymlinkCapTimeoutCredEnv then [] else [.rejected path .tuiConfigSymlinkOrAmbientCredEnv]) ++
    (if cfg.enforcesAspSupervisorScrubTimeoutEndpointPath then [] else [.rejected path .aspSupervisorLeakHangOrSsrf]) ++
    (if cfg.enforcesProbeNoFollowByteCap then [] else [.rejected path .runtimeProbeSymlinkOrDiskFlood]) ++
    (if cfg.enforcesBootstrapExeFirstNoSymlink then [] else [.rejected path .bootstrapCwdOrSymlinkHijack])
  validInventory := Or.inl rfl

def marlinTuiConfinementContract :
    Contract TuiConfinementConfig TuiConfinementKey Unit TuiConfinementIssue :=
  refine baseTuiConfinementContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin SM39 contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm39_marlin_contract_refinement_laws
    (cfg : TuiConfinementConfig) (path : List TuiConfinementKey) :
    (diagnose baseTuiConfinementContract cfg path ≠ [] →
      diagnose marlinTuiConfinementContract cfg path ≠ []) ∧
    (diagnose marlinTuiConfinementContract cfg path = [] ↔
      diagnose baseTuiConfinementContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path TuiConfinementIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseTuiConfinementContract _ cfg path,
   refine_accepts_iff baseTuiConfinementContract _ cfg path⟩

inductive TuiConfinementProofKey where
  | configConfinement
  | aspSupervisorIsolation
  | probeFileConfinement
  | bootstrapTrustOrder
  | pressureTier
  | probePollIntervalMs
  deriving DecidableEq

abbrev TuiConfinementProofValue : TuiConfinementProofKey → Type
  | .configConfinement => Bool
  | .aspSupervisorIsolation => Bool
  | .probeFileConfinement => Bool
  | .bootstrapTrustOrder => Bool
  | .pressureTier => AdversarialPressureTier
  | .probePollIntervalMs => Nat

def tuiConfinementObligation :
    LeanPoo.Proof.Obligation TuiConfinementProofKey TuiConfinementProofValue where
  dependencies := [
    .configConfinement,
    .aspSupervisorIsolation,
    .probeFileConfinement,
    .bootstrapTrustOrder,
    .pressureTier
  ]
  holds := fun s =>
    s .configConfinement = true ∧
    s .aspSupervisorIsolation = true ∧
    s .probeFileConfinement = true ∧
    s .bootstrapTrustOrder = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .configConfinement = after .configConfinement :=
      same .configConfinement (by simp)
    have h2 : before .aspSupervisorIsolation = after .aspSupervisorIsolation :=
      same .aspSupervisorIsolation (by simp)
    have h3 : before .probeFileConfinement = after .probeFileConfinement :=
      same .probeFileConfinement (by simp)
    have h4 : before .bootstrapTrustOrder = after .bootstrapTrustOrder :=
      same .bootstrapTrustOrder (by simp)
    have h5 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5] using holds

def baselineTuiConfinementProof :
    LeanPoo.Proof.ProofObject TuiConfinementProofKey TuiConfinementProofValue where
  state := fun
    | .configConfinement => true
    | .aspSupervisorIsolation => true
    | .probeFileConfinement => true
    | .bootstrapTrustOrder => true
    | .pressureTier => .l4HostileAttack
    | .probePollIntervalMs => 250
  obligations := [tuiConfinementObligation]

/-- Theorem 9: Baseline ADV-L4 SM39 proof is certified. -/
theorem sm39_baseline_certified :
    LeanPoo.Proof.Certificate baselineTuiConfinementProof := by
  intro obligation member
  have hEq : obligation = tuiConfinementObligation := by
    simpa [baselineTuiConfinementProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

def probePollIntervalPatch :
    LeanPoo.Proof.Patch TuiConfinementProofKey TuiConfinementProofValue :=
  LeanPoo.Proof.Patch.set .probePollIntervalMs 500

/-- Theorem 10: Tuning probe polling cadence leaves SM39 security obligations untouched. -/
theorem sm39_obligation_untouched_by_probe_cadence_tuning :
    LeanPoo.Proof.unaffected tuiConfinementObligation probePollIntervalPatch := by
  intro key dep touched
  have hKey : key = .probePollIntervalMs := by
    simpa [probePollIntervalPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [tuiConfinementObligation] at dep

/-- Theorem 11: Probe cadence tuning cleanly reuses and closes the LeanPoo certificate. -/
theorem sm39_probe_cadence_tuning_reuses_and_closes_certificate :
    tuiConfinementObligation.holds
      (LeanPoo.Proof.append baselineTuiConfinementProof probePollIntervalPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineTuiConfinementProof probePollIntervalPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineTuiConfinementProof probePollIntervalPatch
      sm39_baseline_certified tuiConfinementObligation
      (by simp [baselineTuiConfinementProof]) sm39_obligation_untouched_by_probe_cadence_tuning
  · apply LeanPoo.Proof.close baselineTuiConfinementProof probePollIntervalPatch
      sm39_baseline_certified
    · intro obligation member affected
      have hEq : obligation = tuiConfinementObligation := by
        simpa [baselineTuiConfinementProof] using member
      subst obligation
      exact False.elim (affected sm39_obligation_untouched_by_probe_cadence_tuning)
    · intro obligation member
      simp [probePollIntervalPatch, LeanPoo.Proof.Patch.set] at member

def configRegressionPatch :
    LeanPoo.Proof.Patch TuiConfinementProofKey TuiConfinementProofValue :=
  LeanPoo.Proof.Patch.set .configConfinement false

def supervisorRegressionPatch :
    LeanPoo.Proof.Patch TuiConfinementProofKey TuiConfinementProofValue :=
  LeanPoo.Proof.Patch.set .aspSupervisorIsolation false

def probeRegressionPatch :
    LeanPoo.Proof.Patch TuiConfinementProofKey TuiConfinementProofValue :=
  LeanPoo.Proof.Patch.set .probeFileConfinement false

def bootstrapRegressionPatch :
    LeanPoo.Proof.Patch TuiConfinementProofKey TuiConfinementProofValue :=
  LeanPoo.Proof.Patch.set .bootstrapTrustOrder false

/-- Theorem 12: Regressing any of the 4 SM39 defenses invalidates LeanPoo certificate reuse. -/
theorem sm39_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected tuiConfinementObligation configRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected tuiConfinementObligation supervisorRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected tuiConfinementObligation probeRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected tuiConfinementObligation bootstrapRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    exact h .configConfinement (by simp [tuiConfinementObligation])
      (by simp [configRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .aspSupervisorIsolation (by simp [tuiConfinementObligation])
      (by simp [supervisorRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .probeFileConfinement (by simp [tuiConfinementObligation])
      (by simp [probeRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .bootstrapTrustOrder (by simp [tuiConfinementObligation])
      (by simp [bootstrapRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.TuiConfigSupervisorProbeConfinement
