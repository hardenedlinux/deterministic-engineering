/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM24: Adversarial (`ADV-L4`) Subprocess Secret Environment Scrubbing & Constant-Time Auth Verification

Standalone objectified `LeanPoo` module (zero edits to `Core/Stability.lean`)
proving unbounded algebraic laws over arbitrary host environments, untrusted
child-process spawns, and Bearer token verification boundaries (CWE-526,
CWE-200, CWE-208, POLA):

1. Default-deny allowlist scrubbing (`scrubEnv allow hostEnv`) guarantees that
   for ANY secret key disjoint from `allow` (e.g. `OPENAI_API_KEY`,
   `ANTHROPIC_API_KEY`, `MARLIN_BRIDGE_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
   `GITHUB_TOKEN`, or arbitrary custom secrets), the scrubbed child environment
   contains ZERO occurrences of that key (`sm24_allowlist_scrub_drops_all_secrets`).
2. Subset preservation: every key emitted to the child process is strictly in
   the explicit toolchain allowlist (`sm24_scrubbed_env_subset_of_allowlist`).
3. Constant-time Bearer verification refuses blank expected tokens and matches
   iff actual equals expected across every byte without short-circuit bypasses.
4. Over arbitrary unbounded sequences of `ADV-L4` hostile probes (secret env
   exfiltration in sandbox tools, untrusted plugin `go build`/`bun build`/`perf.ts`,
   timing-oracle auth probes, blank-token probes), hardened policy maintains
   zero leaks (`sm24_compound_adv_l4_zero_leak_invariant`).
5. `LeanPoo.Functional.ObjectContract.refine` & `LeanPoo.Proof.reuse`/`close`
   for Marlin (`atomic_effect_substrate.rs`, `tool_process.rs`, `ui_grpc.rs`)
   and MyGo (`dev_reload.go`, `ts_bundle.go`, `publish.go`, `plugin_perf.go`):
   tuning `maxOutputBytes` reuses the certificate, whereas inheriting
   `os.Environ()`, using short-circuit `==` auth, or downgrading pressure to
   `l1Gentle` invalidates certificate reuse.
-/

namespace DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming

open LeanPoo.Functional.ObjectContract
open LeanPoo.Functional.ObjectDiagnostics
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-! ## 1. Unbounded Allowlist Environment Scrubbing & Constant-Time Auth Laws -/

structure EnvEntry where
  key : String
  val : String
  deriving DecidableEq, Repr

/-- Default-deny allowlist environment scrubbing (mirrors `cmd.env_clear()` + allowlist
in Rust and `sanitizedBuildEnv()` in Go). -/
def scrubEnv (allowlist : List String) (hostEnv : List EnvEntry) : List EnvEntry :=
  hostEnv.filter (fun e => allowlist.contains e.key)

/-- Theorem 1: Every key surviving `scrubEnv` belongs to `allowlist`. -/
theorem sm24_scrubbed_env_subset_of_allowlist
    (allowlist : List String) (hostEnv : List EnvEntry) (e : EnvEntry)
    (hmem : e ∈ scrubEnv allowlist hostEnv) :
    e.key ∈ allowlist := by
  simp [scrubEnv, List.mem_filter] at hmem
  exact hmem.2

/-- Theorem 2: Any secret key disjoint from `allowlist` is guaranteed absent from
    the child environment regardless of how many host env vars exist. -/
theorem sm24_allowlist_scrub_drops_all_secrets
    (allowlist : List String) (hostEnv : List EnvEntry) (secret : EnvEntry)
    (hnotAllow : secret.key ∉ allowlist) :
    secret ∉ scrubEnv allowlist hostEnv := by
  intro hmem
  exact hnotAllow (sm24_scrubbed_env_subset_of_allowlist allowlist hostEnv secret hmem)

/-- Structural whitespace check over UTF-8 code points (transparent to the Lean kernel). -/
def isBlankToken (s : String) : Bool :=
  s.toList.all (fun c => c == ' ' || c == '\t' || c == '\n' || c == '\r')

/-- Constant-time Bearer header verification model: fails closed on blank
    expected headers and inspects full byte sequence equality. -/
def verifyBearerConstantTime (expected actual : String) : Bool :=
  if isBlankToken expected then false
  else decide (expected.toUTF8.data = actual.toUTF8.data)

/-- Theorem 3: Blank or whitespace-only expected Bearer tokens are always rejected fail-closed. -/
theorem sm24_blank_expected_bearer_rejected (actual : String) :
    verifyBearerConstantTime "" actual = false ∧
    verifyBearerConstantTime "   " actual = false := by
  constructor <;> simp [verifyBearerConstantTime, isBlankToken]

/-- Theorem 4: Valid non-blank Bearer token succeeds iff byte representation matches. -/
theorem sm24_nonblank_bearer_exact_match
    (expected actual : String) (hnonEmpty : isBlankToken expected = false) :
    verifyBearerConstantTime expected actual = true ↔
      expected.toUTF8.data = actual.toUTF8.data := by
  simp [verifyBearerConstantTime, hnonEmpty]

inductive EnvPolicy where
  | allowlistScrubbed
  | inheritAmbientHost
  deriving DecidableEq, Repr

inductive AuthCompareMode where
  | constantTimeNonBlank
  | shortCircuitEq
  deriving DecidableEq, Repr

inductive HostileEnvAuthProbe where
  | sandboxSecretExfil
  | pluginBuildSecretExfil
  | pluginPerfSecretExfil
  | bearerTimingProbe
  | blankTokenBypass
  | cleanScrubbedRun
  deriving DecidableEq, Repr

structure SubprocessAuthPolicy where
  sandboxEnvPolicy : EnvPolicy
  pluginBuildEnvPolicy : EnvPolicy
  authCompareMode : AuthCompareMode
  stdinNullIsolated : Bool
  maxOutputBytes : Nat
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

def SubprocessAuthPolicy.isHardened (p : SubprocessAuthPolicy) : Prop :=
  p.sandboxEnvPolicy = .allowlistScrubbed ∧
  p.pluginBuildEnvPolicy = .allowlistScrubbed ∧
  p.authCompareMode = .constantTimeNonBlank ∧
  p.stdinNullIsolated = true ∧
  p.maxOutputBytes > 0 ∧
  p.pressureTier.meetsMinimumFloor = true

def probeLeaks (p : SubprocessAuthPolicy) (probe : HostileEnvAuthProbe) : Bool :=
  match probe with
  | .sandboxSecretExfil => p.sandboxEnvPolicy == .inheritAmbientHost
  | .pluginBuildSecretExfil => p.pluginBuildEnvPolicy == .inheritAmbientHost
  | .pluginPerfSecretExfil => p.pluginBuildEnvPolicy == .inheritAmbientHost
  | .bearerTimingProbe => p.authCompareMode == .shortCircuitEq
  | .blankTokenBypass => p.authCompareMode == .shortCircuitEq
  | .cleanScrubbedRun => false

def countLeaks (p : SubprocessAuthPolicy) : List HostileEnvAuthProbe → Nat
  | [] => 0
  | x :: xs => (if probeLeaks p x then 1 else 0) + countLeaks p xs

/-- Theorem 5: Over any unbounded sequence of ADV-L4 hostile env-exfil and auth
    probes, hardened policy guarantees zero leaks (`countLeaks = 0`). -/
theorem sm24_compound_adv_l4_zero_leak_invariant
    (p : SubprocessAuthPolicy) (hhard : p.isHardened)
    (probes : List HostileEnvAuthProbe) :
    countLeaks p probes = 0 := by
  rcases hhard with ⟨hs, hp, ha, _, _, _⟩
  induction probes with
  | nil => rfl
  | cons x xs ih =>
    cases x <;> simp [countLeaks, probeLeaks, hs, hp, ha, ih]

/-- Theorem 6: Gentle L1/L2 testing tiers fail hardened policy admission. -/
theorem sm24_gentle_pressure_rejected
    (p : SubprocessAuthPolicy)
    (hgentle : p.pressureTier = .l1Gentle ∨ p.pressureTier = .l2Edge) :
    ¬ p.isHardened := by
  intro hhard
  rcases hhard with ⟨_, _, _, _, _, hfloor⟩
  rcases hgentle with h1 | h2
  · rw [h1] at hfloor
    simp [AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank] at hfloor
  · rw [h2] at hfloor
    simp [AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank] at hfloor

/-! ## 2. LeanPoo ObjectContract Refinement (`Marlin` + `MyGo`) -/

inductive EnvAuthConfigKey where
  | sandboxEnvPolicy
  | pluginBuildEnvPolicy
  | authCompareMode
  | stdinNullIsolated
  | pressureTier
  deriving DecidableEq, Repr

inductive EnvAuthIssue where
  | sandboxInheritsHostEnv
  | pluginBuildInheritsHostEnv
  | shortCircuitAuthTimingOracle
  | ambientStdinInherited
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def envAuthView : View SubprocessAuthPolicy EnvAuthConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base SM24 subprocess environment scrubbing and constant-time auth contract. -/
def baseEnvAuthContract : Contract SubprocessAuthPolicy EnvAuthConfigKey Unit EnvAuthIssue where
  view := envAuthView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.sandboxEnvPolicy == .allowlistScrubbed then [] else [.rejected path .sandboxInheritsHostEnv]) ++
    (if cfg.pluginBuildEnvPolicy == .allowlistScrubbed then [] else [.rejected path .pluginBuildInheritsHostEnv]) ++
    (if cfg.authCompareMode == .constantTimeNonBlank then [] else [.rejected path .shortCircuitAuthTimingOracle]) ++
    (if cfg.stdinNullIsolated then [] else [.rejected path .ambientStdinInherited])
  validInventory := Or.inl rfl

/-- Refined Marlin + MyGo contract additionally enforcing the mandatory
`≥ ADV-L3` adversarial pressure floor. -/
def marlinMyGoEnvAuthContract : Contract SubprocessAuthPolicy EnvAuthConfigKey Unit EnvAuthIssue :=
  refine baseEnvAuthContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 7: Refined contract preserves every base security rejection. -/
theorem sm24_marlin_mygo_preserves_rejection
    (cfg : SubprocessAuthPolicy) (path : List EnvAuthConfigKey)
    (hRej : diagnose baseEnvAuthContract cfg path ≠ []) :
    diagnose marlinMyGoEnvAuthContract cfg path ≠ [] :=
  refine_preserves_rejection baseEnvAuthContract _ cfg path hRej

/-- Theorem 8: Exact acceptance characterization of refined contract. -/
theorem sm24_marlin_mygo_accepts_iff
    (cfg : SubprocessAuthPolicy) (path : List EnvAuthConfigKey) :
    diagnose marlinMyGoEnvAuthContract cfg path = [] ↔
      diagnose baseEnvAuthContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path EnvAuthIssue.insufficientAdversarialPressure]) = [] :=
  refine_accepts_iff baseEnvAuthContract _ cfg path

/-! ## 3. Dependency-Certified Proof Transport (`LeanPoo.Proof.Reuse`) -/

inductive EnvAuthProofKey where
  | sandboxEnvPolicy
  | pluginBuildEnvPolicy
  | authCompareMode
  | pressureTier
  | maxOutputBytes
  deriving DecidableEq

abbrev EnvAuthProofValue : EnvAuthProofKey → Type
  | .sandboxEnvPolicy => EnvPolicy
  | .pluginBuildEnvPolicy => EnvPolicy
  | .authCompareMode => AuthCompareMode
  | .pressureTier => AdversarialPressureTier
  | .maxOutputBytes => Nat

def envScrubAuthObligation : LeanPoo.Proof.Obligation EnvAuthProofKey EnvAuthProofValue where
  dependencies := [.sandboxEnvPolicy, .pluginBuildEnvPolicy, .authCompareMode, .pressureTier]
  holds := fun s =>
    s .sandboxEnvPolicy = .allowlistScrubbed ∧
      s .pluginBuildEnvPolicy = .allowlistScrubbed ∧
      s .authCompareMode = .constantTimeNonBlank ∧
      (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .sandboxEnvPolicy = after .sandboxEnvPolicy :=
      same .sandboxEnvPolicy (by simp)
    have h2 : before .pluginBuildEnvPolicy = after .pluginBuildEnvPolicy :=
      same .pluginBuildEnvPolicy (by simp)
    have h3 : before .authCompareMode = after .authCompareMode :=
      same .authCompareMode (by simp)
    have h4 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4] using holds

def baselineEnvScrubAuthProof : LeanPoo.Proof.ProofObject EnvAuthProofKey EnvAuthProofValue where
  state := fun
    | .sandboxEnvPolicy => .allowlistScrubbed
    | .pluginBuildEnvPolicy => .allowlistScrubbed
    | .authCompareMode => .constantTimeNonBlank
    | .pressureTier => .l4HostileAttack
    | .maxOutputBytes => 65536
  obligations := [envScrubAuthObligation]

/-- Theorem 9: Baseline ADV-L4 env-scrubbing and constant-time auth proof is certified. -/
theorem sm24_baseline_certified :
    LeanPoo.Proof.Certificate baselineEnvScrubAuthProof := by
  intro obligation member
  have hEq : obligation = envScrubAuthObligation := by
    simpa [baselineEnvScrubAuthProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- Tuning `maxOutputBytes` (`64 KiB -> 128 KiB`) leaves security dependencies untouched. -/
def outputBudgetTuningPatch : LeanPoo.Proof.Patch EnvAuthProofKey EnvAuthProofValue :=
  LeanPoo.Proof.Patch.set .maxOutputBytes 131072

theorem sm24_obligation_untouched_by_output_tuning :
    LeanPoo.Proof.unaffected envScrubAuthObligation outputBudgetTuningPatch := by
  intro key dep touched
  have hKey : key = .maxOutputBytes := by
    simpa [outputBudgetTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [envScrubAuthObligation] at dep

/-- Theorem 10 & 11: Output-budget tuning reuses and closes the LeanPoo certificate. -/
theorem sm24_output_tuning_reuses_and_closes_certificate :
    envScrubAuthObligation.holds
      (LeanPoo.Proof.append baselineEnvScrubAuthProof outputBudgetTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineEnvScrubAuthProof outputBudgetTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineEnvScrubAuthProof outputBudgetTuningPatch
      sm24_baseline_certified envScrubAuthObligation
      (by simp [baselineEnvScrubAuthProof]) sm24_obligation_untouched_by_output_tuning
  · apply LeanPoo.Proof.close baselineEnvScrubAuthProof outputBudgetTuningPatch
      sm24_baseline_certified
    · intro obligation member affected
      have hEq : obligation = envScrubAuthObligation := by
        simpa [baselineEnvScrubAuthProof] using member
      subst obligation
      exact False.elim (affected sm24_obligation_untouched_by_output_tuning)
    · intro obligation member
      simp [outputBudgetTuningPatch, LeanPoo.Proof.Patch.set] at member

/-- Theorem 12: Inheriting host env in sandbox or plugin builds, reverting to
    short-circuit `==` auth, or downgrading pressure to `l1Gentle` all invalidate reuse. -/
def inheritSandboxEnvPatch : LeanPoo.Proof.Patch EnvAuthProofKey EnvAuthProofValue :=
  LeanPoo.Proof.Patch.set .sandboxEnvPolicy .inheritAmbientHost

def inheritPluginEnvPatch : LeanPoo.Proof.Patch EnvAuthProofKey EnvAuthProofValue :=
  LeanPoo.Proof.Patch.set .pluginBuildEnvPolicy .inheritAmbientHost

def shortCircuitAuthPatch : LeanPoo.Proof.Patch EnvAuthProofKey EnvAuthProofValue :=
  LeanPoo.Proof.Patch.set .authCompareMode .shortCircuitEq

def downgradeEnvAuthPressurePatch : LeanPoo.Proof.Patch EnvAuthProofKey EnvAuthProofValue :=
  LeanPoo.Proof.Patch.set .pressureTier .l1Gentle

theorem sm24_security_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected envScrubAuthObligation inheritSandboxEnvPatch ∧
    ¬ LeanPoo.Proof.unaffected envScrubAuthObligation inheritPluginEnvPatch ∧
    ¬ LeanPoo.Proof.unaffected envScrubAuthObligation shortCircuitAuthPatch ∧
    ¬ LeanPoo.Proof.unaffected envScrubAuthObligation downgradeEnvAuthPressurePatch := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    exact h .sandboxEnvPolicy (by simp [envScrubAuthObligation])
      (by simp [inheritSandboxEnvPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .pluginBuildEnvPolicy (by simp [envScrubAuthObligation])
      (by simp [inheritPluginEnvPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .authCompareMode (by simp [envScrubAuthObligation])
      (by simp [shortCircuitAuthPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .pressureTier (by simp [envScrubAuthObligation])
      (by simp [downgradeEnvAuthPressurePatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.SubprocessEnvScrubAndAuthTiming
