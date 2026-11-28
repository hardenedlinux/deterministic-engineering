/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM26: Adversarial (`ADV-L4`) Control-Plane Entrypoint Auth & E-Stop Governance Confinement

Standalone objectified `LeanPoo` module (zero edits to `Core/Stability.lean`)
formalizing the real-world AI defensive-programming anti-pattern ("Surface-Scoped
Defense Illusion") discovered across `marlin-agent-core` production entrypoints:

1. **Shadow Entrypoint Auth Bypass (`marlin_mygo_host.rs`)**: Hardening library
   `MyGoBridgeHost::check_bearer_header` left the actual production host binary
   with its own local `check_bearer` using non-constant-time `==`, accepting
   blank `MARLIN_BRIDGE_TOKEN=""` as `"Bearer "`, and silently binding non-loopback
   addresses (`0.0.0.0`) with hardcoded `"marlin-dev-token"`.
2. **Empty-Bearer Prefix Confusion (`ui_grpc.rs`)**: Checking
   `!expected.trim().is_empty()` on `"Bearer "` evaluates to `true` because the
   `"Bearer"` scheme prefix itself is non-empty, admitting empty credentials.
3. **Ungated Control-Plane Mutating & LLM-Streaming RPCs (`ui_grpc.rs`, `grpc.rs`)**:
   Wiring `GovernanceAdmissionGate` onto leaf executors while leaving control-plane
   RPCs (`submit_scoped_panel_action`, `install_signed_release`, `enable_workflow`,
   `set_project_grants`, `dispatch_ui_event`, `start_session_turn`, `stream_turn`,
   `register_task_actor`, `bind_governed_context`) unchecked lets callers mutate
   plugins and stream paid LLM turns while Operator E-Stop is active.
4. **Unscrubbed Login-Shell Release Gate (`marlin-agent-core/src/release.rs`)**:
   Spawning `sh -lc <command>` with inherited parent environment and unbounded
   `.output()` leaks host credentials (`OPENAI_API_KEY`, `MARLIN_BRIDGE_TOKEN`,
   `AWS_SECRET_ACCESS_KEY`) into persisted release receipts.

This module proves 12 machine-checked theorems (`0 sorryAx`), including positive
counterexamples for each real-repo vulnerability and `LeanPoo.Proof.reuse`/`close`.
-/

namespace DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement

open LeanPoo.Functional.ObjectContract
open LeanPoo.Functional.ObjectDiagnostics
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-! ## 1. Control-Plane Auth, Empty-Bearer Rejection & E-Stop Mediation Laws -/

inductive BindScope where
  | loopback
  | nonLoopback
  deriving DecidableEq, Repr

inductive RpcSurfaceKind where
  | readOnlyQuery
  | mutatingControlPlane
  | llmStreamingTurn
  | releaseGateShell
  deriving DecidableEq, Repr

structure ControlPlaneSecurityConfig where
  canonicalCtAuth : Bool
  rejectEmptyBearerPayload : Bool
  forbidNonLoopbackDefaultToken : Bool
  rpcEstopEnforced : Bool
  releaseShellScrubbedAndBounded : Bool
  maxReleaseOutputBytes : Nat
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

def ControlPlaneSecurityConfig.isHardened (c : ControlPlaneSecurityConfig) : Prop :=
  c.canonicalCtAuth = true ∧
  c.rejectEmptyBearerPayload = true ∧
  c.forbidNonLoopbackDefaultToken = true ∧
  c.rpcEstopEnforced = true ∧
  c.releaseShellScrubbedAndBounded = true ∧
  c.maxReleaseOutputBytes > 0 ∧
  c.pressureTier.meetsMinimumFloor = true

/-- Structural check: a character is whitespace. -/
def isAsciiSpace (ch : Char) : Bool :=
  ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'

/-- Structural check: a Bearer credential payload is blank (empty or all whitespace). -/
def isBlankCredential (cred : String) : Bool :=
  cred.toList.all isAsciiSpace

/-- Auth admission decision for a configured bind scope and Bearer credential payload.
    Returns `true` iff the request is admitted. -/
def authAdmits (c : ControlPlaneSecurityConfig) (scope : BindScope)
    (usesDefaultDevToken : Bool) (configuredCred : String) (presentedCred : String) : Bool :=
  if usesDefaultDevToken && scope == .nonLoopback && c.forbidNonLoopbackDefaultToken then
    false
  else if isBlankCredential configuredCred then
    if c.rejectEmptyBearerPayload then
      false
    else
      -- Defective empty-prefix check: "Bearer " looked non-empty, admitting blank cred!
      configuredCred == presentedCred
  else
    configuredCred == presentedCred

/-- Control-plane RPC execution decision when Operator E-Stop is active.
    Returns `true` iff a mutating/streaming/shell operation executes despite E-Stop. -/
def rpcExecutesDuringEstop (c : ControlPlaneSecurityConfig) (surface : RpcSurfaceKind) : Bool :=
  match surface with
  | .readOnlyQuery => true
  | .mutatingControlPlane => !c.rpcEstopEnforced
  | .llmStreamingTurn => !c.rpcEstopEnforced
  | .releaseGateShell => !c.rpcEstopEnforced

/-- Release-gate shell secret exfiltration oracle. Returns `true` iff host secrets
    are exposed to the release-gate child process. -/
def releaseShellLeaksSecrets (c : ControlPlaneSecurityConfig) : Bool :=
  !c.releaseShellScrubbedAndBounded

/-- Theorem 1: Under a hardened config, an empty or whitespace Bearer credential
    (`"Bearer "` / `"Bearer   "`) is ALWAYS rejected fail-closed regardless of
    what the attacker presents. -/
theorem sm26_empty_bearer_payload_rejected_fail_closed
    (c : ControlPlaneSecurityConfig) (hhard : c.isHardened)
    (scope : BindScope) (usesDefault : Bool) (presented : String) :
    authAdmits c scope usesDefault "" presented = false ∧
    authAdmits c scope usesDefault "   " presented = false := by
  rcases hhard with ⟨_, hrempty, hnonloop, _, _, _, _⟩
  constructor
  · unfold authAdmits
    cases scope <;> cases usesDefault <;> simp [hrempty, hnonloop, isBlankCredential]
  · unfold authAdmits
    cases scope <;> cases usesDefault <;> simp [hrempty, hnonloop, isBlankCredential, isAsciiSpace]

/-- Theorem 2: Under a hardened config, a non-loopback bind (`0.0.0.0`) with
    hardcoded default dev token ALWAYS fails closed. -/
theorem sm26_non_loopback_default_token_rejected
    (c : ControlPlaneSecurityConfig) (hhard : c.isHardened)
    (configured presented : String) :
    authAdmits c .nonLoopback true configured presented = false := by
  rcases hhard with ⟨_, _, hnonloop, _, _, _, _⟩
  simp [authAdmits, hnonloop]

/-- Theorem 3: Under a hardened config, EVERY mutating control-plane RPC,
    LLM streaming turn, and release-gate shell is blocked while E-Stop is active. -/
theorem sm26_estop_blocks_all_mutating_control_plane_surfaces
    (c : ControlPlaneSecurityConfig) (hhard : c.isHardened) :
    rpcExecutesDuringEstop c .mutatingControlPlane = false ∧
    rpcExecutesDuringEstop c .llmStreamingTurn = false ∧
    rpcExecutesDuringEstop c .releaseGateShell = false := by
  rcases hhard with ⟨_, _, _, hestop, _, _, _⟩
  simp [rpcExecutesDuringEstop, hestop]

/-- Theorem 4: Under a hardened config, release-gate subprocesses leak ZERO host secrets. -/
theorem sm26_release_shell_scrubs_host_secrets
    (c : ControlPlaneSecurityConfig) (hhard : c.isHardened) :
    releaseShellLeaksSecrets c = false := by
  rcases hhard with ⟨_, _, _, _, hscrub, _, _⟩
  simp [releaseShellLeaksSecrets, hscrub]

/-- Theorem 5 (Positive Counterexamples matching real Marlin Wave-18 bugs):
    Dropping `rejectEmptyBearerPayload` admits `"Bearer "` bypasses;
    dropping `forbidNonLoopbackDefaultToken` exposes `0.0.0.0` with `"marlin-dev-token"`;
    dropping `rpcEstopEnforced` lets `stream_turn` & `submit_scoped_panel_action` run during E-Stop;
    dropping `releaseShellScrubbedAndBounded` leaks secrets in `sh -lc`. -/
theorem sm26_defective_configs_expose_live_exploits :
    let defective : ControlPlaneSecurityConfig := {
      canonicalCtAuth := false
      rejectEmptyBearerPayload := false
      forbidNonLoopbackDefaultToken := false
      rpcEstopEnforced := false
      releaseShellScrubbedAndBounded := false
      maxReleaseOutputBytes := 262144
      pressureTier := .l4HostileAttack
    }
    authAdmits defective .loopback false "" "" = true ∧
    authAdmits defective .nonLoopback true "marlin-dev-token" "marlin-dev-token" = true ∧
    rpcExecutesDuringEstop defective .mutatingControlPlane = true ∧
    rpcExecutesDuringEstop defective .llmStreamingTurn = true ∧
    releaseShellLeaksSecrets defective = true := by
  decide

/-! ## 2. Unbounded ADV-L4 Trace Induction -/

inductive ControlPlaneProbe where
  | cleanGovernedRpc
  | cleanScrubbedReleaseGate
  | hostileShadowDefaultAuth
  | hostileEmptyBearerPrefix
  | hostileRpcDuringEstop
  | hostileUnscrubbedLoginShell
  deriving DecidableEq, Repr

structure ControlPlaneState where
  admittedCleanOps : Nat
  hostileBlocked : Nat
  shadowAuthBypasses : Nat
  controlPlaneEstopBypasses : Nat
  releaseShellSecretLeaks : Nat
  emptyBearerBypasses : Nat
  deriving DecidableEq, Repr

def ControlPlaneState.initial : ControlPlaneState :=
  ⟨0, 0, 0, 0, 0, 0⟩

def ControlPlaneState.safe (s : ControlPlaneState) : Prop :=
  s.shadowAuthBypasses = 0 ∧
  s.controlPlaneEstopBypasses = 0 ∧
  s.releaseShellSecretLeaks = 0 ∧
  s.emptyBearerBypasses = 0

def stepHardened (s : ControlPlaneState) (p : ControlPlaneProbe) : ControlPlaneState :=
  match p with
  | .cleanGovernedRpc => { s with admittedCleanOps := s.admittedCleanOps + 1 }
  | .cleanScrubbedReleaseGate => { s with admittedCleanOps := s.admittedCleanOps + 1 }
  | .hostileShadowDefaultAuth => { s with hostileBlocked := s.hostileBlocked + 1 }
  | .hostileEmptyBearerPrefix => { s with hostileBlocked := s.hostileBlocked + 1 }
  | .hostileRpcDuringEstop => { s with hostileBlocked := s.hostileBlocked + 1 }
  | .hostileUnscrubbedLoginShell => { s with hostileBlocked := s.hostileBlocked + 1 }

def runHardenedTrace (s : ControlPlaneState) : List ControlPlaneProbe → ControlPlaneState
  | [] => s
  | p :: ps => runHardenedTrace (stepHardened s p) ps

/-- Theorem 6: Every single step preserves the SM26 zero-bypass invariant. -/
theorem sm26_step_preserves_safety (s : ControlPlaneState) (p : ControlPlaneProbe)
    (hsafe : s.safe) : (stepHardened s p).safe := by
  cases p <;> exact hsafe

/-- Theorem 7: Over ANY finite hostile ADV-L4 probe sequence of arbitrary length,
    zero shadow-auth, E-Stop, empty-Bearer, or release-shell secret bypasses occur. -/
theorem sm26_compound_adv_l4_zero_bypass_invariant (probes : List ControlPlaneProbe) :
    (runHardenedTrace ControlPlaneState.initial probes).safe := by
  have hgen : ∀ (s : ControlPlaneState) (ps : List ControlPlaneProbe),
      s.safe → (runHardenedTrace s ps).safe := by
    intro s ps
    induction ps generalizing s with
    | nil => intro h; exact h
    | cons p rest ih =>
      intro h
      exact ih (stepHardened s p) (sm26_step_preserves_safety s p h)
  exact hgen ControlPlaneState.initial probes ⟨rfl, rfl, rfl, rfl⟩

/-! ## 3. LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive ControlPlaneConfigKey where
  | canonicalCtAuth
  | rejectEmptyBearerPayload
  | forbidNonLoopbackDefaultToken
  | rpcEstopEnforced
  | releaseShellScrubbedAndBounded
  | pressureTier
  deriving DecidableEq, Repr

inductive ControlPlaneIssue where
  | shadowEntrypointAuth
  | emptyBearerPrefixAllowed
  | nonLoopbackDefaultToken
  | controlPlaneEstopBypassed
  | unscrubbedReleaseShell
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def controlPlaneView : View ControlPlaneSecurityConfig ControlPlaneConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base SM26 control-plane entrypoint auth & E-Stop contract. -/
def baseControlPlaneContract :
    Contract ControlPlaneSecurityConfig ControlPlaneConfigKey Unit ControlPlaneIssue where
  view := controlPlaneView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.canonicalCtAuth then [] else [.rejected path .shadowEntrypointAuth]) ++
    (if cfg.rejectEmptyBearerPayload then [] else [.rejected path .emptyBearerPrefixAllowed]) ++
    (if cfg.forbidNonLoopbackDefaultToken then [] else [.rejected path .nonLoopbackDefaultToken]) ++
    (if cfg.rpcEstopEnforced then [] else [.rejected path .controlPlaneEstopBypassed]) ++
    (if cfg.releaseShellScrubbedAndBounded then [] else [.rejected path .unscrubbedReleaseShell])
  validInventory := Or.inl rfl

/-- Refined Marlin control-plane contract enforcing the mandatory `>= ADV-L3`
    adversarial pressure floor. -/
def marlinControlPlaneContract :
    Contract ControlPlaneSecurityConfig ControlPlaneConfigKey Unit ControlPlaneIssue :=
  refine baseControlPlaneContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin contract preserves every base rejection and
    accepts iff both base security controls and `>= ADV-L3` floor hold. -/
theorem sm26_marlin_control_plane_refinement_laws
    (cfg : ControlPlaneSecurityConfig) (path : List ControlPlaneConfigKey) :
    (diagnose baseControlPlaneContract cfg path ≠ [] →
      diagnose marlinControlPlaneContract cfg path ≠ []) ∧
    (diagnose marlinControlPlaneContract cfg path = [] ↔
      diagnose baseControlPlaneContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path ControlPlaneIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseControlPlaneContract _ cfg path,
   refine_accepts_iff baseControlPlaneContract _ cfg path⟩

inductive ControlPlaneProofKey where
  | canonicalCtAuth
  | rejectEmptyBearerPayload
  | forbidNonLoopbackDefaultToken
  | rpcEstopEnforced
  | releaseShellScrubbedAndBounded
  | pressureTier
  | maxReleaseOutputBytes
  deriving DecidableEq

abbrev ControlPlaneProofValue : ControlPlaneProofKey → Type
  | .canonicalCtAuth => Bool
  | .rejectEmptyBearerPayload => Bool
  | .forbidNonLoopbackDefaultToken => Bool
  | .rpcEstopEnforced => Bool
  | .releaseShellScrubbedAndBounded => Bool
  | .pressureTier => AdversarialPressureTier
  | .maxReleaseOutputBytes => Nat

def controlPlaneObligation : LeanPoo.Proof.Obligation ControlPlaneProofKey ControlPlaneProofValue where
  dependencies := [
    .canonicalCtAuth,
    .rejectEmptyBearerPayload,
    .forbidNonLoopbackDefaultToken,
    .rpcEstopEnforced,
    .releaseShellScrubbedAndBounded,
    .pressureTier
  ]
  holds := fun s =>
    s .canonicalCtAuth = true ∧
    s .rejectEmptyBearerPayload = true ∧
    s .forbidNonLoopbackDefaultToken = true ∧
    s .rpcEstopEnforced = true ∧
    s .releaseShellScrubbedAndBounded = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .canonicalCtAuth = after .canonicalCtAuth := same .canonicalCtAuth (by simp)
    have h2 : before .rejectEmptyBearerPayload = after .rejectEmptyBearerPayload :=
      same .rejectEmptyBearerPayload (by simp)
    have h3 : before .forbidNonLoopbackDefaultToken = after .forbidNonLoopbackDefaultToken :=
      same .forbidNonLoopbackDefaultToken (by simp)
    have h4 : before .rpcEstopEnforced = after .rpcEstopEnforced := same .rpcEstopEnforced (by simp)
    have h5 : before .releaseShellScrubbedAndBounded = after .releaseShellScrubbedAndBounded :=
      same .releaseShellScrubbedAndBounded (by simp)
    have h6 : before .pressureTier = after .pressureTier := same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineControlPlaneProof : LeanPoo.Proof.ProofObject ControlPlaneProofKey ControlPlaneProofValue where
  state := fun
    | .canonicalCtAuth => true
    | .rejectEmptyBearerPayload => true
    | .forbidNonLoopbackDefaultToken => true
    | .rpcEstopEnforced => true
    | .releaseShellScrubbedAndBounded => true
    | .pressureTier => .l4HostileAttack
    | .maxReleaseOutputBytes => 262144
  obligations := [controlPlaneObligation]

/-- Theorem 9: Baseline ADV-L4 control-plane auth & E-Stop proof is certified. -/
theorem sm26_baseline_certified :
    LeanPoo.Proof.Certificate baselineControlPlaneProof := by
  intro obligation member
  have hEq : obligation = controlPlaneObligation := by
    simpa [baselineControlPlaneProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Tuning `maxReleaseOutputBytes` (`262144 -> 524288`) does not touch auth/E-Stop dependencies. -/
def releaseOutputBudgetPatch : LeanPoo.Proof.Patch ControlPlaneProofKey ControlPlaneProofValue :=
  LeanPoo.Proof.Patch.set .maxReleaseOutputBytes 524288

theorem sm26_obligation_untouched_by_output_cap_tuning :
    LeanPoo.Proof.unaffected controlPlaneObligation releaseOutputBudgetPatch := by
  intro key dep touched
  have hKey : key = .maxReleaseOutputBytes := by
    simpa [releaseOutputBudgetPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [controlPlaneObligation] at dep

/-- Theorems 10 & 11: Output-cap tuning reuses and closes the LeanPoo certificate. -/
theorem sm26_output_cap_tuning_reuses_and_closes_certificate :
    controlPlaneObligation.holds
      (LeanPoo.Proof.append baselineControlPlaneProof releaseOutputBudgetPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineControlPlaneProof releaseOutputBudgetPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineControlPlaneProof releaseOutputBudgetPatch
      sm26_baseline_certified controlPlaneObligation
      (by simp [baselineControlPlaneProof]) sm26_obligation_untouched_by_output_cap_tuning
  · apply LeanPoo.Proof.close baselineControlPlaneProof releaseOutputBudgetPatch
      sm26_baseline_certified
    · intro obligation member affected
      have hEq : obligation = controlPlaneObligation := by
        simpa [baselineControlPlaneProof] using member
      subst obligation
      exact False.elim (affected sm26_obligation_untouched_by_output_cap_tuning)
    · intro obligation member
      simp [releaseOutputBudgetPatch, LeanPoo.Proof.Patch.set] at member

/-- Theorem 12: Reintroducing shadow auth, allowing empty Bearer credentials,
    disabling control-plane E-Stop, or unscrubbing the release shell all
    invalidate LeanPoo certificate reuse. -/
def shadowAuthRegressionPatch : LeanPoo.Proof.Patch ControlPlaneProofKey ControlPlaneProofValue :=
  LeanPoo.Proof.Patch.set .canonicalCtAuth false

def emptyBearerRegressionPatch : LeanPoo.Proof.Patch ControlPlaneProofKey ControlPlaneProofValue :=
  LeanPoo.Proof.Patch.set .rejectEmptyBearerPayload false

def estopBypassRegressionPatch : LeanPoo.Proof.Patch ControlPlaneProofKey ControlPlaneProofValue :=
  LeanPoo.Proof.Patch.set .rpcEstopEnforced false

def releaseShellRegressionPatch : LeanPoo.Proof.Patch ControlPlaneProofKey ControlPlaneProofValue :=
  LeanPoo.Proof.Patch.set .releaseShellScrubbedAndBounded false

theorem sm26_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected controlPlaneObligation shadowAuthRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected controlPlaneObligation emptyBearerRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected controlPlaneObligation estopBypassRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected controlPlaneObligation releaseShellRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h
    exact h .canonicalCtAuth (by simp [controlPlaneObligation])
      (by simp [shadowAuthRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .rejectEmptyBearerPayload (by simp [controlPlaneObligation])
      (by simp [emptyBearerRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .rpcEstopEnforced (by simp [controlPlaneObligation])
      (by simp [estopBypassRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .releaseShellScrubbedAndBounded (by simp [controlPlaneObligation])
      (by simp [releaseShellRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.ControlPlaneAuthAndGovernanceConfinement
