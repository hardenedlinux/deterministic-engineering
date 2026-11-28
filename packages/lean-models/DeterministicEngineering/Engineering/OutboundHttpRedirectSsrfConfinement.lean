/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM23: Adversarial (`ADV-L4`) Outbound HTTP Redirect, SSRF & Credential Confinement

Standalone objectified `LeanPoo` module (zero edits to `Core/Stability.lean`)
composing directly with `AdversarialPressureTier` from
`Engineering.SandboxSymlinkArchiveConfinement`:

1. Fail-closed `noRedirect` blocks arbitrary-hop 3xx redirect chains to loopback,
   cloud metadata (`169.254.169.254`), or cross-origin exfiltration targets.
2. Remote Bearer credentials require `https`; cleartext `http` is permitted only
   on explicit loopback targets (matching canonical owner `weaver-llm`).
3. Catalog `DownloadURL` confinement blocks HTTPS->HTTP scheme downgrade and
   cross-origin / private-IP SSRF escapes.
4. URL userinfo (`@`) and control-byte rejection defeats authority spoofing.
5. `lstat` symlink-free file serving blocks static HTTP directory symlink leaks.
6. Explicit `LeanPoo.Functional.ObjectContract.refine` & `LeanPoo.Proof.reuse`/`close`
   proving timeout tuning preserves certificates while re-enabling redirects,
   bypassing the canonical owner (`weaver-llm`), or downgrading pressure to
   `l1Gentle` invalidates certificate reuse.
-/

namespace DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement

open LeanPoo.Functional.ObjectContract
open LeanPoo.Functional.ObjectDiagnostics
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-! ## 1. Unbounded Adversarial (`ADV-L4`) HTTP Confinement Laws -/

inductive RedirectPolicy where
  | noRedirect
  | followUnchecked
  deriving DecidableEq, Repr

inductive HostileHttpProbe where
  | redirect3xx (hops : Nat) (hpos : hops > 0)
  | remoteCleartextBearer
  | downloadUrlDowngradeOrSsrf
  | userinfoOrControlSmuggle
  | symlinkStaticServe
  | cleanPinnedHttps
  deriving Repr

structure OutboundHttpPolicy where
  redirectPolicy : RedirectPolicy
  requireHttpsRemoteAuth : Bool
  confineDownloadOrigin : Bool
  rejectUserinfoAndControls : Bool
  rejectSymlinkServe : Bool
  delegatesToCanonicalOwner : Bool
  timeoutSeconds : Nat
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

def OutboundHttpPolicy.isHardened (p : OutboundHttpPolicy) : Prop :=
  p.redirectPolicy = .noRedirect ∧
  p.requireHttpsRemoteAuth = true ∧
  p.confineDownloadOrigin = true ∧
  p.rejectUserinfoAndControls = true ∧
  p.rejectSymlinkServe = true ∧
  p.delegatesToCanonicalOwner = true ∧
  p.timeoutSeconds > 0 ∧
  p.pressureTier.meetsMinimumFloor = true

def probeAdmitted (p : OutboundHttpPolicy) (probe : HostileHttpProbe) : Bool :=
  match probe with
  | .redirect3xx _ _ => p.redirectPolicy == .followUnchecked
  | .remoteCleartextBearer => !p.requireHttpsRemoteAuth
  | .downloadUrlDowngradeOrSsrf => !p.confineDownloadOrigin
  | .userinfoOrControlSmuggle => !p.rejectUserinfoAndControls
  | .symlinkStaticServe => !p.rejectSymlinkServe
  | .cleanPinnedHttps => true

def probeIsEscape (p : OutboundHttpPolicy) (probe : HostileHttpProbe) : Bool :=
  match probe with
  | .cleanPinnedHttps => false
  | _ => probeAdmitted p probe

def countEscapes (p : OutboundHttpPolicy) : List HostileHttpProbe → Nat
  | [] => 0
  | x :: xs => (if probeIsEscape p x then 1 else 0) + countEscapes p xs

def countHostileProbes : List HostileHttpProbe → Nat
  | [] => 0
  | .cleanPinnedHttps :: xs => countHostileProbes xs
  | _ :: xs => 1 + countHostileProbes xs

def countBlocked (p : OutboundHttpPolicy) : List HostileHttpProbe → Nat
  | [] => 0
  | x :: xs => (if !probeAdmitted p x then 1 else 0) + countBlocked p xs

/-- Theorem 1: No-redirect policy blocks arbitrary-hop 3xx redirect SSRF chains. -/
theorem sm23_no_redirect_blocks_all_3xx_ssrf
    (p : OutboundHttpPolicy) (hops : Nat) (hpos : hops > 0)
    (hhard : p.isHardened) :
    probeAdmitted p (.redirect3xx hops hpos) = false := by
  rcases hhard with ⟨hredir, _, _, _, _, _, _, _⟩
  simp [probeAdmitted, hredir]

/-- Theorem 2: Remote cleartext Bearer credential emission is strictly rejected. -/
theorem sm23_remote_cleartext_credential_leak_impossible
    (p : OutboundHttpPolicy) (hhard : p.isHardened) :
    probeAdmitted p .remoteCleartextBearer = false := by
  rcases hhard with ⟨_, htls, _, _, _, _, _, _⟩
  simp [probeAdmitted, htls]

/-- Theorem 3: DownloadURL confinement blocks HTTPS->HTTP downgrade and SSRF. -/
theorem sm23_download_url_origin_confinement_blocks_ssrf_and_downgrade
    (p : OutboundHttpPolicy) (hhard : p.isHardened) :
    probeAdmitted p .downloadUrlDowngradeOrSsrf = false := by
  rcases hhard with ⟨_, _, hssrf, _, _, _, _, _⟩
  simp [probeAdmitted, hssrf]

/-- Theorem 4: URL userinfo (`@`) and control-byte rejection blocks authority spoofing. -/
theorem sm23_userinfo_and_control_char_rejection_prevents_authority_spoof
    (p : OutboundHttpPolicy) (hhard : p.isHardened) :
    probeAdmitted p .userinfoOrControlSmuggle = false := by
  rcases hhard with ⟨_, _, _, huser, _, _, _, _⟩
  simp [probeAdmitted, huser]

/-- Theorem 5: Lstat symlink refusal prevents static HTTP directory symlink leaks. -/
theorem sm23_lstat_serve_policy_blocks_symlink_file_disclosure
    (p : OutboundHttpPolicy) (hhard : p.isHardened) :
    probeAdmitted p .symlinkStaticServe = false := by
  rcases hhard with ⟨_, _, _, _, hsym, _, _, _⟩
  simp [probeAdmitted, hsym]

/-- Theorem 6: Over any unbounded sequence of ADV-L4 hostile probes, hardened
    policy achieves zero escapes (`countEscapes = 0`). -/
theorem sm23_compound_adv_l4_zero_escape_invariant
    (p : OutboundHttpPolicy) (hhard : p.isHardened) (probes : List HostileHttpProbe) :
    countEscapes p probes = 0 := by
  rcases hhard with ⟨hredir, htls, hssrf, huser, hsym, _, _, _⟩
  induction probes with
  | nil => rfl
  | cons x xs ih =>
    cases x <;> simp [countEscapes, probeIsEscape, probeAdmitted, hredir, htls, hssrf, huser, hsym, ih]

/-- Theorem 7: Every hostile probe in an unbounded trace is explicitly blocked. -/
theorem sm23_compound_adv_l4_blocks_every_hostile_probe
    (p : OutboundHttpPolicy) (hhard : p.isHardened) (probes : List HostileHttpProbe) :
    countBlocked p probes = countHostileProbes probes := by
  rcases hhard with ⟨hredir, htls, hssrf, huser, hsym, _, _, _⟩
  induction probes with
  | nil => rfl
  | cons x xs ih =>
    cases x <;> simp [countBlocked, countHostileProbes, probeAdmitted, hredir, htls, hssrf, huser, hsym, ih]

/-- Theorem 8: Gentle L1/L2 testing tiers fail hardened policy admission. -/
theorem sm23_gentle_tier_rejected_by_outbound_http_gate
    (p : OutboundHttpPolicy)
    (hgentle : p.pressureTier = .l1Gentle ∨ p.pressureTier = .l2Edge) :
    ¬ p.isHardened := by
  intro hhard
  rcases hhard with ⟨_, _, _, _, _, _, _, hfloor⟩
  rcases hgentle with h1 | h2
  · rw [h1] at hfloor
    simp [AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank] at hfloor
  · rw [h2] at hfloor
    simp [AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank] at hfloor

/-! ## 2. LeanPoo ObjectContract Refinement (`Weaver` + `MyGo`) -/

inductive HttpConfigKey where
  | redirectPolicy
  | requireHttpsRemoteAuth
  | confineDownloadOrigin
  | rejectSymlinkServe
  | delegatesToCanonicalOwner
  | pressureTier
  deriving DecidableEq, Repr

inductive HttpIssue where
  | defaultRedirectSsrf
  | cleartextRemoteCredentialLeak
  | unconfinedDownloadUrlSsrf
  | statFollowsSymlinkServe
  | bypassedCanonicalTransportOwner
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def httpPolicyView : View OutboundHttpPolicy HttpConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

/-- Base SM23 outbound HTTP confinement contract. -/
def baseHttpConfinementContract : Contract OutboundHttpPolicy HttpConfigKey Unit HttpIssue where
  view := httpPolicyView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.redirectPolicy == .noRedirect then [] else [.rejected path .defaultRedirectSsrf]) ++
    (if cfg.requireHttpsRemoteAuth then [] else [.rejected path .cleartextRemoteCredentialLeak]) ++
    (if cfg.confineDownloadOrigin then [] else [.rejected path .unconfinedDownloadUrlSsrf]) ++
    (if cfg.rejectSymlinkServe then [] else [.rejected path .statFollowsSymlinkServe])
  validInventory := Or.inl rfl

/-- Refined contract for Weaver LLM (`weaver-llm`) & MyGo marketplace HTTP boundaries:
additionally enforces canonical transport-owner delegation (no raw `reqwest` bypass)
and the mandatory `≥ ADV-L3` adversarial pressure floor. -/
def weaverAndMyGoHttpContract : Contract OutboundHttpPolicy HttpConfigKey Unit HttpIssue :=
  refine baseHttpConfinementContract fun cfg path =>
    (if cfg.delegatesToCanonicalOwner then [] else [.rejected path .bypassedCanonicalTransportOwner]) ++
    (if cfg.pressureTier.meetsMinimumFloor then [] else [.rejected path .insufficientAdversarialPressure])

/-- Theorem 9: Refined Weaver/MyGo contract preserves all base rejections. -/
theorem sm23_weaver_mygo_preserves_rejection
    (cfg : OutboundHttpPolicy) (path : List HttpConfigKey)
    (hRej : diagnose baseHttpConfinementContract cfg path ≠ []) :
    diagnose weaverAndMyGoHttpContract cfg path ≠ [] :=
  refine_preserves_rejection baseHttpConfinementContract _ cfg path hRej

/-- Theorem 10: Exact acceptance characterization for refined Weaver/MyGo HTTP contract. -/
theorem sm23_weaver_mygo_accepts_iff
    (cfg : OutboundHttpPolicy) (path : List HttpConfigKey) :
    diagnose weaverAndMyGoHttpContract cfg path = [] ↔
      diagnose baseHttpConfinementContract cfg path = [] ∧
      ((if cfg.delegatesToCanonicalOwner then [] else [Issue.rejected path HttpIssue.bypassedCanonicalTransportOwner]) ++
       (if cfg.pressureTier.meetsMinimumFloor then [] else [Issue.rejected path HttpIssue.insufficientAdversarialPressure])) = [] :=
  refine_accepts_iff baseHttpConfinementContract _ cfg path

/-! ## 3. Dependency-Certified Proof Transport (`LeanPoo.Proof.Reuse`) -/

inductive HttpProofKey where
  | redirectPolicy
  | delegatesToCanonicalOwner
  | pressureTier
  | timeoutSeconds
  deriving DecidableEq

abbrev HttpProofValue : HttpProofKey → Type
  | .redirectPolicy => RedirectPolicy
  | .delegatesToCanonicalOwner => Bool
  | .pressureTier => AdversarialPressureTier
  | .timeoutSeconds => Nat

def outboundHttpObligation : LeanPoo.Proof.Obligation HttpProofKey HttpProofValue where
  dependencies := [.redirectPolicy, .delegatesToCanonicalOwner, .pressureTier]
  holds := fun s =>
    s .redirectPolicy = .noRedirect ∧
      s .delegatesToCanonicalOwner = true ∧
      (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .redirectPolicy = after .redirectPolicy :=
      same .redirectPolicy (by simp)
    have h2 : before .delegatesToCanonicalOwner = after .delegatesToCanonicalOwner :=
      same .delegatesToCanonicalOwner (by simp)
    have h3 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3] using holds

def baselineWeaverHttpProof : LeanPoo.Proof.ProofObject HttpProofKey HttpProofValue where
  state := fun
    | .redirectPolicy => .noRedirect
    | .delegatesToCanonicalOwner => true
    | .pressureTier => .l4HostileAttack
    | .timeoutSeconds => 15
  obligations := [outboundHttpObligation]

theorem baselineWeaverHttpCertified :
    LeanPoo.Proof.Certificate baselineWeaverHttpProof := by
  intro obligation member
  have hEq : obligation = outboundHttpObligation := by
    simpa [baselineWeaverHttpProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl⟩

/-- Tuning HTTP timeout (`15s -> 30s`) does not touch security dependencies and reuses
the certificate via `LeanPoo.Proof.reuse` / `LeanPoo.Proof.close`. -/
def timeoutTuningPatch : LeanPoo.Proof.Patch HttpProofKey HttpProofValue :=
  LeanPoo.Proof.Patch.set .timeoutSeconds 30

theorem httpObligationUntouchedByTimeoutTuning :
    LeanPoo.Proof.unaffected outboundHttpObligation timeoutTuningPatch := by
  intro key dep touched
  have hKey : key = .timeoutSeconds := by
    simpa [timeoutTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [outboundHttpObligation] at dep

/-- Theorem 11: Timeout tuning transports and closes the certified LeanPoo proof. -/
theorem sm23_timeout_tuning_certified :
    outboundHttpObligation.holds
      (LeanPoo.Proof.append baselineWeaverHttpProof timeoutTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineWeaverHttpProof timeoutTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineWeaverHttpProof timeoutTuningPatch
      baselineWeaverHttpCertified outboundHttpObligation
      (by simp [baselineWeaverHttpProof]) httpObligationUntouchedByTimeoutTuning
  · apply LeanPoo.Proof.close baselineWeaverHttpProof timeoutTuningPatch
      baselineWeaverHttpCertified
    · intro obligation member affected
      have hEq : obligation = outboundHttpObligation := by
        simpa [baselineWeaverHttpProof] using member
      subst obligation
      exact False.elim (affected httpObligationUntouchedByTimeoutTuning)
    · intro obligation member
      simp [timeoutTuningPatch, LeanPoo.Proof.Patch.set] at member

/-- Theorem 12: Re-enabling unchecked redirects, bypassing canonical owner (`weaver-llm`),
or downgrading pressure tier to `l1Gentle` invalidates certificate reuse. -/
def enableRedirectsPatch : LeanPoo.Proof.Patch HttpProofKey HttpProofValue :=
  LeanPoo.Proof.Patch.set .redirectPolicy .followUnchecked

def bypassCanonicalOwnerPatch : LeanPoo.Proof.Patch HttpProofKey HttpProofValue :=
  LeanPoo.Proof.Patch.set .delegatesToCanonicalOwner false

def downgradeHttpPressurePatch : LeanPoo.Proof.Patch HttpProofKey HttpProofValue :=
  LeanPoo.Proof.Patch.set .pressureTier .l1Gentle

theorem sm23_security_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected outboundHttpObligation enableRedirectsPatch ∧
    ¬ LeanPoo.Proof.unaffected outboundHttpObligation bypassCanonicalOwnerPatch ∧
    ¬ LeanPoo.Proof.unaffected outboundHttpObligation downgradeHttpPressurePatch := by
  refine ⟨?_, ?_, ?_⟩
  · intro h
    exact h .redirectPolicy (by simp [outboundHttpObligation])
      (by simp [enableRedirectsPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .delegatesToCanonicalOwner (by simp [outboundHttpObligation])
      (by simp [bypassCanonicalOwnerPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .pressureTier (by simp [outboundHttpObligation])
      (by simp [downgradeHttpPressurePatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.OutboundHttpRedirectSsrfConfinement
