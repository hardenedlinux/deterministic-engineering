/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.MetaGovernance
import DeterministicEngineering.Core.Transport

/-!
# Self-Verifying Meta-Governance Soundness (`Engineering.MetaGovernanceSoundness`)

Refines `Core.MetaGovernance` and `Core.Transport` to certify the repository's own
multi-method verification kernel (`library/verification-flow/ascent-rules.ss` `MR01`–`MR06`,
`ER01`–`ER04`, `IR01`–`IR06`, and Ed25519 pinned-key attestation) as a first-class
zero-glue SysML v2 verification subject (`engineering.governance.meta-governance-soundness`).
-/

namespace DeterministicEngineering.Engineering.MetaGovernanceSoundness

open DeterministicEngineering.Core.MetaGovernance
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-- Under the live Fleet policy (`requireSignedCache = True`), any reused cache entry
is guaranteed passing, input-clean, toolchain-clean, and cryptographically attested. -/
theorem fleetSignedCache_reusable_is_authentic {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) (s : Step)
    (hPolicy : sys.requireSignedCache)
    (hReuse : Reusable sys s) :
    sys.hasPassingCache s ∧ ¬ inputDirty sys s ∧ ¬ toolchainDirty sys s ∧ sys.attested s := by
  have h := reusable_sound sys s hReuse
  exact ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.2 hPolicy⟩

/-- Tampering or toolchain-drifting an upstream Quint/CBMC node prevents reuse of any
downstream consumer at arbitrary DAG depth. -/
theorem upstreamTamper_blocks_arbitrary_downstream_reuse {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {u v : Step}
    (hPath : DagPath sys.dagEdge u v)
    (hPolicy : sys.requireSignedCache)
    (hTampered : ¬ sys.attested u) :
    ¬ Reusable sys v :=
  upstream_forged_cache_prevents_downstream_reuse sys hPath hPolicy hTampered

/-- Constructive zero-axiom certification that any two steps scheduled in the same
Fun-Flow parallel wave (e.g. `quintTarget || leanPooTarget || sourceContractTarget`)
are causally independent and conflict-free across arbitrary DAG depths. -/
theorem parallelWave_concurrent_execution_race_free {Step : Type}
    {edge conflict : Step → Step → Prop} {waveOf : Step → Nat}
    (hValid : ValidWaveSchedule edge conflict waveOf)
    {a b : Step} (hSameWave : waveOf a = waveOf b) :
    ¬ NonEmptyDagPath edge a b ∧ ¬ NonEmptyDagPath edge b a ∧ ¬ conflict a b :=
  same_wave_implies_independent hValid hSameWave

/-- Constructive zero-axiom certification of pinned-key 2-level Fleet Merkle integrity. -/
theorem fleetAttestation_rejects_tamper_and_rogue_key {PubKey Payload Digest Sig : Type}
    (m : FleetMerkleModel PubKey Payload Digest Sig)
    {pk pk' : PubKey} {p p' : Payload} {sig : Sig}
    (hValid : m.verify pk p sig) :
    (p ≠ p' → ¬ m.verify pk p' sig) ∧
    (pk ≠ pk' → ¬ m.verify pk' p sig) ∧
    (m.digestOf p ≠ m.digestOf p' → ¬ m.verify pk p' sig) :=
  fleet_merkle_pinned_key_tamper_resistant m hValid

/-- Constructive zero-axiom certification of `IR07` strict cross-method premise-chain
revalidation across mixed Quint->Oracle (`IR03`) and Oracle/CBMC->LeanPoo (`IR07`) chains. -/
theorem strictPremisePolicy_blocks_stale_downstream_proofs {Step Key Digest Toolchain : Type}
    (sys : ReuseSystem Step Key Digest Toolchain) {u v : Step}
    (hStrict : sys.strictPremiseRecheck)
    (hPath : DagPath (fun a b => sys.dagEdge a b ∨ sys.premiseSupportEdge a b) u v)
    (hReuseV : Reusable sys v) :
    Reusable sys u :=
  ir07_reusable_implies_premise_supporters_reusable sys hStrict hPath hReuseV

/-! ## Two-Step LeanPoo `ObjectContract.refine` (via `Core.Transport`) -/

structure MetaGovConfig where
  mrPreflightEnabled : Bool
  erAdmissionEnabled : Bool
  ed25519SignedCacheEnabled : Bool
  deriving DecidableEq, Repr

inductive MetaGovKey where
  | mrPreflightEnabled
  | erAdmissionEnabled
  | ed25519SignedCacheEnabled
  deriving DecidableEq, Repr

inductive MetaGovIssue where
  | missingMrGate
  | missingErGate
  | unsignedCacheAllowed
  deriving DecidableEq, Repr

private def metaGovView : View MetaGovConfig MetaGovKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseMetaGovContract : Contract MetaGovConfig MetaGovKey Unit MetaGovIssue where
  view := metaGovView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.mrPreflightEnabled then [] else [.rejected path .missingMrGate]
  validInventory := Or.inl rfl

def erAdmissionExt (cfg : MetaGovConfig) (path : List MetaGovKey) :
    List (Issue MetaGovKey MetaGovIssue) :=
  if cfg.erAdmissionEnabled then [] else [.rejected path .missingErGate]

def signedCacheExt (cfg : MetaGovConfig) (path : List MetaGovKey) :
    List (Issue MetaGovKey MetaGovIssue) :=
  if cfg.ed25519SignedCacheEnabled then [] else [.rejected path .unsignedCacheAllowed]

def fullMetaGovContract : Contract MetaGovConfig MetaGovKey Unit MetaGovIssue :=
  refine (refine baseMetaGovContract erAdmissionExt) signedCacheExt

/-- One-line 2-step monotonic refinement proof reusing `Core.Transport`. -/
theorem fullMetaGovContract_preserves_rejection
    (cfg : MetaGovConfig) (path : List MetaGovKey)
    (hRej : diagnose baseMetaGovContract cfg path ≠ []) :
    diagnose fullMetaGovContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseMetaGovContract erAdmissionExt signedCacheExt cfg path hRej

/-! ## One-Line Proof Transport via `Core.Transport` -/

inductive MetaProofKey where
  | signedCacheRequired
  | reportIndentSpaces
  deriving DecidableEq

abbrev MetaProofValue : MetaProofKey → Type
  | .signedCacheRequired => Bool
  | .reportIndentSpaces => Nat

def signedCacheObligation : LeanPoo.Proof.Obligation MetaProofKey MetaProofValue where
  dependencies := [.signedCacheRequired]
  holds := fun s => s .signedCacheRequired = true
  stable := by
    intro before after same holds
    exact (same .signedCacheRequired (by simp)).symm.trans holds

def baselineMetaGov : LeanPoo.Proof.ProofObject MetaProofKey MetaProofValue where
  state := fun
    | .signedCacheRequired => true
    | .reportIndentSpaces => 2
  obligations := [signedCacheObligation]

theorem baselineMetaGovCertified : LeanPoo.Proof.Certificate baselineMetaGov := by
  intro ob hMem
  have hEq : ob = signedCacheObligation := by simpa [baselineMetaGov] using hMem
  subst ob
  rfl

/-- One-line proof transport across non-semantic report formatting change. -/
theorem reportFormatTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineMetaGov
        (LeanPoo.Proof.Patch.set .reportIndentSpaces 4)) :=
  close_single_set_untouched baselineMetaGov signedCacheObligation
    .reportIndentSpaces 4 rfl baselineMetaGovCertified (by simp [signedCacheObligation])

/-- Negative control: disabling `.signedCacheRequired` invalidates proof reuse. -/
theorem disableSignedCache_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected signedCacheObligation
        (LeanPoo.Proof.Patch.set .signedCacheRequired false) :=
  set_dependency_invalidates_unaffected signedCacheObligation
    .signedCacheRequired false (by simp [signedCacheObligation])

end DeterministicEngineering.Engineering.MetaGovernanceSoundness
