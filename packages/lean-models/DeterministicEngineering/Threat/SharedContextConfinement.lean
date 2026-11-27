/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Transport

/-!
# Multi-Party Shared Context Governance, Scope Lattice & Taint Isolation (`Threat.SharedContextConfinement`)

LeanPoo AI-Security refinement sharing `Core.Order` (monotonic ACL-epoch revocation
fencing) and `Core.Transport` (`ObjectContract.refine` + `Patch.frame` + `Proof.reuse`)
with zero duplicated base mathematics.

Orthogonal to Quint (`packages/quint-models/threat/zero-trust/shared-context-governance/SharedContextGovernance.qnt`,
which bounds `aclEpoch <= 4` and checks 4 finite guard-pruned countermodels):
this module proves:
1. **Private-scope isolation**: scope `0` (private) is never readable by a peer principal.
2. **Owner-only confidential scope promotion**: promoting a confidential context entry
   requires BOTH `actorIsOwner = true` AND `explicitDeclassify = true`.
3. **Unbounded ACL-epoch revocation (`Core.Order`)**: advancing the channel ACL epoch
   upon member revocation rejects every peer handle minted at any older epoch `e < aclEpoch`.
4. **Multi-party taint gate**: once shared context is tainted by an untrusted peer,
   privileged agent tool execution is blocked unless `humanGateApproved = true`.
5. **Two-step LeanPoo `ObjectContract.refine` & one-line `Proof.reuse` (`Core.Transport`)**:
   AI-safe audit-batch tuning transports the certificate cleanly, while disabling the
   multi-party taint gate invalidates proof reuse.
-/

namespace DeterministicEngineering.Threat.SharedContextConfinement

open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## 1. Unbounded Scope, Declassification, ACL-Epoch & Taint Laws -/

/-- Whether a peer read of a context entry is admitted. -/
def peerContextReadAdmitted
    (entryScope : Nat) (peerInChannel : Bool) (currentAclEpoch handleEpoch : Nat) : Bool :=
  match entryScope with
  | 0 => false
  | _ + 1 =>
    match peerInChannel with
    | false => false
    | true => admitEpoch currentAclEpoch handleEpoch

/-- Whether promoting a confidential private entry to shared scope is admitted. -/
def scopePromotionAdmitted
    (actorIsOwner entryConfidential explicitDeclassify : Bool) : Bool :=
  match actorIsOwner with
  | false => false
  | true =>
    match entryConfidential with
    | false => true
    | true => explicitDeclassify

/-- Whether an AI agent tool call driven by shared context is admitted. -/
def sharedContextToolExecAdmitted (channelTainted humanGateApproved : Bool) : Bool :=
  match channelTainted with
  | false => true
  | true => humanGateApproved

/-- Theorem 1: Private context (`scope = 0`) is never readable by any peer principal. -/
theorem privateScope_never_readable_by_peer
    (peerInChannel : Bool) (aclEp handleEp : Nat) :
    peerContextReadAdmitted 0 peerInChannel aclEp handleEp = false :=
  rfl

/-- Theorem 2: Confidential scope promotion fails closed unless performed by the owner
    with explicit declassification. -/
theorem confidentialScopePromotion_requires_owner_and_declass
    (owner declass : Bool) :
    scopePromotionAdmitted false true declass = false ∧
    scopePromotionAdmitted owner true false = false ∧
    scopePromotionAdmitted true true true = true := by
  refine ⟨rfl, ?_, rfl⟩
  cases owner <;> rfl

/-- Theorem 3: Advancing the channel ACL epoch unconditionally rejects every peer handle
    minted at a strictly older epoch (reusing `Core.Order.advanceEpoch_rejects_strictly_older`). -/
theorem revokedAclEpoch_rejects_all_staleHandles
    (scopePlusOne : Nat) (peerInChannel : Bool) (aclEpoch nextEpoch staleHandleEpoch : Nat)
    (hStale : staleHandleEpoch < aclEpoch) :
    peerContextReadAdmitted (scopePlusOne + 1) peerInChannel
      (advanceEpoch aclEpoch nextEpoch) staleHandleEpoch = false := by
  unfold peerContextReadAdmitted
  cases peerInChannel
  · rfl
  · exact advanceEpoch_rejects_strictly_older aclEpoch nextEpoch staleHandleEpoch hStale

/-- Theorem 4: Tainted multi-party shared context unconditionally blocks agent tool
    execution unless a human gate explicitly approves. -/
theorem taintedSharedChannel_blocks_toolExec_without_humanGate :
    sharedContextToolExecAdmitted true false = false ∧
    sharedContextToolExecAdmitted true true = true :=
  ⟨rfl, rfl⟩

/-! ## 2. Two-Step LeanPoo `ObjectContract.refine` (reusing `Core.Transport`) -/

structure SharedContextConfig where
  enforcesPrivateScopeIsolation : Bool
  enforcesAclEpochRevocation : Bool
  enforcesMultiPartyTaintGate : Bool
  deriving DecidableEq, Repr

inductive SharedContextConfigKey where
  | enforcesPrivateScopeIsolation
  | enforcesAclEpochRevocation
  | enforcesMultiPartyTaintGate
  deriving DecidableEq, Repr

inductive SharedContextIssue where
  | missingPrivateScopeIsolation
  | missingAclEpochRevocation
  | missingMultiPartyTaintGate
  deriving DecidableEq, Repr

private def sharedContextView : View SharedContextConfig SharedContextConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseSharedContextContract :
    Contract SharedContextConfig SharedContextConfigKey Unit SharedContextIssue where
  view := sharedContextView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.enforcesPrivateScopeIsolation then [] else [.rejected path .missingPrivateScopeIsolation]
  validInventory := Or.inl rfl

def aclEpochExt (cfg : SharedContextConfig) (path : List SharedContextConfigKey) :
    List (Issue SharedContextConfigKey SharedContextIssue) :=
  if cfg.enforcesAclEpochRevocation then [] else [.rejected path .missingAclEpochRevocation]

def taintGateExt (cfg : SharedContextConfig) (path : List SharedContextConfigKey) :
    List (Issue SharedContextConfigKey SharedContextIssue) :=
  if cfg.enforcesMultiPartyTaintGate then [] else [.rejected path .missingMultiPartyTaintGate]

def sharedContextContract :
    Contract SharedContextConfig SharedContextConfigKey Unit SharedContextIssue :=
  refine (refine baseSharedContextContract aclEpochExt) taintGateExt

/-- Theorem 5: Two-step shared-context contract refinement monotonically preserves all base rejections. -/
theorem sharedContextContract_preserves_rejection
    (cfg : SharedContextConfig) (path : List SharedContextConfigKey)
    (hRej : diagnose baseSharedContextContract cfg path ≠ []) :
    diagnose sharedContextContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseSharedContextContract aclEpochExt taintGateExt cfg path hRej

/-! ## 3. AI-SE Proof Transport via `Core.Transport` -/

inductive SharedContextProofKey where
  | privateScopeChecked
  | aclEpochChecked
  | multiPartyTaintGateChecked
  | auditBatchSize
  deriving DecidableEq

abbrev SharedContextProofValue : SharedContextProofKey → Type
  | .privateScopeChecked => Bool
  | .aclEpochChecked => Bool
  | .multiPartyTaintGateChecked => Bool
  | .auditBatchSize => Nat

def sharedContextObligation :
    LeanPoo.Proof.Obligation SharedContextProofKey SharedContextProofValue where
  dependencies := [.privateScopeChecked, .aclEpochChecked, .multiPartyTaintGateChecked]
  holds := fun s =>
    s .privateScopeChecked = true ∧
    s .aclEpochChecked = true ∧
    s .multiPartyTaintGateChecked = true
  stable := by
    intro before after same holds
    exact ⟨(same .privateScopeChecked (by simp)).symm.trans holds.1,
           (same .aclEpochChecked (by simp)).symm.trans holds.2.1,
           (same .multiPartyTaintGateChecked (by simp)).symm.trans holds.2.2⟩

def baselineSharedContext :
    LeanPoo.Proof.ProofObject SharedContextProofKey SharedContextProofValue where
  state := fun
    | .privateScopeChecked => true
    | .aclEpochChecked => true
    | .multiPartyTaintGateChecked => true
    | .auditBatchSize => 16
  obligations := [sharedContextObligation]

theorem baselineSharedContextCertified : LeanPoo.Proof.Certificate baselineSharedContext := by
  intro ob hMem
  have hEq : ob = sharedContextObligation := by simpa [baselineSharedContext] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl⟩

/-- Theorem 6: AI-safe audit-batch tuning transports the shared-context certificate in 1 line. -/
theorem sharedContextAuditTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineSharedContext
        (LeanPoo.Proof.Patch.set .auditBatchSize 64)) :=
  close_single_set_untouched baselineSharedContext sharedContextObligation
    .auditBatchSize 64 rfl baselineSharedContextCertified (by simp [sharedContextObligation])

/-- Theorem 7: Negative control — AI regression disabling the multi-party taint gate invalidates reuse. -/
theorem disableTaintGate_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected sharedContextObligation
        (LeanPoo.Proof.Patch.set .multiPartyTaintGateChecked false) :=
  set_dependency_invalidates_unaffected sharedContextObligation
    .multiPartyTaintGateChecked false (by simp [sharedContextObligation])

end DeterministicEngineering.Threat.SharedContextConfinement
