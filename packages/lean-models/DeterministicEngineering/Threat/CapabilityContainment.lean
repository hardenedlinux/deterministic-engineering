/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Containment
import DeterministicEngineering.Core.Order
import DeterministicEngineering.Core.Transport

/-!
# Capability Delegation Containment & Monotonic Attenuation (`Threat.CapabilityContainment`)

First **Threat-domain** LeanPoo refinement (10.154 Layer B2), sharing the EXACT SAME
mathematical cores (`Core.Containment`, `Core.Order`, `Core.Transport`) already refined
by Engineering subjects (`Engineering.ProcessTree`, `Engineering.LeaseFencing`) with
ZERO duplicated base math.

Orthogonal to Quint (`packages/quint-models/threat/identity/delegated-agent-authz/DelegatedAgentAuthz.qnt`,
which explicitly bounds RFC 8693 OBO delegation to depth 1 and explores 4 finite
guard-pruning countermodels): this module proves:
1. **Arbitrary-depth (`∀ d, k`) multi-hop capability revocation closure**: revoking the
   root human session container terminates every delegated agent token at any nesting depth,
   even if an intermediate delegating agent has already crashed (`Core.Containment`).
2. **Arbitrary-depth monotonic scope attenuation**: across any multi-hop delegation chain
   where every hop attenuates `child.scope ≤ parent.scope`, no descendant can ever amplify
   beyond the root human scope.
3. **Unbounded epoch revocation currency (`Core.Order`)**: advancing the human session epoch
   unconditionally rejects every delegated token minted at any strictly older epoch `e < current`.
4. **Two-step LeanPoo `ObjectContract.refine` & one-line `Proof.reuse` (`Core.Transport`)**.
-/

namespace DeterministicEngineering.Threat.CapabilityContainment

open DeterministicEngineering.Core.Containment
open DeterministicEngineering.Core.Order
open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## 1. Arbitrary-Depth Multi-Hop Delegation Revocation Closure (reusing `Core.Containment`) -/

/-- Revoking the root human session container kills every delegated agent token at any depth. -/
theorem revokeRootSession_kills_all_delegated_hops
    (rootSessionId : Nat) (delegationTree : OwnershipTree Nat)
    (hBound : containerClosed rootSessionId delegationTree) :
    allDead (killContainer rootSessionId delegationTree) :=
  killContainer_allDead_of_closed rootSessionId delegationTree hBound

/-- Crash-safe multi-hop revocation: even if the root or intermediate agent process crashes
before cascading userspace revocation, firing session-container revocation still leaves zero
surviving delegated capabilities at any depth. -/
theorem crashSafe_sessionRevocation_zero_zombie_tokens
    (rootSessionId : Nat) (delegationTree : OwnershipTree Nat)
    (hBound : containerClosed rootSessionId delegationTree) :
    allDead (killContainer rootSessionId (sigkillRootOnly delegationTree)) :=
  crashSafe_killContainer_after_root_sigkill rootSessionId delegationTree hBound

/-! ## 2. Arbitrary-Depth Monotonic Scope Attenuation -/

/-- Arbitrary-depth multi-hop OBO capability delegation tree carrying numeric scope levels. -/
inductive DelegationScopeTree where
  | grant (actorId : Nat) (scopeLevel : Nat) (subgrants : List DelegationScopeTree)

/-- Extract the scope level at the root of a delegation subtree. -/
def rootScope : DelegationScopeTree → Nat
  | .grant _ s _ => s

/-- Every delegation hop enforces RFC 8693 monotonic attenuation: `childScope ≤ parentScope`. -/
def hopAttenuated : DelegationScopeTree → Prop
  | .grant _ scope children =>
      ∀ child ∈ children, rootScope child ≤ scope ∧ hopAttenuated child

/-- Every actor at every depth of the delegation tree is bounded by `rootMax`. -/
def allScopesWithin (rootMax : Nat) : DelegationScopeTree → Prop
  | .grant _ scope children =>
      scope ≤ rootMax ∧ ∀ child ∈ children, allScopesWithin rootMax child

/-- Structural induction: local per-hop attenuation guarantees global zero scope amplification
across arbitrarily deep nested `act` delegation chains. -/
theorem multiHop_attenuation_prevents_amplification
    (rootMax : Nat) : ∀ t : DelegationScopeTree,
    rootScope t ≤ rootMax →
    hopAttenuated t →
    allScopesWithin rootMax t
  | .grant _ scope children, hRootLe, hAtten => by
      unfold hopAttenuated at hAtten
      unfold allScopesWithin
      refine ⟨hRootLe, ?_⟩
      intro child hMem
      rcases hAtten child hMem with ⟨hChildLe, hChildAtten⟩
      exact multiHop_attenuation_prevents_amplification rootMax child
        (Nat.le_trans hChildLe hRootLe) hChildAtten

/-! ## 3. Unbounded Epoch Revocation Currency (reusing `Core.Order`) -/

/-- Once the human authority epoch advances, any delegated token from a strictly older epoch
is unconditionally rejected as a zombie delegation. -/
theorem revokedEpoch_rejects_zombie_delegation
    (humanEpoch nextEpoch delegatedEpoch : Nat)
    (hStale : delegatedEpoch < humanEpoch) :
    admitEpoch (advanceEpoch humanEpoch nextEpoch) delegatedEpoch = false :=
  advanceEpoch_rejects_strictly_older humanEpoch nextEpoch delegatedEpoch hStale

/-! ## 4. Two-Step LeanPoo `ObjectContract.refine` (reusing `Core.Transport`) -/

structure DelegatedAuthzConfig where
  enforcesActorProvenance : Bool
  enforcesScopeAttenuation : Bool
  enforcesRevocationEpoch : Bool
  deriving DecidableEq, Repr

inductive AuthzConfigKey where
  | enforcesActorProvenance
  | enforcesScopeAttenuation
  | enforcesRevocationEpoch
  deriving DecidableEq, Repr

inductive AuthzIssue where
  | missingActorProvenance
  | missingScopeAttenuation
  | missingRevocationEpoch
  deriving DecidableEq, Repr

private def authzView : View DelegatedAuthzConfig AuthzConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseAuthzContract : Contract DelegatedAuthzConfig AuthzConfigKey Unit AuthzIssue where
  view := authzView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    if cfg.enforcesActorProvenance then [] else [.rejected path .missingActorProvenance]
  validInventory := Or.inl rfl

def scopeAttenuationExt (cfg : DelegatedAuthzConfig) (path : List AuthzConfigKey) :
    List (Issue AuthzConfigKey AuthzIssue) :=
  if cfg.enforcesScopeAttenuation then [] else [.rejected path .missingScopeAttenuation]

def revocationEpochExt (cfg : DelegatedAuthzConfig) (path : List AuthzConfigKey) :
    List (Issue AuthzConfigKey AuthzIssue) :=
  if cfg.enforcesRevocationEpoch then [] else [.rejected path .missingRevocationEpoch]

def oboDelegationContract : Contract DelegatedAuthzConfig AuthzConfigKey Unit AuthzIssue :=
  refine (refine baseAuthzContract scopeAttenuationExt) revocationEpochExt

/-- Two-step monotonic refinement preserves all inherited provenance rejections. -/
theorem oboDelegationContract_preserves_rejection
    (cfg : DelegatedAuthzConfig) (path : List AuthzConfigKey)
    (hRej : diagnose baseAuthzContract cfg path ≠ []) :
    diagnose oboDelegationContract cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseAuthzContract scopeAttenuationExt revocationEpochExt cfg path hRej

/-! ## 5. One-Line Proof Transport via `Core.Transport` -/

inductive AuthzProofKey where
  | revocationEpochChecked
  | scopeAttenuationChecked
  | auditLogBatchSize
  deriving DecidableEq

abbrev AuthzProofValue : AuthzProofKey → Type
  | .revocationEpochChecked => Bool
  | .scopeAttenuationChecked => Bool
  | .auditLogBatchSize => Nat

def delegationSafetyObligation : LeanPoo.Proof.Obligation AuthzProofKey AuthzProofValue where
  dependencies := [.revocationEpochChecked, .scopeAttenuationChecked]
  holds := fun s => s .revocationEpochChecked = true ∧ s .scopeAttenuationChecked = true
  stable := by
    intro before after same holds
    exact ⟨(same .revocationEpochChecked (by simp)).symm.trans holds.1,
           (same .scopeAttenuationChecked (by simp)).symm.trans holds.2⟩

def baselineOboAuthz : LeanPoo.Proof.ProofObject AuthzProofKey AuthzProofValue where
  state := fun
    | .revocationEpochChecked => true
    | .scopeAttenuationChecked => true
    | .auditLogBatchSize => 32
  obligations := [delegationSafetyObligation]

theorem baselineOboAuthzCertified : LeanPoo.Proof.Certificate baselineOboAuthz := by
  intro ob hMem
  have hEq : ob = delegationSafetyObligation := by simpa [baselineOboAuthz] using hMem
  subst ob
  exact ⟨rfl, rfl⟩

/-- Tuning audit log batch size transports the OBO delegation safety certificate in 1 line. -/
theorem auditBatchTunedCertified :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineOboAuthz
        (LeanPoo.Proof.Patch.set .auditLogBatchSize 128)) :=
  close_single_set_untouched baselineOboAuthz delegationSafetyObligation
    .auditLogBatchSize 128 rfl baselineOboAuthzCertified (by simp [delegationSafetyObligation])

/-- Negative control: disabling revocation epoch checking invalidates proof reuse. -/
theorem disableRevocationEpoch_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected delegationSafetyObligation
        (LeanPoo.Proof.Patch.set .revocationEpochChecked false) :=
  set_dependency_invalidates_unaffected delegationSafetyObligation
    .revocationEpochChecked false (by simp [delegationSafetyObligation])

end DeterministicEngineering.Threat.CapabilityContainment
