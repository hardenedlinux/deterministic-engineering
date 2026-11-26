/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Core.Transport

/-!
# LeanPoo Unbounded HITL Cold-Hibernation, R1 Hot Policy Co-Evolution & R5 AEAD Tenant Isolation (`B1`, `B2`, `B5`, `R1`, `R5`)

Built strictly on **Lean 4 core + `LeanPoo`** (zero Mathlib, zero Cedar dependency).
Completes the **64-theorem `LeanPoo` formal library** across 5 engineering modules,
achieving 100% unbounded machine-checked coverage across `B1`–`B10c`, `R1`–`R5`, and
the `cedar-poo-spec` Dual-Sovereignty Bridge.

Machine-checked theorems (12 total, zero `sorry`, zero custom axioms):
1. `sod_forbids_requester_self_approval` — requester can never appear in valid `k`-of-`N` quorum
2. `duplicate_approver_rejected_in_quorum` — duplicate principal cannot inflate quorum cardinality
3. `baseline_drift_invalidates_hitl_resume` — any receipt with drifted `baseCut` blocks resume
4. `intersecting_policy_drift_invalidates_approval` — intersecting policy change fails closed (`B5 × R1`)
5. `disjoint_policy_upgrade_preserves_approval` — non-empty disjoint upgrade preserves approval (`R1`)
6. `veto_tombstone_blocks_nagging_retry_forever` — monotonic veto persistence blocks nagging retries
7. `cross_tenant_aead_read_always_refused` — distinct tenant keys can never decrypt another partition (`B2/R5`)
8. `ciphertext_transplant_across_row_or_tenant_refused` — AAD mismatch blocks cross-row/tenant transplant
9. `unrevoked_m3_or_veto_or_freeze_blocks_resume` — unrevoked M3 lease, veto, or freeze blocks resume
10. `hitlCoevolutionContract_preserves_rejection` — 2-step `LeanPoo` refinement (+ `cedar-poo-spec` Governance)
11. `briefRenderLimitTuning_preserves_hitl_certificate` — 1-line `Core.Transport` proof reuse
12. `disablingVetoPersistence_invalidates_reuse` — 1-line `Core.Transport` negative control
-/

namespace DeterministicEngineering.Engineering.HitlAndCoevolution

open DeterministicEngineering.Core.Transport
open LeanPoo.Functional.ObjectContract

/-! ## Section 1: Unbounded HITL Cold-Hibernation, `k`-of-`N` SoD Quorum & `R1` Policy Co-Evolution (`B1`, `B5`, `R1`) -/

section HitlAndCoevolution

structure ApprovalReceipt (Principal Hash : Type) where
  approver : Principal
  boundBaseCut : Hash
  boundPolicyEpoch : Hash
  expiresAtEpoch : Nat
  deriving DecidableEq, Repr

structure SuspensionAnchor (Principal Scope Hash Target : Type) where
  requester : Principal
  target : Target
  proposalHash : Hash
  baseCut : Hash
  policyEpoch : Hash
  affectedScopes : List Scope
  requiredApprovals : Nat
  m3LeaseRevokedAtSuspend : Bool
  deriving DecidableEq, Repr

structure LiveWorld (Scope Hash : Type) where
  currentBaseCut : Hash
  currentPolicyEpoch : Hash
  policyChangedScopes : List Scope
  currentEpoch : Nat
  emergencyFreezeActive : Bool
  deriving DecidableEq, Repr

def isNodup [DecidableEq α] : List α → Bool
  | [] => true
  | x :: xs => !(decide (x ∈ xs)) && isNodup xs

/-- Valid `k`-of-`N` human quorum:
    1. At least `k` approvals (`approvers.length ≥ k`),
    2. All approvers strictly distinct (`isNodup approvers`),
    3. Separation of Duties (`SoD`): requester NEVER approves their own proposal. -/
def validQuorumApprovers [DecidableEq Principal]
    (requester : Principal) (approvers : List Principal) (k : Nat) : Bool :=
  decide (approvers.length ≥ k) &&
  isNodup approvers &&
  approvers.all (fun a => decide (a ≠ requester))

/-- `R1` bounded negative-dependency policy co-evolution check:
    - Exact policy hash match -> compatible.
    - Different policy hash + unknown/empty changed scopes -> fail closed (`false`).
    - Different policy hash + changed scopes disjoint from proposal `affectedScopes` -> compatible (`true`). -/
def policyDriftCompatible [DecidableEq Scope] [DecidableEq Hash]
    (boundPolicy : Hash) (affectedScopes : List Scope)
    (worldPolicy : Hash) (changedScopes : List Scope) : Bool :=
  if boundPolicy = worldPolicy then
    true
  else if changedScopes.isEmpty then
    false
  else
    !(changedScopes.any (fun s => decide (s ∈ affectedScopes)))

/-- Complete HITL resume admissibility gate matching `DurableHitlApprovalEngine.evaluateAndResume`. -/
def hitlCanResume [DecidableEq Principal] [DecidableEq Scope] [DecidableEq Hash]
    (anchor : SuspensionAnchor Principal Scope Hash Target)
    (receipts : List (ApprovalReceipt Principal Hash))
    (vetoed : Bool)
    (world : LiveWorld Scope Hash) : Bool :=
  anchor.m3LeaseRevokedAtSuspend &&
  !vetoed &&
  !world.emergencyFreezeActive &&
  validQuorumApprovers anchor.requester (receipts.map (·.approver)) anchor.requiredApprovals &&
  receipts.all (fun r =>
    decide (world.currentEpoch ≤ r.expiresAtEpoch) &&
    decide (r.boundBaseCut = world.currentBaseCut) &&
    policyDriftCompatible r.boundPolicyEpoch anchor.affectedScopes
      world.currentPolicyEpoch world.policyChangedScopes)

/-- Anti-nagging human veto persistence gate:
    blocks any previously vetoed proposal hash, any retry lacking explicit fix evidence,
    or any retry exceeding the bounded re-submission budget. -/
def vetoTombstoneAllowsResubmission [DecidableEq Hash]
    (vetoedHashes : List Hash)
    (candidateHash : Hash)
    (hasFixEvidence : Bool)
    (attemptsUsed maxAttempts : Nat) : Bool :=
  !(decide (candidateHash ∈ vetoedHashes)) &&
  hasFixEvidence &&
  decide (attemptsUsed ≤ maxAttempts)

/-- **Theorem 1 (Unbounded `SoD` Self-Approval Refusal)**: For ANY requester `r`,
    ANY quorum threshold `k`, and ANY approver list containing `r`, `validQuorumApprovers`
    unconditionally returns `false`. -/
theorem sod_forbids_requester_self_approval [DecidableEq Principal]
    (requester : Principal) (approvers : List Principal) (k : Nat)
    (hSelf : requester ∈ approvers) :
    validQuorumApprovers requester approvers k = false := by
  have hall : approvers.all (fun a => decide (a ≠ requester)) = false := by
    cases h : approvers.all (fun a => decide (a ≠ requester)) with
    | false => rfl
    | true =>
      have hneq := List.all_eq_true.mp h requester hSelf
      have hne : requester ≠ requester := of_decide_eq_true hneq
      exact False.elim (hne rfl)
  simp only [validQuorumApprovers, hall, Bool.and_false]

/-- **Theorem 2 (Unbounded Duplicate-Approver Quorum Stuffing Refusal)**: If a principal `a`
    appears more than once (`a ∈ rest` in `a :: rest`), `isNodup` and `validQuorumApprovers`
    both return `false` regardless of list length. -/
theorem duplicate_approver_rejected_in_quorum [DecidableEq Principal]
    (requester a : Principal) (rest : List Principal) (k : Nat)
    (hDup : a ∈ rest) :
    validQuorumApprovers requester (a :: rest) k = false := by
  have hnodup : isNodup (a :: rest) = false := by
    simp [isNodup, hDup]
  simp [validQuorumApprovers, hnodup]

/-- **Theorem 3 (Unbounded `B5` Baseline-Drift Invalidation)**: If ANY approval receipt
    in an arbitrary-sized quorum was signed against a stale `baseCut ≠ world.currentBaseCut`,
    `hitlCanResume` unconditionally returns `false`. -/
theorem baseline_drift_invalidates_hitl_resume [DecidableEq Principal] [DecidableEq Scope] [DecidableEq Hash]
    (anchor : SuspensionAnchor Principal Scope Hash Target)
    (receipts : List (ApprovalReceipt Principal Hash))
    (vetoed : Bool)
    (world : LiveWorld Scope Hash)
    (r : ApprovalReceipt Principal Hash)
    (hrMem : r ∈ receipts)
    (hDrift : r.boundBaseCut ≠ world.currentBaseCut) :
    hitlCanResume anchor receipts vetoed world = false := by
  have hall : receipts.all (fun x =>
      decide (world.currentEpoch ≤ x.expiresAtEpoch) &&
      decide (x.boundBaseCut = world.currentBaseCut) &&
      policyDriftCompatible x.boundPolicyEpoch anchor.affectedScopes
        world.currentPolicyEpoch world.policyChangedScopes) = false := by
    cases h : receipts.all (fun x =>
        decide (world.currentEpoch ≤ x.expiresAtEpoch) &&
        decide (x.boundBaseCut = world.currentBaseCut) &&
        policyDriftCompatible x.boundPolicyEpoch anchor.affectedScopes
          world.currentPolicyEpoch world.policyChangedScopes) with
    | false => rfl
    | true =>
      have hr := List.all_eq_true.mp h r hrMem
      have hbase : decide (r.boundBaseCut = world.currentBaseCut) = true := by
        cases h1 : decide (world.currentEpoch ≤ r.expiresAtEpoch) <;>
        cases h2 : decide (r.boundBaseCut = world.currentBaseCut) <;>
        simp [h1, h2] at hr ⊢
      exact False.elim (hDrift (of_decide_eq_true hbase))
  simp [hitlCanResume, hall]

/-- **Theorem 4 (Unbounded `B5 × R1` Intersecting Policy-Drift Refusal)**: Whenever the
    active policy epoch changed (`boundPolicy ≠ worldPolicy`) AND at least one scope
    `s` belongs to both `affectedScopes` and `changedScopes`, `policyDriftCompatible`
    fails closed (`false`). -/
theorem intersecting_policy_drift_invalidates_approval [DecidableEq Scope] [DecidableEq Hash]
    (boundPolicy worldPolicy : Hash)
    (affectedScopes changedScopes : List Scope)
    (s : Scope)
    (hPolicyChanged : boundPolicy ≠ worldPolicy)
    (hsAffected : s ∈ affectedScopes)
    (hsChanged : s ∈ changedScopes) :
    policyDriftCompatible boundPolicy affectedScopes worldPolicy changedScopes = false := by
  have hNonEmpty : changedScopes.isEmpty = false := by
    cases changedScopes with
    | nil => exact nomatch hsChanged
    | cons _ _ => rfl
  have hany : changedScopes.any (fun x => decide (x ∈ affectedScopes)) = true :=
    List.any_eq_true.mpr ⟨s, hsChanged, decide_eq_true hsAffected⟩
  simp [policyDriftCompatible, hPolicyChanged, hNonEmpty, hany]

/-- **Theorem 5 (Unbounded `R1` Disjoint Hot Policy Co-Evolution Preservation)**: Whenever
    a policy upgrade declares non-empty `changedScopes` completely disjoint from the
    proposal's `affectedScopes`, `policyDriftCompatible` preserves prior approval (`true`). -/
theorem disjoint_policy_upgrade_preserves_approval [DecidableEq Scope] [DecidableEq Hash]
    (boundPolicy worldPolicy : Hash)
    (affectedScopes changedScopes : List Scope)
    (hNonEmpty : changedScopes ≠ [])
    (hDisjoint : ∀ s ∈ changedScopes, s ∉ affectedScopes) :
    policyDriftCompatible boundPolicy affectedScopes worldPolicy changedScopes = true := by
  by_cases hEq : boundPolicy = worldPolicy
  · simp [policyDriftCompatible, hEq]
  · have hEmptyFalse : changedScopes.isEmpty = false := by
      cases changedScopes with
      | nil => exact False.elim (hNonEmpty rfl)
      | cons _ _ => rfl
    have hanyFalse : changedScopes.any (fun x => decide (x ∈ affectedScopes)) = false := by
      cases h : changedScopes.any (fun x => decide (x ∈ affectedScopes)) with
      | false => rfl
      | true =>
        obtain ⟨s, hsC, hsA⟩ := List.any_eq_true.mp h
        exact False.elim (hDisjoint s hsC (of_decide_eq_true hsA))
    simp [policyDriftCompatible, hEq, hEmptyFalse, hanyFalse]

/-- **Theorem 6 (Unbounded Monotonic Anti-Nagging Veto Persistence)**: Once `candidateHash`
    is recorded in `vetoedHashes`, appending arbitrary future vetoes `futureVetoes` NEVER
    re-admits `candidateHash` (monotonic permanent veto tombstone). -/
theorem veto_tombstone_blocks_nagging_retry_forever [DecidableEq Hash]
    (vetoedHashes futureVetoes : List Hash)
    (candidateHash : Hash)
    (hasFixEvidence : Bool)
    (attemptsUsed maxAttempts : Nat)
    (hVetoed : candidateHash ∈ vetoedHashes) :
    vetoTombstoneAllowsResubmission (vetoedHashes ++ futureVetoes)
      candidateHash hasFixEvidence attemptsUsed maxAttempts = false := by
  have hMem : candidateHash ∈ vetoedHashes ++ futureVetoes :=
    List.mem_append_left futureVetoes hVetoed
  simp [vetoTombstoneAllowsResubmission, hMem]

end HitlAndCoevolution

/-! ## Section 2: Unbounded Multi-Tenant AEAD Partition Isolation & Cold Hibernation Fence (`B2`, `R5`, `R3`) -/

section MultiTenantAeadIsolation

structure AeadKey (Tenant : Type) where
  keyTenant : Tenant
  keyMaterialId : Nat
  deriving DecidableEq, Repr

structure EncryptedRow (Tenant RowKey : Type) where
  rowTenant : Tenant
  rowKey : RowKey
  aadTenant : Tenant
  aadRowKey : RowKey
  keyMaterialId : Nat
  tagAuthentic : Bool
  deriving DecidableEq, Repr

/-- Cryptographic AES-256-GCM partition & AAD admissibility predicate matching
    `CapabilityPartitionedAeadStore.getEncryptedRow`. -/
def aeadDecryptAdmitted [DecidableEq Tenant] [DecidableEq RowKey]
    (callerKey : AeadKey Tenant)
    (targetTenant : Tenant)
    (targetRowKey : RowKey)
    (row : EncryptedRow Tenant RowKey) : Bool :=
  decide (callerKey.keyTenant = targetTenant) &&
  decide (row.rowTenant = targetTenant) &&
  decide (row.aadTenant = targetTenant) &&
  decide (row.aadRowKey = targetRowKey) &&
  decide (callerKey.keyMaterialId = row.keyMaterialId) &&
  row.tagAuthentic

/-- **Theorem 7 (Unbounded `B2`/`R5` Cross-Tenant AEAD Isolation)**: For ANY two distinct
    tenants `callerKey.keyTenant ≠ targetTenant`, decryption is unconditionally refused. -/
theorem cross_tenant_aead_read_always_refused [DecidableEq Tenant] [DecidableEq RowKey]
    (callerKey : AeadKey Tenant)
    (targetTenant : Tenant)
    (targetRowKey : RowKey)
    (row : EncryptedRow Tenant RowKey)
    (hDiffTenant : callerKey.keyTenant ≠ targetTenant) :
    aeadDecryptAdmitted callerKey targetTenant targetRowKey row = false := by
  simp [aeadDecryptAdmitted, hDiffTenant]

/-- **Theorem 8 (Unbounded `R5` Cross-Row / Cross-Tenant Ciphertext Transplant Refusal)**:
    Any ciphertext row transplanted to a different `(targetTenant, targetRowKey)` than its
    authenticated AAD `(row.aadTenant, row.aadRowKey)` is unconditionally refused even if
    the caller holds a valid key for the destination partition. -/
theorem ciphertext_transplant_across_row_or_tenant_refused [DecidableEq Tenant] [DecidableEq RowKey]
    (callerKey : AeadKey Tenant)
    (targetTenant : Tenant)
    (targetRowKey : RowKey)
    (row : EncryptedRow Tenant RowKey)
    (hTransplant : row.aadTenant ≠ targetTenant ∨ row.aadRowKey ≠ targetRowKey) :
    aeadDecryptAdmitted callerKey targetTenant targetRowKey row = false := by
  cases hTransplant with
  | inl hTenant => simp [aeadDecryptAdmitted, hTenant]
  | inr hRow => simp [aeadDecryptAdmitted, hRow]

/-- **Theorem 9 (Cold Hibernation `R3` Lease Revocation, Veto & Emergency Freeze Fence)**:
    If an anchor did not revoke its live `M3` lease on suspend, OR a human veto exists,
    OR an emergency freeze is active, `hitlCanResume` unconditionally returns `false`. -/
theorem unrevoked_m3_or_veto_or_freeze_blocks_resume [DecidableEq Principal] [DecidableEq Scope] [DecidableEq Hash]
    (anchor : SuspensionAnchor Principal Scope Hash Target)
    (receipts : List (ApprovalReceipt Principal Hash))
    (vetoed : Bool)
    (world : LiveWorld Scope Hash)
    (hBlock : anchor.m3LeaseRevokedAtSuspend = false ∨ vetoed = true ∨ world.emergencyFreezeActive = true) :
    hitlCanResume anchor receipts vetoed world = false := by
  rcases hBlock with hLease | hVeto | hFreeze
  · simp [hitlCanResume, hLease]
  · simp [hitlCanResume, hVeto]
  · simp [hitlCanResume, hFreeze]

end MultiTenantAeadIsolation

/-! ## Section 3: LeanPoo Two-Step Refinement (`B5 -> B2/R5 -> cedar-poo-spec Governance`) & Proof Transport -/

section LeanPooHitlCoevolutionContract

structure HitlCoevolutionConfig where
  sodQuorumEnforced : Bool
  vetoPersistenceEnforced : Bool
  r1PolicyDriftChecked : Bool
  aeadTenantIsolationEnforced : Bool
  hostGovernancePolicyBound : Bool
  deriving DecidableEq, Repr

inductive HitlCoevolutionKey where
  | sodQuorumEnforced
  | vetoPersistenceEnforced
  | r1PolicyDriftChecked
  | aeadTenantIsolationEnforced
  | hostGovernancePolicyBound
  deriving DecidableEq, Repr

inductive HitlCoevolutionIssue where
  | sodOrQuorumViolation
  | vetoPersistenceDisabled
  | unsafePolicyDriftAdmitted
  | crossTenantAeadLeak
  | hostGovernancePolicyBypassed
  deriving DecidableEq, Repr

private def hitlCoevolutionView : View HitlCoevolutionConfig HitlCoevolutionKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseHitlContract :
    Contract HitlCoevolutionConfig HitlCoevolutionKey Unit HitlCoevolutionIssue where
  view := hitlCoevolutionView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.sodQuorumEnforced then [] else [.rejected path .sodOrQuorumViolation]) ++
    (if cfg.vetoPersistenceEnforced then [] else [.rejected path .vetoPersistenceDisabled]) ++
    (if cfg.r1PolicyDriftChecked then [] else [.rejected path .unsafePolicyDriftAdmitted])
  validInventory := Or.inl rfl

def aeadTenantIsolationExt (cfg : HitlCoevolutionConfig) (path : List HitlCoevolutionKey) :
    List (Issue HitlCoevolutionKey HitlCoevolutionIssue) :=
  if cfg.aeadTenantIsolationEnforced then [] else [.rejected path .crossTenantAeadLeak]

/-- **Theorem 10 (`LeanPoo` Two-Step Refinement + `cedar-poo-spec` Governance Host)**:
    Layering `B2`/`R5` AEAD tenant isolation AND ANY downstream `cedar-poo-spec` governance
    extension `hostGovExt` (e.g. `CedarPooSpec.Governance.{Veto,SeparationOfDuties,ScopedApproval}`)
    onto `baseHitlContract` monotonically preserves every library HITL/co-evolution rejection. -/
theorem hitlCoevolutionContract_preserves_rejection
    (hostGovExt : HitlCoevolutionConfig → List HitlCoevolutionKey →
      List (Issue HitlCoevolutionKey HitlCoevolutionIssue))
    (cfg : HitlCoevolutionConfig) (path : List HitlCoevolutionKey)
    (hRej : diagnose baseHitlContract cfg path ≠ []) :
    diagnose (refine (refine baseHitlContract aeadTenantIsolationExt) hostGovExt) cfg path ≠ [] :=
  refine_two_step_preserves_rejection baseHitlContract aeadTenantIsolationExt hostGovExt cfg path hRej

inductive HitlProofKey where
  | sodQuorumEnforced
  | vetoPersistenceEnforced
  | r1PolicyDriftChecked
  | aeadTenantIsolationEnforced
  | briefSummaryMaxBytes
  deriving DecidableEq

abbrev HitlProofValue : HitlProofKey → Type
  | .sodQuorumEnforced => Bool
  | .vetoPersistenceEnforced => Bool
  | .r1PolicyDriftChecked => Bool
  | .aeadTenantIsolationEnforced => Bool
  | .briefSummaryMaxBytes => Nat

def hitlCoevolutionObligation : LeanPoo.Proof.Obligation HitlProofKey HitlProofValue where
  dependencies :=
    [.sodQuorumEnforced, .vetoPersistenceEnforced, .r1PolicyDriftChecked, .aeadTenantIsolationEnforced]
  holds := fun s =>
    s .sodQuorumEnforced = true ∧
    s .vetoPersistenceEnforced = true ∧
    s .r1PolicyDriftChecked = true ∧
    s .aeadTenantIsolationEnforced = true
  stable := by
    intro before after same ⟨h1, h2, h3, h4⟩
    exact ⟨(same .sodQuorumEnforced (by simp)).symm.trans h1,
           (same .vetoPersistenceEnforced (by simp)).symm.trans h2,
           (same .r1PolicyDriftChecked (by simp)).symm.trans h3,
           (same .aeadTenantIsolationEnforced (by simp)).symm.trans h4⟩

def baselineHitlSystem : LeanPoo.Proof.ProofObject HitlProofKey HitlProofValue where
  state := fun
    | .sodQuorumEnforced => true
    | .vetoPersistenceEnforced => true
    | .r1PolicyDriftChecked => true
    | .aeadTenantIsolationEnforced => true
    | .briefSummaryMaxBytes => 4096
  obligations := [hitlCoevolutionObligation]

theorem baselineHitlCertified : LeanPoo.Proof.Certificate baselineHitlSystem := by
  intro ob hMem
  have hEq : ob = hitlCoevolutionObligation := by simpa [baselineHitlSystem] using hMem
  subst ob
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- **Theorem 11**: Tuning `.briefSummaryMaxBytes` transports the `LeanPoo.Proof.Certificate` in 1 line. -/
theorem briefRenderLimitTuning_preserves_hitl_certificate :
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineHitlSystem
        (LeanPoo.Proof.Patch.set .briefSummaryMaxBytes 8192)) :=
  close_single_set_untouched baselineHitlSystem hitlCoevolutionObligation
    .briefSummaryMaxBytes 8192 rfl baselineHitlCertified (by simp [hitlCoevolutionObligation])

/-- **Theorem 12 (Negative Control)**: Disabling `.vetoPersistenceEnforced` always invalidates reuse. -/
theorem disablingVetoPersistence_invalidates_reuse :
    ¬ LeanPoo.Proof.unaffected hitlCoevolutionObligation
        (LeanPoo.Proof.Patch.set .vetoPersistenceEnforced false) :=
  set_dependency_invalidates_unaffected hitlCoevolutionObligation
    .vetoPersistenceEnforced false (by simp [hitlCoevolutionObligation])

end LeanPooHitlCoevolutionContract

end DeterministicEngineering.Engineering.HitlAndCoevolution
