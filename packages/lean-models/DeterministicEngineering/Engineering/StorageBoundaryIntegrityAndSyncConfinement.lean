/-
SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
SPDX-License-Identifier: LGPL-2.1-or-later
-/

import LeanPoo.Functional.ObjectContract
import LeanPoo.Functional.ObjectContractRefinement
import LeanPoo.Proof.Reuse
import DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-!
# SM31: Adversarial (`ADV-L4`) Storage Boundary Deserialization Parity, CAS Integrity, Sync TLS & Context-Index Confinement

Standalone objectified `LeanPoo` module (49th Lean module, zero edits to
`Core/Stability.lean`) formalizing five real `ADV-L4` persistence-layer
vulnerabilities discovered in `marlin-agent-storage` and `marlin-agent-sessions`:

1. **Deserialization Validation Parity**: Derived Serde `Deserialize` on
   `StoragePageLimit`, all 11 `string_id!` identifiers, and `SessionId`
   bypassed `::new()` validation, admitting `limit = 0`, `limit = 65535`
   (65x `MAX_LIMIT`), and empty/blank `""` IDs that break nonempty-key cursor
   invariants.
2. **Content-Addressed Artifact Integrity**: `put_artifact` on both
   `InMemoryAgentStorage` and `TursoAgentStorage` accepted forged
   `size_bytes != body.len()` (including `u64::MAX -> -1` SQLite wrap) and
   poisoned payloads under cryptographic `sha256:<64-hex>` artifact hashes.
3. **Sync Transport TLS & Authority Confinement**: `TursoSyncRemoteUrl::new`
   admitted remote cleartext `http://` endpoints, empty hosts, `@` userinfo
   smuggling, and CRLF injection carrying redacted `TursoSyncAuthToken`.
4. **Immutable Context-Index Revision Replay**: `TursoContextIndex::rebuild`
   deleted and overwrote `context_locators` when re-invoked at an already
   finalized `(sequence == applied == frontier, receipt == cursor.receipt)`
   with divergent cuts, and `apply_change` used unchecked `cursor.applied + 1`.
5. **Idempotent CAS Audit Receipts**: `compare_and_swap_artifact_pointer`
   wrote internal CAS audit receipts via non-idempotent `INSERT INTO
   visibility_receipts`, crashing repeated conflict retries with `UNIQUE
   constraint failed` and leaving committed pointer updates split-brained.
-/

namespace DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement

open LeanPoo.Functional.ObjectContract
open DeterministicEngineering.Engineering.SandboxSymlinkArchiveConfinement

/-- Deserialized page limit admission law (`1 <= limit <= maxLimit`). -/
def deserializedPageLimitAdmitted (limit maxLimit : Nat) : Bool :=
  (1 ≤ limit) && (limit ≤ maxLimit)

/-- Content-addressed artifact write admission law. -/
def artifactWriteAdmitted
    (sizeMatchesBody : Bool)
    (fitsSignedSqliteInt : Bool)
    (sha256DigestMatchesIfCryptographic : Bool) : Bool :=
  sizeMatchesBody && fitsSignedSqliteInt && sha256DigestMatchesIfCryptographic

/-- Remote sync URL admission law enforcing TLS for remote hosts and zero userinfo/control chars. -/
def syncRemoteUrlAdmitted
    (hasValidHostNoUserinfoOrControl : Bool)
    (usesTlsScheme : Bool)
    (isLoopbackHost : Bool) : Bool :=
  hasValidHostNoUserinfoOrControl && (usesTlsScheme || isLoopbackHost)

/-- Outcome of `TursoContextIndex::rebuild` at finalized revision (`applied == frontier`). -/
inductive RebuildOutcome where
  | superseded
  | replayed
  | conflict
  | applied
  deriving DecidableEq, Repr

def finalizedRebuildDecision
    (incomingSeq appliedSeq frontierSeq : Nat)
    (receiptMatches cutsMatch : Bool) : RebuildOutcome :=
  if incomingSeq < frontierSeq then .superseded
  else if incomingSeq == appliedSeq && appliedSeq == frontierSeq then
    if receiptMatches && cutsMatch then .replayed else .conflict
  else .applied

/-- Security posture of a Marlin storage & session persistence boundary. -/
structure StorageBoundarySecurityConfig where
  enforcesValidatedSerdeNewtypes : Bool
  enforcesArtifactSizeAndSha256Integrity : Bool
  enforcesTlsMandatorySyncTransport : Bool
  enforcesImmutableIndexRebuildAndCheckedSeq : Bool
  enforcesIdempotentCasAuditReceipts : Bool
  pressureTier : AdversarialPressureTier
  deriving DecidableEq, Repr

/-- Whether a storage configuration satisfies strict SM31 confinement. -/
def strictSm31Admitted (c : StorageBoundarySecurityConfig) : Bool :=
  c.enforcesValidatedSerdeNewtypes &&
  c.enforcesArtifactSizeAndSha256Integrity &&
  c.enforcesTlsMandatorySyncTransport &&
  c.enforcesImmutableIndexRebuildAndCheckedSeq &&
  c.enforcesIdempotentCasAuditReceipts &&
  c.pressureTier.meetsMinimumFloor

/-- Whether any of the 5 SM31 hostile exploit classes remain reachable. -/
def anySm31ExploitReachable (c : StorageBoundarySecurityConfig) : Bool :=
  !c.enforcesValidatedSerdeNewtypes ||
  !c.enforcesArtifactSizeAndSha256Integrity ||
  !c.enforcesTlsMandatorySyncTransport ||
  !c.enforcesImmutableIndexRebuildAndCheckedSeq ||
  !c.enforcesIdempotentCasAuditReceipts

/-- Canonical hardened SM31 Marlin storage posture. -/
def hardenedSm31Config : StorageBoundarySecurityConfig :=
  { enforcesValidatedSerdeNewtypes := true
    enforcesArtifactSizeAndSha256Integrity := true
    enforcesTlsMandatorySyncTransport := true
    enforcesImmutableIndexRebuildAndCheckedSeq := true
    enforcesIdempotentCasAuditReceipts := true
    pressureTier := .l4HostileAttack }

def defectiveSerdeBypassConfig : StorageBoundarySecurityConfig :=
  { hardenedSm31Config with enforcesValidatedSerdeNewtypes := false }

def defectiveCasIntegrityConfig : StorageBoundarySecurityConfig :=
  { hardenedSm31Config with enforcesArtifactSizeAndSha256Integrity := false }

def defectiveSyncTransportConfig : StorageBoundarySecurityConfig :=
  { hardenedSm31Config with enforcesTlsMandatorySyncTransport := false }

def defectiveIndexRebuildConfig : StorageBoundarySecurityConfig :=
  { hardenedSm31Config with enforcesImmutableIndexRebuildAndCheckedSeq := false }

def defectiveCasAuditConfig : StorageBoundarySecurityConfig :=
  { hardenedSm31Config with enforcesIdempotentCasAuditReceipts := false }

def defectiveGentleTierConfig : StorageBoundarySecurityConfig :=
  { hardenedSm31Config with pressureTier := .l1Gentle }

/-- Theorem 1: Deserialized `StoragePageLimit` unconditionally rejects `0` and any value exceeding `maxLimit`. -/
theorem sm31_deserialized_page_limit_bounds (limit maxLimit : Nat) :
    deserializedPageLimitAdmitted 0 maxLimit = false ∧
    (maxLimit < limit → deserializedPageLimitAdmitted limit maxLimit = false) := by
  constructor
  · simp [deserializedPageLimitAdmitted]
  · intro hgt
    have hnotle : ¬ (limit ≤ maxLimit) := Nat.not_le_of_gt hgt
    simp [deserializedPageLimitAdmitted, hnotle]

/-- Theorem 2: Forged `size_bytes`, negative SQLite `i64` wraps, and poisoned `sha256:<64-hex>` payloads are all refused. -/
theorem sm31_artifact_integrity_refuses_size_lie_and_digest_poison (a b c : Bool) :
    artifactWriteAdmitted false b c = false ∧
    artifactWriteAdmitted a false c = false ∧
    artifactWriteAdmitted a b false = false ∧
    artifactWriteAdmitted true true true = true := by
  cases a <;> cases b <;> cases c <;> decide

/-- Theorem 3: Remote cleartext `http://` sync URLs and any URL with userinfo/control chars are unconditionally refused. -/
theorem sm31_sync_url_refuses_remote_cleartext_and_smuggling (tls loop : Bool) :
    syncRemoteUrlAdmitted false tls loop = false ∧
    syncRemoteUrlAdmitted true false false = false ∧
    syncRemoteUrlAdmitted true true false = true ∧
    syncRemoteUrlAdmitted true false true = true := by
  cases tls <;> cases loop <;> decide

/-- Theorem 4: Rebuilding an already-finalized context-index revision (`applied == frontier`) with divergent cuts
    never overwrites (`applied`); it returns `conflict` even if the receipt string matches. -/
theorem sm31_finalized_rebuild_divergent_cuts_returns_conflict (rev : Nat) (receiptMatches : Bool) :
    finalizedRebuildDecision rev rev rev receiptMatches false = .conflict ∧
    finalizedRebuildDecision rev rev rev true true = .replayed := by
  cases receiptMatches <;> simp [finalizedRebuildDecision]

/-- Theorem 5: Strict SM31 admission eliminates all 5 storage/session exploit classes. -/
theorem sm31_strict_admission_eliminates_all_exploits (c : StorageBoundarySecurityConfig)
    (h : strictSm31Admitted c = true) :
    anySm31ExploitReachable c = false := by
  cases c with
  | mk s a t i r tier =>
    simp [strictSm31Admitted] at h
    rcases h with ⟨⟨⟨⟨⟨hs, ha⟩, ht⟩, hi⟩, hr⟩, _⟩
    subst hs; subst ha; subst ht; subst hi; subst hr
    rfl

/-- Theorem 6: Gentle ADV-L1/ADV-L2 tiers fail mandatory SM31 admission. -/
theorem sm31_gentle_pressure_rejected (c : StorageBoundarySecurityConfig)
    (htier : c.pressureTier = .l1Gentle ∨ c.pressureTier = .l2Edge) :
    strictSm31Admitted c = false := by
  rcases htier with h1 | h2
  · simp [strictSm31Admitted, h1, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]
  · simp [strictSm31Admitted, h2, AdversarialPressureTier.meetsMinimumFloor, AdversarialPressureTier.rank]

/-- Theorem 7: Positive countermodels prove every defective config exposes live exploits while hardened config is clean. -/
theorem sm31_defective_configs_expose_live_exploits :
    anySm31ExploitReachable defectiveSerdeBypassConfig = true ∧
    anySm31ExploitReachable defectiveCasIntegrityConfig = true ∧
    anySm31ExploitReachable defectiveSyncTransportConfig = true ∧
    anySm31ExploitReachable defectiveIndexRebuildConfig = true ∧
    anySm31ExploitReachable defectiveCasAuditConfig = true ∧
    strictSm31Admitted defectiveGentleTierConfig = false ∧
    strictSm31Admitted hardenedSm31Config = true ∧
    anySm31ExploitReachable hardenedSm31Config = false := by
  decide

/-! ## LeanPoo ObjectContract Refinement & Proof Reuse/Close -/

inductive StorageBoundaryConfigKey where
  | validatedSerdeNewtypes
  | artifactSizeAndSha256
  | tlsMandatorySyncTransport
  | immutableIndexRebuild
  | idempotentCasAudit
  | pressureTier
  deriving DecidableEq, Repr

inductive StorageBoundaryIssue where
  | serdeValidationBypass
  | casSizeOrDigestPoisoning
  | cleartextRemoteSyncOrUserinfo
  | mutableAppliedIndexRevision
  | nonIdempotentCasAuditReceipt
  | insufficientAdversarialPressure
  deriving DecidableEq, Repr

private def storageBoundaryView : View StorageBoundarySecurityConfig StorageBoundaryConfigKey Unit where
  isObject := fun _ => true
  prototype := fun _ => true
  names := fun _ => []
  lookup := fun _ _ => none

def baseStorageBoundaryContract :
    Contract StorageBoundarySecurityConfig StorageBoundaryConfigKey Unit StorageBoundaryIssue where
  view := storageBoundaryView
  fields := []
  strict := true
  constraints := []
  obligations := fun cfg path =>
    (if cfg.enforcesValidatedSerdeNewtypes then [] else [.rejected path .serdeValidationBypass]) ++
    (if cfg.enforcesArtifactSizeAndSha256Integrity then [] else [.rejected path .casSizeOrDigestPoisoning]) ++
    (if cfg.enforcesTlsMandatorySyncTransport then [] else [.rejected path .cleartextRemoteSyncOrUserinfo]) ++
    (if cfg.enforcesImmutableIndexRebuildAndCheckedSeq then [] else [.rejected path .mutableAppliedIndexRevision]) ++
    (if cfg.enforcesIdempotentCasAuditReceipts then [] else [.rejected path .nonIdempotentCasAuditReceipt])
  validInventory := Or.inl rfl

def marlinStorageBoundaryContract :
    Contract StorageBoundarySecurityConfig StorageBoundaryConfigKey Unit StorageBoundaryIssue :=
  refine baseStorageBoundaryContract fun cfg path =>
    if cfg.pressureTier.meetsMinimumFloor then []
    else [.rejected path .insufficientAdversarialPressure]

/-- Theorem 8: Refined Marlin storage contract preserves base rejections and requires ADV-L3+ floor. -/
theorem sm31_marlin_contract_refinement_laws
    (cfg : StorageBoundarySecurityConfig) (path : List StorageBoundaryConfigKey) :
    (diagnose baseStorageBoundaryContract cfg path ≠ [] →
      diagnose marlinStorageBoundaryContract cfg path ≠ []) ∧
    (diagnose marlinStorageBoundaryContract cfg path = [] ↔
      diagnose baseStorageBoundaryContract cfg path = [] ∧
      (if cfg.pressureTier.meetsMinimumFloor then []
       else [Issue.rejected path StorageBoundaryIssue.insufficientAdversarialPressure]) = []) :=
  ⟨refine_preserves_rejection baseStorageBoundaryContract _ cfg path,
   refine_accepts_iff baseStorageBoundaryContract _ cfg path⟩

inductive StorageBoundaryProofKey where
  | validatedSerdeNewtypes
  | artifactSizeAndSha256
  | tlsMandatorySyncTransport
  | immutableIndexRebuild
  | idempotentCasAudit
  | pressureTier
  | pageLimitMax
  deriving DecidableEq

abbrev StorageBoundaryProofValue : StorageBoundaryProofKey → Type
  | .validatedSerdeNewtypes => Bool
  | .artifactSizeAndSha256 => Bool
  | .tlsMandatorySyncTransport => Bool
  | .immutableIndexRebuild => Bool
  | .idempotentCasAudit => Bool
  | .pressureTier => AdversarialPressureTier
  | .pageLimitMax => Nat

def storageBoundaryObligation :
    LeanPoo.Proof.Obligation StorageBoundaryProofKey StorageBoundaryProofValue where
  dependencies := [
    .validatedSerdeNewtypes,
    .artifactSizeAndSha256,
    .tlsMandatorySyncTransport,
    .immutableIndexRebuild,
    .idempotentCasAudit,
    .pressureTier
  ]
  holds := fun s =>
    s .validatedSerdeNewtypes = true ∧
    s .artifactSizeAndSha256 = true ∧
    s .tlsMandatorySyncTransport = true ∧
    s .immutableIndexRebuild = true ∧
    s .idempotentCasAudit = true ∧
    (s .pressureTier).meetsMinimumFloor = true
  stable := by
    intro before after same holds
    have h1 : before .validatedSerdeNewtypes = after .validatedSerdeNewtypes :=
      same .validatedSerdeNewtypes (by simp)
    have h2 : before .artifactSizeAndSha256 = after .artifactSizeAndSha256 :=
      same .artifactSizeAndSha256 (by simp)
    have h3 : before .tlsMandatorySyncTransport = after .tlsMandatorySyncTransport :=
      same .tlsMandatorySyncTransport (by simp)
    have h4 : before .immutableIndexRebuild = after .immutableIndexRebuild :=
      same .immutableIndexRebuild (by simp)
    have h5 : before .idempotentCasAudit = after .idempotentCasAudit :=
      same .idempotentCasAudit (by simp)
    have h6 : before .pressureTier = after .pressureTier :=
      same .pressureTier (by simp)
    simpa [h1, h2, h3, h4, h5, h6] using holds

def baselineStorageBoundaryProof :
    LeanPoo.Proof.ProofObject StorageBoundaryProofKey StorageBoundaryProofValue where
  state := fun
    | .validatedSerdeNewtypes => true
    | .artifactSizeAndSha256 => true
    | .tlsMandatorySyncTransport => true
    | .immutableIndexRebuild => true
    | .idempotentCasAudit => true
    | .pressureTier => .l4HostileAttack
    | .pageLimitMax => 1000
  obligations := [storageBoundaryObligation]

/-- Theorem 9: Baseline ADV-L4 SM31 proof is certified. -/
theorem sm31_baseline_certified :
    LeanPoo.Proof.Certificate baselineStorageBoundaryProof := by
  intro obligation member
  have hEq : obligation = storageBoundaryObligation := by
    simpa [baselineStorageBoundaryProof] using member
  subst obligation
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def pageLimitTuningPatch :
    LeanPoo.Proof.Patch StorageBoundaryProofKey StorageBoundaryProofValue :=
  LeanPoo.Proof.Patch.set .pageLimitMax 500

theorem sm31_obligation_untouched_by_page_tuning :
    LeanPoo.Proof.unaffected storageBoundaryObligation pageLimitTuningPatch := by
  intro key dep touched
  have hKey : key = .pageLimitMax := by
    simpa [pageLimitTuningPatch, LeanPoo.Proof.Patch.set] using touched
  subst key
  simp [storageBoundaryObligation] at dep

/-- Theorem 10: Tuning bounded page-limit constants cleanly reuses and closes the LeanPoo certificate. -/
theorem sm31_page_tuning_reuses_and_closes_certificate :
    storageBoundaryObligation.holds
      (LeanPoo.Proof.append baselineStorageBoundaryProof pageLimitTuningPatch).state ∧
    LeanPoo.Proof.Certificate
      (LeanPoo.Proof.append baselineStorageBoundaryProof pageLimitTuningPatch) := by
  refine ⟨?_, ?_⟩
  · exact LeanPoo.Proof.reuse baselineStorageBoundaryProof pageLimitTuningPatch
      sm31_baseline_certified storageBoundaryObligation
      (by simp [baselineStorageBoundaryProof]) sm31_obligation_untouched_by_page_tuning
  · apply LeanPoo.Proof.close baselineStorageBoundaryProof pageLimitTuningPatch
      sm31_baseline_certified
    · intro obligation member affected
      have hEq : obligation = storageBoundaryObligation := by
        simpa [baselineStorageBoundaryProof] using member
      subst obligation
      exact False.elim (affected sm31_obligation_untouched_by_page_tuning)
    · intro obligation member
      simp [pageLimitTuningPatch, LeanPoo.Proof.Patch.set] at member

def serdeRegressionPatch :
    LeanPoo.Proof.Patch StorageBoundaryProofKey StorageBoundaryProofValue :=
  LeanPoo.Proof.Patch.set .validatedSerdeNewtypes false

def casIntegrityRegressionPatch :
    LeanPoo.Proof.Patch StorageBoundaryProofKey StorageBoundaryProofValue :=
  LeanPoo.Proof.Patch.set .artifactSizeAndSha256 false

def syncTlsRegressionPatch :
    LeanPoo.Proof.Patch StorageBoundaryProofKey StorageBoundaryProofValue :=
  LeanPoo.Proof.Patch.set .tlsMandatorySyncTransport false

def indexRebuildRegressionPatch :
    LeanPoo.Proof.Patch StorageBoundaryProofKey StorageBoundaryProofValue :=
  LeanPoo.Proof.Patch.set .immutableIndexRebuild false

def casAuditRegressionPatch :
    LeanPoo.Proof.Patch StorageBoundaryProofKey StorageBoundaryProofValue :=
  LeanPoo.Proof.Patch.set .idempotentCasAudit false

/-- Theorem 11: Regressing any of the 5 SM31 storage defenses invalidates LeanPoo certificate reuse. -/
theorem sm31_regressions_invalidate_reuse :
    ¬ LeanPoo.Proof.unaffected storageBoundaryObligation serdeRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected storageBoundaryObligation casIntegrityRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected storageBoundaryObligation syncTlsRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected storageBoundaryObligation indexRebuildRegressionPatch ∧
    ¬ LeanPoo.Proof.unaffected storageBoundaryObligation casAuditRegressionPatch := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro h
    exact h .validatedSerdeNewtypes (by simp [storageBoundaryObligation])
      (by simp [serdeRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .artifactSizeAndSha256 (by simp [storageBoundaryObligation])
      (by simp [casIntegrityRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .tlsMandatorySyncTransport (by simp [storageBoundaryObligation])
      (by simp [syncTlsRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .immutableIndexRebuild (by simp [storageBoundaryObligation])
      (by simp [indexRebuildRegressionPatch, LeanPoo.Proof.Patch.set])
  · intro h
    exact h .idempotentCasAudit (by simp [storageBoundaryObligation])
      (by simp [casAuditRegressionPatch, LeanPoo.Proof.Patch.set])

end DeterministicEngineering.Engineering.StorageBoundaryIntegrityAndSyncConfinement
