;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM31 (ADV-L4): Storage Deserialization Validation Parity, Content-Addressed
;;; Artifact Integrity, TLS-Mandatory Sync Transport, Immutable Context-Index
;;; Replay & Idempotent CAS Audit Confinement.
;;; Formalizes five real ADV-L4 vulnerabilities discovered in marlin-agent-storage
;;; and marlin-agent-sessions:
;;;  1. Derived Serde Deserialize on StoragePageLimit, all 11 string_id! storage
;;;     identifiers, and marlin_agent_sessions::SessionId bypassed ::new() checks,
;;;     admitting limit=0 / limit=65535 (65x MAX_LIMIT) and empty/blank "" IDs
;;;     that break Turso nonempty-key invariants and hide ghost events.
;;;  2. put_artifact (both InMemoryAgentStorage and TursoAgentStorage) accepted
;;;     forged size_bytes != body.len() (including u64::MAX -> -1 i64 wrap in
;;;     SQLite) and poisoned payloads under sha256:<64-hex> content hashes.
;;;  3. TursoSyncRemoteUrl::new admitted remote cleartext http:// URLs, empty
;;;     hosts, @ userinfo smuggling, and CRLF injection carrying TursoSyncAuthToken.
;;;  4. TursoContextIndex::rebuild deleted and overwrote context_locators when
;;;     re-invoked at an already-applied (sequence, receipt) with divergent cuts,
;;;     and apply_change used unchecked cursor.applied + 1 arithmetic.
;;;  5. TursoAgentStorage::compare_and_swap_artifact_pointer wrote internal CAS
;;;     audit receipts with non-idempotent INSERT INTO visibility_receipts,
;;;     crashing conflict retries with UNIQUE constraint errors and leaving
;;;     committed pointer updates split-brained on receipt collision.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export StorageBoundaryIntegrityAndSyncConfinementModel)

(.def (StorageBoundaryIntegrityAndSyncConfinementModel @ ThreatModel.)
  identity: 'threat.execution.storage-boundary-integrity-and-sync-confinement
  family: 'threat.execution.storage-boundary-integrity-and-sync-confinement
  title: "Storage Boundary Deserialization Parity, CAS Integrity, Sync TLS & Context-Index Confinement (SM31)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM31 ADV-L4 validated Serde Deserialize parity for StoragePageLimit and all storage/session identifiers, put_artifact size_bytes == body.len() and cryptographic sha256:<64-hex> binding, TLS-mandatory remote TursoSyncRemoteUrl with loopback-only http:// and userinfo/CRLF refusal, immutable same-revision TursoContextIndex::rebuild conflict detection with checked sequence arithmetic, and idempotent CAS audit visibility receipts.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-storage and marlin-agent-sessions derived Serde Deserialize bypassed StoragePageLimit(1..=1000) and non-blank ID invariants; put_artifact accepted forged size_bytes=u64::MAX (-1 in SQLite) and poisoned sha256:<64-hex> blobs; TursoSyncRemoteUrl accepted remote cleartext http:// and userinfo@ smuggling; TursoContextIndex::rebuild wiped applied locators on same-receipt overwrite; compare_and_swap_artifact_pointer crashed on repeated conflict receipt PK collision."))
  quint-module: "execution_storage_boundary_integrity_and_sync_confinement"
  quint-file: "StorageBoundaryIntegrityAndSyncConfinement.qnt"
  domain-dir: "threat/execution/storage-boundary-integrity-and-sync-confinement"
  rules:
  '((storage-boundary-safe DE-SM31-SAFE quint)
    (storage-boundary-countermodel DE-SM31-COUNTER quint))
  dependencies:
  '((DE-SM31-SAFE source)
    (DE-SM31-SAFE profile)
    (DE-SM31-SAFE method)
    (DE-SM31-COUNTER source)
    (DE-SM31-COUNTER profile)
    (DE-SM31-COUNTER method))
  invariant: "No deserialized empty/blank storage ID or out-of-range StoragePageLimit is admitted (serdeBypassBreaches == 0), no artifact is stored with mismatched size_bytes or forged sha256:<64-hex> payload (casIntegrityBreaches == 0), remote sync URLs enforce TLS without userinfo or control chars (syncTransportBreaches == 0 and syncTlsEnforced), applied context-index revisions remain immutable against divergent same-receipt rebuilds and CAS conflict retries preserve idempotent audit receipts (indexOrCasAuditBreaches == 0 and indexImmutable and casAuditIdempotent)."
  limits: "Finite bounded storage contract, Turso CAS/sync transport & derived context-index state machine (appliedRev <= 4, stepCount <= 12); models validated Deserialize parity on StoragePageLimit and storage IDs, put_artifact size_bytes == body.len() and cryptographic sha256:<64-hex> binding, TLS-mandatory remote TursoSyncRemoteUrl with loopback-only http:// and userinfo/CRLF refusal, immutable same-revision TursoContextIndex::rebuild replay/conflict enforcement, and idempotent CAS visibility receipt persistence, without modeling SQLite disk corruption or SHA-256 preimage breaks.")
