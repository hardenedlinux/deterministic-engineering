// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.storage-boundary-integrity-and-sync-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-serde-bypass-empty-id-or-unbounded-page step=stepSerdeBypass max-steps=6 itf="h.serdeBypassBreaches > 0"
// @countermodel forbid-artifact-size-lie-or-sha256-cas-poisoning step=stepCasIntegrityBypass max-steps=6 itf="h.casIntegrityBreaches > 0"
// @countermodel forbid-cleartext-remote-sync-or-userinfo-smuggle step=stepSyncTransportBypass max-steps=6 itf="h.syncTransportBreaches > 0"
// @countermodel forbid-context-index-same-rev-overwrite-or-cas-receipt-crash step=stepIndexOrCasAuditBypass max-steps=6 itf="h.indexOrCasAuditBreaches > 0"
// Limits: Finite bounded storage contract, Turso CAS/sync transport & derived context-index state machine (appliedRev <= 4, stepCount <= 12); models validated Deserialize parity on StoragePageLimit and storage IDs, put_artifact size_bytes == body.len() and cryptographic sha256:<64-hex> binding, TLS-mandatory remote TursoSyncRemoteUrl with loopback-only http:// and userinfo/CRLF refusal, immutable same-revision TursoContextIndex::rebuild replay/conflict enforcement, and idempotent CAS visibility receipt persistence, without modeling SQLite disk corruption or SHA-256 preimage breaks.
module execution_storage_boundary_integrity_and_sync_confinement {
  type State = { appliedRev: int, frontierRev: int, casEntriesVerified: int, syncTlsEnforced: bool, indexImmutable: bool, casAuditIdempotent: bool, serdeBypassBreaches: int, casIntegrityBreaches: int, syncTransportBreaches: int, indexOrCasAuditBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { appliedRev: 0, frontierRev: 0, casEntriesVerified: 0, syncTlsEnforced: true, indexImmutable: true, casAuditIdempotent: true, serdeBypassBreaches: 0, casIntegrityBreaches: 0, syncTransportBreaches: 0, indexOrCasAuditBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action admitValidatedSerdeRequest = if ((h.stepCount < 12)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action putVerifiedContentAddressedArtifact = if ((h.stepCount < 12 and h.casEntriesVerified < 6)) h' = h.with("casEntriesVerified", (h.casEntriesVerified + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action admitTlsOrLoopbackSyncUrl = if ((h.stepCount < 12 and h.syncTlsEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action advanceContextIndexRevision = if ((h.stepCount < 12 and h.appliedRev < 4 and h.appliedRev == h.frontierRev and h.indexImmutable)) h' = h.with("appliedRev", (h.appliedRev + 1)).with("frontierRev", (h.frontierRev + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action observeContextIndexGap = if ((h.stepCount < 12 and h.frontierRev < 4 and h.indexImmutable)) h' = h.with("frontierRev", (h.frontierRev + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action rebuildCatchUpToFrontier = if ((h.stepCount < 12 and h.appliedRev < h.frontierRev and h.indexImmutable)) h' = h.with("appliedRev", h.frontierRev).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action retryCasConflictIdempotentAudit = if ((h.stepCount < 12 and h.casAuditIdempotent)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { admitValidatedSerdeRequest, putVerifiedContentAddressedArtifact, admitTlsOrLoopbackSyncUrl, advanceContextIndexRevision, observeContextIndexGap, rebuildCatchUpToFrontier, retryCasConflictIdempotentAudit }
  val safety = (h.serdeBypassBreaches == 0 and h.casIntegrityBreaches == 0 and h.syncTransportBreaches == 0 and h.indexOrCasAuditBreaches == 0 and h.syncTlsEnforced and h.indexImmutable and h.casAuditIdempotent and h.appliedRev >= 0 and h.appliedRev <= h.frontierRev and h.frontierRev <= 4 and h.stepCount <= 12)
  // Countermodel threat.execution.storage-boundary-integrity-and-sync-confinement.serde-bypass (dropped guard: forbid-serde-bypass-empty-id-or-unbounded-page)
  action exploitSerdeBypass = if ((h.stepCount < 12)) h' = h.with("serdeBypassBreaches", (h.serdeBypassBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepSerdeBypass = any { step, exploitSerdeBypass }
  // Countermodel threat.execution.storage-boundary-integrity-and-sync-confinement.cas-integrity-bypass (dropped guard: forbid-artifact-size-lie-or-sha256-cas-poisoning)
  action exploitCasIntegrityBypass = if ((h.stepCount < 12)) h' = h.with("casIntegrityBreaches", (h.casIntegrityBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepCasIntegrityBypass = any { step, exploitCasIntegrityBypass }
  // Countermodel threat.execution.storage-boundary-integrity-and-sync-confinement.sync-transport-bypass (dropped guard: forbid-cleartext-remote-sync-or-userinfo-smuggle)
  action exploitSyncTransportBypass = if ((h.stepCount < 12)) h' = h.with("syncTlsEnforced", false).with("syncTransportBreaches", (h.syncTransportBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepSyncTransportBypass = any { step, exploitSyncTransportBypass }
  // Countermodel threat.execution.storage-boundary-integrity-and-sync-confinement.index-or-cas-audit-bypass (dropped guard: forbid-context-index-same-rev-overwrite-or-cas-receipt-crash)
  action exploitIndexOverwriteOrCasCrash = if ((h.stepCount < 12)) h' = h.with("indexImmutable", false).with("casAuditIdempotent", false).with("indexOrCasAuditBreaches", (h.indexOrCasAuditBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepIndexOrCasAuditBypass = any { step, exploitIndexOverwriteOrCasCrash }
  action checkSm31Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm31Violated = all { assert((h.serdeBypassBreaches > 0 or h.casIntegrityBreaches > 0 or h.syncTransportBreaches > 0 or h.indexOrCasAuditBreaches > 0)), assert(not(safety)), h' = h }
  run cleanStorageBoundarySafeTest = init.then(admitValidatedSerdeRequest).then(putVerifiedContentAddressedArtifact).then(admitTlsOrLoopbackSyncUrl).then(advanceContextIndexRevision).then(observeContextIndexGap).then(rebuildCatchUpToFrontier).then(retryCasConflictIdempotentAudit).then(checkSm31Safe)
  run serdeBypassRefutedTest = init.then(exploitSerdeBypass).then(checkSm31Violated)
  run casIntegrityBypassRefutedTest = init.then(exploitCasIntegrityBypass).then(checkSm31Violated)
  run syncTransportBypassRefutedTest = init.then(exploitSyncTransportBypass).then(checkSm31Violated)
  run indexOrCasAuditBypassRefutedTest = init.then(exploitIndexOverwriteOrCasCrash).then(checkSm31Violated)
}
