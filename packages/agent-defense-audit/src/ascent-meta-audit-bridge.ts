// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 20 (10.168): Cross-Runtime N-Version Proof-Carrying Governance Bridge
 * (TypeScript B1-B9 Runtimes <-> Live Gerbil Scheme ASCENT Datalog Oracle).
 *
 * Implements Avizienis (1985) N-Version Programming & Necula (POPL 1997)
 * Proof-Carrying Governance across two heterogeneous languages and paradigms:
 *   1. Projects live TypeScript B1-B9 objects (Macaroon DelegationCertificates,
 *      DurableMemoryTmsStore beliefs, DIFC TaintedValues, RFC 6962 Ed25519 STHs,
 *      SoD release proposals, Saga pivot flags) into an M1 content-addressed
 *      `MetaAuditFactBundle` and injection-safe Scheme S-expression alist.
 *   2. Invokes our compiled Gerbil Scheme ASCENT Datalog engine
 *      (`reason-durable-governance-meta-audit`) over stdin/stdout as an
 *      independent declarative fixed-point verifier.
 *   3. Enforces a Fail-Closed Cross-Language Agreement Gate:
 *        - If a buggy/compromised imperative TypeScript Coordinator claims ADMIT
 *          while the declarative Scheme Datalog oracle disqualifies the release,
 *          admission is deterministically REFUSED (`oracle-disagreement-fail-closed`)
 *          with a pinned M1 `DisagreementForensicReceipt`.
 *        - If the external Gerbil runtime is unavailable, returns explicit epistemic
 *          `PendingMethod` (NEVER silently degrades to ok:true!).
 */

import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {ContentAddressedKvStore, sha256Digest} from './durable-merkle-store.ts';
import type {DelegationCertificate} from './capability-attenuation.ts';
import type {MemoryBeliefNode} from './durable-memory-tms.ts';
import type {TaintedValue, ToolSinkPolicy} from './difc-exfiltration-fence.ts';
import type {SignedTreeHead} from './transparency-log-equivocation.ts';
import type {
  ThresholdCosignedCheckpoint,
  WitnessCosignature,
} from './witness-quorum-finality.ts';

export interface MetaAuditFactBundle {
  delegation_edge: Array<[string, string]>;
  revoked_principal: Array<[string]>;
  belief_proposer: Array<[string, string]>;
  belief_has_oracle: Array<[string]>;
  belief_sole_dep: Array<[string, string]>;
  retracted_belief: Array<[string]>;
  base_taint: Array<[string, string]>;
  derived_from: Array<[string, string]>;
  declassified_tag: Array<[string, string]>;
  sink_emits: Array<[string, string]>;
  sink_allows: Array<[string, string]>;
  witness_sth: Array<[string, string, string, string]>;
  release_proposal: Array<[string, string, string, string]>;
  release_uses_belief: Array<[string, string]>;
  saga_pivot_crossed: Array<[string]>;
  saga_rollback_attempted: Array<[string]>;
  witness_roster: Array<[string, string]>;
  witness_cosign: Array<[string, string, string, string, string]>;
  claimed_finalized: Array<[string, string, string, string]>;
  release_requires_finality: Array<[string, string]>;
  slashed_witness: Array<[string, string]>;
  next_epoch_roster: Array<[string, string, string]>;
  mcp_tool_pinned_schema: Array<[string, string]>;
  mcp_tool_invoked: Array<[string, string, string, string]>;
  context_pinned_constraint: Array<[string, string]>;
  distillation_retained: Array<[string, string]>;
  swarm_wait_edge: Array<[string, string, string]>;
  swarm_session_release: Array<[string, string]>;
  lockfile_pinned_dep: Array<[string]>;
  cve_tombstone: Array<[string]>;
  release_sbom_dep: Array<[string, string]>;
  build_attestation: Array<[string, string, string, string]>;
  expected_enclave_measurement: Array<[string, string]>;
  enclave_quote: Array<[string, string, string, string, string]>;
  revoked_tee_platform: Array<[string]>;
  tee_quote_nonce: Array<[string, string]>;
  tenant_active_key_epoch: Array<[string, string]>;
  shredded_key_epoch: Array<[string, string]>;
  release_aead_write: Array<[string, string, string]>;
  release_aead_read: Array<[string, string, string, string]>;
  pq_allowed_suite: Array<[string]>;
  pq_deprecated_suite: Array<[string]>;
  release_pq_envelope: Array<[string, string, string, string, string]>;
  pq_ots_leaf_use: Array<[string, string, string]>;
  zk_forbidden_secret_field: Array<[string]>;
  zk_required_public_field: Array<[string]>;
  release_zk_proof: Array<[string, string, string, string, string]>;
  release_zk_disclosed_field: Array<[string, string]>;
  geo_allowed_region: Array<[string]>;
  geo_sanctioned_region: Array<[string]>;
  release_geo_placement: Array<[string, string, string, string, string]>;
  geo_transfer_permit: Array<[string, string, string, string]>;
  fed_ratified_treaty: Array<[string]>;
  fed_revoked_org: Array<[string]>;
  fed_dispute_freeze: Array<[string]>;
  release_fed_reciprocity: Array<[string, string, string, string, string]>;
  model_pinned_weight: Array<[string, string]>;
  model_approved_adapter: Array<[string]>;
  model_revoked_id: Array<[string]>;
  release_model_inference: Array<[string, string, string, string, string]>;
}

export interface AscentMetaAuditOutput {
  effectively_revoked: string[][];
  belief_poisoned: string[][];
  tainted_value: string[][];
  exfiltration_violation: string[][];
  equivocation_violation: string[][];
  byzantine_witness_equivocation: string[][];
  invalid_witness_cosign: string[][];
  quorum_3_verified: string[][];
  sub_quorum_finality_violation: string[][];
  split_world_finality_breach: string[][];
  slashed_witness_reentry_violation: string[][];
  mcp_tool_violation: string[][];
  distillation_amnesia_violation: string[][];
  swarm_deadlock_cycle: string[][];
  supply_chain_dep_violation: string[][];
  reproducible_build_violation: string[][];
  enclave_attestation_violation: string[][];
  enclave_nonce_replay_violation: string[][];
  key_rotation_write_violation: string[][];
  crypto_shred_read_violation: string[][];
  pq_agility_violation: string[][];
  pq_ots_reuse_violation: string[][];
  zk_disclosure_violation: string[][];
  zk_nullifier_replay_violation: string[][];
  geo_residency_violation: string[][];
  geo_cross_border_violation: string[][];
  fed_reciprocity_violation: string[][];
  fed_dispute_freeze_violation: string[][];
  model_weight_violation: string[][];
  model_adapter_violation: string[][];
  release_disqualified: string[][];
  release_admitted: string[][];
}

export type AscentOracleRunVerdict =
  | {
      kind: 'Verified';
      output: AscentMetaAuditOutput;
      outputDigest: string;
      durationMs: number;
    }
  | {kind: 'PendingMethod'; reason: 'gerbil-runtime-unavailable'}
  | {kind: 'SetupDefect'; reason: string};

export type DualOracleReleaseVerdict =
  | {
      kind: 'Proven';
      releaseId: string;
      dualAdmissionReceiptHash: string;
      factBundleMerkleHash: string;
      oracleOutputDigest: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'imperative-coordinator-refused'
        | 'oracle-disagreement-fail-closed'
        | 'oracle-disqualified-release';
      disagreementReceiptHash: string;
      ascentDisqualificationReasons: string[];
    }
  | {kind: 'PendingMethod'; reason: 'gerbil-runtime-unavailable'}
  | {kind: 'SetupDefect'; reason: string};

const BEGIN_MARKER = 'BEGIN_ASCENT_META_AUDIT_JSON';
const END_MARKER = 'END_ASCENT_META_AUDIT_JSON';

export function escapeSchemeString(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`;
}

function dedupeTuples<T extends string[]>(rows: T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const r of rows) {
    const k = JSON.stringify(r);
    if (!seen.has(k)) {
      seen.add(k);
      out.push(r);
    }
  }
  return out;
}

/**
 * Extracts a canonical, M1-pinned `MetaAuditFactBundle` directly from live TypeScript
 * B1-B10 governance objects with zero hand-crafted Scheme tuples.
 */
export function extractMetaAuditBundleFromLiveObjects(params: {
  kv: ContentAddressedKvStore;
  delegationCertificates: readonly DelegationCertificate[];
  revokedPrincipals: readonly string[];
  beliefNodes: readonly MemoryBeliefNode[];
  taintedValues: readonly TaintedValue<unknown>[];
  declassifiedTags?: ReadonlyArray<{valueId: string; tag: string}>;
  sinkEmissions: ReadonlyArray<{sink: ToolSinkPolicy; valueId: string}>;
  witnessObservations: ReadonlyArray<{witnessId: string; sth: SignedTreeHead}>;
  witnessRosters?: ReadonlyArray<{logId: string; witnessIds: readonly string[]}>;
  witnessCosignatures?: ReadonlyArray<{
    cosig: WitnessCosignature;
    consistencyVerified: boolean;
  }>;
  claimedFinalizedCheckpoints?: ReadonlyArray<{
    checkpointId: string;
    checkpoint: ThresholdCosignedCheckpoint;
    consistencyVerifiedByWitness?: Readonly<Record<string, boolean>>;
  }>;
  slashedWitnesses?: ReadonlyArray<{logId: string; witnessId: string}>;
  nextEpochRosters?: ReadonlyArray<{logId: string; epoch: number; witnessIds: readonly string[]}>;
  mcpPinnedTools?: ReadonlyArray<{toolId: string; pinnedSchemaHash: string}>;
  mcpToolInvocations?: ReadonlyArray<{
    releaseId: string;
    toolId: string;
    observedSchemaHash: string;
    scopeOk: boolean;
  }>;
  contextPinnedConstraints?: ReadonlyArray<{releaseId: string; constraintHash: string}>;
  distillationRetainedConstraints?: ReadonlyArray<{releaseId: string; constraintHash: string}>;
  swarmWaitEdges?: ReadonlyArray<{sessionId: string; waitingAgent: string; blockingAgent: string}>;
  swarmSessionReleases?: ReadonlyArray<{releaseId: string; sessionId: string}>;
  lockfilePinnedDeps?: readonly string[];
  cveTombstones?: readonly string[];
  releaseSbomDeps?: ReadonlyArray<{releaseId: string; depDigest: string}>;
  buildAttestations?: ReadonlyArray<{
    releaseId: string;
    builderId: string;
    artifactDigest: string;
    hermetic: boolean;
  }>;
  expectedEnclaveMeasurements?: ReadonlyArray<{releaseId: string; artifactDigest: string}>;
  enclaveQuotes?: ReadonlyArray<{
    releaseId: string;
    platformId: string;
    measuredDigest: string;
    debugDisabled: boolean;
    tcbOk: boolean;
  }>;
  revokedTeePlatforms?: readonly string[];
  teeQuoteNonces?: ReadonlyArray<{releaseId: string; nonce: string}>;
  tenantActiveKeyEpochs?: ReadonlyArray<{tenantId: string; epoch: number}>;
  shreddedKeyEpochs?: ReadonlyArray<{tenantId: string; epoch: number}>;
  releaseAeadWrites?: ReadonlyArray<{releaseId: string; tenantId: string; writeEpoch: number}>;
  releaseAeadReads?: ReadonlyArray<{
    releaseId: string;
    tenantId: string;
    readEpoch: number;
    digestPreserved: boolean;
  }>;
  pqAllowedSuites?: readonly string[];
  pqDeprecatedSuites?: readonly string[];
  releasePqEnvelopes?: ReadonlyArray<{
    releaseId: string;
    suiteId: string;
    classicalOk: boolean;
    pqOk: boolean;
    domainOk: boolean;
  }>;
  pqOtsLeafUses?: ReadonlyArray<{
    releaseId: string;
    signerId: string;
    leafIndex: number;
  }>;
  zkForbiddenSecretFields?: readonly string[];
  zkRequiredPublicFields?: readonly string[];
  releaseZkProofs?: ReadonlyArray<{
    releaseId: string;
    proverId: string;
    rootOk: boolean;
    sigmaOk: boolean;
    nullifier: string;
  }>;
  releaseZkDisclosedFields?: ReadonlyArray<{
    releaseId: string;
    fieldId: string;
  }>;
  geoAllowedRegions?: readonly string[];
  geoSanctionedRegions?: readonly string[];
  releaseGeoPlacements?: ReadonlyArray<{
    releaseId: string;
    sourceRegion: string;
    targetRegion: string;
    inferenceEndpointRegion: string;
    attestationOk: boolean;
  }>;
  geoTransferPermits?: ReadonlyArray<{
    releaseId: string;
    sourceRegion: string;
    targetRegion: string;
    permitOk: boolean;
  }>;
  fedRatifiedTreaties?: readonly string[];
  fedRevokedOrgs?: readonly string[];
  fedDisputeFreezes?: readonly string[];
  releaseFedReciprocities?: ReadonlyArray<{
    releaseId: string;
    treatyId: string;
    originOrgId: string;
    targetOrgId: string;
    bilateralOk: boolean;
  }>;
  modelPinnedWeights?: ReadonlyArray<{
    modelId: string;
    weightRoot: string;
  }>;
  modelApprovedAdapters?: readonly string[];
  modelRevokedIds?: readonly string[];
  releaseModelInferences?: ReadonlyArray<{
    releaseId: string;
    modelId: string;
    observedWeightRoot: string;
    adapterDigest: string;
    deterministicSamplingOk: boolean;
  }>;
  releaseProposals: ReadonlyArray<{
    releaseId: string;
    authorId: string;
    approverId: string;
    logId: string;
    supportingBeliefIds: readonly string[];
    sagaPivotCrossed?: boolean;
    sagaRollbackAttempted?: boolean;
    requiredCheckpointId?: string;
  }>;
}): {bundle: MetaAuditFactBundle; factBundleMerkleHash: string} {
  const delegation_edge: Array<[string, string]> = [];
  for (const cert of params.delegationCertificates) {
    delegation_edge.push([cert.delegatorId, cert.delegateeId]);
  }

  const revoked_principal: Array<[string]> = params.revokedPrincipals.map(p => [p]);

  const belief_proposer: Array<[string, string]> = [];
  const belief_has_oracle: Array<[string]> = [];
  const belief_sole_dep: Array<[string, string]> = [];
  const retracted_belief: Array<[string]> = [];

  for (const b of params.beliefNodes) {
    belief_proposer.push([b.beliefId, b.proposerId]);
    if (b.oracleReceiptHash) {
      belief_has_oracle.push([b.beliefId]);
    }
    if (b.status === 'RetractedPoisoned') {
      retracted_belief.push([b.beliefId]);
    }
    // Single justification set -> sole-support causal edges for TMS retraction:
    if (b.justifications.length === 1) {
      for (const supId of b.justifications[0]!) {
        belief_sole_dep.push([b.beliefId, supId]);
      }
    }
  }

  const valueIdByHash = new Map<string, string>();
  for (const tv of params.taintedValues) {
    valueIdByHash.set(tv.valueMerkleHash, tv.valueId);
  }
  const base_taint: Array<[string, string]> = [];
  const derived_from: Array<[string, string]> = [];
  for (const tv of params.taintedValues) {
    if (tv.parentValueHashes.length === 0) {
      for (const tag of tv.secrecyTags) {
        base_taint.push([tv.valueId, tag]);
      }
    } else {
      for (const ph of tv.parentValueHashes) {
        const parentId = valueIdByHash.get(ph);
        if (parentId) derived_from.push([tv.valueId, parentId]);
      }
    }
  }

  const declassified_tag: Array<[string, string]> = (params.declassifiedTags ?? []).map(d => [
    d.valueId,
    d.tag,
  ]);

  const sink_emits: Array<[string, string]> = [];
  const sink_allows: Array<[string, string]> = [];
  for (const em of params.sinkEmissions) {
    sink_emits.push([em.sink.sinkId, em.valueId]);
    for (const tag of em.sink.allowedSecrecyTags) {
      sink_allows.push([em.sink.sinkId, tag]);
    }
  }

  const witness_sth: Array<[string, string, string, string]> = params.witnessObservations.map(
    obs => [obs.witnessId, obs.sth.logId, String(obs.sth.treeSize), obs.sth.rootHashHex],
  );

  const release_proposal: Array<[string, string, string, string]> = [];
  const release_uses_belief: Array<[string, string]> = [];
  const saga_pivot_crossed: Array<[string]> = [];
  const saga_rollback_attempted: Array<[string]> = [];
  const release_requires_finality: Array<[string, string]> = [];

  for (const rel of params.releaseProposals) {
    release_proposal.push([rel.releaseId, rel.authorId, rel.approverId, rel.logId]);
    for (const bid of rel.supportingBeliefIds) {
      release_uses_belief.push([rel.releaseId, bid]);
    }
    if (rel.sagaPivotCrossed) saga_pivot_crossed.push([rel.releaseId]);
    if (rel.sagaRollbackAttempted) saga_rollback_attempted.push([rel.releaseId]);
    if (rel.requiredCheckpointId) {
      release_requires_finality.push([rel.releaseId, rel.requiredCheckpointId]);
    }
  }

  const witness_roster: Array<[string, string]> = [];
  for (const r of params.witnessRosters ?? []) {
    for (const wid of r.witnessIds) {
      witness_roster.push([r.logId, wid]);
    }
  }

  const witness_cosign: Array<[string, string, string, string, string]> = [];
  for (const wc of params.witnessCosignatures ?? []) {
    witness_cosign.push([
      wc.cosig.witnessId,
      wc.cosig.logId,
      String(wc.cosig.treeSize),
      wc.cosig.rootHashHex,
      wc.consistencyVerified ? 'yes' : 'no',
    ]);
  }

  const claimed_finalized: Array<[string, string, string, string]> = [];
  for (const cf of params.claimedFinalizedCheckpoints ?? []) {
    const sth = cf.checkpoint.sth;
    claimed_finalized.push([cf.checkpointId, sth.logId, String(sth.treeSize), sth.rootHashHex]);
    for (const cosig of cf.checkpoint.cosignatures) {
      const ok = cf.consistencyVerifiedByWitness
        ? Boolean(cf.consistencyVerifiedByWitness[cosig.witnessId])
        : true;
      witness_cosign.push([
        cosig.witnessId,
        cosig.logId,
        String(cosig.treeSize),
        cosig.rootHashHex,
        ok ? 'yes' : 'no',
      ]);
    }
  }

  const slashed_witness: Array<[string, string]> = (params.slashedWitnesses ?? []).map(s => [
    s.logId,
    s.witnessId,
  ]);
  const next_epoch_roster: Array<[string, string, string]> = [];
  for (const nr of params.nextEpochRosters ?? []) {
    for (const wid of nr.witnessIds) {
      next_epoch_roster.push([nr.logId, String(nr.epoch), wid]);
    }
  }

  const mcp_tool_pinned_schema: Array<[string, string]> = (params.mcpPinnedTools ?? []).map(t => [
    t.toolId,
    t.pinnedSchemaHash,
  ]);
  const mcp_tool_invoked: Array<[string, string, string, string]> = (
    params.mcpToolInvocations ?? []
  ).map(inv => [
    inv.releaseId,
    inv.toolId,
    inv.observedSchemaHash,
    inv.scopeOk ? 'yes' : 'no',
  ]);

  const context_pinned_constraint: Array<[string, string]> = (
    params.contextPinnedConstraints ?? []
  ).map(c => [c.releaseId, c.constraintHash]);
  const distillation_retained: Array<[string, string]> = (
    params.distillationRetainedConstraints ?? []
  ).map(c => [c.releaseId, c.constraintHash]);
  const swarm_wait_edge: Array<[string, string, string]> = (params.swarmWaitEdges ?? []).map(e => [
    e.sessionId,
    e.waitingAgent,
    e.blockingAgent,
  ]);
  const swarm_session_release: Array<[string, string]> = (params.swarmSessionReleases ?? []).map(
    sr => [sr.releaseId, sr.sessionId],
  );
  const lockfile_pinned_dep: Array<[string]> = (params.lockfilePinnedDeps ?? []).map(d => [d]);
  const cve_tombstone: Array<[string]> = (params.cveTombstones ?? []).map(d => [d]);
  const release_sbom_dep: Array<[string, string]> = (params.releaseSbomDeps ?? []).map(sd => [
    sd.releaseId,
    sd.depDigest,
  ]);
  const build_attestation: Array<[string, string, string, string]> = (
    params.buildAttestations ?? []
  ).map(ba => [ba.releaseId, ba.builderId, ba.artifactDigest, ba.hermetic ? 'yes' : 'no']);
  const expected_enclave_measurement: Array<[string, string]> = (
    params.expectedEnclaveMeasurements ?? []
  ).map(em => [em.releaseId, em.artifactDigest]);
  const enclave_quote: Array<[string, string, string, string, string]> = (
    params.enclaveQuotes ?? []
  ).map(eq => [
    eq.releaseId,
    eq.platformId,
    eq.measuredDigest,
    eq.debugDisabled ? 'yes' : 'no',
    eq.tcbOk ? 'yes' : 'no',
  ]);
  const revoked_tee_platform: Array<[string]> = (params.revokedTeePlatforms ?? []).map(p => [p]);
  const tee_quote_nonce: Array<[string, string]> = (params.teeQuoteNonces ?? []).map(n => [
    n.releaseId,
    n.nonce,
  ]);
  const tenant_active_key_epoch: Array<[string, string]> = (
    params.tenantActiveKeyEpochs ?? []
  ).map(t => [t.tenantId, String(t.epoch)]);
  const shredded_key_epoch: Array<[string, string]> = (params.shreddedKeyEpochs ?? []).map(s => [
    s.tenantId,
    String(s.epoch),
  ]);
  const release_aead_write: Array<[string, string, string]> = (params.releaseAeadWrites ?? []).map(
    w => [w.releaseId, w.tenantId, String(w.writeEpoch)],
  );
  const release_aead_read: Array<[string, string, string, string]> = (
    params.releaseAeadReads ?? []
  ).map(r => [r.releaseId, r.tenantId, String(r.readEpoch), r.digestPreserved ? 'yes' : 'no']);
  const pq_allowed_suite: Array<[string]> = (params.pqAllowedSuites ?? []).map(s => [s]);
  const pq_deprecated_suite: Array<[string]> = (params.pqDeprecatedSuites ?? []).map(s => [s]);
  const release_pq_envelope: Array<[string, string, string, string, string]> = (
    params.releasePqEnvelopes ?? []
  ).map(e => [
    e.releaseId,
    e.suiteId,
    e.classicalOk ? 'yes' : 'no',
    e.pqOk ? 'yes' : 'no',
    e.domainOk ? 'yes' : 'no',
  ]);
  const pq_ots_leaf_use: Array<[string, string, string]> = (params.pqOtsLeafUses ?? []).map(u => [
    u.releaseId,
    u.signerId,
    String(u.leafIndex),
  ]);
  const zk_forbidden_secret_field: Array<[string]> = (params.zkForbiddenSecretFields ?? []).map(
    f => [f],
  );
  const zk_required_public_field: Array<[string]> = (params.zkRequiredPublicFields ?? []).map(
    f => [f],
  );
  const release_zk_proof: Array<[string, string, string, string, string]> = (
    params.releaseZkProofs ?? []
  ).map(p => [
    p.releaseId,
    p.proverId,
    p.rootOk ? 'yes' : 'no',
    p.sigmaOk ? 'yes' : 'no',
    p.nullifier,
  ]);
  const release_zk_disclosed_field: Array<[string, string]> = (
    params.releaseZkDisclosedFields ?? []
  ).map(d => [d.releaseId, d.fieldId]);
  const geo_allowed_region: Array<[string]> = (params.geoAllowedRegions ?? []).map(r => [r]);
  const geo_sanctioned_region: Array<[string]> = (params.geoSanctionedRegions ?? []).map(r => [r]);
  const release_geo_placement: Array<[string, string, string, string, string]> = (
    params.releaseGeoPlacements ?? []
  ).map(g => [
    g.releaseId,
    g.sourceRegion,
    g.targetRegion,
    g.inferenceEndpointRegion,
    g.attestationOk ? 'yes' : 'no',
  ]);
  const geo_transfer_permit: Array<[string, string, string, string]> = (
    params.geoTransferPermits ?? []
  ).map(p => [p.releaseId, p.sourceRegion, p.targetRegion, p.permitOk ? 'yes' : 'no']);
  const fed_ratified_treaty: Array<[string]> = (params.fedRatifiedTreaties ?? []).map(t => [t]);
  const fed_revoked_org: Array<[string]> = (params.fedRevokedOrgs ?? []).map(o => [o]);
  const fed_dispute_freeze: Array<[string]> = (params.fedDisputeFreezes ?? []).map(t => [t]);
  const release_fed_reciprocity: Array<[string, string, string, string, string]> = (
    params.releaseFedReciprocities ?? []
  ).map(f => [
    f.releaseId,
    f.treatyId,
    f.originOrgId,
    f.targetOrgId,
    f.bilateralOk ? 'yes' : 'no',
  ]);
  const model_pinned_weight: Array<[string, string]> = (params.modelPinnedWeights ?? []).map(m => [
    m.modelId,
    m.weightRoot,
  ]);
  const model_approved_adapter: Array<[string]> = (params.modelApprovedAdapters ?? []).map(a => [a]);
  const model_revoked_id: Array<[string]> = (params.modelRevokedIds ?? []).map(id => [id]);
  const release_model_inference: Array<[string, string, string, string, string]> = (
    params.releaseModelInferences ?? []
  ).map(inf => [
    inf.releaseId,
    inf.modelId,
    inf.observedWeightRoot,
    inf.adapterDigest,
    inf.deterministicSamplingOk ? 'yes' : 'no',
  ]);

  const bundle: MetaAuditFactBundle = {
    delegation_edge: dedupeTuples(delegation_edge),
    revoked_principal: dedupeTuples(revoked_principal),
    belief_proposer: dedupeTuples(belief_proposer),
    belief_has_oracle: dedupeTuples(belief_has_oracle),
    belief_sole_dep: dedupeTuples(belief_sole_dep),
    retracted_belief: dedupeTuples(retracted_belief),
    base_taint: dedupeTuples(base_taint),
    derived_from: dedupeTuples(derived_from),
    declassified_tag: dedupeTuples(declassified_tag),
    sink_emits: dedupeTuples(sink_emits),
    sink_allows: dedupeTuples(sink_allows),
    witness_sth: dedupeTuples(witness_sth),
    release_proposal: dedupeTuples(release_proposal),
    release_uses_belief: dedupeTuples(release_uses_belief),
    saga_pivot_crossed: dedupeTuples(saga_pivot_crossed),
    saga_rollback_attempted: dedupeTuples(saga_rollback_attempted),
    witness_roster: dedupeTuples(witness_roster),
    witness_cosign: dedupeTuples(witness_cosign),
    claimed_finalized: dedupeTuples(claimed_finalized),
    release_requires_finality: dedupeTuples(release_requires_finality),
    slashed_witness: dedupeTuples(slashed_witness),
    next_epoch_roster: dedupeTuples(next_epoch_roster),
    mcp_tool_pinned_schema: dedupeTuples(mcp_tool_pinned_schema),
    mcp_tool_invoked: dedupeTuples(mcp_tool_invoked),
    context_pinned_constraint: dedupeTuples(context_pinned_constraint),
    distillation_retained: dedupeTuples(distillation_retained),
    swarm_wait_edge: dedupeTuples(swarm_wait_edge),
    swarm_session_release: dedupeTuples(swarm_session_release),
    lockfile_pinned_dep: dedupeTuples(lockfile_pinned_dep),
    cve_tombstone: dedupeTuples(cve_tombstone),
    release_sbom_dep: dedupeTuples(release_sbom_dep),
    build_attestation: dedupeTuples(build_attestation),
    expected_enclave_measurement: dedupeTuples(expected_enclave_measurement),
    enclave_quote: dedupeTuples(enclave_quote),
    revoked_tee_platform: dedupeTuples(revoked_tee_platform),
    tee_quote_nonce: dedupeTuples(tee_quote_nonce),
    tenant_active_key_epoch: dedupeTuples(tenant_active_key_epoch),
    shredded_key_epoch: dedupeTuples(shredded_key_epoch),
    release_aead_write: dedupeTuples(release_aead_write),
    release_aead_read: dedupeTuples(release_aead_read),
    pq_allowed_suite: dedupeTuples(pq_allowed_suite),
    pq_deprecated_suite: dedupeTuples(pq_deprecated_suite),
    release_pq_envelope: dedupeTuples(release_pq_envelope),
    pq_ots_leaf_use: dedupeTuples(pq_ots_leaf_use),
    zk_forbidden_secret_field: dedupeTuples(zk_forbidden_secret_field),
    zk_required_public_field: dedupeTuples(zk_required_public_field),
    release_zk_proof: dedupeTuples(release_zk_proof),
    release_zk_disclosed_field: dedupeTuples(release_zk_disclosed_field),
    geo_allowed_region: dedupeTuples(geo_allowed_region),
    geo_sanctioned_region: dedupeTuples(geo_sanctioned_region),
    release_geo_placement: dedupeTuples(release_geo_placement),
    geo_transfer_permit: dedupeTuples(geo_transfer_permit),
    fed_ratified_treaty: dedupeTuples(fed_ratified_treaty),
    fed_revoked_org: dedupeTuples(fed_revoked_org),
    fed_dispute_freeze: dedupeTuples(fed_dispute_freeze),
    release_fed_reciprocity: dedupeTuples(release_fed_reciprocity),
    model_pinned_weight: dedupeTuples(model_pinned_weight),
    model_approved_adapter: dedupeTuples(model_approved_adapter),
    model_revoked_id: dedupeTuples(model_revoked_id),
    release_model_inference: dedupeTuples(release_model_inference),
  };

  const factBundleMerkleHash = params.kv.putBlob('ascent-meta-audit-fact-bundle', bundle, []);
  params.kv.pinHistoricalCut(factBundleMerkleHash);
  return {bundle, factBundleMerkleHash};
}

export function serializeFactBundleToSchemeAlist(bundle: MetaAuditFactBundle): string {
  const keys = Object.keys(bundle) as Array<keyof MetaAuditFactBundle>;
  const entries = keys.map(k => {
    const rows = bundle[k].map(
      row => `(${row.map(cell => escapeSchemeString(cell)).join(' ')})`,
    );
    return `(${k} . (${rows.join(' ')}))`;
  });
  return `(${entries.join('\n ')})\n`;
}

export function parseFramedAscentOutput(rawStdout: string): AscentOracleRunVerdict {
  const start = rawStdout.indexOf(BEGIN_MARKER);
  const end = rawStdout.indexOf(END_MARKER);
  if (start === -1 || end === -1 || end <= start) {
    return {kind: 'SetupDefect', reason: 'missing-framed-ascent-json-markers'};
  }
  const body = rawStdout.slice(start + BEGIN_MARKER.length, end).trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    return {
      kind: 'SetupDefect',
      reason: `invalid-ascent-json: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!parsed || typeof parsed !== 'object') {
    return {kind: 'SetupDefect', reason: 'ascent-json-not-object'};
  }
  const obj = parsed as Record<string, unknown>;
  const requiredFields: Array<keyof AscentMetaAuditOutput> = [
    'effectively_revoked',
    'belief_poisoned',
    'tainted_value',
    'exfiltration_violation',
    'equivocation_violation',
    'byzantine_witness_equivocation',
    'invalid_witness_cosign',
    'quorum_3_verified',
    'sub_quorum_finality_violation',
    'split_world_finality_breach',
    'slashed_witness_reentry_violation',
    'mcp_tool_violation',
    'distillation_amnesia_violation',
    'swarm_deadlock_cycle',
    'supply_chain_dep_violation',
    'reproducible_build_violation',
    'enclave_attestation_violation',
    'enclave_nonce_replay_violation',
    'key_rotation_write_violation',
    'crypto_shred_read_violation',
    'pq_agility_violation',
    'pq_ots_reuse_violation',
    'zk_disclosure_violation',
    'zk_nullifier_replay_violation',
    'geo_residency_violation',
    'geo_cross_border_violation',
    'fed_reciprocity_violation',
    'fed_dispute_freeze_violation',
    'model_weight_violation',
    'model_adapter_violation',
    'release_disqualified',
    'release_admitted',
  ];
  for (const field of requiredFields) {
    if (!Array.isArray(obj[field])) {
      return {kind: 'SetupDefect', reason: `missing-ascent-output-relation:${field}`};
    }
  }
  const output = obj as unknown as AscentMetaAuditOutput;
  return {
    kind: 'Verified',
    output,
    outputDigest: sha256Digest(output),
    durationMs: 0,
  };
}

const DEFAULT_REPO_ROOT = resolve(import.meta.dir, '../../..');
const LIVE_ASCENT_M1_CACHE = new Map<string, AscentOracleRunVerdict>();

export function isGerbilAscentRuntimeAvailable(repoRoot = DEFAULT_REPO_ROOT): boolean {
  const compiledLib = resolve(
    repoRoot,
    '.gerbil/lib/deterministic-engineering/library/defensive-governance/func.ssi',
  );
  if (!existsSync(compiledLib)) return false;
  const probe = spawnSync('gerbil', ['version'], {encoding: 'utf8'});
  return !probe.error && probe.status === 0;
}

/**
 * Invokes the live compiled Gerbil Scheme ASCENT Datalog engine (`gxi`) over stdin/stdout.
 * Returns explicit epistemic `PendingMethod` if Gerbil is unavailable (never silent ok:true!).
 */
export function runLiveGerbilAscentMetaAudit(
  bundle: MetaAuditFactBundle,
  opts?: {repoRoot?: string; gerbilBinary?: string},
): AscentOracleRunVerdict {
  const repoRoot = opts?.repoRoot ?? DEFAULT_REPO_ROOT;
  const gerbilBin = opts?.gerbilBinary ?? 'gerbil';
  const cacheKey =
    !opts?.gerbilBinary && !opts?.repoRoot ? sha256Digest(bundle) : undefined;
  if (cacheKey) {
    const cached = LIVE_ASCENT_M1_CACHE.get(cacheKey);
    if (cached) return cached;
  }
  const compiledLib = resolve(
    repoRoot,
    '.gerbil/lib/deterministic-engineering/library/defensive-governance/func.ssi',
  );
  if (!existsSync(compiledLib)) {
    return {kind: 'PendingMethod', reason: 'gerbil-runtime-unavailable'};
  }

  const schemeDriver = `
(import :clan/poo/object
        :deterministic-engineering/library/defensive-governance/func)
(let* ((facts (read))
       (res (reason-durable-governance-meta-audit facts))
       (rows-of (.ref res 'rows-of))
       (emit-str (lambda (s) (write s)))
       (emit-list (lambda (xs emit-item)
                    (display "[")
                    (let loop ((rem xs) (first #t))
                      (when (pair? rem)
                        (unless first (display ","))
                        (emit-item (car rem))
                        (loop (cdr rem) #f)))
                    (display "]")))
       (emit-rows (lambda (rows) (emit-list rows (lambda (r) (emit-list r emit-str)))))
       (keys '(effectively_revoked belief_poisoned tainted_value exfiltration_violation
               equivocation_violation byzantine_witness_equivocation invalid_witness_cosign
               quorum_3_verified sub_quorum_finality_violation split_world_finality_breach
               slashed_witness_reentry_violation mcp_tool_violation
               distillation_amnesia_violation swarm_deadlock_cycle
               supply_chain_dep_violation reproducible_build_violation
               enclave_attestation_violation enclave_nonce_replay_violation
               key_rotation_write_violation crypto_shred_read_violation
               pq_agility_violation pq_ots_reuse_violation
               zk_disclosure_violation zk_nullifier_replay_violation
               geo_residency_violation geo_cross_border_violation
               fed_reciprocity_violation fed_dispute_freeze_violation
               model_weight_violation model_adapter_violation
               release_disqualified release_admitted)))
  (display "${BEGIN_MARKER}\\n{")
  (let loop ((ks keys) (first #t))
    (when (pair? ks)
      (unless first (display ","))
      (emit-str (symbol->string (car ks)))
      (display ":")
      (emit-rows (rows-of (car ks)))
      (loop (cdr ks) #f)))
  (display "}\\n${END_MARKER}\\n"))
`;

  const inputSexpr = serializeFactBundleToSchemeAlist(bundle);
  const t0 = Date.now();
  const proc = spawnSync(
    gerbilBin,
    ['-:max-heap=2G,debug=q', 'env', 'gxi', '-e', schemeDriver],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        GERBIL_LOADPATH: resolve(repoRoot, '.gerbil/lib'),
      },
      input: inputSexpr,
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  const durationMs = Date.now() - t0;

  if (proc.error) {
    const code = (proc.error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return {kind: 'PendingMethod', reason: 'gerbil-runtime-unavailable'};
    }
    return {kind: 'SetupDefect', reason: `gerbil-spawn-error: ${proc.error.message}`};
  }
  if (proc.status !== 0) {
    return {
      kind: 'SetupDefect',
      reason: `gerbil-exit-${proc.status}: ${(proc.stderr || proc.stdout).slice(0, 300)}`,
    };
  }

  const parsed = parseFramedAscentOutput(proc.stdout);
  if (parsed.kind === 'Verified') {
    const verified: AscentOracleRunVerdict = {...parsed, durationMs};
    if (cacheKey) LIVE_ASCENT_M1_CACHE.set(cacheKey, verified);
    return verified;
  }
  return parsed;
}

/**
 * N-Version Cross-Language Agreement Gate:
 * Requires BOTH the imperative TypeScript Coordinator AND the independent declarative
 * Gerbil Scheme ASCENT Datalog Oracle to agree before admitting a release.
 */
export function verifyReleaseWithIndependentAscentOracle(params: {
  releaseId: string;
  imperativeTsVerdict: 'ADMIT' | 'REFUSE';
  bundle: MetaAuditFactBundle;
  factBundleMerkleHash: string;
  kv: ContentAddressedKvStore;
  oracleRunner?: (bundle: MetaAuditFactBundle) => AscentOracleRunVerdict;
}): DualOracleReleaseVerdict {
  const runner = params.oracleRunner ?? runLiveGerbilAscentMetaAudit;
  const oracleRes = runner(params.bundle);

  if (oracleRes.kind === 'PendingMethod') return oracleRes;
  if (oracleRes.kind === 'SetupDefect') return oracleRes;

  const disqReasons = oracleRes.output.release_disqualified
    .filter(row => row[0] === params.releaseId)
    .map(row => row[1] ?? 'unknown')
    .sort();
  const oracleAdmitted = oracleRes.output.release_admitted.some(row => row[0] === params.releaseId);

  if (params.imperativeTsVerdict === 'ADMIT' && (!oracleAdmitted || disqReasons.length > 0)) {
    // CRITICAL N-Version Catch: imperative TS coordinator had a bug/compromise, Scheme Datalog caught it!
    const disagreementReceiptHash = params.kv.putBlob(
      'dual-oracle-disagreement-forensic',
      {
        releaseId: params.releaseId,
        imperativeTsVerdict: params.imperativeTsVerdict,
        oracleAdmitted,
        ascentDisqualificationReasons: disqReasons,
        factBundleMerkleHash: params.factBundleMerkleHash,
        oracleOutputDigest: oracleRes.outputDigest,
      },
      [params.factBundleMerkleHash],
    );
    params.kv.pinHistoricalCut(disagreementReceiptHash);
    return {
      kind: 'Refuted',
      reason: 'oracle-disagreement-fail-closed',
      disagreementReceiptHash,
      ascentDisqualificationReasons: disqReasons,
    };
  }

  if (params.imperativeTsVerdict !== 'ADMIT') {
    const receiptHash = params.kv.putBlob(
      'dual-oracle-refusal-receipt',
      {
        releaseId: params.releaseId,
        imperativeTsVerdict: params.imperativeTsVerdict,
        ascentDisqualificationReasons: disqReasons,
        factBundleMerkleHash: params.factBundleMerkleHash,
      },
      [params.factBundleMerkleHash],
    );
    params.kv.pinHistoricalCut(receiptHash);
    return {
      kind: 'Refuted',
      reason: 'imperative-coordinator-refused',
      disagreementReceiptHash: receiptHash,
      ascentDisqualificationReasons: disqReasons,
    };
  }

  // Both heterogeneous engines independently verified ADMIT -> pin DualOracleAdmissionReceipt!
  const dualAdmissionReceiptHash = params.kv.putBlob(
    'dual-oracle-admission-receipt',
    {
      releaseId: params.releaseId,
      imperativeTsVerdict: 'ADMIT',
      declarativeSchemeAscentVerdict: 'ADMIT',
      factBundleMerkleHash: params.factBundleMerkleHash,
      oracleOutputDigest: oracleRes.outputDigest,
    },
    [params.factBundleMerkleHash],
  );
  params.kv.pinHistoricalCut(dualAdmissionReceiptHash);

  return {
    kind: 'Proven',
    releaseId: params.releaseId,
    dualAdmissionReceiptHash,
    factBundleMerkleHash: params.factBundleMerkleHash,
    oracleOutputDigest: oracleRes.outputDigest,
  };
}
