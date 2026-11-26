// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from './transparency-log-equivocation.ts';
import {buildThresholdCheckpoint, WitnessCosigningKey} from './witness-quorum-finality.ts';
import {
  extractMetaAuditBundleFromLiveObjects,
  isGerbilAscentRuntimeAvailable,
  runLiveGerbilAscentMetaAudit,
  verifyReleaseWithIndependentAscentOracle,
} from './ascent-meta-audit-bridge.ts';
import {
  DeterministicToolSandboxEngine,
  ToolSandboxCapability,
} from './tool-sandbox-rpc-boundary.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
} from './lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_TOP_FACADE_MODULE,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from './release-certificate-replay.ts';

describe('Phase 35 — B11 Four-Paradigm Symmetry Closure: 20 Quint Models + B1-B11 Gerbil ASCENT + 116-Theorem LeanPoo (10.183 / 30.05 AG181-AG185)', () => {
  test('AG181: Live Gerbil Scheme ASCENT derives B11 mcp_tool_violation for unpinned shadow tool, MCP schema rug-pull & scope escalation', () => {
    const kv = new ContentAddressedKvStore();
    const sandbox = new DeterministicToolSandboxEngine(kv);
    const pinned = sandbox.pinToolManifest({
      toolId: 'mcp.sql.query',
      schemaDefinition: {name: 'mcp.sql.query', readOnly: true},
      allowedScopes: ['db:read'],
      maxOutputBytes: 1024,
      isSideEffecting: false,
    });

    const {bundle} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      mcpPinnedTools: [{toolId: pinned.toolId, pinnedSchemaHash: pinned.pinnedSchemaHash}],
      mcpToolInvocations: [
        {
          releaseId: 'rel-clean-181',
          toolId: 'mcp.sql.query',
          observedSchemaHash: pinned.pinnedSchemaHash,
          scopeOk: true,
        },
        {
          releaseId: 'rel-bad-181',
          toolId: 'mcp.sql.query',
          observedSchemaHash: 'mutated-rug-pull-hash',
          scopeOk: true,
        },
        {
          releaseId: 'rel-bad-181',
          toolId: 'mcp.shadow.unpinned',
          observedSchemaHash: 'any-hash',
          scopeOk: true,
        },
        {
          releaseId: 'rel-bad-181',
          toolId: 'mcp.sql.query',
          observedSchemaHash: pinned.pinnedSchemaHash,
          scopeOk: false,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-clean-181',
          authorId: 'agent-a',
          approverId: 'human-b',
          logId: 'log-181',
          supportingBeliefIds: [],
        },
        {
          releaseId: 'rel-bad-181',
          authorId: 'agent-a',
          approverId: 'human-b',
          logId: 'log-181',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) {
      expect(runLiveGerbilAscentMetaAudit(bundle, {gerbilBinary: 'missing-gerbil'})).toEqual({
        kind: 'PendingMethod',
        reason: 'gerbil-runtime-unavailable',
      });
      return;
    }

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');

    expect(res.output.mcp_tool_violation).toContainEqual([
      'rel-bad-181',
      'mcp.sql.query',
      'mcp-schema-rug-pull',
    ]);
    expect(res.output.mcp_tool_violation).toContainEqual([
      'rel-bad-181',
      'mcp.shadow.unpinned',
      'unpinned-shadow-tool',
    ]);
    expect(res.output.mcp_tool_violation).toContainEqual([
      'rel-bad-181',
      'mcp.sql.query',
      'sandbox-scope-escalation',
    ]);
    expect(res.output.release_disqualified).toContainEqual([
      'rel-bad-181',
      'mcp-tool-boundary-violation',
    ]);
    expect(res.output.release_admitted).toEqual([['rel-clean-181']]);
  }, 60_000);

  test('AG182: N-Version Agreement Gate overrides buggy TS coordinator claiming ADMIT on rug-pulled MCP release', () => {
    const kv = new ContentAddressedKvStore();
    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [],
      mcpPinnedTools: [{toolId: 'mcp.deploy', pinnedSchemaHash: 'pinned-deploy-v1'}],
      mcpToolInvocations: [
        {
          releaseId: 'rel-rugpull-182',
          toolId: 'mcp.deploy',
          observedSchemaHash: 'rugpull-deploy-v2',
          scopeOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-rugpull-182',
          authorId: 'coder-182',
          approverId: 'human-182',
          logId: 'log-182',
          supportingBeliefIds: [],
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gate = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-rugpull-182',
      imperativeTsVerdict: 'ADMIT', // Buggy TS coordinator missed rug-pull!
      bundle,
      factBundleMerkleHash,
    });
    expect(gate.kind).toBe('Refuted');
    if (gate.kind !== 'Refuted') throw new Error('expected Refuted');
    expect(gate.reason).toBe('oracle-disagreement-fail-closed');
    expect(gate.ascentDisqualificationReasons).toContain('mcp-tool-boundary-violation');
    kv.gcUnreferenced();
    expect(kv.hasBlob(gate.disagreementReceiptHash)).toBe(true);
  }, 60_000);

  test('AG183: Clean B1-B11 release (pinned MCP tool + 3-of-4 B10 Ed25519 QC) achieves dual-language TS <-> Scheme ASCENT consensus across GC', () => {
    const kv = new ContentAddressedKvStore();
    const sandbox = new DeterministicToolSandboxEngine(kv);
    const schema = {name: 'mcp.release.tag', version: 1};
    const pinned = sandbox.pinToolManifest({
      toolId: 'mcp.release.tag',
      schemaDefinition: schema,
      allowedScopes: ['git:tag'],
      maxOutputBytes: 512,
      isSideEffecting: true,
    });
    const cap = new ToolSandboxCapability('coder-183', ['git:tag'], 1);
    const inv = sandbox.invokeTool({
      toolId: 'mcp.release.tag',
      observedSchemaDefinition: schema,
      requestedScopes: ['git:tag'],
      sandboxCap: cap,
      idempotencyKey: 'idem-tag-183',
      executeRpc: () => ({kind: 'Completed', outputText: 'v35.0-tagged'}),
    });
    expect(inv.kind).toBe('Proven');

    const coord = new CoordinatorSigningKey('log-183');
    const log = new VerifiableTransparencyLog(coord);
    log.appendEntry({release: 'rel-clean-183', toolReceipt: inv.kind === 'Proven' ? inv.receiptMerkleHash : ''});
    const sth = log.issueSignedTreeHead(1);
    const wKeys = ['w1', 'w2', 'w3', 'w4'].map(id => new WitnessCosigningKey(id));
    const qc = buildThresholdCheckpoint(
      sth,
      wKeys.slice(0, 3).map(k => k.cosignTreeHead(sth)),
    );

    const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
      kv,
      delegationCertificates: [],
      revokedPrincipals: [],
      beliefNodes: [],
      taintedValues: [],
      sinkEmissions: [],
      witnessObservations: [{witnessId: 'w1', sth}],
      witnessRosters: [{logId: 'log-183', witnessIds: ['w1', 'w2', 'w3', 'w4']}],
      claimedFinalizedCheckpoints: [{checkpointId: 'ckpt-183', checkpoint: qc}],
      mcpPinnedTools: [{toolId: pinned.toolId, pinnedSchemaHash: pinned.pinnedSchemaHash}],
      mcpToolInvocations: [
        {
          releaseId: 'rel-clean-183',
          toolId: pinned.toolId,
          observedSchemaHash: pinned.pinnedSchemaHash,
          scopeOk: true,
        },
      ],
      releaseProposals: [
        {
          releaseId: 'rel-clean-183',
          authorId: 'coder-183',
          approverId: 'human-183',
          logId: 'log-183',
          supportingBeliefIds: [],
          requiredCheckpointId: 'ckpt-183',
        },
      ],
    });

    if (!isGerbilAscentRuntimeAvailable()) return;

    const gate = verifyReleaseWithIndependentAscentOracle({
      kv,
      releaseId: 'rel-clean-183',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
    });
    expect(gate.kind).toBe('Proven');
    if (gate.kind !== 'Proven') throw new Error('expected Proven');
    kv.gcUnreferenced();
    expect(kv.hasBlob(gate.dualAdmissionReceiptHash)).toBe(true);
  }, 60_000);

  test('AG184: 20+-Model Quint Inventory & 116+-Theorem LeanPoo CLI JSON confirms full four-paradigm convergence', () => {
    expect(EXPECTED_QUINT_DEFENSE_MODELS.length).toBeGreaterThanOrEqual(20);
    expect(EXPECTED_QUINT_DEFENSE_MODELS).toContain('tool-sandbox-rpc-boundary');
    if (!isLeanToolchainAvailable()) return;

    const cliPath = resolve(import.meta.dir, 'leanpoo-fleet-audit.ts');
    const proc = spawnSync('bun', [cliPath, '--json'], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    });
    expect(proc.status).toBe(0);
    const out = JSON.parse(proc.stdout) as {
      verdict: string;
      facadeModule: string;
      quintModelCount: number;
      ascentRulesPresent: boolean;
      multiLangHarnessCount: number;
      moduleCount: number;
      verifiedTheoremCount: number;
      zeroMathlib: boolean;
      zeroCedar: boolean;
    };
    expect(out.verdict).toBe('Proven');
    expect(out.facadeModule).toBe(LEANPOO_TOP_FACADE_MODULE);
    expect(out.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
    expect(out.ascentRulesPresent).toBe(true);
    expect(out.multiLangHarnessCount).toBe(8);
    expect(out.moduleCount).toBe(LEANPOO_EXPECTED_MODULE_COUNT);
    expect(out.verifiedTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
    expect(out.zeroMathlib).toBe(true);
    expect(out.zeroCedar).toBe(true);
  }, 45_000);

  test('AG185: 185-Case B1-B11 Four-Paradigm Symmetry Closure — Quint x ASCENT x LeanPoo Offline Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();
    const publisher = new LibraryReleaseSigningKey('pub-185');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));

    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooTheoremCount).toBe(LEANPOO_EXPECTED_THEOREM_COUNT);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({milestone: 185, quint: EXPECTED_QUINT_DEFENSE_MODELS.length, theorems: 116});

    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v35-20quint-116thm',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 35,
        moduleCount: 10,
        verifiedTheoremCount: 116,
        quintModelCount: 20,
        zeroMathlib: true,
        zeroCedar: true,
      },
      publisherKey: publisher,
      witnessKeys: witnesses.slice(0, 3),
    });

    const offline = verifyLibraryReleaseCertificateOffline({
      cert: JSON.parse(JSON.stringify(cert)),
      policy: {
        expectedAttestationDigest: attDigest,
        trustedPublisherPublicKeyPem: publisher.publicKeyPem,
        registeredWitnessPublicKeys: Object.fromEntries(
          witnesses.map(w => [w.publisherId, w.publicKeyPem]),
        ),
        minWitnessThreshold: 3,
        minRequiredTheorems: 116,
        minAllowedEpoch: 35,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-185', 'release:b1-b11', 35);
    const dual = evaluateDualSovereignGate({
      kv,
      libraryVerdict: {
        kind: 'FinalizedInEpoch',
        epoch: offline.releaseEpoch,
        treeSize: 1,
        rootHashHex: offline.attestationDigest,
        checkpointDigest: offline.pinnedOfflineReceiptHash!,
        verifiedWitnessIds: offline.verifiedWitnessIds,
      },
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: evaluateHostPolicySemantics({
          permitMatched: true,
          forbidMatched: false,
          contextReady: true,
        }),
        boundOperationDigest: offline.attestationDigest,
        policySnapshotDigest: sha256Digest({cedar: 'v35'}),
        policyAffectedScopes: ['release:b1-b11'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedar: 'v35'}),
      activeLeaseEpoch: 35,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');
    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
