// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {
  ContentAddressedKvStore,
  LiveM3Capability,
  LlmMemoizationLedger,
  PerAgentAsyncCutCoordinator,
  sha256Digest,
} from './durable-merkle-store.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
  WitnessEquivocationMonitor,
} from './transparency-log-equivocation.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';
import {
  LEANPOO_EXPECTED_MODULE_COUNT,
  LEANPOO_EXPECTED_THEOREM_COUNT,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_MERKLE_ASYNC_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {auditFourParadigmCrossConsistency} from './leanpoo-fleet-audit.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from './release-certificate-replay.ts';

const MERKLE_ASYNC_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_MERKLE_ASYNC_FACADE_MODULE,
)!.theorems;

describe('Phase 33 — 106-Theorem LeanPoo Milestone (B9 Merkle Consistency, R2 Async Merge & R4 LLM Drift) (10.181 / 30.05 AG171-AG175)', () => {
  test('AG171: Live Lean 4 / LeanPoo verifies all 10 MerkleConsistencyAndAsyncCut theorems + single-shot 106/106-theorem 9-module fleet attestation', () => {
    expect(MERKLE_ASYNC_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBe(9);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBe(106);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_MERKLE_ASYNC_FACADE_MODULE,
          namespacePrefix: LEANPOO_MERKLE_ASYNC_FACADE_MODULE,
          expectedTheorems: MERKLE_ASYNC_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_MERKLE_ASYNC_FACADE_MODULE,
      namespacePrefix: LEANPOO_MERKLE_ASYNC_FACADE_MODULE,
      expectedTheorems: MERKLE_ASYNC_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(9);
    expect(fleet.verifiedTheoremCount).toBe(106);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG172: B9 RFC 6962 monotonic prefix growth (1->4->9->16) verified via public key & split-view equivocation caught', () => {
    const coord = new CoordinatorSigningKey('log-b9-172');
    const log = new VerifiableTransparencyLog(coord);
    const monitor = new WitnessEquivocationMonitor('log-b9-172', coord.publicKeyPem);

    const checkpoints: number[] = [1, 4, 9, 16];
    let prevSize = 0;
    let total = 0;
    for (const target of checkpoints) {
      while (total < target) {
        log.appendEntry({seq: total, msg: `entry-${total}`});
        total += 1;
      }
      const sth = log.issueSignedTreeHead(target);
      if (prevSize === 0) {
        const res = monitor.observeSignedTreeHead(sth);
        expect(res.kind).toBe('AcceptedConsistent');
      } else {
        const proof = log.getConsistencyProof(prevSize, target);
        const res = monitor.observeSignedTreeHead(sth, proof);
        expect(res.kind).toBe('AcceptedConsistent');
      }
      prevSize = target;
    }

    // Forked log with identical coordinator key & same treeSize=16 but mutated leaf #2 -> EquivocationDetected!
    const forkedLog = new VerifiableTransparencyLog(coord);
    for (let i = 0; i < 16; i++) {
      forkedLog.appendEntry({seq: i, msg: i === 2 ? 'TAMPERED-ENTRY-2' : `entry-${i}`});
    }
    const equivSth = forkedLog.issueSignedTreeHead(16);
    const fraud = monitor.observeSignedTreeHead(equivSth);
    expect(fraud.kind).toBe('EquivocationDetected');
  });

  test('AG173: R2 Chandy-Lamport async branch commits merge disjoint edits cleanly & surface explicit Conflict on divergent edits (no LWW)', () => {
    const kv = new ContentAddressedKvStore();
    const coord = new PerAgentAsyncCutCoordinator(kv);
    const baseFiles = {'a.ts': 'h-a0', 'b.ts': 'h-b0', 'shared.ts': 'h-s0'};

    // Agent A & Agent B make disjoint edits while peer C is blocked (straggler freedom):
    coord.markAgentBlocked('agent-c', true);
    coord.commitAgentBranch('agent-a', {'a.ts': 'h-a1', 'b.ts': 'h-b0', 'shared.ts': 'h-s0'});
    coord.commitAgentBranch('agent-b', {'a.ts': 'h-a0', 'b.ts': 'h-b1', 'shared.ts': 'h-s0'});

    const cleanMerge = coord.mergeTwoBranches(baseFiles, 'agent-a', 'agent-b');
    expect(cleanMerge.kind).toBe('Proven');
    if (cleanMerge.kind !== 'Proven') throw new Error('expected Proven');
    expect(cleanMerge.mergedFiles).toEqual({'a.ts': 'h-a1', 'b.ts': 'h-b1', 'shared.ts': 'h-s0'});

    // Concurrent divergent edits on shared.ts MUST surface explicit Conflict (never silent LWW!):
    coord.commitAgentBranch('agent-a', {'a.ts': 'h-a1', 'b.ts': 'h-b0', 'shared.ts': 'h-s-agentA'});
    coord.commitAgentBranch('agent-b', {'a.ts': 'h-a0', 'b.ts': 'h-b1', 'shared.ts': 'h-s-agentB'});
    const divMerge = coord.mergeTwoBranches(baseFiles, 'agent-a', 'agent-b');
    expect(divMerge).toEqual({kind: 'Conflict', conflictingFiles: ['shared.ts']});
  });

  test('AG174: R4 4-axis LLM semantic-drift memoization reuses M1 on exact match & invalidates on ANY single drifted axis', () => {
    const kv = new ContentAddressedKvStore();
    const ledger = new LlmMemoizationLedger(kv);
    const baseEnv = {
      repoCommitDigest: 'commit-174',
      promptTemplateDigest: 'prompt-v1',
      policyDigest: 'pol-v1',
      modelId: 'model-v1',
    };

    const recorded = ledger.recordLlmStep('step-audit', baseEnv, {summary: 'clean-patch'});
    const exact = ledger.lookupStep<{summary: string}>('step-audit', {...baseEnv});
    expect(exact).toEqual({
      kind: 'ReuseM1',
      m1OutputHash: recorded.m1OutputHash,
      output: {summary: 'clean-patch'},
    });

    // Drifting ANY of the 4 axes MUST return InvalidatedByDrift naming that exact axis:
    const axes = [
      'repoCommitDigest',
      'promptTemplateDigest',
      'policyDigest',
      'modelId',
    ] as const;
    for (const axis of axes) {
      const drifted = ledger.lookupStep('step-audit', {...baseEnv, [axis]: `${baseEnv[axis]}-NEW`});
      expect(drifted).toEqual({
        kind: 'InvalidatedByDrift',
        driftedAxes: [axis],
        priorM1Hash: recorded.m1OutputHash,
      });
    }
  });

  test('AG175: 175-Case & 106-Theorem Grand Closure — Live CLI JSON -> Air-Gapped Ed25519 Cert -> cedar-poo-spec Dual-Sovereign Admission', () => {
    const kv = new ContentAddressedKvStore();
    const publisher = new LibraryReleaseSigningKey('pub-175');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));

    let attDigest = sha256Digest({milestone: 175, theorems: 106});
    if (isLeanToolchainAvailable()) {
      const cliPath = resolve(import.meta.dir, 'leanpoo-fleet-audit.ts');
      const proc = spawnSync('bun', [cliPath, '--json'], {
        encoding: 'utf8',
        maxBuffer: 4 * 1024 * 1024,
      });
      expect(proc.status).toBe(0);
      const cliOut = JSON.parse(proc.stdout) as {
        verdict: string;
        moduleCount: number;
        verifiedTheoremCount: number;
        quintModelCount: number;
        zeroMathlib: boolean;
        zeroCedar: boolean;
        releaseAttestationDigest: string;
      };
      expect(cliOut.verdict).toBe('Proven');
      expect(cliOut.moduleCount).toBe(9);
      expect(cliOut.verifiedTheoremCount).toBe(106);
      expect(cliOut.quintModelCount).toBe(19);
      expect(cliOut.zeroMathlib).toBe(true);
      expect(cliOut.zeroCedar).toBe(true);

      const liveRep = auditFourParadigmCrossConsistency({kv});
      expect(liveRep.verdict).toBe('Proven');
      expect(liveRep.releaseAttestationDigest).toBe(cliOut.releaseAttestationDigest);
      attDigest = liveRep.releaseAttestationDigest;
    }

    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-v33-106-theorems',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_MERKLE_ASYNC_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 33,
        moduleCount: 9,
        verifiedTheoremCount: 106,
        quintModelCount: 19,
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
        minRequiredTheorems: 106,
        minAllowedEpoch: 33,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    const lease = new LiveM3Capability('lease-175-grand', 'release:106-theorems', 33);
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
        policySnapshotDigest: sha256Digest({cedar: 'v33'}),
        policyAffectedScopes: ['release:106-theorems'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedar: 'v33'}),
      activeLeaseEpoch: 33,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
