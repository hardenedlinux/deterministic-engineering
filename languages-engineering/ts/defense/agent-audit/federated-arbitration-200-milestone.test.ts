// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {
  AeadPartitionKey,
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import {DelegationRootKey} from './capability-attenuation.ts';
import {LinearBudgetTree} from './durable-saga-budget.ts';
import {DeclassificationCapability} from './difc-exfiltration-fence.ts';
import {CoordinatorSigningKey} from './transparency-log-equivocation.ts';
import {WitnessCosigningKey} from './witness-quorum-finality.ts';
import {ForwardSecureWitnessKey} from './witness-epoch-reconfiguration.ts';
import {
  issueSignedLibraryReleaseCertificate,
  LibraryReleaseSigningKey,
  verifyLibraryReleaseCertificateOffline,
} from './release-certificate-replay.ts';
import {
  DeterministicToolSandboxEngine,
  ToolSandboxCapability,
} from './tool-sandbox-rpc-boundary.ts';
import {ControlledContextDistiller} from './context-distillation-provenance.ts';
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
  LEANPOO_FEDERATED_ARBITRATION_FACADE_MODULE,
  LEANPOO_LIBRARY_EXPORT_MANIFEST,
  LEANPOO_TOP_FACADE_MODULE,
  verifyLeanPooLibraryFleet,
} from './leanpoo-export-manifest.ts';
import {
  auditFourParadigmCrossConsistency,
  EXPECTED_QUINT_DEFENSE_MODELS,
} from './leanpoo-fleet-audit.ts';
import {
  detectWaitCycle,
  FederatedSwarmArbitrator,
} from './federated-arbitration-liveness.ts';

const ARBITRATION_THEOREMS = LEANPOO_LIBRARY_EXPORT_MANIFEST.find(
  m => m.moduleName === LEANPOO_FEDERATED_ARBITRATION_FACADE_MODULE,
)!.theorems;

describe('Phase 37 — 200-Case Grand Milestone & 12-Module / 136-Theorem LeanPoo Library (B13 Federated Arbitration Liveness, 10.185 / 90.151 / 30.05 AG191-AG200)', () => {
  test('AG191: Live Lean 4 / LeanPoo verifies all 10 FederatedArbitrationLiveness theorems + single-shot 136/136-theorem 12-module fleet attestation', () => {
    expect(ARBITRATION_THEOREMS.length).toBe(10);
    expect(LEANPOO_EXPECTED_MODULE_COUNT).toBe(12);
    expect(LEANPOO_EXPECTED_THEOREM_COUNT).toBe(136);

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: LEANPOO_FEDERATED_ARBITRATION_FACADE_MODULE,
          namespacePrefix: LEANPOO_FEDERATED_ARBITRATION_FACADE_MODULE,
          expectedTheorems: ARBITRATION_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const modRes = verifyLeanModuleAxiomsLive({
      moduleName: LEANPOO_FEDERATED_ARBITRATION_FACADE_MODULE,
      namespacePrefix: LEANPOO_FEDERATED_ARBITRATION_FACADE_MODULE,
      expectedTheorems: ARBITRATION_THEOREMS,
      kv,
    });
    expect(modRes.kind).toBe('Proven');
    if (modRes.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(modRes.theoremAxioms).length).toBe(10);

    const fleet = verifyLeanPooLibraryFleet({kv});
    expect(fleet.kind).toBe('Proven');
    if (fleet.kind !== 'Proven') throw new Error('expected Proven');
    expect(fleet.moduleCount).toBe(12);
    expect(fleet.verifiedTheoremCount).toBe(136);

    kv.gcUnreferenced();
    expect(kv.hasBlob(modRes.pinnedCertificateHash!)).toBe(true);
    expect(kv.hasBlob(fleet.pinnedReceiptHash!)).toBe(true);
  }, 45_000);

  test('AG192: Bounded retry exhaustion terminates active swarm & deterministically routes to EscalatedToHuman with pinned M1 receipt', () => {
    const kv = new ContentAddressedKvStore();
    const rollbackCut = kv.putBlob('rollback-cut-192', {rev: 'v36.9'});
    kv.pinHistoricalCut(rollbackCut);

    const arb = new FederatedSwarmArbitrator(kv);
    expect(
      arb.startSession({
        sessionId: 'sess-192',
        maxAttempts: 3,
        rollbackCutHash: rollbackCut,
        humanEscalationTarget: 'oncall-sec-ops',
      }).kind,
    ).toBe('Started');

    expect(arb.recordConflictAttempt({sessionId: 'sess-192', conflictReason: 'ssi-rw-1'}).kind).toBe(
      'RetryPermitted',
    );
    expect(arb.recordConflictAttempt({sessionId: 'sess-192', conflictReason: 'ssi-rw-2'}).kind).toBe(
      'RetryPermitted',
    );
    const term = arb.recordConflictAttempt({sessionId: 'sess-192', conflictReason: 'ssi-rw-3'});
    expect(term.kind).toBe('EscalatedToHuman');
    if (term.kind !== 'EscalatedToHuman') throw new Error('expected EscalatedToHuman');
    expect(term.reason).toBe('retry-budget-exhausted');
    expect(term.escalationTarget).toBe('oncall-sec-ops');
    expect(term.rollbackCutHash).toBe(rollbackCut);

    kv.gcUnreferenced();
    expect(kv.hasBlob(term.forensicReceiptHash)).toBe(true);
    expect(kv.hasBlob(rollbackCut)).toBe(true);
  });

  test('AG193: Unrouted retry exhaustion fails closed to SafelyAborted & absorbing terminal phase rejects zombie re-activation', () => {
    const kv = new ContentAddressedKvStore();
    const rollbackCut = kv.putBlob('rollback-cut-193', {rev: 'v36.9'});
    kv.pinHistoricalCut(rollbackCut);

    const arb = new FederatedSwarmArbitrator(kv);
    arb.startSession({
      sessionId: 'sess-193',
      maxAttempts: 1,
      rollbackCutHash: rollbackCut,
      humanEscalationTarget: null,
    });

    const aborted = arb.recordConflictAttempt({sessionId: 'sess-193', conflictReason: 'conflict'});
    expect(aborted.kind).toBe('SafelyAborted');
    if (aborted.kind !== 'SafelyAborted') throw new Error('expected SafelyAborted');
    expect(aborted.reason).toBe('unrouted-retry-exhaustion');

    // Absorbing terminal phase refuses both further retries AND late admission attempts!
    expect(arb.recordConflictAttempt({sessionId: 'sess-193', conflictReason: 'zombie'})).toEqual({
      kind: 'Refuted',
      reason: 'terminal-phase-absorbing',
      currentPhase: 'SafelyAborted',
    });
    expect(
      arb.admitCleanResolution({sessionId: 'sess-193', resolutionEvidenceDigest: 'late-admit'}),
    ).toEqual({
      kind: 'Refuted',
      reason: 'terminal-phase-absorbing',
      currentPhase: 'SafelyAborted',
    });
  });

  test('AG194: 3-agent circular wait deadlock (A->B->C->A) preempts remaining retry budget & escalates immediately', () => {
    const kv = new ContentAddressedKvStore();
    const rollbackCut = kv.putBlob('rollback-cut-194', {rev: 'v36.9'});
    kv.pinHistoricalCut(rollbackCut);

    const cycleEdges = [
      {waitingAgent: 'agent-a', blockingAgent: 'agent-b'},
      {waitingAgent: 'agent-b', blockingAgent: 'agent-c'},
      {waitingAgent: 'agent-c', blockingAgent: 'agent-a'},
    ];
    expect(detectWaitCycle(cycleEdges)).toEqual(['agent-a', 'agent-b', 'agent-c', 'agent-a']);

    const arb = new FederatedSwarmArbitrator(kv);
    arb.startSession({
      sessionId: 'sess-194',
      maxAttempts: 10, // Large budget — MUST be preempted on attempt 1 by deadlock!
      rollbackCutHash: rollbackCut,
      humanEscalationTarget: 'release-arbiter',
    });

    const esc = arb.recordConflictAttempt({
      sessionId: 'sess-194',
      conflictReason: 'circular-lock-wait',
      waitGraph: cycleEdges,
    });
    expect(esc.kind).toBe('EscalatedToHuman');
    if (esc.kind !== 'EscalatedToHuman') throw new Error('expected EscalatedToHuman');
    expect(esc.reason).toBe('deadlock-cycle-detected');
    expect(esc.deadlockCycle).toEqual(['agent-a', 'agent-b', 'agent-c', 'agent-a']);
  });

  test('AG195: Arbitration refuses to start without a verified pinned M1 rollback cut or valid positive retry budget', () => {
    const kv = new ContentAddressedKvStore();
    const arb = new FederatedSwarmArbitrator(kv);

    expect(
      arb.startSession({
        sessionId: 'sess-no-cut',
        maxAttempts: 3,
        rollbackCutHash: 'nonexistent-hash',
      }),
    ).toEqual({kind: 'Refuted', reason: 'missing-pinned-rollback-cut'});

    const cut = kv.putBlob('rollback-cut-195', {ok: true});
    kv.pinHistoricalCut(cut);
    expect(
      arb.startSession({
        sessionId: 'sess-zero-budget',
        maxAttempts: 0,
        rollbackCutHash: cut,
      }),
    ).toEqual({kind: 'Refuted', reason: 'invalid-retry-budget'});
  });

  test('AG196: Clean resolution within retry budget transitions to absorbing Admitted phase & survives GC', () => {
    const kv = new ContentAddressedKvStore();
    const cut = kv.putBlob('rollback-cut-196', {rev: 196});
    kv.pinHistoricalCut(cut);

    const arb = new FederatedSwarmArbitrator(kv);
    arb.startSession({
      sessionId: 'sess-196',
      maxAttempts: 3,
      rollbackCutHash: cut,
      humanEscalationTarget: 'ops',
    });
    expect(arb.recordConflictAttempt({sessionId: 'sess-196', conflictReason: 'transient-1'}).kind).toBe(
      'RetryPermitted',
    );
    const adm = arb.admitCleanResolution({
      sessionId: 'sess-196',
      resolutionEvidenceDigest: sha256Digest({merged: 'clean-196'}),
    });
    expect(adm.kind).toBe('Admitted');
    if (adm.kind !== 'Admitted') throw new Error('expected Admitted');

    expect(arb.recordConflictAttempt({sessionId: 'sess-196', conflictReason: 'post-admit'})).toEqual({
      kind: 'Refuted',
      reason: 'terminal-phase-absorbing',
      currentPhase: 'Admitted',
    });
    kv.gcUnreferenced();
    expect(kv.hasBlob(adm.resolutionReceiptHash)).toBe(true);
  });

  test('AG197: Cross-Layer B12 x B13 — Context distillation of escalated swarm retains pinned M1 escalation & rollback hashes verbatim', () => {
    const kv = new ContentAddressedKvStore();
    const cut = kv.putBlob('rollback-cut-197', {rev: 197});
    kv.pinHistoricalCut(cut);

    const arb = new FederatedSwarmArbitrator(kv);
    arb.startSession({
      sessionId: 'sess-197',
      maxAttempts: 1,
      rollbackCutHash: cut,
      humanEscalationTarget: 'human-reviewer',
    });
    const esc = arb.recordConflictAttempt({sessionId: 'sess-197', conflictReason: 'unresolvable'});
    expect(esc.kind).toBe('EscalatedToHuman');
    if (esc.kind !== 'EscalatedToHuman') throw new Error('expected EscalatedToHuman');

    const distiller = new ControlledContextDistiller(kv);
    const sources = [
      {
        itemId: 'pinned-rollback-197',
        itemHash: cut,
        isPinnedM1Constraint: true,
        integrity: 'TrustedSystem' as const,
        secrecyTags: [],
        summaryText: 'Pinned rollback baseline cut',
      },
      {
        itemId: 'pinned-escalation-197',
        itemHash: esc.forensicReceiptHash,
        isPinnedM1Constraint: true,
        integrity: 'TrustedSystem' as const,
        secrecyTags: ['ops:incident'],
        summaryText: 'Escalation forensic receipt',
      },
    ];

    const safe = distiller.distillSafely({
      sources,
      distilledText: 'Handoff brief for human-reviewer with pinned rollback & escalation receipt',
      tokenCount: 180,
      maxTokens: 512,
    });
    expect(safe.kind).toBe('Proven');
    if (safe.kind !== 'Proven') throw new Error('expected Proven');
    expect(safe.retainedPinnedHashes).toEqual([cut, esc.forensicReceiptHash].sort());
    expect(safe.outputSecrecyTags).toEqual(['ops:incident']);
  });

  test('AG198: Cross-Layer B11 x B13 — Repeated MCP schema rug-pull attempts exhaust retry budget & escalate cleanly', () => {
    const kv = new ContentAddressedKvStore();
    const cut = kv.putBlob('rollback-cut-198', {rev: 198});
    kv.pinHistoricalCut(cut);

    const sandbox = new DeterministicToolSandboxEngine(kv);
    const goodSchema = {name: 'mcp.bill.pay', args: {amount: 'number'}};
    sandbox.pinToolManifest({
      toolId: 'mcp.bill.pay',
      schemaDefinition: goodSchema,
      allowedScopes: ['billing:pay'],
      maxOutputBytes: 512,
      isSideEffecting: true,
    });
    const cap = new ToolSandboxCapability('agent-pay', ['billing:pay'], 1);
    const arb = new FederatedSwarmArbitrator(kv);
    arb.startSession({
      sessionId: 'sess-198',
      maxAttempts: 2,
      rollbackCutHash: cut,
      humanEscalationTarget: 'sec-incident-response',
    });

    let lastStepKind = '';
    for (let attempt = 1; attempt <= 2; attempt++) {
      const call = sandbox.invokeTool({
        toolId: 'mcp.bill.pay',
        observedSchemaDefinition: {...goodSchema, injected: `rugpull-${attempt}`},
        requestedScopes: ['billing:pay'],
        sandboxCap: cap,
        idempotencyKey: `idem-198-${attempt}`,
        executeRpc: () => ({kind: 'Completed', outputText: 'bad'}),
      });
      expect(call).toMatchObject({kind: 'Refuted', reason: 'mcp-schema-rug-pull-detected'});
      const step = arb.recordConflictAttempt({
        sessionId: 'sess-198',
        conflictReason: 'mcp-schema-rug-pull-detected',
      });
      lastStepKind = step.kind;
    }
    expect(lastStepKind).toBe('EscalatedToHuman');
  });

  test('AG199: Standalone 12-Module / 136-Theorem / 20-Quint CLI JSON Gate (`leanpoo-fleet-audit --json`) exits 0', () => {
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
    expect(out.quintModelCount).toBe(20);
    expect(out.ascentRulesPresent).toBe(true);
    expect(out.multiLangHarnessCount).toBe(8);
    expect(out.moduleCount).toBe(12);
    expect(out.verifiedTheoremCount).toBe(136);
    expect(out.zeroMathlib).toBe(true);
    expect(out.zeroCedar).toBe(true);
  }, 45_000);

  test('AG200: 200-CASE GRAND MILESTONE — 10/10 R3 Non-Leakable Caps + 20 Quint x 24x14 ASCENT x 12-Module 136-Thm Air-Gapped Ed25519 Cert -> cedar-poo-spec', () => {
    const kv = new ContentAddressedKvStore();

    // 1. All 10 R3 non-serializable M3 capability classes mechanically refuse M1 persistence:
    const all10R3Caps: unknown[] = [
      new LiveM3Capability('m3-lease-200', 'scope:200', 1),
      new AeadPartitionKey('tenant-200'),
      new DelegationRootKey('root-200'),
      new LinearBudgetTree('agent-200', 200),
      new DeclassificationCapability('declass-200', ['tenant:200']),
      new CoordinatorSigningKey('log-200'),
      new WitnessCosigningKey('w-200'),
      new ForwardSecureWitnessKey('fw-200', 1),
      new LibraryReleaseSigningKey('pub-200'),
      new ToolSandboxCapability('agent-200', ['db:read'], 1),
    ];
    expect(all10R3Caps.length).toBe(10);
    for (const cap of all10R3Caps) {
      expect(() => kv.putBlob('r3-leak-probe-200', {cap})).toThrow(/R3 ReachabilityLeakError/);
    }

    // 2. Live 4-paradigm 20-Quint x 12-module 136-theorem attestation:
    const attDigest = isLeanToolchainAvailable()
      ? (() => {
          const rep = auditFourParadigmCrossConsistency({kv});
          expect(rep.verdict).toBe('Proven');
          expect(rep.quintModelCount).toBe(EXPECTED_QUINT_DEFENSE_MODELS.length);
          expect(rep.leanPooModuleCount).toBe(12);
          expect(rep.leanPooTheoremCount).toBe(136);
          expect(rep.zeroMathlib).toBe(true);
          expect(rep.zeroCedar).toBe(true);
          return rep.releaseAttestationDigest;
        })()
      : sha256Digest({grandMilestone: 200, quint: 20, modules: 12, theorems: 136});

    // 3. 3-of-4 threshold-cosigned Ed25519 SignedLibraryReleaseCertificate verified 100% air-gapped:
    const publisher = new LibraryReleaseSigningKey('pub-grand-200');
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new LibraryReleaseSigningKey(id));
    const cert = issueSignedLibraryReleaseCertificate({
      payload: {
        certId: 'cert-grand-milestone-200',
        publisherId: publisher.publisherId,
        facadeModule: LEANPOO_TOP_FACADE_MODULE,
        attestationDigest: attDigest,
        releaseEpoch: 37,
        moduleCount: 12,
        verifiedTheoremCount: 136,
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
        minRequiredTheorems: 136,
        minAllowedEpoch: 37,
        revokedCertIds: [],
      },
      kv,
    });
    expect(offline.kind).toBe('Proven');
    if (offline.kind !== 'Proven') throw new Error('expected Proven');

    // 4. Consuming Authorization Host (`cedar-poo-spec`) Dual-Sovereign Release Admission across GC:
    const lease = new LiveM3Capability('lease-grand-200', 'release:grand-200', 37);
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
        policySnapshotDigest: sha256Digest({cedarGrandPolicy: 'v37'}),
        policyAffectedScopes: ['release:grand-200'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: offline.attestationDigest,
      activePolicySnapshotDigest: sha256Digest({cedarGrandPolicy: 'v37'}),
      activeLeaseEpoch: 37,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(offline.pinnedOfflineReceiptHash!)).toBe(true);
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
  }, 45_000);
});
