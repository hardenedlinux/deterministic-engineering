// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from '../src/durable-merkle-store.ts';
import {arbitrateConcurrentWorkspaces} from '../src/symbol-ssi-arbitrator.ts';
import {DurableAgentSagaEngine, LinearBudgetTree} from '../src/durable-saga-budget.ts';
import {
  DeclassificationCapability,
  DifcAgentMonitor,
} from '../src/difc-exfiltration-fence.ts';
import {DurableMemoryTmsStore} from '../src/durable-memory-tms.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from '../src/transparency-log-equivocation.ts';
import {buildThresholdCheckpoint} from '../src/witness-quorum-finality.ts';
import {
  createEpochRoster,
  ForwardSealedEpochVerifier,
  ForwardSecureWitnessKey,
} from '../src/witness-epoch-reconfiguration.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from '../src/host-authorization-bridge.ts';
import {
  auditLeanSourceAntiFabrication,
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from '../src/lean-proof-oracle.ts';

const SAGA_SSI_LEAN_PATH = resolve(
  import.meta.dir,
  '../../lean-models/DeterministicEngineering/Engineering/SagaAndSsi.lean',
);

const SAGA_SSI_THEOREMS = [
  'post_pivot_rollback_always_forbidden',
  'pending_unknown_fences_both_forward_and_rollback',
  'reverse_compensation_covers_all_executed_steps',
  'second_pivot_breaks_at_most_one_pivot',
  'mutual_write_skew_always_blocked',
  'direct_ww_conflict_always_blocked',
  'de01_independent_peer_always_admitted',
  'read_only_agents_never_conflict',
  'sagaSsiContract_preserves_rejection',
  'retryBackoffTuning_preserves_saga_ssi_certificate',
  'disablingPivotFence_invalidates_reuse',
] as const;

describe('Phase 28 150-Case Grand Milestone — LeanPoo Saga & SSI + 52-Theorem Library Verification (10.176 / 30.05 AG146-AG150)', () => {
  test('AG146: Live Lean 4 / LeanPoo oracle verifies all 11 SagaAndSsi theorems carry zero sorry/custom axioms & pins M1 cert', () => {
    const src = readFileSync(SAGA_SSI_LEAN_PATH, 'utf8');
    expect(auditLeanSourceAntiFabrication(src)).toEqual({passed: true, findings: []});

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: 'DeterministicEngineering.Engineering.SagaAndSsi',
          namespacePrefix: 'DeterministicEngineering.Engineering.SagaAndSsi',
          expectedTheorems: SAGA_SSI_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const res = verifyLeanModuleAxiomsLive({
      moduleName: 'DeterministicEngineering.Engineering.SagaAndSsi',
      namespacePrefix: 'DeterministicEngineering.Engineering.SagaAndSsi',
      expectedTheorems: SAGA_SSI_THEOREMS,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(SAGA_SSI_THEOREMS.length);
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG147: 6-step pre-pivot Saga failure triggers exact reverse-order compensation (s4->s3->s2->s1->s0) & conserves linear budget', () => {
    const kv = new ContentAddressedKvStore();
    const budget = new LinearBudgetTree('coordinator', 200);
    const saga = new DurableAgentSagaEngine(kv, budget);

    const compOrder: string[] = [];
    const steps = [0, 1, 2, 3, 4].map(i => ({
      stepId: `s${i}`,
      agentId: 'coordinator',
      reversibility: 'Compensable' as const,
      costUnits: 10,
      compensatorActionName: `undo-s${i}`,
      executeForward: () => ({kind: 'Committed' as const, externalReceiptId: `rcpt-s${i}`}),
      executeCompensate: () => {
        compOrder.push(`s${i}`);
        return {compensated: true};
      },
    }));

    // 6th step fails cleanly pre-pivot -> MUST compensate s4, s3, s2, s1, s0 in exact reverse order!
    steps.push({
      stepId: 's5-fail',
      agentId: 'coordinator',
      reversibility: 'Compensable' as const,
      costUnits: 10,
      compensatorActionName: 'undo-s5',
      executeForward: () => ({kind: 'FailedCleanly' as const, errorCode: 'upstream-rejected'}),
      executeCompensate: () => ({compensated: true}),
    });

    expect(saga.registerSaga('saga-6-step-reverse', steps).kind).toBe('Registered');
    const res = saga.runSaga('saga-6-step-reverse');
    expect(res.kind).toBe('CompensatedRollback');
    expect(compOrder).toEqual(['s4', 's3', 's2', 's1', 's0']);
    expect(budget.conservationAudit().conserved).toBe(true);
  });

  test('AG148: 5-agent concurrent AST Symbol SSI swarm blocks cyclic rw pair (A<->B) while admitting all 3 independent peers (DE01)', () => {
    const kv = new ContentAddressedKvStore();
    const baseFiles = {
      'src/pricing.ts': `
        import {computeTax} from './tax';
        export function calcTotal(net: number): number { return net + computeTax(net); }
      `,
      'src/tax.ts': `
        import {calcTotal} from './pricing';
        export function computeTax(net: number): number { return Math.round(net * 0.1); }
        export function rate(net: number): number { return computeTax(net) / calcTotal(net); }
      `,
      'src/docs.ts': `export const DOC_VER = 1;`,
      'src/metrics.ts': `export const METRICS_VER = 1;`,
      'src/health.ts': `export const HEALTH_VER = 1;`,
    };

    const res = arbitrateConcurrentWorkspaces({
      baseFiles,
      activeLeaseEpoch: 9,
      kv,
      proposals: [
        {
          agentId: 'agent-pricing',
          fencingEpoch: 9,
          modifiedFiles: {
            'src/pricing.ts': `
              import {computeTax} from './tax';
              export function calcTotal(net: number, fee: number): number { return net + fee + computeTax(net); }
            `,
          },
        },
        {
          agentId: 'agent-tax',
          fencingEpoch: 9,
          modifiedFiles: {
            'src/tax.ts': `
              import {calcTotal} from './pricing';
              export function computeTax(net: number, region: string): number { return region ? net * 0.2 : 0; }
              export function rate(net: number): number { return computeTax(net, 'us') / calcTotal(net); }
            `,
          },
        },
        {
          agentId: 'agent-docs',
          fencingEpoch: 9,
          modifiedFiles: {'src/docs.ts': `export const DOC_VER = 2;`},
        },
        {
          agentId: 'agent-metrics',
          fencingEpoch: 9,
          modifiedFiles: {'src/metrics.ts': `export const METRICS_VER = 2;`},
        },
        {
          agentId: 'agent-health',
          fencingEpoch: 9,
          modifiedFiles: {'src/health.ts': `export const HEALTH_VER = 2;`},
        },
      ],
    });

    // Cyclic agents pricing & tax are blocked; all 3 independent peers admit cleanly (DE01)!
    expect(res.admittedAgents.sort()).toEqual(['agent-docs', 'agent-health', 'agent-metrics']);
    expect(res.admittedAgents).not.toContain('agent-pricing');
    expect(res.admittedAgents).not.toContain('agent-tax');
  });

  test('AG149: Complete 52-Theorem LeanPoo Library Live Audit across all 4 modules (zero sorry, zero custom axioms)', () => {
    const modules = [
      {
        name: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
        theorems: [
          'bft_quorum_intersection_honest_witness',
          'bft_no_conflicting_finality',
          'handover_chain_monotonic',
          'handover_chain_rejects_all_retired_epochs',
          'm1_persistable_forbids_any_m3_descendant',
          'm3_leak_always_refused',
          'split_preserves_total_budget',
          'spend_preserves_total_budget',
          'attenuation_chain_bounded_by_root',
          'ancestor_revocation_invalidates_chain',
          'durableQuorumContract_preserves_rejection',
          'hostPolicyRefinement_preserves_library_rejection',
          'gossipTuning_preserves_quorum_certificate',
          'batchSizeTuning_preserves_quorum_certificate',
          'droppingExternalPolicyHost_invalidates_reuse',
          'slashed_witness_is_byzantine',
          'slashed_witness_never_reenters_future_epochs',
          'hostPolicyOverSlashing_preserves_library_rejection',
          'droppingSlashReentryGuard_invalidates_reuse',
        ],
      },
      {
        name: 'DeterministicEngineering.Engineering.HostAuthorizationBridge',
        theorems: [
          'forbid_always_overrides_permit',
          'default_deny_when_no_permit',
          'cedar_permit_cannot_bypass_library_refusal',
          'library_finalized_cannot_bypass_host_forbid',
          'library_finalized_cannot_bypass_host_pending',
          'cross_operation_permit_replay_blocked',
          'stale_policy_snapshot_permit_blocked',
          'revoked_use_time_authority_blocked',
          'dualSovereignBridge_preserves_library_rejection',
          'disjointHostPolicyEvolution_preserves_bridge_certificate',
          'weakeningBoundOperation_invalidates_reuse',
        ],
      },
      {
        name: 'DeterministicEngineering.Engineering.InformationFlowAndTms',
        theorems: [
          'difc_secrecy_monotonic_without_declass',
          'difc_no_write_down_blocks_exfiltration',
          'difc_failed_declass_preserves_taint',
          'camel_integrity_meet_never_elevates',
          'camel_control_slot_blocks_untrusted',
          'doyle_single_justification_retraction_cascades',
          'atms_clean_alternative_justification_survives',
          'poison_immunization_tombstone_blocks_reproposal',
          'difcAtmsContract_preserves_rejection',
          'retentionTuning_preserves_difc_atms_certificate',
          'disablingCamelIntegrity_invalidates_reuse',
        ],
      },
      {
        name: 'DeterministicEngineering.Engineering.SagaAndSsi',
        theorems: [...SAGA_SSI_THEOREMS],
      },
    ] as const;

    const totalTheorems = modules.reduce((acc, m) => acc + m.theorems.length, 0);
    expect(totalTheorems).toBe(52);

    if (!isLeanToolchainAvailable()) return;

    const kv = new ContentAddressedKvStore();
    let verifiedCount = 0;
    for (const mod of modules) {
      const res = verifyLeanModuleAxiomsLive({
        moduleName: mod.name,
        namespacePrefix: mod.name,
        expectedTheorems: mod.theorems,
        kv,
      });
      expect(res.kind).toBe('Proven');
      if (res.kind === 'Proven') {
        verifiedCount += Object.keys(res.theoremAxioms).length;
      }
    }
    expect(verifiedCount).toBe(52);
  }, 60_000);

  test('AG150: 150-Case Grand Milestone — Full B4 SSI + B6 Saga/Budget + B7 DIFC + B8 ATMS + B10 Quorum + cedar-poo-spec Dual-Sovereign Closure', () => {
    const kv = new ContentAddressedKvStore();

    // 1. B4 Clean AST SSI admission:
    const ssi = arbitrateConcurrentWorkspaces({
      baseFiles: {'src/release.ts': `export const REL = 149;`},
      activeLeaseEpoch: 15,
      kv,
      proposals: [
        {
          agentId: 'coder-150',
          fencingEpoch: 15,
          modifiedFiles: {'src/release.ts': `export const REL = 150;`},
        },
      ],
    });
    expect(ssi.admittedAgents).toEqual(['coder-150']);

    // 2. B7 Sanitized declassification + B8 ATMS verified belief:
    const difc = new DifcAgentMonitor(kv);
    const tms = new DurableMemoryTmsStore(kv, 2);
    const raw = difc.ingestData({
      valueId: 'raw-150',
      value: 'internal-150-ok',
      secrecyTags: ['tenant:150'],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'verifier',
    });
    const cap = new DeclassificationCapability('redactor-150', ['tenant:150']);
    const decl = difc.declassify({
      capability: cap,
      source: raw,
      redactedValue: 'release-150-summary-clean',
      tagsToRemove: ['tenant:150'],
      deterministicSanitizer: v => ({clean: !v.includes('internal')}),
    });
    expect(decl.kind).toBe('Declassified');
    if (decl.kind !== 'Declassified') throw new Error('expected Declassified');

    tms.proposeProvisionalBelief({
      beliefId: 'b-150',
      claimText: 'Release 150 verified across all 4 formal paradigms',
      proposerId: 'coder-150',
      sourceIntegrity: 'TrustedSystem',
    });
    expect(
      tms.promoteToVerifiedMemory({beliefId: 'b-150', oracleReceiptHash: decl.auditReceiptHash})
        .kind,
    ).toBe('PromotedM1');

    // 3. B6 Compensable Saga + Linear Budget conservation:
    const budget = new LinearBudgetTree('coordinator', 150);
    const saga = new DurableAgentSagaEngine(kv, budget);
    expect(
      saga.registerSaga('saga-150', [
        {
          stepId: 'stage-artifact',
          agentId: 'coordinator',
          reversibility: 'Compensable',
          costUnits: 25,
          compensatorActionName: 'unstage',
          executeForward: () => ({kind: 'Committed', externalReceiptId: 'staged-150'}),
          executeCompensate: () => ({compensated: true}),
        },
        {
          stepId: 'publish-pivot',
          agentId: 'coordinator',
          reversibility: 'PivotIrreversible',
          costUnits: 25,
          executeForward: () => ({kind: 'Committed', externalReceiptId: 'published-150'}),
        },
      ]).kind,
    ).toBe('Registered');
    expect(saga.runSaga('saga-150').kind).toBe('Completed');
    expect(budget.conservationAudit().conserved).toBe(true);

    // 4. B10 Quorum finality + cedar-poo-spec Dual-Sovereign admission:
    const logId = 'log-grand-milestone-150';
    const coordKey = new CoordinatorSigningKey(logId);
    const w1 = new ForwardSecureWitnessKey('w1', 1);
    const w2 = new ForwardSecureWitnessKey('w2', 1);
    const w3 = new ForwardSecureWitnessKey('w3', 1);
    const w4 = new ForwardSecureWitnessKey('w4', 1);
    const roster = createEpochRoster({
      logId,
      epoch: 1,
      witnessPublicKeys: {
        w1: w1.getPublicKeyPem(1),
        w2: w2.getPublicKeyPem(1),
        w3: w3.getPublicKeyPem(1),
        w4: w4.getPublicKeyPem(1),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const log = new VerifiableTransparencyLog(coordKey);
    const opDigest = sha256Digest({milestone: 150, belief: 'b-150', declass: decl.auditReceiptHash});
    log.appendEntry({opDigest});
    const sth = log.issueSignedTreeHead(1);
    const qc = buildThresholdCheckpoint(sth, [
      w1.cosignCheckpoint(sth),
      w2.cosignCheckpoint(sth),
      w3.cosignCheckpoint(sth),
    ]);
    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, roster);
    const libVerdict = verifier.verifyCheckpointInCurrentEpoch({checkpoint: qc});
    expect(libVerdict.kind).toBe('FinalizedInEpoch');

    const polDigest = sha256Digest({policy: 'cedar-poo-spec-v150'});
    const lease = new LiveM3Capability('lease-150', 'release:150', 15);
    const dual = evaluateDualSovereignGate({
      kv,
      libraryVerdict: libVerdict,
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: evaluateHostPolicySemantics({
          permitMatched: true,
          forbidMatched: false,
          contextReady: true,
        }),
        boundOperationDigest: opDigest,
        policySnapshotDigest: polDigest,
        policyAffectedScopes: ['release:150'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: polDigest,
      activeLeaseEpoch: 15,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');

    kv.gcUnreferenced();
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
    expect(kv.hasBlob(decl.auditReceiptHash)).toBe(true);
  });
});
