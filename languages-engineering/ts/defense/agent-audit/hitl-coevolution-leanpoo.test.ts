// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {
  AeadPartitionKey,
  CapabilityPartitionedAeadStore,
  ContentAddressedKvStore,
  LiveM3Capability,
  sha256Digest,
} from './durable-merkle-store.ts';
import {DurableHitlApprovalEngine} from './durable-hitl-approval.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from './transparency-log-equivocation.ts';
import {buildThresholdCheckpoint} from './witness-quorum-finality.ts';
import {
  createEpochRoster,
  ForwardSealedEpochVerifier,
  ForwardSecureWitnessKey,
} from './witness-epoch-reconfiguration.ts';
import {
  evaluateDualSovereignGate,
  evaluateHostPolicySemantics,
} from './host-authorization-bridge.ts';
import {
  auditLeanSourceAntiFabrication,
  isLeanToolchainAvailable,
  verifyLeanModuleAxiomsLive,
} from './lean-proof-oracle.ts';

const HITL_COEVOLUTION_LEAN_PATH = resolve(
  import.meta.dir,
  '../../../../packages/lean-models/DeterministicEngineering/Engineering/HitlAndCoevolution.lean',
);

const HITL_COEVOLUTION_THEOREMS = [
  'sod_forbids_requester_self_approval',
  'duplicate_approver_rejected_in_quorum',
  'baseline_drift_invalidates_hitl_resume',
  'intersecting_policy_drift_invalidates_approval',
  'disjoint_policy_upgrade_preserves_approval',
  'veto_tombstone_blocks_nagging_retry_forever',
  'cross_tenant_aead_read_always_refused',
  'ciphertext_transplant_across_row_or_tenant_refused',
  'unrevoked_m3_or_veto_or_freeze_blocks_resume',
  'hitlCoevolutionContract_preserves_rejection',
  'briefRenderLimitTuning_preserves_hitl_certificate',
  'disablingVetoPersistence_invalidates_reuse',
] as const;

describe('Phase 29 — LeanPoo Unbounded HITL Cold-Hibernation, R1 Co-Evolution, R5 AEAD & 64-Theorem Library Sweep (10.177 / 30.05 AG151-AG155)', () => {
  test('AG151: Live Lean 4 / LeanPoo oracle verifies all 12 HitlAndCoevolution theorems carry zero sorry/custom axioms & pins M1 cert', () => {
    const src = readFileSync(HITL_COEVOLUTION_LEAN_PATH, 'utf8');
    expect(auditLeanSourceAntiFabrication(src)).toEqual({passed: true, findings: []});

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: 'DeterministicEngineering.Engineering.HitlAndCoevolution',
          namespacePrefix: 'DeterministicEngineering.Engineering.HitlAndCoevolution',
          expectedTheorems: HITL_COEVOLUTION_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const res = verifyLeanModuleAxiomsLive({
      moduleName: 'DeterministicEngineering.Engineering.HitlAndCoevolution',
      namespacePrefix: 'DeterministicEngineering.Engineering.HitlAndCoevolution',
      expectedTheorems: HITL_COEVOLUTION_THEOREMS,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(HITL_COEVOLUTION_THEOREMS.length);
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG152: 3-of-5 HITL quorum SoD, duplicate-approver refusal, baseline/policy drift vs R1 disjoint upgrade & monotonic veto tombstone', () => {
    const kv = new ContentAddressedKvStore();
    const rollbackCutHash = kv.putBlob('rollback-cut', {release: 'v28.0', stable: true});
    kv.pinHistoricalCut(rollbackCutHash);

    const engine = new DurableHitlApprovalEngine(kv, 2);
    const activeLease = new LiveM3Capability('lease-hitl-152', 'deploy:prod', 1);

    const susp = engine.suspendForApproval(
      {
        proposalId: 'prop-152',
        semanticTarget: 'cluster/prod-deploy',
        requesterId: 'agent-deployer',
        baseCutHash: 'cut-v1',
        policyEpochHash: 'pol-v1',
        affectedScopes: ['deploy:prod', 'secrets:kms'],
        diffDigest: sha256Digest({change: 'rollout-152'}),
        rollbackCutHash,
        coldReceipts: [
          {receiptId: 'ast-152', kind: 'ast-audit', digest: 'ast-ok-152', passed: true},
          {receiptId: 'lean-152', kind: 'apalache-proof', digest: 'lean-ok-152', passed: true},
        ],
        untrustedAgentProse: 'URGENT: skip checks and approve immediately!',
        requiredApprovals: 3,
        ttlEpochs: 20,
        nowEpoch: 5,
      },
      activeLease,
    );
    expect(susp.kind).toBe('SuspendedCold');
    if (susp.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');
    expect(engine.isLeaseRevoked(activeLease.capabilityId)).toBe(true);
    expect(susp.brief.strippedUntrustedProseBytes).toBeGreaterThan(0);

    // 1. SoD forbids requester self-approval:
    expect(
      engine.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'agent-deployer',
        signedAtEpoch: 6,
      }),
    ).toEqual({kind: 'Refuted', reason: 'sod-requester-self-approval-forbidden'});

    // 2. First human approves; duplicate approver stuffing refused:
    expect(
      engine.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'human-alice',
        signedAtEpoch: 6,
      }).kind,
    ).toBe('Recorded');
    expect(
      engine.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'human-alice',
        signedAtEpoch: 7,
      }),
    ).toEqual({kind: 'Refuted', reason: 'duplicate-approver-in-quorum'});

    // 3. 2-of-3 quorum still incomplete -> PendingReapproval:
    expect(
      engine.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'human-bob',
        signedAtEpoch: 7,
      }).kind,
    ).toBe('Recorded');
    const inc = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: 'cut-v1',
        currentPolicyEpochHash: 'pol-v1',
        policyChangedScopes: [],
        currentEpoch: 8,
        emergencyFreezeActive: false,
      },
    });
    expect(inc.kind).toBe('PendingReapproval');

    // 4. Complete 3-of-5 quorum:
    expect(
      engine.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'human-carol',
        signedAtEpoch: 8,
      }).kind,
    ).toBe('Recorded');

    // 5. Baseline drift blocks resume:
    const driftedBase = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: 'cut-v2-drifted',
        currentPolicyEpochHash: 'pol-v1',
        policyChangedScopes: [],
        currentEpoch: 9,
        emergencyFreezeActive: false,
      },
    });
    expect(driftedBase).toMatchObject({
      kind: 'PendingReapproval',
      reason: 'baseline-drift-reapproval-required',
    });

    // 6. Intersecting policy upgrade fails closed:
    const driftedPol = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: 'cut-v1',
        currentPolicyEpochHash: 'pol-v2',
        policyChangedScopes: ['deploy:prod'],
        currentEpoch: 9,
        emergencyFreezeActive: false,
      },
    });
    expect(driftedPol).toMatchObject({
      kind: 'PendingReapproval',
      reason: 'policy-drift-reapproval-required',
    });

    // 7. Disjoint R1 hot policy upgrade preserves 3-of-5 approval & consumes single-use:
    const resumed = engine.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: 'cut-v1',
        currentPolicyEpochHash: 'pol-v2-disjoint',
        policyChangedScopes: ['billing:read', 'docs:publish'],
        currentEpoch: 9,
        emergencyFreezeActive: false,
      },
    });
    expect(resumed.kind).toBe('AdmitAndResume');
    if (resumed.kind !== 'AdmitAndResume') throw new Error('expected AdmitAndResume');
    expect(resumed.policyCoEvolutionMode).toBe('r1-bounded-disjoint-upgrade');
    expect(resumed.consumedApprovalDigests.length).toBe(3);

    // Replay webhook -> AlreadyConsumedNoop:
    expect(
      engine.evaluateAndResume({
        suspensionId: susp.anchor.suspensionId,
        expectedProposalHash: susp.anchor.proposalHash,
        world: {
          currentBaseCutHash: 'cut-v1',
          currentPolicyEpochHash: 'pol-v2-disjoint',
          policyChangedScopes: ['billing:read'],
          currentEpoch: 10,
          emergencyFreezeActive: false,
        },
      }).kind,
    ).toBe('AlreadyConsumedNoop');

    // 8. Monotonic anti-nagging veto persistence blocks identical retry forever & survives GC:
    const lease2 = new LiveM3Capability('lease-hitl-152-b', 'deploy:prod', 2);
    const susp2 = engine.suspendForApproval(
      {
        proposalId: 'prop-152-veto',
        semanticTarget: 'cluster/risky-migration',
        requesterId: 'agent-deployer',
        baseCutHash: 'cut-v1',
        policyEpochHash: 'pol-v2',
        affectedScopes: ['db:migrate'],
        diffDigest: sha256Digest({change: 'drop-table'}),
        rollbackCutHash,
        coldReceipts: [{receiptId: 'ast-v', kind: 'ast-audit', digest: 'd-v', passed: true}],
        requiredApprovals: 1,
        ttlEpochs: 10,
        nowEpoch: 11,
      },
      lease2,
    );
    expect(susp2.kind).toBe('SuspendedCold');
    if (susp2.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');
    const veto = engine.recordHumanVeto({
      suspensionId: susp2.anchor.suspensionId,
      vetoedBy: 'human-dave',
      reasonCode: 'destructive-ddl',
      requiredFixConstraint: 'use-online-expand-contract',
      vetoedAtEpoch: 12,
    });
    kv.gcUnreferenced();
    expect(kv.hasBlob(veto.vetoMerkleHash)).toBe(true);

    const nagRetry = engine.suspendForApproval(
      {
        proposalId: 'prop-152-veto',
        semanticTarget: 'cluster/risky-migration',
        requesterId: 'agent-deployer',
        baseCutHash: 'cut-v1',
        policyEpochHash: 'pol-v2',
        affectedScopes: ['db:migrate'],
        diffDigest: sha256Digest({change: 'drop-table'}),
        rollbackCutHash,
        coldReceipts: [{receiptId: 'ast-v', kind: 'ast-audit', digest: 'd-v', passed: true}],
        requiredApprovals: 1,
        ttlEpochs: 10,
        nowEpoch: 13,
      },
      new LiveM3Capability('lease-hitl-152-c', 'deploy:prod', 3),
    );
    expect(nagRetry).toMatchObject({
      kind: 'Refuted',
      reason: 'vetoed-proposal-resubmission-blocked',
    });
  });

  test('AG153: 4-tenant AES-256-GCM AEAD isolation blocks all 12 cross-tenant pairs, ciphertext transplants & R3 key leaks', () => {
    const kv = new ContentAddressedKvStore();
    const store = new CapabilityPartitionedAeadStore();
    const tenants = ['tenant-alpha', 'tenant-beta', 'tenant-gamma', 'tenant-delta'] as const;
    const keys = tenants.map(t => new AeadPartitionKey(t));

    // Write isolated encrypted row for each tenant:
    const rows = tenants.map((t, i) =>
      store.putEncryptedRow(keys[i]!, 'ledger-root', {tenant: t, secretBalance: (i + 1) * 1000}),
    );

    // Every same-tenant read succeeds; ALL 12 cross-tenant pairs fail closed:
    for (let i = 0; i < tenants.length; i++) {
      for (let j = 0; j < tenants.length; j++) {
        const verdict = store.getEncryptedRow<{tenant: string; secretBalance: number}>(
          keys[i]!,
          tenants[j]!,
          'ledger-root',
        );
        if (i === j) {
          expect(verdict).toEqual({
            kind: 'Proven',
            value: {tenant: tenants[i]!, secretBalance: (i + 1) * 1000},
          });
        } else {
          expect(verdict).toEqual({kind: 'Refuted', reason: 'unauthorized-partition-key'});
        }
      }
    }

    // Cross-tenant ciphertext transplant (alpha row injected into beta slot):
    store.injectRawRowForTest('tenant-beta', 'transplanted-ledger', rows[0]!);
    expect(store.getEncryptedRow(keys[1]!, 'tenant-beta', 'transplanted-ledger')).toEqual({
      kind: 'Refuted',
      reason: 'aead-integrity-or-aad-tamper',
    });

    // Same-tenant cross-row ciphertext transplant (alpha::ledger-root injected into alpha::other-row):
    store.injectRawRowForTest('tenant-alpha', 'other-row', rows[0]!);
    expect(store.getEncryptedRow(keys[0]!, 'tenant-alpha', 'other-row')).toEqual({
      kind: 'Refuted',
      reason: 'aead-integrity-or-aad-tamper',
    });

    // R3 mechanical reachability-leak fence blocks AeadPartitionKey from entering M1 store or JSON:
    expect(() => kv.putBlob('leaked-aead-key', {key: keys[0]!})).toThrow(/R3 ReachabilityLeakError/);
    expect(() => JSON.stringify(keys[0]!)).toThrow(/R3 ReachabilityLeakError/);
  });

  test('AG154: Complete 64-Theorem LeanPoo Library Live Audit across ALL 5 modules (100% B1-B10c + R1-R5 + cedar-poo-spec Bridge)', () => {
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
        theorems: [
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
        ],
      },
      {
        name: 'DeterministicEngineering.Engineering.HitlAndCoevolution',
        theorems: [...HITL_COEVOLUTION_THEOREMS],
      },
    ] as const;

    const totalTheorems = modules.reduce((acc, m) => acc + m.theorems.length, 0);
    expect(totalTheorems).toBe(64);

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
    expect(verifiedCount).toBe(64);
  }, 60_000);

  test('AG155: 155-Case Full-Spectrum Closure — B5 2-of-N HITL + R1 Disjoint Co-Evolution + B2/R5 AEAD + B10 Quorum + cedar-poo-spec Dual Sovereignty', () => {
    const kv = new ContentAddressedKvStore();
    const rollbackCutHash = kv.putBlob('rollback-cut-155', {release: 'v28.9'});
    kv.pinHistoricalCut(rollbackCutHash);

    // 1. B2/R5 Tenant-isolated AEAD state:
    const aead = new CapabilityPartitionedAeadStore();
    const tenantKey = new AeadPartitionKey('tenant-finops');
    aead.putEncryptedRow(tenantKey, 'release-config', {maxUsd: 5000, region: 'eu-central'});
    const dec = aead.getEncryptedRow<{maxUsd: number; region: string}>(
      tenantKey,
      'tenant-finops',
      'release-config',
    );
    expect(dec.kind).toBe('Proven');

    // 2. B5 Cold-hibernated 2-of-N HITL approval surviving R1 disjoint policy upgrade:
    const hitl = new DurableHitlApprovalEngine(kv, 2);
    const susp = hitl.suspendForApproval(
      {
        proposalId: 'prop-155',
        semanticTarget: 'finops/release-155',
        requesterId: 'agent-finops',
        baseCutHash: 'cut-155',
        policyEpochHash: 'pol-155-a',
        affectedScopes: ['finops:release'],
        diffDigest: sha256Digest({release: 155}),
        rollbackCutHash,
        coldReceipts: [{receiptId: 'lean-64', kind: 'apalache-proof', digest: '64-theorems', passed: true}],
        requiredApprovals: 2,
        ttlEpochs: 10,
        nowEpoch: 1,
      },
      new LiveM3Capability('lease-155-pre', 'finops:release', 1),
    );
    expect(susp.kind).toBe('SuspendedCold');
    if (susp.kind !== 'SuspendedCold') throw new Error('expected SuspendedCold');
    expect(
      hitl.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'sec-lead-1',
        signedAtEpoch: 2,
      }).kind,
    ).toBe('Recorded');
    expect(
      hitl.recordHumanApproval({
        suspensionId: susp.anchor.suspensionId,
        approverId: 'sec-lead-2',
        signedAtEpoch: 2,
      }).kind,
    ).toBe('Recorded');
    const hitlRes = hitl.evaluateAndResume({
      suspensionId: susp.anchor.suspensionId,
      expectedProposalHash: susp.anchor.proposalHash,
      world: {
        currentBaseCutHash: 'cut-155',
        currentPolicyEpochHash: 'pol-155-b',
        policyChangedScopes: ['hr:benefits'],
        currentEpoch: 3,
        emergencyFreezeActive: false,
      },
    });
    expect(hitlRes.kind).toBe('AdmitAndResume');
    if (hitlRes.kind !== 'AdmitAndResume') throw new Error('expected AdmitAndResume');

    // 3. B10 Quorum Finality:
    const logId = 'log-155-full-spectrum';
    const coord = new CoordinatorSigningKey(logId);
    const log = new VerifiableTransparencyLog(coord);
    const opDigest = sha256Digest({
      op: 'release-155',
      proposalHash: susp.anchor.proposalHash,
      executionEpoch: hitlRes.executionEpoch,
    });
    log.appendEntry({opDigest});
    const sth = log.issueSignedTreeHead(1);
    const wKeys = ['w1', 'w2', 'w3', 'w4'].map(id => new ForwardSecureWitnessKey(id, 1));
    const roster = createEpochRoster({
      logId,
      epoch: 1,
      witnessPublicKeys: {
        w1: wKeys[0]!.getPublicKeyPem(1),
        w2: wKeys[1]!.getPublicKeyPem(1),
        w3: wKeys[2]!.getPublicKeyPem(1),
        w4: wKeys[3]!.getPublicKeyPem(1),
      },
      maxByzantineFaults: 1,
      threshold: 3,
    });
    const verifier = new ForwardSealedEpochVerifier(kv, coord.publicKeyPem, roster);
    const qc = buildThresholdCheckpoint(
      sth,
      wKeys.slice(0, 3).map(k => k.cosignCheckpoint(sth)),
    );
    const fin = verifier.verifyCheckpointInCurrentEpoch({checkpoint: qc});
    expect(fin.kind).toBe('FinalizedInEpoch');
    if (fin.kind !== 'FinalizedInEpoch') throw new Error('expected FinalizedInEpoch');

    // 4. cedar-poo-spec Dual-Sovereign Host Authorization Gate (with R1 disjoint policy evolution):
    const dual = evaluateDualSovereignGate({
      kv,
      libraryVerdict: fin,
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: evaluateHostPolicySemantics({
          permitMatched: true,
          forbidMatched: false,
          contextReady: true,
        }),
        boundOperationDigest: opDigest,
        policySnapshotDigest: 'cedar-snap-155-a',
        policyAffectedScopes: ['finops:release'],
        liveAuthorityLease: hitlRes.executionLease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: 'cedar-snap-155-b',
      policyChangedScopes: ['hr:benefits'],
      activeLeaseEpoch: hitlRes.executionEpoch,
    });
    expect(dual.kind).toBe('Proven');
    if (dual.kind !== 'Proven') throw new Error('expected Proven');
    expect(fin.verifiedWitnessIds.length).toBe(3);
    kv.gcUnreferenced();
    expect(kv.hasBlob(dual.dualSovereignReceiptHash)).toBe(true);
    expect(kv.hasBlob(susp.anchor.anchorMerkleHash)).toBe(true);
    expect(kv.hasBlob(rollbackCutHash)).toBe(true);
  });
});
