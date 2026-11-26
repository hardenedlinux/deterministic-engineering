// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from './durable-merkle-store.ts';
import {
  CapabilityDelegationAuthority,
  DelegationRootKey,
} from './capability-attenuation.ts';
import {DurableMemoryTmsStore} from './durable-memory-tms.ts';
import {DifcAgentMonitor, ToolSinkPolicy} from './difc-exfiltration-fence.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from './transparency-log-equivocation.ts';
import {
  extractMetaAuditBundleFromLiveObjects,
  isGerbilAscentRuntimeAvailable,
  parseFramedAscentOutput,
  runLiveGerbilAscentMetaAudit,
  serializeFactBundleToSchemeAlist,
  verifyReleaseWithIndependentAscentOracle,
} from './ascent-meta-audit-bridge.ts';

function buildLiveCrossPillarFixture() {
  const kv = new ContentAddressedKvStore();
  const delegation = new CapabilityDelegationAuthority(kv, new DelegationRootKey('bridge-root'));

  // B3: 4-hop chain admin -> c1 -> c2 -> c3 -> worker4, plus clean sibling admin -> clean-coder
  const rAdmin = delegation.mintRootCertificate({
    certId: 'c-root',
    rootAuthorityId: 'admin',
    delegateeId: 'c1',
    caveats: {
      allowedPathPrefixes: ['/src'],
      allowedActions: ['read', 'write'],
      expiresAtEpoch: 500,
      remainingHops: 4,
      delegatable: true,
    },
    issuedAtEpoch: 1,
  });
  const hop2 = delegation.attenuateAndDelegate({
    certId: 'c-2',
    parentCert: rAdmin,
    delegateeId: 'c2',
    childCaveats: {
      allowedPathPrefixes: ['/src'],
      allowedActions: ['read', 'write'],
      expiresAtEpoch: 450,
      remainingHops: 3,
      delegatable: true,
    },
    issuedAtEpoch: 2,
  });
  if (hop2.kind !== 'Delegated') throw new Error('expected Delegated');
  const hop3 = delegation.attenuateAndDelegate({
    certId: 'c-3',
    parentCert: hop2.cert,
    delegateeId: 'c3',
    childCaveats: {
      allowedPathPrefixes: ['/src'],
      allowedActions: ['write'],
      expiresAtEpoch: 400,
      remainingHops: 2,
      delegatable: true,
    },
    issuedAtEpoch: 3,
  });
  if (hop3.kind !== 'Delegated') throw new Error('expected Delegated');
  const hop4 = delegation.attenuateAndDelegate({
    certId: 'c-4',
    parentCert: hop3.cert,
    delegateeId: 'worker4',
    childCaveats: {
      allowedPathPrefixes: ['/src/mod'],
      allowedActions: ['write'],
      expiresAtEpoch: 350,
      remainingHops: 0,
      delegatable: false,
    },
    issuedAtEpoch: 4,
  });
  if (hop4.kind !== 'Delegated') throw new Error('expected Delegated');

  const rClean = delegation.mintRootCertificate({
    certId: 'c-clean',
    rootAuthorityId: 'admin',
    delegateeId: 'clean-coder',
    caveats: {
      allowedPathPrefixes: ['/src/clean'],
      allowedActions: ['write'],
      expiresAtEpoch: 500,
      remainingHops: 0,
      delegatable: false,
    },
    issuedAtEpoch: 1,
  });

  // B8: worker4 proposed b-root (quorum, no oracle) -> b-mid -> b-leaf; clean-coder has oracle
  const tms = new DurableMemoryTmsStore(kv, 2);
  const oracleHash = kv.putBlob('apalache-clean', {passed: 6}, []);

  tms.proposeProvisionalBelief({
    beliefId: 'b-root',
    claimText: 'Internal bypass ok',
    proposerId: 'worker4',
    sourceIntegrity: 'VerifiedInternal',
  });
  tms.promoteToVerifiedMemory({beliefId: 'b-root', attesters: ['peer-a', 'peer-b']});

  tms.proposeProvisionalBelief({
    beliefId: 'b-mid',
    claimText: 'Derived mid rule',
    proposerId: 'planner',
    sourceIntegrity: 'VerifiedInternal',
    justifications: [['b-root']],
  });
  tms.promoteToVerifiedMemory({beliefId: 'b-mid', attesters: ['peer-a', 'peer-b']});

  tms.proposeProvisionalBelief({
    beliefId: 'b-leaf',
    claimText: 'Derived leaf rule',
    proposerId: 'planner',
    sourceIntegrity: 'VerifiedInternal',
    justifications: [['b-mid']],
  });
  tms.promoteToVerifiedMemory({beliefId: 'b-leaf', attesters: ['peer-a', 'peer-b']});

  tms.proposeProvisionalBelief({
    beliefId: 'b-clean',
    claimText: 'Verified safe invariant',
    proposerId: 'clean-coder',
    sourceIntegrity: 'TrustedSystem',
  });
  tms.promoteToVerifiedMemory({beliefId: 'b-clean', oracleReceiptHash: oracleHash});

  // B7: Multi-hop DIFC taint v0 (tenant:alpha) -> v1 -> v2 (leaked to public-sink)
  const difc = new DifcAgentMonitor(kv);
  const v0 = difc.ingestData({
    valueId: 'v0',
    value: 'secret-alpha',
    secrecyTags: ['tenant:alpha'],
    integrity: 'TrustedSystem',
    sourcePrincipal: 'vault',
  });
  const v1 = difc.deriveValue({valueId: 'v1', inputs: [v0], derivedValue: 'sum1', derivedBy: 'llm'});
  const v2 = difc.deriveValue({valueId: 'v2', inputs: [v1], derivedValue: 'sum2', derivedBy: 'llm'});
  const publicSink: ToolSinkPolicy = {
    sinkId: 'public-sink',
    allowedSecrecyTags: [],
    minControlIntegrity: 'VerifiedInternal',
  };

  // B9: Honest log vs Split-view equivocating log
  const honestKey = new CoordinatorSigningKey('log-honest');
  const honestLog = new VerifiableTransparencyLog(honestKey);
  honestLog.appendEntry({rel: 'rel-clean'});
  const sthHonest = honestLog.issueSignedTreeHead(1);

  const evilKey = new CoordinatorSigningKey('log-split');
  const splitA = new VerifiableTransparencyLog(evilKey);
  splitA.appendEntry({rel: 'clean'});
  const sthSplitA = splitA.issueSignedTreeHead(1);
  const splitB = new VerifiableTransparencyLog(evilKey);
  splitB.appendEntry({rel: 'BACKDOOR'});
  const sthSplitB = splitB.issueSignedTreeHead(2);

  const {bundle, factBundleMerkleHash} = extractMetaAuditBundleFromLiveObjects({
    kv,
    delegationCertificates: [rAdmin, hop2.cert, hop3.cert, hop4.cert, rClean],
    revokedPrincipals: ['c1'],
    beliefNodes: [
      tms.getBelief('b-root')!,
      tms.getBelief('b-mid')!,
      tms.getBelief('b-leaf')!,
      tms.getBelief('b-clean')!,
    ],
    taintedValues: [v0, v1, v2],
    sinkEmissions: [{sink: publicSink, valueId: 'v2'}],
    witnessObservations: [
      {witnessId: 'w-reg', sth: sthHonest},
      {witnessId: 'w-prod', sth: sthHonest},
      {witnessId: 'w-reg', sth: sthSplitA},
      {witnessId: 'w-prod', sth: sthSplitB},
    ],
    releaseProposals: [
      {
        releaseId: 'rel-clean',
        authorId: 'clean-coder',
        approverId: 'human-approver',
        logId: 'log-honest',
        supportingBeliefIds: ['b-clean'],
      },
      {
        releaseId: 'rel-poison-chain',
        authorId: 'clean-coder',
        approverId: 'human-approver',
        logId: 'log-honest',
        supportingBeliefIds: ['b-leaf'],
      },
      {
        releaseId: 'rel-split-log',
        authorId: 'clean-coder',
        approverId: 'human-approver',
        logId: 'log-split',
        supportingBeliefIds: ['b-clean'],
      },
    ],
  });

  return {kv, bundle, factBundleMerkleHash};
}

describe('Phase 20 Cross-Runtime Proof-Carrying TS <-> Gerbil Scheme ASCENT Bridge (10.168 / 30.05 AG106-AG110)', () => {
  test('AG106: Projects live B1-B9 TypeScript objects into M1-pinned fact bundle & injection-safe Scheme S-expression alist', () => {
    const {kv, bundle, factBundleMerkleHash} = buildLiveCrossPillarFixture();
    expect(kv.hasBlob(factBundleMerkleHash)).toBe(true);
    expect(bundle.delegation_edge).toContainEqual(['c3', 'worker4']);
    expect(bundle.belief_sole_dep).toContainEqual(['b-leaf', 'b-mid']);
    expect(bundle.derived_from).toContainEqual(['v2', 'v1']);
    expect(bundle.witness_sth.length).toBe(4);

    const sexpr = serializeFactBundleToSchemeAlist(bundle);
    expect(sexpr).toContain('(delegation_edge . (');
    expect(sexpr).toContain('("c3" "worker4")');
    expect(sexpr).toContain('(release_proposal . (');
  });

  test('AG107: Live Gerbil Scheme ASCENT Datalog engine independently derives 4-hop B3->B8 poisoning, B7 exfil & B9 split-view from TS facts', () => {
    const {bundle} = buildLiveCrossPillarFixture();
    if (!isGerbilAscentRuntimeAvailable()) {
      const verdict = runLiveGerbilAscentMetaAudit(bundle);
      expect(verdict).toEqual({kind: 'PendingMethod', reason: 'gerbil-runtime-unavailable'});
      return;
    }

    const res = runLiveGerbilAscentMetaAudit(bundle);
    expect(res.kind).toBe('Verified');
    if (res.kind !== 'Verified') throw new Error('expected Verified');
    expect(res.output.effectively_revoked).toContainEqual(['worker4']);
    expect(res.output.effectively_revoked).not.toContainEqual(['clean-coder']);
    expect(res.output.belief_poisoned).toContainEqual(['b-leaf']);
    expect(res.output.belief_poisoned).not.toContainEqual(['b-clean']);
    expect(res.output.exfiltration_violation).toEqual([['public-sink', 'v2', 'tenant:alpha']]);
    expect(res.output.equivocation_violation.some(r => r[0] === 'log-split')).toBe(true);
    expect(res.output.release_admitted).toEqual([['rel-clean']]);
  }, 30_000);

  test('AG108: N-Version Agreement Gate catches buggy/compromised TS coordinator claiming ADMIT on poisoned or split-view release', () => {
    const {kv, bundle, factBundleMerkleHash} = buildLiveCrossPillarFixture();
    // Run the independent live Gerbil Scheme ASCENT oracle once per content-addressed fact bundle:
    const liveResult = isGerbilAscentRuntimeAvailable()
      ? runLiveGerbilAscentMetaAudit(bundle)
      : ({
          kind: 'Verified',
          outputDigest: 'sim-digest',
          durationMs: 1,
          output: {
            effectively_revoked: [['c1'], ['c2'], ['c3'], ['worker4']],
            belief_poisoned: [['b-root'], ['b-mid'], ['b-leaf']],
            tainted_value: [['v0', 'tenant:alpha'], ['v1', 'tenant:alpha'], ['v2', 'tenant:alpha']],
            exfiltration_violation: [['public-sink', 'v2', 'tenant:alpha']],
            equivocation_violation: [['log-split', '1', 'a', 'b']],
            byzantine_witness_equivocation: [],
            invalid_witness_cosign: [],
            quorum_3_verified: [],
            sub_quorum_finality_violation: [],
            split_world_finality_breach: [],
            release_disqualified: [
              ['rel-poison-chain', 'poisoned-supporting-belief'],
              ['rel-split-log', 'coordinator-equivocated'],
            ],
            release_admitted: [['rel-clean']],
          },
        } as const);
    const runner = () => liveResult;

    // Buggy TS coordinator falsely claims 'ADMIT' on `rel-poison-chain` -> Scheme oracle catches it!
    const caughtPoison = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-poison-chain',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
      kv,
      oracleRunner: runner,
    });
    expect(caughtPoison.kind).toBe('Refuted');
    if (caughtPoison.kind === 'Refuted') {
      expect(caughtPoison.reason).toBe('oracle-disagreement-fail-closed');
      expect(caughtPoison.ascentDisqualificationReasons).toEqual(['poisoned-supporting-belief']);
      expect(kv.hasBlob(caughtPoison.disagreementReceiptHash)).toBe(true);
    }

    // Buggy TS coordinator falsely claims 'ADMIT' on `rel-split-log` -> Scheme oracle catches it!
    const caughtSplit = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-split-log',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
      kv,
      oracleRunner: runner,
    });
    expect(caughtSplit.kind).toBe('Refuted');
    if (caughtSplit.kind === 'Refuted') {
      expect(caughtSplit.reason).toBe('oracle-disagreement-fail-closed');
      expect(caughtSplit.ascentDisqualificationReasons).toEqual(['coordinator-equivocated']);
    }
  }, 30_000);

  test('AG109: Clean dual-language consensus pins M1 DualOracleAdmissionReceipt that survives GC', () => {
    const {kv, bundle, factBundleMerkleHash} = buildLiveCrossPillarFixture();
    const runner = isGerbilAscentRuntimeAvailable()
      ? runLiveGerbilAscentMetaAudit
      : () =>
          ({
            kind: 'Verified',
            outputDigest: 'sim-clean',
            durationMs: 1,
            output: {
              effectively_revoked: [],
              belief_poisoned: [],
              tainted_value: [],
              exfiltration_violation: [],
              equivocation_violation: [],
              byzantine_witness_equivocation: [],
              invalid_witness_cosign: [],
              quorum_3_verified: [],
              sub_quorum_finality_violation: [],
              split_world_finality_breach: [],
              release_disqualified: [],
              release_admitted: [['rel-clean']],
            },
          }) as const;

    const ok = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-clean',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
      kv,
      oracleRunner: runner,
    });
    expect(ok.kind).toBe('Proven');
    if (ok.kind === 'Proven') {
      kv.gcUnreferenced();
      expect(kv.hasBlob(ok.dualAdmissionReceiptHash)).toBe(true);
      expect(kv.hasBlob(ok.factBundleMerkleHash)).toBe(true);
    }
  }, 30_000);

  test('AG110: Unavailable Gerbil binary & malformed oracle stdout fail closed as PendingMethod / SetupDefect (never ok:true)', () => {
    const {kv, bundle, factBundleMerkleHash} = buildLiveCrossPillarFixture();

    const missingRuntime = verifyReleaseWithIndependentAscentOracle({
      releaseId: 'rel-clean',
      imperativeTsVerdict: 'ADMIT',
      bundle,
      factBundleMerkleHash,
      kv,
      oracleRunner: b =>
        runLiveGerbilAscentMetaAudit(b, {gerbilBinary: 'nonexistent-gerbil-binary-xyz'}),
    });
    expect(missingRuntime).toEqual({kind: 'PendingMethod', reason: 'gerbil-runtime-unavailable'});

    expect(parseFramedAscentOutput('garbage without markers')).toEqual({
      kind: 'SetupDefect',
      reason: 'missing-framed-ascent-json-markers',
    });
  });
});
