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
import {
  DeclassificationCapability,
  DifcAgentMonitor,
  TaintedValue,
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

const INFOFLOW_LEAN_PATH = resolve(
  import.meta.dir,
  '../../lean-models/DeterministicEngineering/Engineering/InformationFlowAndTms.lean',
);

const INFOFLOW_TMS_THEOREMS = [
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
] as const;

describe('Phase 27 LeanPoo Unbounded DIFC Non-Interference, CaMeL Integrity & ATMS Survival (10.175 / 30.05 AG141-AG145)', () => {
  test('AG141: Live Lean 4 / LeanPoo oracle verifies all 11 InformationFlowAndTms theorems carry zero sorry/custom axioms & pins M1 cert', () => {
    const src = readFileSync(INFOFLOW_LEAN_PATH, 'utf8');
    expect(auditLeanSourceAntiFabrication(src)).toEqual({passed: true, findings: []});

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      expect(
        verifyLeanModuleAxiomsLive({
          moduleName: 'DeterministicEngineering.Engineering.InformationFlowAndTms',
          namespacePrefix: 'DeterministicEngineering.Engineering.InformationFlowAndTms',
          expectedTheorems: INFOFLOW_TMS_THEOREMS,
          kv,
        }),
      ).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const res = verifyLeanModuleAxiomsLive({
      moduleName: 'DeterministicEngineering.Engineering.InformationFlowAndTms',
      namespacePrefix: 'DeterministicEngineering.Engineering.InformationFlowAndTms',
      expectedTheorems: INFOFLOW_TMS_THEOREMS,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(INFOFLOW_TMS_THEOREMS.length);
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG142: 12-hop LLM synthesis preserves DIFC secrecy tag & blocks exfiltration; failed sanitizer/cap preserves taint (Theorems 1-3)', () => {
    const kv = new ContentAddressedKvStore();
    const difc = new DifcAgentMonitor(kv);

    let current: TaintedValue<unknown> = difc.ingestData({
      valueId: 'secret-hop-0',
      value: 'alice@corp.example SSN 123-45-6789',
      secrecyTags: ['tenant:alpha', 'secret:pii'],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'vault',
    });

    // 12 consecutive synthesis/summarization hops mixing public notes -> secret tags MUST survive!
    for (let hop = 1; hop <= 12; hop++) {
      const pubNote = difc.ingestData({
        valueId: `pub-hop-${hop}`,
        value: `summary-step-${hop}`,
        secrecyTags: [],
        integrity: 'TrustedSystem',
        sourcePrincipal: 'planner',
      });
      current = difc.deriveValue({
        valueId: `synth-hop-${hop}`,
        inputs: [current, pubNote],
        derivedValue: `obfuscated-summary-${hop}`,
        derivedBy: 'llm-worker',
      });
    }
    expect(current.secrecyTags).toContain('tenant:alpha');
    expect(current.secrecyTags).toContain('secret:pii');

    const ctrl = difc.ingestData({
      valueId: 'ctrl-url',
      value: 'https://public.wiki.example',
      secrecyTags: [],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'platform',
    });
    const publicSink = {
      sinkId: 'public-wiki',
      allowedSecrecyTags: [],
      minControlIntegrity: 'TrustedSystem' as const,
    };

    expect(
      difc.dispatchToToolSink({
        sink: publicSink,
        controlArg: ctrl,
        payload: current,
        agentId: 'llm-worker',
      }).kind,
    ).toBe('Refuted');

    // Failed sanitizer (still contains email/SSN!) refuses declassification & preserves taint!
    const cap = new DeclassificationCapability('redactor', ['secret:pii']);
    const badDeclass = difc.declassify({
      capability: cap,
      source: current,
      redactedValue: 'still-leaks alice@corp.example',
      tagsToRemove: ['secret:pii'],
      deterministicSanitizer: v => ({
        clean: !/@|\d{3}-\d{2}-\d{4}/.test(v),
        detail: 'pii-still-present',
      }),
    });
    expect(badDeclass.kind).toBe('Refuted');
  });

  test('AG143: 10-hop CaMeL synthesis mixing 1 UntrustedExternal leaf collapses integrity & blocks privileged control slot (Theorems 4-5)', () => {
    const kv = new ContentAddressedKvStore();
    const difc = new DifcAgentMonitor(kv);

    let ctrl: TaintedValue<unknown> = difc.ingestData({
      valueId: 'untrusted-web-0',
      value: 'https://attacker.evil/exfil',
      secrecyTags: [],
      integrity: 'UntrustedExternal',
      sourcePrincipal: 'web-scraper',
    });

    // Attempt to launder untrusted URL through 10 TrustedSystem synthesis steps:
    for (let hop = 1; hop <= 10; hop++) {
      const trustedPrefix = difc.ingestData({
        valueId: `trusted-mix-${hop}`,
        value: `trusted-wrapper-${hop}`,
        secrecyTags: [],
        integrity: 'TrustedSystem',
        sourcePrincipal: 'system',
      });
      ctrl = difc.deriveValue({
        valueId: `launder-hop-${hop}`,
        inputs: [trustedPrefix, ctrl],
        derivedValue: `https://attacker.evil/exfil?hop=${hop}`,
        derivedBy: 'llm-router',
      });
    }

    expect(ctrl.integrity).toBe('UntrustedExternal');
    const cleanPayload = difc.ingestData({
      valueId: 'clean-body',
      value: {ok: true},
      secrecyTags: [],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'system',
    });

    const res = difc.dispatchToToolSink({
      sink: {
        sinkId: 'privileged-http',
        allowedSecrecyTags: [],
        minControlIntegrity: 'VerifiedInternal',
      },
      controlArg: ctrl,
      payload: cleanPayload,
      agentId: 'llm-router',
    });
    expect(res.kind).toBe('Refuted');
    if (res.kind === 'Refuted') {
      expect(res.reason).toBe('untrusted-control-flow-hijack');
    }
  });

  test('AG144: 5-hop Doyle sole-support cascade vs. 4-way ATMS multi-justification survival & immunization tombstone (Theorems 6-8)', () => {
    const kv = new ContentAddressedKvStore();
    const tms = new DurableMemoryTmsStore(kv, 2);
    const oracleHash = kv.putBlob('oracle-clean-144', {ok: true}, []);

    // 1. 5-hop sole-support chain: b0 -> b1 -> b2 -> b3 -> b4
    tms.proposeProvisionalBelief({
      beliefId: 'b0',
      claimText: 'Unverified root assumption',
      proposerId: 'agent-a',
      sourceIntegrity: 'VerifiedInternal',
    });
    tms.promoteToVerifiedMemory({beliefId: 'b0', attesters: ['rev-1', 'rev-2']});

    for (let i = 1; i <= 4; i++) {
      tms.proposeProvisionalBelief({
        beliefId: `b${i}`,
        claimText: `Derived hop ${i}`,
        proposerId: 'planner',
        sourceIntegrity: 'VerifiedInternal',
        justifications: [[`b${i - 1}`]],
      });
      tms.promoteToVerifiedMemory({beliefId: `b${i}`, attesters: ['rev-1', 'rev-2']});
    }

    // 2. Clean independent root + 4-way ATMS belief backed by 3 poisoned roots + 1 clean root!
    for (const pId of ['p1', 'p2', 'p3']) {
      tms.proposeProvisionalBelief({
        beliefId: pId,
        claimText: `Poison candidate ${pId}`,
        proposerId: 'agent-a',
        sourceIntegrity: 'VerifiedInternal',
      });
      tms.promoteToVerifiedMemory({beliefId: pId, attesters: ['rev-1', 'rev-2']});
    }
    tms.proposeProvisionalBelief({
      beliefId: 'b-clean-root',
      claimText: 'Formal proof invariant',
      proposerId: 'verifier',
      sourceIntegrity: 'TrustedSystem',
    });
    tms.promoteToVerifiedMemory({beliefId: 'b-clean-root', oracleReceiptHash: oracleHash});

    tms.proposeProvisionalBelief({
      beliefId: 'b-atms-resilient',
      claimText: 'Resilient policy conclusion',
      proposerId: 'planner',
      sourceIntegrity: 'VerifiedInternal',
      justifications: [['p1'], ['p2'], ['p3'], ['b-clean-root']],
    });
    tms.promoteToVerifiedMemory({beliefId: 'b-atms-resilient', attesters: ['rev-1', 'rev-2']});

    // Retract b0 -> cascades all the way to b4!
    const retr = tms.retractPoisonedBelief('b0', 'discovered-contradiction');
    expect(retr.retractedBeliefIds).toEqual(['b0', 'b1', 'b2', 'b3', 'b4']);

    // Retract p1, p2, p3 -> b-atms-resilient STILL SURVIVES via `['b-clean-root']`!
    tms.retractPoisonedBelief('p1', 'poisoned-1');
    tms.retractPoisonedBelief('p2', 'poisoned-2');
    tms.retractPoisonedBelief('p3', 'poisoned-3');
    expect(tms.getBelief('b-atms-resilient')?.status).toBe('VerifiedM1');

    // Poison immunization tombstone survives GC & blocks exact re-proposal!
    kv.gcUnreferenced();
    const repropose = tms.proposeProvisionalBelief({
      beliefId: 'b0-reborn',
      claimText: 'Unverified root assumption',
      proposerId: 'agent-b',
      sourceIntegrity: 'VerifiedInternal',
    });
    expect(repropose.kind).toBe('Refuted');
    if (repropose.kind === 'Refuted') {
      expect(repropose.reason).toBe('poisoned-claim-immunized');
    }
  });

  test('AG145: 145-Case Milestone — Sanitized DIFC + ATMS Verified Memory + B10 Quorum + cedar-poo-spec Dual-Sovereign Admission', () => {
    const kv = new ContentAddressedKvStore();
    const difc = new DifcAgentMonitor(kv);
    const tms = new DurableMemoryTmsStore(kv, 2);

    // 1. B7 Sanitized M3 declassification of tenant metric:
    const rawMetric = difc.ingestData({
      valueId: 'raw-145',
      value: 'tenant=alpha count=42',
      secrecyTags: ['tenant:alpha:stats'],
      integrity: 'TrustedSystem',
      sourcePrincipal: 'analytics',
    });
    const declassCap = new DeclassificationCapability('redactor-145', ['tenant:alpha:stats']);
    const declassRes = difc.declassify({
      capability: declassCap,
      source: rawMetric,
      redactedValue: 'aggregate_count=42',
      tagsToRemove: ['tenant:alpha:stats'],
      deterministicSanitizer: v => ({clean: !v.includes('tenant=alpha')}),
    });
    expect(declassRes.kind).toBe('Declassified');
    if (declassRes.kind !== 'Declassified') throw new Error('expected Declassified');

    // 2. B8 ATMS-verified memory backed by cold oracle:
    tms.proposeProvisionalBelief({
      beliefId: 'b-145-clean',
      claimText: 'Aggregate metric cleared for publication',
      proposerId: 'analytics',
      sourceIntegrity: 'TrustedSystem',
    });
    expect(
      tms.promoteToVerifiedMemory({
        beliefId: 'b-145-clean',
        oracleReceiptHash: declassRes.auditReceiptHash,
      }).kind,
    ).toBe('PromotedM1');

    // 3. B10 Quorum finality over the publication operation:
    const logId = 'log-milestone-145';
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
    const opDigest = sha256Digest({
      op: 'publish-aggregate-145',
      declassReceipt: declassRes.auditReceiptHash,
      beliefId: 'b-145-clean',
    });
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

    // 4. cedar-poo-spec Dual-Sovereign Gate:
    const polDigest = sha256Digest({policy: 'cedar-disclosure-v145'});
    const lease = new LiveM3Capability('lease-145', 'disclosure:pub', 3);
    const hostDecision = evaluateHostPolicySemantics({
      permitMatched: true,
      forbidMatched: false,
      contextReady: true,
    });
    const admitted = evaluateDualSovereignGate({
      kv,
      libraryVerdict: libVerdict,
      hostReceipt: {
        hostSystem: 'cedar-poo-spec',
        decision: hostDecision,
        boundOperationDigest: opDigest,
        policySnapshotDigest: polDigest,
        policyAffectedScopes: ['disclosure:pub'],
        liveAuthorityLease: lease,
        authorityLiveAtUse: true,
      },
      expectedOperationDigest: opDigest,
      activePolicySnapshotDigest: polDigest,
      activeLeaseEpoch: 3,
    });
    expect(admitted.kind).toBe('Proven');
    if (admitted.kind !== 'Proven') throw new Error('expected Proven');

    // Aggressive GC preserves declassification receipt & dual-sovereign admission receipt!
    kv.gcUnreferenced();
    expect(kv.hasBlob(admitted.dualSovereignReceiptHash)).toBe(true);
  });
});
