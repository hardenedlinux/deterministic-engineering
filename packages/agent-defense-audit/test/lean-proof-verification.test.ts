// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {ContentAddressedKvStore} from '../src/durable-merkle-store.ts';
import {LinearBudgetTree} from '../src/durable-saga-budget.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
} from '../src/transparency-log-equivocation.ts';
import {
  buildThresholdCheckpoint,
  validateBftQuorumParameters,
} from '../src/witness-quorum-finality.ts';
import {
  buildJointHandoverCertificate,
  createEpochRoster,
  ForwardSealedEpochVerifier,
  ForwardSecureWitnessKey,
} from '../src/witness-epoch-reconfiguration.ts';
import {
  auditLeanSourceAntiFabrication,
  isLeanToolchainAvailable,
  parseLeanPrintAxiomsOutput,
  verifyLeanModuleAxiomsLive,
} from '../src/lean-proof-oracle.ts';

const LEAN_MODULE_PATH = resolve(
  import.meta.dir,
  '../../lean-models/DeterministicEngineering/Engineering/DurableGovernanceQuorum.lean',
);

const CORE_UNBOUNDED_THEOREMS = [
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
] as const;

describe('Phase 24 Unbounded Lean 4 / LeanPoo Machine-Checked Meta-Theorems & Proof-Carrying Oracle (10.172 / 30.05 AG126-AG130)', () => {
  test('AG126: Live Lean 4 / LeanPoo oracle verifies all 15 unbounded & contract-refinement theorems carry zero sorry/custom axioms & pins M1 certificate', () => {
    const leanSource = readFileSync(LEAN_MODULE_PATH, 'utf8');
    const staticCheck = auditLeanSourceAntiFabrication(leanSource);
    expect(staticCheck).toEqual({passed: true, findings: []});

    const kv = new ContentAddressedKvStore();
    if (!isLeanToolchainAvailable()) {
      const verdict = verifyLeanModuleAxiomsLive({
        moduleName: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
        namespacePrefix: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
        expectedTheorems: CORE_UNBOUNDED_THEOREMS,
        kv,
      });
      expect(verdict).toEqual({kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'});
      return;
    }

    const res = verifyLeanModuleAxiomsLive({
      moduleName: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
      namespacePrefix: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
      expectedTheorems: CORE_UNBOUNDED_THEOREMS,
      kv,
    });
    expect(res.kind).toBe('Proven');
    if (res.kind !== 'Proven') throw new Error('expected Proven');
    expect(Object.keys(res.theoremAxioms).length).toBe(CORE_UNBOUNDED_THEOREMS.length);
    expect(res.pinnedCertificateHash).toBeDefined();

    // Pinned M1 Lean 4 proof-carrying certificate survives aggressive GC!
    kv.gcUnreferenced();
    expect(kv.hasBlob(res.pinnedCertificateHash!)).toBe(true);
  }, 30_000);

  test('AG127: Runtime B10 BFT quorum parameter gate matches unbounded Lean 4 theorem (2*t > N + f) across N = 4, 7, 10, 31, 100', () => {
    // Valid BFT configurations (N = 3f + 1, t = 2f + 1) across unbounded scales:
    for (const [n, f, t, expectedHonestOverlap] of [
      [4, 1, 3, 1],
      [7, 2, 5, 1],
      [10, 3, 7, 1],
      [31, 10, 21, 1],
      [100, 33, 67, 1],
      [100, 10, 60, 10],
    ] as const) {
      expect(
        validateBftQuorumParameters({
          totalWitnesses: n,
          maxByzantineFaults: f,
          threshold: t,
        }),
      ).toEqual({kind: 'Valid', minHonestIntersection: expectedHonestOverlap});
    }

    // Exact boundary violations (2*t <= N + f) MUST be refused at every scale:
    for (const [n, f, t] of [
      [4, 1, 2],
      [7, 2, 4],
      [10, 3, 6],
      [31, 10, 20],
      [100, 33, 66],
    ] as const) {
      expect(
        validateBftQuorumParameters({
          totalWitnesses: n,
          maxByzantineFaults: f,
          threshold: t,
        }),
      ).toEqual({kind: 'Refuted', reason: 'unsafe-non-intersecting-quorum'});
    }
  });

  test('AG128: Multi-epoch unbounded handover chain (Epoch 1 -> 2 -> 3 -> 4 -> 5) defeats posterior corruption of ALL 4 retired committees', () => {
    const kv = new ContentAddressedKvStore();
    const logId = 'log-5-epoch-chain';
    const coordKey = new CoordinatorSigningKey(logId);
    const log = new VerifiableTransparencyLog(coordKey);

    // Provision 4 witnesses across epochs 1..5 (rotating keys at every epoch!):
    const witnesses = ['w1', 'w2', 'w3', 'w4'].map(id => new ForwardSecureWitnessKey(id, 1));
    const rosters = [1, 2, 3, 4, 5].map(epoch => {
      const pems: Record<string, string> = {};
      for (const w of witnesses) {
        pems[w.witnessId] = w.provisionEpochKey(epoch);
      }
      return createEpochRoster({
        logId,
        epoch,
        witnessPublicKeys: pems,
        maxByzantineFaults: 1,
        threshold: 3,
      });
    });

    // Save retired Epoch 1..4 checkpoints BEFORE zeroizing to simulate posterior key compromise!
    const retiredCheckpoints: ReturnType<typeof buildThresholdCheckpoint>[] = [];
    const verifier = new ForwardSealedEpochVerifier(kv, coordKey.publicKeyPem, rosters[0]!);

    for (let epoch = 1; epoch <= 4; epoch++) {
      const prevSize = log.size;
      log.appendEntry({epoch, seq: log.size, msg: `entry-e${epoch}`});
      const sth = log.issueSignedTreeHead(epoch);
      const qc = buildThresholdCheckpoint(sth, [
        witnesses[0]!.cosignCheckpoint(sth),
        witnesses[1]!.cosignCheckpoint(sth),
        witnesses[2]!.cosignCheckpoint(sth),
      ]);
      const proof = prevSize > 0 ? log.getConsistencyProof(prevSize, log.size) : [];
      expect(
        verifier.verifyCheckpointInCurrentEpoch({
          checkpoint: qc,
          consistencyProofFromAnchor: proof,
        }).kind,
      ).toBe('FinalizedInEpoch');
      retiredCheckpoints.push(qc);

      // Perform Joint-Consensus Dual-Quorum Handover epoch -> epoch + 1:
      const oldRoster = rosters[epoch - 1]!;
      const newRoster = rosters[epoch]!;
      const common = {
        logId,
        fromEpoch: epoch,
        toEpoch: epoch + 1,
        anchorTreeSize: sth.treeSize,
        anchorRootHashHex: sth.rootHashHex,
        oldRosterDigest: oldRoster.rosterDigest,
        newRosterDigest: newRoster.rosterDigest,
      };
      const cert = buildJointHandoverCertificate({
        logId,
        fromEpoch: epoch,
        toEpoch: epoch + 1,
        anchorTreeSize: sth.treeSize,
        anchorRootHashHex: sth.rootHashHex,
        oldRoster,
        newRoster,
        oldQuorumCosignatures: [0, 1, 2].map(i =>
          witnesses[i]!.signHandover({...common, signingEpoch: epoch}),
        ),
        newQuorumCosignatures: [0, 1, 3].map(i =>
          witnesses[i]!.signHandover({...common, signingEpoch: epoch + 1}),
        ),
      });
      const applied = verifier.applyJointHandover({cert});
      expect(applied.kind).toBe('EpochAdvanced');

      // Zeroize retired epoch key on honest witnesses!
      for (const w of witnesses) {
        w.zeroizeRetiredEpochKey(epoch);
        expect(w.isEpochZeroized(epoch)).toBe(true);
      }
    }

    expect(verifier.getPinnedEpoch()).toBe(5);

    // EVERY retired epoch (1, 2, 3, 4) is deterministically rejected after reaching Epoch 5!
    for (const retiredQc of retiredCheckpoints) {
      expect(verifier.verifyCheckpointInCurrentEpoch({checkpoint: retiredQc})).toEqual({
        kind: 'Refuted',
        reason: 'long-range-retired-epoch-refused',
      });
    }

    // Epoch 5 checkpoint verifies cleanly with RFC 6962 continuity from Epoch 4 anchor!
    const anchorSize = log.size;
    log.appendEntry({epoch: 5, seq: log.size, msg: 'entry-e5'});
    const sthE5 = log.issueSignedTreeHead(5);
    const qcE5 = buildThresholdCheckpoint(sthE5, [
      witnesses[0]!.cosignCheckpoint(sthE5),
      witnesses[2]!.cosignCheckpoint(sthE5),
      witnesses[3]!.cosignCheckpoint(sthE5),
    ]);
    expect(
      verifier.verifyCheckpointInCurrentEpoch({
        checkpoint: qcE5,
        consistencyProofFromAnchor: log.getConsistencyProof(anchorSize, log.size),
      }).kind,
    ).toBe('FinalizedInEpoch');
  });

  test('AG129: Arbitrary-depth R3 reachability guard (20 levels) & multi-level 15-agent LinearBudgetTree match Lean 4 Theorems 3 & 4', () => {
    const kv = new ContentAddressedKvStore();
    const buriedKey = new ForwardSecureWitnessKey('deep-w1', 1);

    // Bury an M3 ForwardSecureWitnessKey 20 levels deep inside nested M1-looking JSON objects:
    let nested: Record<string, unknown> = {leaf: buriedKey};
    for (let depth = 0; depth < 20; depth++) {
      nested = {level: depth, child: nested};
    }
    expect(() => kv.putBlob('deep-20-level-leak', nested, [])).toThrow(/R3 ReachabilityLeakError/);

    // 4-level binary delegation fan-out (15 total handles) preserves exact linear conservation = 1000!
    const rootBudget = new LinearBudgetTree('root', 1000);
    expect(rootBudget.splitSubBudget('root', 'a', 500).kind).toBe('Allocated');
    expect(rootBudget.splitSubBudget('root', 'b', 400).kind).toBe('Allocated');
    expect(rootBudget.splitSubBudget('a', 'a1', 200).kind).toBe('Allocated');
    expect(rootBudget.splitSubBudget('a', 'a2', 200).kind).toBe('Allocated');
    expect(rootBudget.splitSubBudget('b', 'b1', 150).kind).toBe('Allocated');
    expect(rootBudget.splitSubBudget('b', 'b2', 150).kind).toBe('Allocated');
    for (const [parent, c1, c2] of [
      ['a1', 'a1x', 'a1y'],
      ['a2', 'a2x', 'a2y'],
      ['b1', 'b1x', 'b1y'],
      ['b2', 'b2x', 'b2y'],
    ] as const) {
      expect(rootBudget.splitSubBudget(parent, c1, 50).kind).toBe('Allocated');
      expect(rootBudget.splitSubBudget(parent, c2, 50).kind).toBe('Allocated');
    }

    // Spend across leaves & interior nodes; global sum remaining + spent MUST equal 1000!
    const ev = kv.putBlob('budget-step-ev', {step: 'ok'}, []);
    expect(rootBudget.consume('a1x', 35, 'step-1', ev).kind).toBe('Consumed');
    expect(rootBudget.consume('b2y', 50, 'step-2', ev).kind).toBe('Consumed');
    expect(rootBudget.consume('root', 100, 'step-3', ev).kind).toBe('Consumed');
    expect(rootBudget.consume('b2y', 1, 'step-over', ev).kind).toBe('BudgetExhaustedHalt');
    const audit = rootBudget.conservationAudit();
    expect(audit).toEqual({
      rootBudgetUnits: 1000,
      totalRemaining: 815,
      totalSpent: 185,
      conserved: true,
    });
  });

  test('AG130: G2 Anti-Fabricated-Proof Gate catches Lean 4 sorry/axiom cheating & missing lake toolchain fails closed as PendingMethod', () => {
    const cheatedLean = `
      axiom trust_me : False
      theorem fake_bft : True := by
        sorry
    `;
    const staticAudit = auditLeanSourceAntiFabrication(cheatedLean);
    expect(staticAudit.passed).toBe(false);
    expect(staticAudit.findings.map(f => f.kind)).toEqual(['custom-axiom', 'sorry']);

    const badAxiomStdout = `
'Foo.fake_bft' depends on axioms: [propext, sorryAx, trust_me]
`;
    const parsed = parseLeanPrintAxiomsOutput(badAxiomStdout, ['fake_bft']);
    expect(parsed).toEqual({
      kind: 'Refuted',
      reason: 'unverified-sorry-or-custom-axiom',
      offendingTheorems: [{theorem: 'Foo.fake_bft', disallowedAxioms: ['sorryAx', 'trust_me']}],
    });

    const missingToolchain = verifyLeanModuleAxiomsLive({
      moduleName: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
      namespacePrefix: 'DeterministicEngineering.Engineering.DurableGovernanceQuorum',
      expectedTheorems: CORE_UNBOUNDED_THEOREMS,
      lakeBinary: 'nonexistent-lake-binary-xyz',
    });
    expect(missingToolchain).toEqual({
      kind: 'PendingMethod',
      reason: 'lean-toolchain-unavailable',
    });
  });
});
