// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from '../src/durable-merkle-store.ts';
import {
  CoordinatorSigningKey,
  VerifiableTransparencyLog,
  verifyInclusionProof,
  verifySignedTreeHead,
  WitnessEquivocationMonitor,
} from '../src/transparency-log-equivocation.ts';

describe('Phase 18 Verifiable Transparency Log (RFC 6962), Ed25519 STH & Split-View Equivocation (10.166 / 30.05 AG101-AG105)', () => {
  test('AG101: Exact RFC 6962 Ed25519 append-only log verifies O(log N) inclusion proofs for all 7 entries & rejects tampered leaf', () => {
    const key = new CoordinatorSigningKey('gov-log-prod');
    const log = new VerifiableTransparencyLog(key);
    const appended: Array<{leafIndex: number; leafBytes: Buffer}> = [];

    for (let i = 0; i < 7; i++) {
      appended.push(log.appendEntry({event: `governance-receipt-${i}`, epoch: i + 1}));
    }

    const sth = log.issueSignedTreeHead(7);
    expect(verifySignedTreeHead(sth, log.publicKeyPem)).toBe(true);

    // Every single entry 0..6 passes RFC 6962 O(log N) inclusion verification!
    for (const item of appended) {
      const proof = log.getInclusionProof(item.leafIndex);
      expect(proof.length).toBeLessThanOrEqual(3);
      expect(
        verifyInclusionProof({
          leafBytes: item.leafBytes,
          index: item.leafIndex,
          treeSize: sth.treeSize,
          proofHex: proof,
          expectedRootHex: sth.rootHashHex,
        }),
      ).toBe(true);
    }

    // Tampered leaf payload MUST fail inclusion proof!
    const proof3 = log.getInclusionProof(3);
    expect(
      verifyInclusionProof({
        leafBytes: Buffer.from(JSON.stringify({event: 'TAMPERED-receipt-3', epoch: 4}), 'utf8'),
        index: 3,
        treeSize: sth.treeSize,
        proofHex: proof3,
        expectedRootHex: sth.rootHashHex,
      }),
    ).toBe(false);
  });

  test('AG102: Exact RFC 6962 append-only consistency proofs across non-power-of-two growth (1 -> 3 -> 5 -> 7 -> 8) verified via public key only', () => {
    const key = new CoordinatorSigningKey('gov-log-growth');
    const log = new VerifiableTransparencyLog(key);
    // External regulator holds ONLY the Ed25519 public key (zero shared secret!)
    const witness = new WitnessEquivocationMonitor('gov-log-growth', log.publicKeyPem);

    const checkpoints = [1, 3, 5, 7, 8];
    let prevSize = 0;

    for (const targetSize of checkpoints) {
      while (log.size < targetSize) {
        log.appendEntry({seq: log.size, action: 'admit-release'});
      }
      const sth = log.issueSignedTreeHead(targetSize * 10);
      const proof = prevSize === 0 ? [] : log.getConsistencyProof(prevSize, targetSize);
      const res = witness.observeSignedTreeHead(sth, proof);
      expect(res.kind).toBe('AcceptedConsistent');
      prevSize = targetSize;
    }

    expect(witness.getLatestSth()?.treeSize).toBe(8);
  });

  test('AG103: Split-View Equivocation Fraud Proof catches compromised coordinator showing divergent roots to Regulator vs Prod Worker', () => {
    const compromisedKey = new CoordinatorSigningKey('gov-log-split');

    // View A shown to external Regulator (4 clean entries):
    const cleanLog = new VerifiableTransparencyLog(compromisedKey);
    for (let i = 0; i < 4; i++) cleanLog.appendEntry({seq: i, decision: 'clean'});
    const sthRegulator = cleanLog.issueSignedTreeHead(10);

    // View B shown to Production Worker (4 entries with secret backdoor at index 2!):
    const evilLog = new VerifiableTransparencyLog(compromisedKey);
    evilLog.appendEntry({seq: 0, decision: 'clean'});
    evilLog.appendEntry({seq: 1, decision: 'clean'});
    evilLog.appendEntry({seq: 2, decision: 'BACKDOOR_RELEASE'});
    evilLog.appendEntry({seq: 3, decision: 'clean'});
    const sthProdWorker = evilLog.issueSignedTreeHead(11);

    // Independent witness gossips both STHs -> catches split-view & emits self-authenticating fraud proof!
    const witness = new WitnessEquivocationMonitor('gov-log-split', compromisedKey.publicKeyPem);
    expect(witness.observeSignedTreeHead(sthRegulator).kind).toBe('AcceptedConsistent');

    const gossipCheck = witness.observeSignedTreeHead(sthProdWorker);
    expect(gossipCheck.kind).toBe('EquivocationDetected');
    if (gossipCheck.kind === 'EquivocationDetected') {
      expect(gossipCheck.fraudProof.fraudKind).toBe('split-view-same-size-divergent-root');
      // Both STHs in the fraud proof carry valid Ed25519 signatures from the coordinator itself!
      expect(verifySignedTreeHead(gossipCheck.fraudProof.sthEarlierOrPeer, compromisedKey.publicKeyPem)).toBe(true);
      expect(verifySignedTreeHead(gossipCheck.fraudProof.sthConflicting, compromisedKey.publicKeyPem)).toBe(true);
      expect(gossipCheck.fraudProof.sthEarlierOrPeer.rootHashHex).not.toBe(
        gossipCheck.fraudProof.sthConflicting.rootHashHex,
      );
    }
  });

  test('AG104: Retroactive history rewrite & monotonic tree-size rollback caught by RFC 6962 consistency check', () => {
    const key = new CoordinatorSigningKey('gov-log-rewrite');
    const honestLog = new VerifiableTransparencyLog(key);
    for (let i = 0; i < 4; i++) honestLog.appendEntry({seq: i, rule: 'original'});
    const sthSize4 = honestLog.issueSignedTreeHead(10);

    const witness = new WitnessEquivocationMonitor('gov-log-rewrite', key.publicKeyPem);
    expect(witness.observeSignedTreeHead(sthSize4).kind).toBe('AcceptedConsistent');

    // 1. Coordinator retroactively rewrites leaf #1 and appends 2 more entries (size 6):
    const rewrittenLog = new VerifiableTransparencyLog(key);
    rewrittenLog.appendEntry({seq: 0, rule: 'original'});
    rewrittenLog.appendEntry({seq: 1, rule: 'RETROACTIVELY_ERASED_INCIDENT'});
    rewrittenLog.appendEntry({seq: 2, rule: 'original'});
    rewrittenLog.appendEntry({seq: 3, rule: 'original'});
    rewrittenLog.appendEntry({seq: 4, rule: 'new-4'});
    rewrittenLog.appendEntry({seq: 5, rule: 'new-5'});
    const sthRewritten6 = rewrittenLog.issueSignedTreeHead(20);
    const fakeConsistencyProof = rewrittenLog.getConsistencyProof(4, 6);

    const rewriteVerdict = witness.observeSignedTreeHead(sthRewritten6, fakeConsistencyProof);
    expect(rewriteVerdict.kind).toBe('EquivocationDetected');
    if (rewriteVerdict.kind === 'EquivocationDetected') {
      expect(rewriteVerdict.fraudProof.fraudKind).toBe('history-rewrite-inconsistent-prefix');
    }

    // 2. Coordinator tries silent rollback from size 4 -> size 2:
    const rolledBackLog = new VerifiableTransparencyLog(key);
    rolledBackLog.appendEntry({seq: 0, rule: 'original'});
    rolledBackLog.appendEntry({seq: 1, rule: 'original'});
    const sthRollback2 = rolledBackLog.issueSignedTreeHead(25);
    const rollbackVerdict = witness.observeSignedTreeHead(sthRollback2, []);
    expect(rollbackVerdict.kind).toBe('EquivocationDetected');
    if (rollbackVerdict.kind === 'EquivocationDetected') {
      expect(rollbackVerdict.fraudProof.fraudKind).toBe('monotonic-tree-size-rollback');
    }
  });

  test('AG105: R3 blocks Ed25519 CoordinatorSigningKey from entering M1 store & rejects forged STH signatures', () => {
    const kv = new ContentAddressedKvStore();
    const key = new CoordinatorSigningKey('gov-log-r3');
    const attackerKey = new CoordinatorSigningKey('gov-log-r3');

    // R3: Private Ed25519 signing key can never enter M1 Merkle persistence!
    expect(() => kv.putBlob('key-leak', {nested: {signingKey: key}}, [])).toThrow(
      /R3 ReachabilityLeakError/,
    );
    expect(() => JSON.stringify(key)).toThrow(/R3 ReachabilityLeakError/);

    // Forged STH signed by wrong Ed25519 private key is deterministically refused!
    const witness = new WitnessEquivocationMonitor('gov-log-r3', key.publicKeyPem);
    const forgedSth = attackerKey.signTreeHead(1, 'ab'.repeat(32), 1);
    expect(witness.observeSignedTreeHead(forgedSth)).toEqual({
      kind: 'Refuted',
      reason: 'invalid-ed25519-signature',
    });
  });
});
