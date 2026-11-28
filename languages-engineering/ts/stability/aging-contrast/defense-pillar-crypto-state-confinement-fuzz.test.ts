// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm38State {
  activeEpoch: number;
  shreddedMaxEpoch: number;
  keyEpochGuarded: boolean;
  zkNormalizedAndFresh: boolean;
  supplyChainPinnedAndDistinct: boolean;
  treatyFreezeAndEpochMonotonic: boolean;
  merkleNoDupAndEmptyRootChecked: boolean;
  keyEpochBreaches: number;
  zkDisclosureBreaches: number;
  supplyChainBreaches: number;
  treatyReciprocityBreaches: number;
  merkleIntegrityBreaches: number;
  cleanVerifiedOps: number;
  stepCount: number;
}

function initState(): Sm38State {
  return {
    activeEpoch: 1,
    shreddedMaxEpoch: 0,
    keyEpochGuarded: true,
    zkNormalizedAndFresh: true,
    supplyChainPinnedAndDistinct: true,
    treatyFreezeAndEpochMonotonic: true,
    merkleNoDupAndEmptyRootChecked: true,
    keyEpochBreaches: 0,
    zkDisclosureBreaches: 0,
    supplyChainBreaches: 0,
    treatyReciprocityBreaches: 0,
    merkleIntegrityBreaches: 0,
    cleanVerifiedOps: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm38State, action: string): Sm38State {
  const s = {...state};
  switch (action) {
    case 'rotateAndShredRetiredEpoch':
      if (s.stepCount < 12 && s.keyEpochGuarded && s.activeEpoch < 12) {
        s.shreddedMaxEpoch = s.activeEpoch;
        s.activeEpoch += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'verifyNormalizedZkDisclosure':
      if (s.stepCount < 12 && s.zkNormalizedAndFresh) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'admitDistinctTwoBuilderRelease':
      if (s.stepCount < 12 && s.supplyChainPinnedAndDistinct) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'admitMonotonicBilateralOp':
      if (s.stepCount < 12 && s.treatyFreezeAndEpochMonotonic) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'verifyDomainSeparatedMerkleAndLogHead':
      if (s.stepCount < 12 && s.merkleNoDupAndEmptyRootChecked) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM38 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm38State): boolean {
  return (
    s.keyEpochBreaches === 0 &&
    s.zkDisclosureBreaches === 0 &&
    s.supplyChainBreaches === 0 &&
    s.treatyReciprocityBreaches === 0 &&
    s.merkleIntegrityBreaches === 0 &&
    s.keyEpochGuarded &&
    s.zkNormalizedAndFresh &&
    s.supplyChainPinnedAndDistinct &&
    s.treatyFreezeAndEpochMonotonic &&
    s.merkleNoDupAndEmptyRootChecked &&
    s.activeEpoch >= 1 &&
    s.activeEpoch <= 12 &&
    s.shreddedMaxEpoch >= 0 &&
    s.shreddedMaxEpoch < s.activeEpoch &&
    s.stepCount <= 12
  );
}

function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

const EMPTY_TREE_ROOT = sha256Hex('');

function canShredEpoch(epoch: number, activeEpoch: number): boolean {
  return Number.isInteger(epoch) && epoch > 0 && epoch < activeEpoch;
}

function canRewrap(fromEpoch: number, toEpoch: number, activeEpoch: number, committed: Set<number>): boolean {
  return fromEpoch > 0 && fromEpoch < toEpoch && toEpoch === activeEpoch && committed.has(fromEpoch);
}

function canonicalKey(raw: string): string {
  return raw.trim().toLowerCase();
}

function checkForbiddenDisclosedFields(forbidden: Set<string>, disclosed: string[]): boolean {
  for (const field of disclosed) {
    if (forbidden.has(field.trim().toLowerCase())) return false;
  }
  return true;
}

function issueFreshNonce(nonce: string, pending: Set<string>, consumed: Set<string>): boolean {
  const n = nonce.trim();
  if (n.length === 0 || consumed.has(n)) return false;
  pending.add(n);
  return true;
}

function buildersDistinct(builderA: string, builderB: string): boolean {
  const a = canonicalKey(builderA);
  const b = canonicalKey(builderB);
  return a.length > 0 && b.length > 0 && a !== b;
}

function canUpdateTreaty(
  existing: {orgA: string; orgB: string; epoch: number; freezeActive: boolean} | undefined,
  next: {orgA: string; orgB: string; epoch: number; freezeActive: boolean},
): boolean {
  if (!buildersDistinct(next.orgA, next.orgB)) return false;
  if (!existing) return true;
  if (existing.freezeActive && !next.freezeActive) return false;
  if (next.epoch < existing.epoch) return false;
  return true;
}

function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function computeShardMerkleRoot(shards: string[]): string {
  const sorted = [...shards].sort();
  const leaves = sorted.map((s) => sha256Hex(`marlin:b21:leaf:${s}`));
  const mth = (slice: string[]): string => {
    if (slice.length === 1) return slice[0]!;
    const k = largestPowerOfTwoLessThan(slice.length);
    return sha256Hex(`marlin:b21:node:${mth(slice.slice(0, k))}:${mth(slice.slice(k))}`);
  };
  return mth(leaves);
}

function verifyEmptyHeadProgression(
  prevRoot: string,
  firstSize: number,
  secondSize: number,
  nextSize: number,
  pathLen: number,
): boolean {
  return (
    prevRoot === EMPTY_TREE_ROOT &&
    firstSize === 0 &&
    secondSize === nextSize &&
    pathLen === 0
  );
}

function makePrng(seed: number): () => number {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return (x >>> 0) / 0x100000000;
  };
}

function bigintFromItf(raw: unknown): number {
  if (typeof raw === 'number') return raw;
  if (raw && typeof raw === 'object' && '#bigint' in raw) {
    return Number((raw as {'#bigint': string})['#bigint']);
  }
  throw new Error(`Expected ITF integer, got ${JSON.stringify(raw)}`);
}

function parseItfState(raw: Record<string, unknown>): Sm38State {
  const h = raw.h as Record<string, unknown>;
  return {
    activeEpoch: bigintFromItf(h.activeEpoch),
    shreddedMaxEpoch: bigintFromItf(h.shreddedMaxEpoch),
    keyEpochGuarded: Boolean(h.keyEpochGuarded),
    zkNormalizedAndFresh: Boolean(h.zkNormalizedAndFresh),
    supplyChainPinnedAndDistinct: Boolean(h.supplyChainPinnedAndDistinct),
    treatyFreezeAndEpochMonotonic: Boolean(h.treatyFreezeAndEpochMonotonic),
    merkleNoDupAndEmptyRootChecked: Boolean(h.merkleNoDupAndEmptyRootChecked),
    keyEpochBreaches: bigintFromItf(h.keyEpochBreaches),
    zkDisclosureBreaches: bigintFromItf(h.zkDisclosureBreaches),
    supplyChainBreaches: bigintFromItf(h.supplyChainBreaches),
    treatyReciprocityBreaches: bigintFromItf(h.treatyReciprocityBreaches),
    merkleIntegrityBreaches: bigintFromItf(h.merkleIntegrityBreaches),
    cleanVerifiedOps: bigintFromItf(h.cleanVerifiedOps),
    stepCount: bigintFromItf(h.stepCount),
  };
}

describe('SM38 (ADV-L4): Defense Pillar Cryptographic & State-Machine Integrity Confinement', () => {
  test('500-trial ADV-L4 hostile fuzz refutes B16/B18/B14/B20/B9/B21 bypass exploits', () => {
    const rand = makePrng(0x534d3338);
    const forbidden = new Set(['raw_pii', 'signing_seed']);

    for (let trial = 0; trial < 500; trial++) {
      const activeEpoch = 2 + (trial % 20);
      const futureEpoch = activeEpoch + 1 + Math.floor(rand() * 10);
      const committed = new Set<number>([1, activeEpoch]);

      // 1. B16: forbid shredding epoch 0, active epoch, or any future epoch; forbid epoch-0 rewrap.
      expect(canShredEpoch(0, activeEpoch)).toBe(false);
      expect(canShredEpoch(activeEpoch, activeEpoch)).toBe(false);
      expect(canShredEpoch(futureEpoch, activeEpoch)).toBe(false);
      expect(canShredEpoch(1, activeEpoch)).toBe(true);
      expect(canRewrap(0, activeEpoch, activeEpoch, committed)).toBe(false);
      expect(canRewrap(1, activeEpoch, activeEpoch, committed)).toBe(true);

      // 2. B18: case/whitespace secret leak & consumed/blank challenge nonce replay fail closed.
      const variants = ['RAW_PII', ' raw_pii ', '\tSigning_Seed\n'];
      expect(checkForbiddenDisclosedFields(forbidden, [variants[trial % variants.length]!])).toBe(false);
      expect(checkForbiddenDisclosedFields(forbidden, ['jurisdiction_tier'])).toBe(true);

      const pending = new Set<string>();
      const consumed = new Set<string>([`zk-chal-${trial}`]);
      expect(issueFreshNonce('   ', pending, consumed)).toBe(false);
      expect(issueFreshNonce(`zk-chal-${trial}`, pending, consumed)).toBe(false);
      expect(issueFreshNonce(`zk-chal-fresh-${trial}`, pending, consumed)).toBe(true);

      // 3. B14: case/whitespace single-builder spoofing fails closed.
      const bId = `builder-eu-${trial}`;
      expect(buildersDistinct(bId, bId.toUpperCase())).toBe(false);
      expect(buildersDistinct(bId, `  ${bId}  `)).toBe(false);
      expect(buildersDistinct(bId, `builder-us-${trial}`)).toBe(true);

      // 4. B20: treaty freeze wipeout, epoch rollback, and self-reciprocity case spoofing fail closed.
      const frozen = {orgA: 'org-alpha', orgB: 'org-beta', epoch: 3 + (trial % 5), freezeActive: true};
      expect(canUpdateTreaty(frozen, {...frozen, freezeActive: false})).toBe(false);
      expect(canUpdateTreaty(frozen, {...frozen, epoch: frozen.epoch - 1})).toBe(false);
      expect(canUpdateTreaty(undefined, {orgA: 'org-alpha', orgB: ' ORG-ALPHA ', epoch: 1, freezeActive: false})).toBe(false);
      expect(canUpdateTreaty(frozen, {...frozen, epoch: frozen.epoch + 1})).toBe(true);

      // 5. B9 & B21: forged empty tree root fails closed; odd-leaf Merkle root resists [A,B,C] vs [A,B,C,C].
      expect(verifyEmptyHeadProgression('f'.repeat(64), 0, 3, 3, 0)).toBe(false);
      expect(verifyEmptyHeadProgression(EMPTY_TREE_ROOT, 1, 3, 3, 0)).toBe(false);
      expect(verifyEmptyHeadProgression(EMPTY_TREE_ROOT, 0, 3, 3, 0)).toBe(true);

      const a = `sha256:${sha256Hex(`s-${trial}-a`)}`;
      const b = `sha256:${sha256Hex(`s-${trial}-b`)}`;
      const c = `sha256:${sha256Hex(`s-${trial}-c`)}`;
      expect(computeShardMerkleRoot([a, b, c])).not.toBe(computeShardMerkleRoot([a, b, c, c]));
    }
  });

  test('6 live Quint --mbt ITF traces refine SM38 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const qntPath = resolve(
      repoRoot,
      'packages/quint-models/threat/execution/defense-pillar-crypto-state-confinement/DefensePillarCryptoStateConfinement.qnt',
    );
    const resolverCli = resolve(repoRoot, 'packages/quint-modules-resolver/src/cli.ts');
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm38-mbt-'));
    try {
      for (let seed = 1; seed <= 6; seed++) {
        const itfPath = join(tmpDir, `sm38-seed-${seed}.itf.json`);
        execFileSync(
          'bun',
          [
            'run',
            resolverCli,
            'run',
            qntPath,
            '--main=execution_defense_pillar_crypto_state_confinement',
            '--invariant=safety',
            '--mbt',
            '--max-steps=12',
            `--seed=${seed}`,
            `--out-itf=${itfPath}`,
          ],
          {cwd: repoRoot, stdio: 'pipe'},
        );
        expect(existsSync(itfPath)).toBe(true);
        const itf = JSON.parse(readFileSync(itfPath, 'utf8')) as {
          states: Array<Record<string, unknown>>;
        };
        expect(itf.states.length).toBeGreaterThan(1);

        let local = initState();
        const initialItf = parseItfState(itf.states[0]!);
        expect(local).toEqual(initialItf);
        expect(isSafetyInvariantHeld(local)).toBe(true);

        for (let i = 1; i < itf.states.length; i++) {
          const actionTaken = itf.states[i]!['mbt::actionTaken'] as string;
          const nextItf = parseItfState(itf.states[i]!);
          local = applySafeAction(local, actionTaken);
          expect(local).toEqual(nextItf);
          expect(isSafetyInvariantHeld(local)).toBe(true);
        }
      }
    } finally {
      rmSync(tmpDir, {recursive: true, force: true});
    }
  }, 30_000);
});
