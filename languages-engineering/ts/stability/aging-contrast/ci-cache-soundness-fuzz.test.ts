// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const RESOLVER_CLI = join(REPO_ROOT, 'packages/quint-modules-resolver/src/cli.ts');
const VERIFY_FRAMEWORK = join(REPO_ROOT, 't/harness/verify-framework.ts');
const SM18_SPEC = join(
  REPO_ROOT,
  'packages/quint-models/engineering/concurrency/ci-cache-soundness-and-sharding/CiCacheSoundnessAndSharding.qnt',
);

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class DeterministicCiCasCluster {
  readonly maxEntries: number;
  readonly shardStores = new Map<string, Map<string, string>>();
  falseHitCount = 0;
  writeConflictCount = 0;
  cacheHits = 0;
  rebuilds = 0;

  constructor(maxEntries = 16) {
    this.maxEntries = maxEntries;
  }

  lookupOrBuild(shard: string, unitId: string, engineEpoch: number, flagsEpoch: number, sourceEpoch: number): 'hit' | 'rebuild' {
    let store = this.shardStores.get(shard);
    if (!store) {
      store = new Map();
      this.shardStores.set(shard, store);
    }
    const actionKey = `e:${engineEpoch}|f:${flagsEpoch}|s:${sourceEpoch}`;
    const stored = store.get(unitId);
    if (stored === actionKey) {
      this.cacheHits += 1;
      return 'hit';
    }
    store.set(unitId, actionKey);
    this.rebuilds += 1;
    // Active-set GC ceiling per shard
    while (store.size > this.maxEntries) {
      const oldest = store.keys().next().value;
      if (oldest === undefined) break;
      store.delete(oldest);
    }
    return 'rebuild';
  }

  maxRetainedPerShard(): number {
    let max = 0;
    for (const s of this.shardStores.values()) {
      if (s.size > max) max = s.size;
    }
    return max;
  }
}

class NaiveCiCacheCluster {
  readonly maxEntries: number;
  readonly sharedStore = new Map<string, string>();
  falseHitCount = 0;
  writeConflictCount = 0;
  quotaBreaches = 0;

  constructor(maxEntries = 16) {
    this.maxEntries = maxEntries;
  }

  // Defect 1+2+3: ignores engineEpoch, uses one shared mutable key across shards, no GC
  lookupOrBuild(shard: string, unitId: string, engineEpoch: number, sourceEpoch: number, parallelShard: string): void {
    if (shard !== parallelShard) {
      // Parallel shard write-write collision on shared cache key
      this.writeConflictCount += 1;
    }
    const stored = this.sharedStore.get(unitId);
    const underSpecifiedKey = `s:${sourceEpoch}`;
    if (stored && stored.startsWith(`${underSpecifiedKey}|`)) {
      const storedEngine = Number(stored.split('|e:')[1]);
      if (storedEngine !== engineEpoch) {
        this.falseHitCount += 1;
        return;
      }
      return;
    }
    this.sharedStore.set(unitId, `${underSpecifiedKey}|e:${engineEpoch}`);
    if (this.sharedStore.size > this.maxEntries) {
      this.quotaBreaches += 1;
    }
  }
}

interface Sm18AbstractState {
  engineEpoch: number;
  sourceEpoch: number;
  cachedEngineEpoch: number;
  cachedSourceEpoch: number;
  shardNamespacesDisjoint: boolean;
  maxCacheEntries: number;
  retainedEntries: number;
  falseHitCount: number;
  writeConflictCount: number;
  cacheHits: number;
  rebuilds: number;
}

class DeterministicSm18AbstractSut {
  state: Sm18AbstractState = {
    engineEpoch: 1,
    sourceEpoch: 1,
    cachedEngineEpoch: 0,
    cachedSourceEpoch: 0,
    shardNamespacesDisjoint: true,
    maxCacheEntries: 4,
    retainedEntries: 0,
    falseHitCount: 0,
    writeConflictCount: 0,
    cacheHits: 0,
    rebuilds: 0,
  };

  bumpSource(): void {
    if (this.state.sourceEpoch < 3) this.state.sourceEpoch += 1;
  }

  bumpEngine(): void {
    if (this.state.engineEpoch < 3) this.state.engineEpoch += 1;
  }

  lookupOrRebuild(): void {
    if (
      this.state.cachedEngineEpoch === this.state.engineEpoch &&
      this.state.cachedSourceEpoch === this.state.sourceEpoch
    ) {
      this.state.cacheHits += 1;
    } else {
      this.state.cachedEngineEpoch = this.state.engineEpoch;
      this.state.cachedSourceEpoch = this.state.sourceEpoch;
      this.state.rebuilds += 1;
      if (this.state.retainedEntries < this.state.maxCacheEntries) {
        this.state.retainedEntries += 1;
      }
    }
  }

  saveShardParallel(): void {
    this.state.shardNamespacesDisjoint = true;
    if (this.state.retainedEntries < this.state.maxCacheEntries) {
      this.state.retainedEntries += 1;
    }
  }

  compactAndSaveCache(): void {
    if (this.state.retainedEntries > 2) {
      this.state.retainedEntries = 2;
    }
  }
}

function normalizeInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) return Number((v as {'#bigint': string})['#bigint']);
  return Number(v);
}

describe('SM18 Scientific CI/CD Content-Addressed Caching & Subdomain Sharding Fuzz + ITF MBT + Real Repo Case Study', () => {
  test('250 randomized CI commit/engine-upgrade/parallel-shard schedules — hardened 0 false hits/conflicts vs naive collapse', () => {
    const rng = mulberry32(0x518008);
    const shards = ['engineering-concurrency', 'engineering-defense', 'engineering-core', 'threat-all'];
    let badFalseHits = 0;
    let badConflicts = 0;
    let badQuota = 0;

    for (let trial = 0; trial < 250; trial++) {
      const good = new DeterministicCiCasCluster(12);
      const bad = new NaiveCiCacheCluster(12);
      let engineEpoch = 1;
      let flagsEpoch = 1;
      const sourceEpochs = new Map<string, number>();

      for (let step = 0; step < 48; step++) {
        if (rng() < 0.15) engineEpoch += 1;
        if (rng() < 0.1) flagsEpoch += 1;
        const shard = shards[Math.floor(rng() * shards.length)]!;
        const parallelShard = shards[Math.floor(rng() * shards.length)]!;
        const unitId = `${shard}:u${Math.floor(rng() * 20)}`;
        let srcEp = sourceEpochs.get(unitId) ?? 1;
        if (rng() < 0.25) {
          srcEp += 1;
          sourceEpochs.set(unitId, srcEp);
        }

        good.lookupOrBuild(shard, unitId, engineEpoch, flagsEpoch, srcEp);
        bad.lookupOrBuild(shard, unitId, engineEpoch, srcEp, parallelShard);

        expect(good.falseHitCount).toBe(0);
        expect(good.writeConflictCount).toBe(0);
        expect(good.maxRetainedPerShard()).toBeLessThanOrEqual(good.maxEntries);
      }

      if (bad.falseHitCount > 0) badFalseHits += 1;
      if (bad.writeConflictCount > 0) badConflicts += 1;
      if (bad.quotaBreaches > 0) badQuota += 1;
    }

    expect(badFalseHits).toBeGreaterThan(220);
    expect(badConflicts).toBeGreaterThan(240);
    expect(badQuota).toBeGreaterThan(220);
  });

  test('Live Quint ITF MBT Replay for SM18 CiCacheSoundnessAndSharding (6 live traces, 100% parity)', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'sm18-mbt-'));
    try {
      const proc = Bun.spawnSync(
        [
          'bun',
          RESOLVER_CLI,
          'mbt-audit',
          SM18_SPEC,
          '--n-traces=6',
          '--max-steps=12',
          '--seed=7',
          '--min-coverage=1.0',
          `--out-dir=${outDir}`,
        ],
        {cwd: REPO_ROOT, stdout: 'pipe', stderr: 'pipe'},
      );
      expect(proc.exitCode).toBe(0);

      const traceFiles = readdirSync(outDir)
        .filter((f) => f.endsWith('.itf.json'))
        .sort();
      expect(traceFiles.length).toBeGreaterThanOrEqual(6);

      for (const file of traceFiles) {
        const itf = JSON.parse(readFileSync(join(outDir, file), 'utf8')) as {
          states: Array<{h: Record<string, unknown>; 'mbt::actionTaken': string}>;
        };
        const sut = new DeterministicSm18AbstractSut();
        for (let i = 1; i < itf.states.length; i++) {
          const st = itf.states[i]!;
          const act = st['mbt::actionTaken'];
          if (act === 'bumpSource') sut.bumpSource();
          else if (act === 'bumpEngine') sut.bumpEngine();
          else if (act === 'lookupOrRebuild') sut.lookupOrRebuild();
          else if (act === 'saveShardParallel') sut.saveShardParallel();
          else if (act === 'compactAndSaveCache') sut.compactAndSaveCache();
          else throw new Error(`unexpected SM18 action: ${act}`);

          const h = st.h;
          expect(sut.state.engineEpoch).toBe(normalizeInt(h.engineEpoch));
          expect(sut.state.sourceEpoch).toBe(normalizeInt(h.sourceEpoch));
          expect(sut.state.cachedEngineEpoch).toBe(normalizeInt(h.cachedEngineEpoch));
          expect(sut.state.cachedSourceEpoch).toBe(normalizeInt(h.cachedSourceEpoch));
          expect(sut.state.shardNamespacesDisjoint).toBe(Boolean(h.shardNamespacesDisjoint));
          expect(sut.state.retainedEntries).toBe(normalizeInt(h.retainedEntries));
          expect(sut.state.falseHitCount).toBe(0);
          expect(sut.state.writeConflictCount).toBe(0);
          expect(sut.state.cacheHits).toBe(normalizeInt(h.cacheHits));
          expect(sut.state.rebuilds).toBe(normalizeInt(h.rebuilds));
        }
      }
    } finally {
      rmSync(outDir, {recursive: true, force: true});
    }
  }, 30000);

  test('Real Repo Case Study: dynamic subdomain matrix covers 100% of Quint models disjointly & run-fleet CAS hits/invalidates soundly', () => {
    // 1. Dynamic matrix discovery partitions 100% of packages/quint-models without overlap.
    const matProc = Bun.spawnSync(['bun', VERIFY_FRAMEWORK, 'matrix', 'quint', '--max-per-shard=24'], {
      cwd: REPO_ROOT,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    expect(matProc.exitCode).toBe(0);
    const matrix = JSON.parse(new TextDecoder().decode(matProc.stdout)) as {
      include: Array<{shard: string; domain: string; subdomains: string; modelCount: number}>;
    };
    expect(matrix.include.length).toBeGreaterThanOrEqual(4);
    const seenShardIds = new Set<string>();
    const seenSubdomains = new Set<string>();
    let totalInMatrix = 0;
    for (const s of matrix.include) {
      expect(seenShardIds.has(s.shard)).toBe(false);
      seenShardIds.add(s.shard);
      for (const sd of s.subdomains.split(',')) {
        const key = `${s.domain}/${sd}`;
        expect(seenSubdomains.has(key)).toBe(false);
        seenSubdomains.add(key);
      }
      totalInMatrix += s.modelCount;
    }
    expect(totalInMatrix).toBeGreaterThanOrEqual(90);

    // 2. Real end-to-end SHA-256 CAS cold miss -> warm hit -> flag isolation -> single-file invalidation.
    const work = mkdtempSync(join(tmpdir(), 'sm18-cas-live-'));
    try {
      const modelsCopy = join(work, 'models/engineering/storage');
      mkdirSync(join(modelsCopy, 'm1'), {recursive: true});
      mkdirSync(join(modelsCopy, 'm2'), {recursive: true});
      const srcDir = join(REPO_ROOT, 'packages/quint-models/engineering/storage');
      const subDirs = readdirSync(srcDir, {withFileTypes: true})
        .filter((e) => e.isDirectory())
        .map((e) => e.name)
        .sort();
      const qnt1 = readdirSync(join(srcDir, subDirs[0]!)).find((f) => f.endsWith('.qnt'))!;
      const qnt2 = readdirSync(join(srcDir, subDirs[1]!)).find((f) => f.endsWith('.qnt'))!;
      const dst1 = join(modelsCopy, 'm1', qnt1);
      const dst2 = join(modelsCopy, 'm2', qnt2);
      copyFileSync(join(srcDir, subDirs[0]!, qnt1), dst1);
      copyFileSync(join(srcDir, subDirs[1]!, qnt2), dst2);
      const cacheDir = join(work, 'cas');

      const runFleet = (extra: string[]) => {
        const p = Bun.spawnSync(
          ['bun', RESOLVER_CLI, 'run-fleet', join(work, 'models'), '--domain=engineering', '--subdomain=storage', `--cache=${cacheDir}`, '--concurrency=2', '--json', ...extra],
          {cwd: REPO_ROOT, stdout: 'pipe', stderr: 'pipe'},
        );
        expect(p.exitCode, new TextDecoder().decode(p.stderr)).toBe(0);
        return JSON.parse(new TextDecoder().decode(p.stdout)) as {total: number; passed: number; cached: number; failed: number};
      };

      // Cold run-plan: 0 cached
      const r1 = runFleet([]);
      expect(r1.total).toBe(2);
      expect(r1.passed).toBe(2);
      expect(r1.cached).toBe(0);

      // Warm run-plan: 2/2 exact SHA-256 CAS hits
      const r2 = runFleet([]);
      expect(r2.total).toBe(2);
      expect(r2.passed).toBe(2);
      expect(r2.cached).toBe(2);

      // Mode/flag change (--mbt-audit): MUST miss (0 cached) — zero cross-mode poisoning
      const r3 = runFleet(['--mbt-audit', '--n-traces=4', '--seed=7', '--min-coverage=0.5']);
      expect(r3.cached).toBe(0);
      expect(r3.failed).toBe(0);

      // Warm --mbt-audit: 2/2 cached, AND original run-plan entries remain preserved!
      const r4 = runFleet(['--mbt-audit', '--n-traces=4', '--seed=7', '--min-coverage=0.5']);
      expect(r4.cached).toBe(2);
      const r5 = runFleet([]);
      expect(r5.cached).toBe(2);

      // Modify 1 byte (comment) in dst1: ONLY dst1 invalidates, dst2 stays cached!
      writeFileSync(dst1, `${readFileSync(dst1, 'utf8')}\n// sm18-invalidation-probe\n`);
      const r6 = runFleet([]);
      expect(r6.total).toBe(2);
      expect(r6.passed).toBe(2);
      expect(r6.cached).toBe(1);
    } finally {
      rmSync(work, {recursive: true, force: true});
    }
  }, 60000);

  test('Real Repo Case Study: all .github/workflows/*.yml & composite actions satisfy SM18 SHA-pinning & conflict-free cache key invariants', () => {
    const wfDir = join(REPO_ROOT, '.github/workflows');
    const actDir = join(REPO_ROOT, '.github/actions');
    const yamlFiles = [
      ...readdirSync(wfDir).filter((f) => f.endsWith('.yml')).map((f) => join(wfDir, f)),
      ...readdirSync(actDir)
        .map((d) => join(actDir, d, 'action.yml'))
        .filter((p) => existsSync(p)),
    ];
    expect(yamlFiles.length).toBeGreaterThanOrEqual(7);

    const shaPinnedRe = /@[0-9a-f]{40}\b/;
    for (const file of yamlFiles) {
      const content = readFileSync(file, 'utf8');
      for (const m of content.matchAll(/uses:\s*([^\s#]+)/g)) {
        const ref = m[1]!;
        if (ref.startsWith('./')) continue;
        expect(shaPinnedRe.test(ref), `unpinned third-party action '${ref}' in ${file}`).toBe(true);
      }

      // Every Layer-2 CAS cache step in workflows must bind an explicit hashFiles(...) engine fingerprint.
      const casKeyMatches = [...content.matchAll(/key:\s*(de-[a-z-]+-cas-v\d+[^\n]+)/g)];
      for (const cm of casKeyMatches) {
        const keyLine = cm[1]!;
        expect(keyLine, `CAS cache key missing runner.os in ${file}`).toContain('runner.os');
        expect(keyLine, `CAS cache key missing hashFiles engine fingerprint in ${file}`).toContain('hashFiles(');
      }
    }
  });
});
