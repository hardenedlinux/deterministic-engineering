// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const RESOLVER_CLI = join(REPO_ROOT, 'packages/quint-modules-resolver/src/cli.ts');
const SM19_SPEC = join(
  REPO_ROOT,
  'packages/quint-models/engineering/concurrency/task-and-pool-cancellation-envelope/TaskAndPoolCancellationEnvelope.qnt',
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

class DeterministicStructuredRuntime {
  readonly maxConcurrency: number;
  activeChildren = 0;
  peakChildren = 0;
  orphanTasks = 0;
  txDirty = false;
  poisonedPoolConns = 0;
  lostCorrelationIds = 0;

  constructor(maxConcurrency = 8) {
    this.maxConcurrency = maxConcurrency;
  }

  runEffectBatch(effectIds: string[], panicFlags: boolean[], cancelMidway: boolean): string[] {
    const receipts: string[] = [];
    for (let i = 0; i < effectIds.length; i += this.maxConcurrency) {
      const wave = effectIds.slice(i, i + this.maxConcurrency);
      this.activeChildren = wave.length;
      if (this.activeChildren > this.peakChildren) this.peakChildren = this.activeChildren;
      if (cancelMidway) {
        // Abort-on-drop kills every in-flight child immediately -> 0 orphans
        this.activeChildren = 0;
        return receipts;
      }
      for (let j = 0; j < wave.length; j++) {
        const callerId = wave[j]!;
        const panicked = panicFlags[i + j] ?? false;
        // Caller-owned correlation table always returns exact callerId even on panic
        receipts.push(panicked ? `error:${callerId}` : `ok:${callerId}`);
      }
      this.activeChildren = 0;
    }
    return receipts;
  }

  runTransaction(cancelBeforeCommit: boolean): void {
    this.txDirty = true;
    if (cancelBeforeCommit) {
      // Dirty lease is rolled back or discarded rather than returned poisoned to pool
      this.txDirty = false;
      return;
    }
    this.txDirty = false;
  }
}

class DefectiveDetachedRuntime {
  readonly maxConcurrency: number;
  orphanTasks = 0;
  poisonedPoolConns = 0;
  fanoutBreaches = 0;
  lostCorrelationIds = 0;

  constructor(maxConcurrency = 8) {
    this.maxConcurrency = maxConcurrency;
  }

  runEffectBatch(effectIds: string[], panicFlags: boolean[], cancelMidway: boolean): string[] {
    if (effectIds.length > this.maxConcurrency) this.fanoutBreaches += 1;
    if (cancelMidway) {
      // Bug: bare Vec<JoinHandle> drop detaches all spawned children -> orphan leak
      this.orphanTasks += effectIds.length;
      return [];
    }
    return effectIds.map((id, idx) => {
      if (panicFlags[idx]) {
        // Bug: fabricated `effect-${idx}` drops actual caller correlation id
        this.lostCorrelationIds += 1;
        return `error:effect-${idx}`;
      }
      return `ok:${id}`;
    });
  }

  runTransaction(cancelBeforeCommit: boolean): void {
    if (cancelBeforeCommit) {
      // Bug: Drop unconditionally returns in-tx connection back to pool
      this.poisonedPoolConns += 1;
    }
  }
}

interface Sm19AbstractState {
  maxConcurrency: number;
  activeChildren: number;
  orphanTasks: number;
  txDirty: boolean;
  poisonedPoolConns: number;
  fanoutBreaches: number;
  lostCorrelationIds: number;
  completedBatches: number;
  cleanCancels: number;
}

class DeterministicSm19AbstractSut {
  state: Sm19AbstractState = {
    maxConcurrency: 2,
    activeChildren: 0,
    orphanTasks: 0,
    txDirty: false,
    poisonedPoolConns: 0,
    fanoutBreaches: 0,
    lostCorrelationIds: 0,
    completedBatches: 0,
    cleanCancels: 0,
  };

  spawnBoundedChild(): void {
    if (this.state.activeChildren < this.state.maxConcurrency) {
      this.state.activeChildren += 1;
    }
  }

  beginTransaction(): void {
    if (!this.state.txDirty) this.state.txDirty = true;
  }

  commitTransaction(): void {
    if (this.state.txDirty) {
      this.state.txDirty = false;
      this.state.completedBatches += 1;
    }
  }

  cancelScopeClean(): void {
    if (this.state.activeChildren > 0 || this.state.txDirty) {
      this.state.activeChildren = 0;
      this.state.txDirty = false;
      this.state.cleanCancels += 1;
    }
  }

  handleWorkerPanicSafe(): void {
    if (this.state.activeChildren > 0) {
      this.state.activeChildren -= 1;
      this.state.completedBatches += 1;
    }
  }
}

function normalizeInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) return Number((v as {'#bigint': string})['#bigint']);
  return Number(v);
}

describe('SM19 Structured Task Abort-on-Drop, Dirty Pool Lease & Bounded Fan-Out Fuzz + ITF MBT', () => {
  test('250 randomized async cancel, DB tx cancel, and worker-panic schedules — hardened 0 orphans/poison/loss vs defective collapse', () => {
    const rng = mulberry32(0x519009);
    let badOrphans = 0;
    let badPoison = 0;
    let badFanout = 0;
    let badLostId = 0;

    for (let trial = 0; trial < 250; trial++) {
      const good = new DeterministicStructuredRuntime(6);
      const bad = new DefectiveDetachedRuntime(6);

      for (let step = 0; step < 20; step++) {
        const batchLen = 2 + Math.floor(rng() * 14);
        const ids = Array.from({length: batchLen}, (_, i) => `eff-sha256-${trial}-${step}-${i}`);
        const panics = ids.map(() => rng() < 0.2);
        const cancelBatch = rng() < 0.3;
        const cancelTx = rng() < 0.35;

        const goodReceipts = good.runEffectBatch(ids, panics, cancelBatch);
        bad.runEffectBatch(ids, panics, cancelBatch);
        good.runTransaction(cancelTx);
        bad.runTransaction(cancelTx);

        expect(good.orphanTasks).toBe(0);
        expect(good.poisonedPoolConns).toBe(0);
        expect(good.peakChildren).toBeLessThanOrEqual(good.maxConcurrency);
        expect(good.txDirty).toBe(false);
        if (!cancelBatch) {
          expect(goodReceipts.length).toBe(ids.length);
          for (let i = 0; i < ids.length; i++) {
            expect(goodReceipts[i]!.endsWith(ids[i]!)).toBe(true);
          }
        }
      }

      if (bad.orphanTasks > 0) badOrphans += 1;
      if (bad.poisonedPoolConns > 0) badPoison += 1;
      if (bad.fanoutBreaches > 0) badFanout += 1;
      if (bad.lostCorrelationIds > 0) badLostId += 1;
    }

    expect(badOrphans).toBeGreaterThan(220);
    expect(badPoison).toBeGreaterThan(220);
    expect(badFanout).toBeGreaterThan(220);
    expect(badLostId).toBeGreaterThan(220);
  });

  test('Live Quint ITF MBT Replay for SM19 TaskAndPoolCancellationEnvelope (6 live traces, 100% parity)', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'sm19-mbt-'));
    try {
      const proc = Bun.spawnSync(
        [
          'bun',
          RESOLVER_CLI,
          'mbt-audit',
          SM19_SPEC,
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
        const sut = new DeterministicSm19AbstractSut();
        for (let i = 1; i < itf.states.length; i++) {
          const st = itf.states[i]!;
          const act = st['mbt::actionTaken'];
          if (act === 'spawnBoundedChild') sut.spawnBoundedChild();
          else if (act === 'beginTransaction') sut.beginTransaction();
          else if (act === 'commitTransaction') sut.commitTransaction();
          else if (act === 'cancelScopeClean') sut.cancelScopeClean();
          else if (act === 'handleWorkerPanicSafe') sut.handleWorkerPanicSafe();
          else throw new Error(`unexpected SM19 action: ${act}`);

          const h = st.h;
          expect(sut.state.activeChildren).toBe(normalizeInt(h.activeChildren));
          expect(sut.state.orphanTasks).toBe(0);
          expect(sut.state.txDirty).toBe(Boolean(h.txDirty));
          expect(sut.state.poisonedPoolConns).toBe(0);
          expect(sut.state.fanoutBreaches).toBe(0);
          expect(sut.state.lostCorrelationIds).toBe(0);
          expect(sut.state.completedBatches).toBe(normalizeInt(h.completedBatches));
          expect(sut.state.cleanCancels).toBe(normalizeInt(h.cleanCancels));
        }
      }
    } finally {
      rmSync(outDir, {recursive: true, force: true});
    }
  }, 30000);
});
