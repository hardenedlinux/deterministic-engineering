// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const RESOLVER_CLI = join(REPO_ROOT, 'packages/quint-modules-resolver/src/cli.ts');
const SM15_SPEC = join(
  REPO_ROOT,
  'packages/quint-models/engineering/concurrency/search-index-snapshot-isolation/SearchIndexSnapshotIsolation.qnt',
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

interface SnapshotIndexState {
  cachedRoot: number;
  activeIndexesForRoot: number;
  snapshotGen: number;
  activeReaders: number;
  pinnedSegments: number;
  leaderActive: boolean;
  waitingFollowers: number;
  splitBrainOpens: number;
  crossWorkspaceHits: number;
  cascadeFailures: number;
}

class DeterministicSearchIndexSlot {
  state: SnapshotIndexState = {
    cachedRoot: 0,
    activeIndexesForRoot: 0,
    snapshotGen: 1,
    activeReaders: 0,
    pinnedSegments: 1,
    leaderActive: false,
    waitingFollowers: 0,
    splitBrainOpens: 0,
    crossWorkspaceHits: 0,
    cascadeFailures: 0,
  };

  coldOpenRoot(rootId: number): void {
    if (this.state.cachedRoot === 0) {
      this.state.cachedRoot = rootId;
      this.state.activeIndexesForRoot = 1;
      this.state.pinnedSegments = 1;
    }
  }

  queryRoot(rootId: number): void {
    if (this.state.cachedRoot === 1 && rootId === 2) {
      this.state.cachedRoot = 2;
      this.state.activeIndexesForRoot = 1;
      this.state.snapshotGen += 1;
    } else if (this.state.cachedRoot !== 0 && this.state.cachedRoot !== rootId) {
      this.state.cachedRoot = rootId;
      this.state.activeIndexesForRoot = 1;
      this.state.snapshotGen += 1;
    }
  }

  startSingleFlightQuery(followers = 1): void {
    if (this.state.cachedRoot > 0 && !this.state.leaderActive) {
      const prevReaders = this.state.activeReaders;
      this.state.leaderActive = true;
      this.state.waitingFollowers = followers;
      this.state.activeReaders = prevReaders + 1;
      this.state.pinnedSegments = prevReaders + 1;
    }
  }

  cancelLeaderReelect(): void {
    if (this.state.leaderActive && this.state.waitingFollowers > 0) {
      this.state.leaderActive = true;
      this.state.waitingFollowers -= 1;
    }
  }

  finishQueryReleaseReader(): void {
    if (this.state.leaderActive) {
      const prevReaders = this.state.activeReaders;
      this.state.leaderActive = false;
      this.state.waitingFollowers = 0;
      this.state.activeReaders = prevReaders > 0 ? prevReaders - 1 : 0;
      this.state.pinnedSegments = prevReaders > 0 ? prevReaders : 1;
    }
  }

  publishAndCompactSnapshot(): void {
    if (this.state.cachedRoot > 0) {
      this.state.snapshotGen += 1;
      this.state.pinnedSegments = this.state.activeReaders + 1;
    }
  }
}

class DefectiveSearchIndexSlot {
  state: SnapshotIndexState = {
    cachedRoot: 0,
    activeIndexesForRoot: 0,
    snapshotGen: 1,
    activeReaders: 0,
    pinnedSegments: 1,
    leaderActive: false,
    waitingFollowers: 0,
    splitBrainOpens: 0,
    crossWorkspaceHits: 0,
    cascadeFailures: 0,
  };

  coldOpenRootUnserialized(rootId: number): void {
    if (this.state.cachedRoot === 0) {
      // Bug: unserialized check-then-act builds duplicate split-brain indexes
      this.state.cachedRoot = rootId;
      this.state.activeIndexesForRoot += 2;
      this.state.splitBrainOpens += 1;
    }
  }

  queryRootUnchecked(rootId: number): void {
    if (this.state.cachedRoot > 0 && this.state.cachedRoot !== rootId) {
      // Bug: returns cached index from a different workspace root without root check
      this.state.crossWorkspaceHits += 1;
    }
  }

  startSingleFlightQuery(followers = 1): void {
    if (this.state.cachedRoot > 0 && !this.state.leaderActive) {
      this.state.leaderActive = true;
      this.state.waitingFollowers = followers;
      this.state.activeReaders += 1;
      this.state.pinnedSegments += 1;
    }
  }

  cancelLeaderCascade(): void {
    if (this.state.leaderActive && this.state.waitingFollowers > 0) {
      // Bug: leader cancellation drops watch::Sender and fails all waiting followers
      this.state.leaderActive = false;
      this.state.waitingFollowers = 0;
      this.state.cascadeFailures += 1;
    }
  }

  finishQueryReleaseReader(): void {
    if (this.state.leaderActive) {
      this.state.leaderActive = false;
      this.state.waitingFollowers = 0;
      this.state.activeReaders = Math.max(0, this.state.activeReaders - 1);
      // Bug: fails to reclaim pinned old snapshot segments on reader drop
    }
  }

  publishWithoutCompaction(): void {
    if (this.state.cachedRoot > 0) {
      this.state.snapshotGen += 1;
      this.state.pinnedSegments += 1; // Bug: leaks old snapshot segment without reclaiming
    }
  }
}

function normalizeInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) return Number((v as {'#bigint': string})['#bigint']);
  return Number(v);
}

describe('SM15 Search Index Snapshot Isolation, Cold-Open & Follower Re-Election Fuzz + ITF MBT', () => {
  test('250 randomized concurrent cold-open, worktree-switch, leader-cancel & compaction schedules', () => {
    const rng = mulberry32(0x515005);
    let badSplitBrain = 0;
    let badCrossRoot = 0;
    let badCascade = 0;
    let badSegmentLeak = 0;

    for (let trial = 0; trial < 250; trial++) {
      const good = new DeterministicSearchIndexSlot();
      const bad = new DefectiveSearchIndexSlot();
      for (let step = 0; step < 64; step++) {
        const op = Math.floor(rng() * 6);
        if (op === 0) {
          good.coldOpenRoot(1);
          bad.coldOpenRootUnserialized(1);
        } else if (op === 1) {
          const targetRoot = rng() < 0.5 ? 2 : 3;
          good.queryRoot(targetRoot);
          bad.queryRootUnchecked(targetRoot);
        } else if (op === 2) {
          const followers = 1 + Math.floor(rng() * 3);
          good.startSingleFlightQuery(followers);
          bad.startSingleFlightQuery(followers);
        } else if (op === 3) {
          good.cancelLeaderReelect();
          bad.cancelLeaderCascade();
        } else if (op === 4) {
          good.finishQueryReleaseReader();
          bad.finishQueryReleaseReader();
        } else {
          good.publishAndCompactSnapshot();
          bad.publishWithoutCompaction();
        }

        expect(good.state.activeIndexesForRoot).toBeLessThanOrEqual(1);
        expect(good.state.splitBrainOpens).toBe(0);
        expect(good.state.crossWorkspaceHits).toBe(0);
        expect(good.state.cascadeFailures).toBe(0);
        expect(good.state.pinnedSegments).toBeLessThanOrEqual(good.state.activeReaders + 1);
      }

      if (bad.state.splitBrainOpens > 0) badSplitBrain += 1;
      if (bad.state.crossWorkspaceHits > 0) badCrossRoot += 1;
      if (bad.state.cascadeFailures > 0) badCascade += 1;
      if (bad.state.pinnedSegments > bad.state.activeReaders + 1) badSegmentLeak += 1;
    }

    expect(badSplitBrain).toBeGreaterThan(200);
    expect(badCrossRoot).toBeGreaterThan(200);
    expect(badCascade).toBeGreaterThan(150);
    expect(badSegmentLeak).toBeGreaterThan(200);
  });

  test('Live Quint ITF MBT Replay for SM15 SearchIndexSnapshotIsolation (6 live traces, 100% parity)', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'sm15-mbt-'));
    try {
      const proc = Bun.spawnSync(
        [
          'bun',
          RESOLVER_CLI,
          'mbt-audit',
          SM15_SPEC,
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
        const sut = new DeterministicSearchIndexSlot();
        for (let i = 1; i < itf.states.length; i++) {
          const st = itf.states[i]!;
          const act = st['mbt::actionTaken'];
          if (act === 'coldOpenRoot1') sut.coldOpenRoot(1);
          else if (act === 'queryRoot2') sut.queryRoot(2);
          else if (act === 'startSingleFlightQuery') sut.startSingleFlightQuery(1);
          else if (act === 'cancelLeaderReelect') sut.cancelLeaderReelect();
          else if (act === 'finishQueryReleaseReader') sut.finishQueryReleaseReader();
          else if (act === 'publishAndCompactSnapshot') sut.publishAndCompactSnapshot();
          else throw new Error(`unexpected SM15 action: ${act}`);

          const h = st.h;
          expect(sut.state.cachedRoot).toBe(normalizeInt(h.cachedRoot));
          expect(sut.state.activeIndexesForRoot).toBe(normalizeInt(h.activeIndexesForRoot));
          expect(sut.state.snapshotGen).toBe(normalizeInt(h.snapshotGen));
          expect(sut.state.activeReaders).toBe(normalizeInt(h.activeReaders));
          expect(sut.state.pinnedSegments).toBe(normalizeInt(h.pinnedSegments));
          expect(sut.state.leaderActive).toBe(Boolean(h.leaderActive));
          expect(sut.state.waitingFollowers).toBe(normalizeInt(h.waitingFollowers));
          expect(sut.state.splitBrainOpens).toBe(0);
          expect(sut.state.crossWorkspaceHits).toBe(0);
          expect(sut.state.cascadeFailures).toBe(0);
        }
      }
    } finally {
      rmSync(outDir, {recursive: true, force: true});
    }
  }, 30000);
});
