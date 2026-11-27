// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const RESOLVER_CLI = join(REPO_ROOT, 'packages/quint-modules-resolver/src/cli.ts');
const SM17_SPEC = join(
  REPO_ROOT,
  'packages/quint-models/engineering/concurrency/streaming-output-budget-envelope/StreamingOutputBudgetEnvelope.qnt',
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

class DeterministicStreamingBudgetGate {
  readonly budgetLimit: number;
  streamOpen = false;
  textBytes = 0;
  thinkingBytes = 0;
  peakRetainedBytes = 0;
  overflowRefusals = 0;
  completedResponses = 0;

  constructor(budgetLimit: number) {
    this.budgetLimit = budgetLimit;
  }

  openStream(declaredContentLength: number | null): 'opened' | 'refused' {
    if (declaredContentLength !== null && declaredContentLength > this.budgetLimit) {
      this.streamOpen = false;
      this.textBytes = 0;
      this.thinkingBytes = 0;
      this.overflowRefusals += 1;
      return 'refused';
    }
    this.streamOpen = true;
    this.textBytes = 0;
    this.thinkingBytes = 0;
    return 'opened';
  }

  receiveDelta(kind: 'text' | 'thinking', chunkBytes: number): 'admitted' | 'refused' | 'ignored' {
    if (!this.streamOpen) return 'ignored';
    const nextTotal = this.textBytes + this.thinkingBytes + chunkBytes;
    if (nextTotal > this.budgetLimit) {
      this.streamOpen = false;
      this.textBytes = 0;
      this.thinkingBytes = 0;
      this.overflowRefusals += 1;
      return 'refused';
    }
    if (kind === 'text') this.textBytes += chunkBytes;
    else this.thinkingBytes += chunkBytes;
    if (nextTotal > this.peakRetainedBytes) this.peakRetainedBytes = nextTotal;
    return 'admitted';
  }

  completeTurn(): boolean {
    if (!this.streamOpen) return false;
    this.completedResponses += 1;
    this.streamOpen = false;
    this.textBytes = 0;
    this.thinkingBytes = 0;
    return true;
  }
}

class DefectiveStreamingBudgetGate {
  readonly budgetLimit: number;
  streamOpen = false;
  textBytes = 0;
  thinkingBytes = 0;
  peakRetainedBytes = 0;
  peakOvershoots = 0;
  thinkingBypasses = 0;
  sseCompleteBypasses = 0;

  constructor(budgetLimit: number) {
    this.budgetLimit = budgetLimit;
  }

  openStream(): void {
    this.streamOpen = true;
    this.textBytes = 0;
    this.thinkingBytes = 0;
  }

  // Defect 1: HTTP check-after-buffering (resp.bytes().await then `if len > MAX`)
  bufferFullHttpThenCheck(totalPayloadBytes: number): 'ok' | 'late-error' {
    const spike = totalPayloadBytes;
    if (spike > this.peakRetainedBytes) this.peakRetainedBytes = spike;
    if (spike > this.budgetLimit) {
      this.peakOvershoots += 1;
      return 'late-error';
    }
    return 'ok';
  }

  // Defect 2: gateway.rs SSE complete ignores Thinking bytes completely
  receiveThinkingUnaccounted(chunkBytes: number): void {
    if (!this.streamOpen) return;
    this.thinkingBytes += chunkBytes;
    if (this.textBytes + this.thinkingBytes > this.budgetLimit) {
      this.thinkingBypasses += 1;
    }
  }

  // Defect 3: gateway.rs SSE complete appends Text delta without checking stream_output_limit
  receiveSseCompleteTextUncapped(chunkBytes: number): void {
    if (!this.streamOpen) return;
    this.textBytes += chunkBytes;
    if (this.textBytes > this.peakRetainedBytes) this.peakRetainedBytes = this.textBytes;
    if (this.textBytes > this.budgetLimit) {
      this.sseCompleteBypasses += 1;
    }
  }

  finish(): void {
    this.streamOpen = false;
    this.textBytes = 0;
    this.thinkingBytes = 0;
  }
}

interface Sm17AbstractState {
  budgetLimit: number;
  streamOpen: boolean;
  textBytes: number;
  thinkingBytes: number;
  peakRetainedBytes: number;
  overflowRefusals: number;
  completedResponses: number;
  budgetBypassCount: number;
  streamReleased: boolean;
}

class DeterministicSm17AbstractSut {
  state: Sm17AbstractState = {
    budgetLimit: 4,
    streamOpen: false,
    textBytes: 0,
    thinkingBytes: 0,
    peakRetainedBytes: 0,
    overflowRefusals: 0,
    completedResponses: 0,
    budgetBypassCount: 0,
    streamReleased: true,
  };

  openStream(): void {
    if (!this.state.streamOpen) {
      this.state.streamOpen = true;
      this.state.textBytes = 0;
      this.state.thinkingBytes = 0;
      this.state.streamReleased = false;
    }
  }

  receiveBoundedText(): void {
    const used = this.state.textBytes + this.state.thinkingBytes;
    if (this.state.streamOpen && used < this.state.budgetLimit) {
      this.state.textBytes += 1;
      const nextUsed = used + 1;
      if (nextUsed > this.state.peakRetainedBytes) this.state.peakRetainedBytes = nextUsed;
    }
  }

  receiveThinkingDelta(): void {
    if (!this.state.streamOpen) return;
    const used = this.state.textBytes + this.state.thinkingBytes;
    if (used < this.state.budgetLimit) {
      this.state.thinkingBytes += 1;
      const nextUsed = used + 1;
      if (nextUsed > this.state.peakRetainedBytes) this.state.peakRetainedBytes = nextUsed;
    } else {
      this.state.streamOpen = false;
      this.state.textBytes = 0;
      this.state.thinkingBytes = 0;
      this.state.overflowRefusals += 1;
      this.state.streamReleased = true;
    }
  }

  refuseOversizeChunk(): void {
    if (!this.state.streamOpen) return;
    this.state.streamOpen = false;
    this.state.textBytes = 0;
    this.state.thinkingBytes = 0;
    this.state.overflowRefusals += 1;
    this.state.streamReleased = true;
  }

  completeSseTurn(): void {
    if (!this.state.streamOpen) return;
    this.state.streamOpen = false;
    this.state.textBytes = 0;
    this.state.thinkingBytes = 0;
    this.state.completedResponses += 1;
    this.state.streamReleased = true;
  }
}

function normalizeInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) return Number((v as {'#bigint': string})['#bigint']);
  return Number(v);
}

describe('SM17 Streaming Output Budget, Pre-Allocation Cap & Thinking Accounting Fuzz + ITF MBT', () => {
  test('250 randomized SSE & HTTP chunked-flood schedules — hardened zero overshoot/leaks vs defective collapse', () => {
    const rng = mulberry32(0x517007);
    let badPeakOvershoots = 0;
    let badThinkingBypass = 0;
    let badSseBypass = 0;

    for (let trial = 0; trial < 250; trial++) {
      const cap = 64 + Math.floor(rng() * 192);
      const good = new DeterministicStreamingBudgetGate(cap);
      const bad = new DefectiveStreamingBudgetGate(cap);

      for (let turn = 0; turn < 12; turn++) {
        const declaredHeader = rng() < 0.25 ? cap + 1 + Math.floor(rng() * 2048) : null;
        good.openStream(declaredHeader);
        bad.openStream();

        if (declaredHeader !== null) {
          expect(good.streamOpen).toBe(false);
          expect(good.textBytes).toBe(0);
          expect(good.thinkingBytes).toBe(0);
          bad.bufferFullHttpThenCheck(declaredHeader);
        }

        const chunkCount = 4 + Math.floor(rng() * 14);
        for (let i = 0; i < chunkCount; i++) {
          const isThinking = rng() < 0.45;
          const delta = 1 + Math.floor(rng() * Math.max(8, Math.floor(cap / 2)));
          good.receiveDelta(isThinking ? 'thinking' : 'text', delta);
          if (isThinking) bad.receiveThinkingUnaccounted(delta);
          else bad.receiveSseCompleteTextUncapped(delta);

          expect(good.textBytes + good.thinkingBytes).toBeLessThanOrEqual(good.budgetLimit);
          expect(good.peakRetainedBytes).toBeLessThanOrEqual(good.budgetLimit);
          if (!good.streamOpen) {
            expect(good.textBytes).toBe(0);
            expect(good.thinkingBytes).toBe(0);
          }
        }

        good.completeTurn();
        bad.finish();
        expect(good.streamOpen).toBe(false);
        expect(good.textBytes).toBe(0);
        expect(good.thinkingBytes).toBe(0);
      }

      if (bad.peakOvershoots > 0) badPeakOvershoots += 1;
      if (bad.thinkingBypasses > 0) badThinkingBypass += 1;
      if (bad.sseCompleteBypasses > 0) badSseBypass += 1;
    }

    expect(badPeakOvershoots).toBeGreaterThan(200);
    expect(badThinkingBypass).toBeGreaterThan(220);
    expect(badSseBypass).toBeGreaterThan(220);
  });

  test('Live Quint ITF MBT Replay for SM17 StreamingOutputBudgetEnvelope (6 live traces, 100% parity)', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'sm17-mbt-'));
    try {
      const proc = Bun.spawnSync(
        [
          'bun',
          RESOLVER_CLI,
          'mbt-audit',
          SM17_SPEC,
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
        const sut = new DeterministicSm17AbstractSut();
        for (let i = 1; i < itf.states.length; i++) {
          const st = itf.states[i]!;
          const act = st['mbt::actionTaken'];
          if (act === 'openStream') sut.openStream();
          else if (act === 'receiveBoundedText') sut.receiveBoundedText();
          else if (act === 'receiveThinkingDelta') sut.receiveThinkingDelta();
          else if (act === 'refuseOversizeChunk') sut.refuseOversizeChunk();
          else if (act === 'completeSseTurn') sut.completeSseTurn();
          else throw new Error(`unexpected SM17 action: ${act}`);

          const h = st.h;
          expect(sut.state.streamOpen).toBe(Boolean(h.streamOpen));
          expect(sut.state.textBytes).toBe(normalizeInt(h.textBytes));
          expect(sut.state.thinkingBytes).toBe(normalizeInt(h.thinkingBytes));
          expect(sut.state.peakRetainedBytes).toBe(normalizeInt(h.peakRetainedBytes));
          expect(sut.state.overflowRefusals).toBe(normalizeInt(h.overflowRefusals));
          expect(sut.state.completedResponses).toBe(normalizeInt(h.completedResponses));
          expect(sut.state.budgetBypassCount).toBe(0);
          expect(sut.state.streamReleased).toBe(Boolean(h.streamReleased));
        }
      }
    } finally {
      rmSync(outDir, {recursive: true, force: true});
    }
  }, 30000);
});
