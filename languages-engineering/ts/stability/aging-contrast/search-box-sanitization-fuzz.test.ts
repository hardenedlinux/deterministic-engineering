// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const RESOLVER_CLI = join(REPO_ROOT, 'packages/quint-modules-resolver/src/cli.ts');
const SM16_SPEC = join(
  REPO_ROOT,
  'packages/quint-models/engineering/concurrency/search-box-input-sanitization-envelope/SearchBoxInputSanitizationEnvelope.qnt',
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

const CONTROL_RE = /[\u0000-\u001f\u007f]/g;
const encoder = new TextEncoder();

function sanitizeBoundedUtf8(raw: string, maxBytes: number): string {
  const clean = raw.replace(CONTROL_RE, '');
  let out = '';
  let used = 0;
  for (const ch of clean) {
    const len = encoder.encode(ch).length;
    if (used + len > maxBytes) break;
    out += ch;
    used += len;
  }
  return out;
}

class DeterministicSanitizedSearchBox {
  readonly maxBytes: number;
  text = '';
  cursorBytes = 0;
  capBypassCount = 0;
  controlLeakCount = 0;
  cursorAligned = true;

  constructor(maxBytes = 256) {
    this.maxBytes = maxBytes;
  }

  byteLen(): number {
    return encoder.encode(this.text).length;
  }

  insertText(raw: string): void {
    const remaining = Math.max(0, this.maxBytes - this.byteLen());
    const chunk = sanitizeBoundedUtf8(raw, remaining);
    this.text += chunk;
    this.cursorBytes = this.byteLen();
    this.cursorAligned = true;
  }

  pasteSelection(yankRegister: string): void {
    this.insertText(yankRegister);
  }

  setInput(raw: string): void {
    this.text = sanitizeBoundedUtf8(raw, this.maxBytes);
    this.cursorBytes = this.byteLen();
    this.cursorAligned = true;
  }

  moveLeftGrapheme(): void {
    const chars = Array.from(this.text);
    if (chars.length === 0 || this.cursorBytes === 0) return;
    let acc = 0;
    let prev = 0;
    for (const ch of chars) {
      const len = encoder.encode(ch).length;
      if (acc + len >= this.cursorBytes) {
        this.cursorBytes = prev;
        this.cursorAligned = true;
        return;
      }
      prev = acc + len;
      acc += len;
    }
  }

  clear(): void {
    this.text = '';
    this.cursorBytes = 0;
    this.cursorAligned = true;
  }
}

class DefectiveSearchBox {
  readonly maxBytes: number;
  text = '';
  cursorBytes = 0;
  capBypassCount = 0;
  controlLeakCount = 0;
  cursorAligned = true;

  constructor(maxBytes = 256) {
    this.maxBytes = maxBytes;
  }

  byteLen(): number {
    return encoder.encode(this.text).length;
  }

  insertText(raw: string): void {
    const remaining = Math.max(0, this.maxBytes - this.byteLen());
    this.text += sanitizeBoundedUtf8(raw, remaining);
    this.cursorBytes = this.byteLen();
  }

  pasteSelectionUncapped(yankRegister: string): void {
    // Bug: PasteSelection bypasses maxBytes ceiling
    const clean = yankRegister.replace(CONTROL_RE, '');
    this.text += clean;
    this.cursorBytes = this.byteLen();
    if (this.byteLen() > this.maxBytes) this.capBypassCount += 1;
  }

  setInputUnstripped(raw: string): void {
    // Bug: setInput bypasses control stripping and maxBytes ceiling
    this.text = raw;
    this.cursorBytes = this.byteLen();
    if (CONTROL_RE.test(raw)) this.controlLeakCount += 1;
    CONTROL_RE.lastIndex = 0;
    if (this.byteLen() > this.maxBytes) this.capBypassCount += 1;
  }

  moveLeftByteBlind(): void {
    if (this.cursorBytes > 0) {
      // Bug: decrementing raw byte offset lands mid-UTF-8 codepoint on CJK/emoji
      this.cursorBytes -= 1;
      const bytes = encoder.encode(this.text);
      const b = bytes[this.cursorBytes] ?? 0;
      if ((b & 0xc0) === 0x80) this.cursorAligned = false;
    }
  }

  clear(): void {
    this.text = '';
    this.cursorBytes = 0;
    this.cursorAligned = true;
  }
}

interface Sm16AbstractState {
  maxBytes: number;
  inputBytes: number;
  cursor: number;
  cursorAligned: boolean;
  editorSynced: boolean;
  capBypassCount: number;
  controlLeakCount: number;
  dirtyPasted: boolean;
}

class DeterministicSm16AbstractSut {
  state: Sm16AbstractState = {
    maxBytes: 4,
    inputBytes: 0,
    cursor: 0,
    cursorAligned: true,
    editorSynced: true,
    capBypassCount: 0,
    controlLeakCount: 0,
    dirtyPasted: false,
  };

  insertCleanChunk(): void {
    if (this.state.inputBytes < this.state.maxBytes) {
      const next = this.state.inputBytes + 1;
      this.state.inputBytes = next;
      this.state.cursor = next;
      this.state.cursorAligned = true;
      this.state.editorSynced = true;
    }
  }

  pasteLargeYank(): void {
    this.state.inputBytes = this.state.maxBytes;
    this.state.cursor = this.state.maxBytes;
    this.state.cursorAligned = true;
    this.state.editorSynced = true;
    this.state.dirtyPasted = true;
  }

  setDirtyInput(): void {
    this.state.inputBytes = 2;
    this.state.cursor = 2;
    this.state.cursorAligned = true;
    this.state.editorSynced = true;
  }

  moveCursorGrapheme(): void {
    if (this.state.cursor > 0) {
      this.state.cursor -= 1;
      this.state.cursorAligned = true;
    }
  }

  clearAndReclaim(): void {
    if (this.state.inputBytes > 0) {
      this.state.inputBytes = 0;
      this.state.cursor = 0;
      this.state.cursorAligned = true;
      this.state.editorSynced = true;
    }
  }
}

function normalizeInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) return Number((v as {'#bigint': string})['#bigint']);
  return Number(v);
}

describe('SM16 Search-Box Input Sanitization, Bounded Paste Cap & Grapheme Cursor Fuzz + ITF MBT', () => {
  test('250 randomized adversarial CJK/Emoji/ANSI/50KB-paste schedules — hardened zero bypass/leaks vs defective collapse', () => {
    const rng = mulberry32(0x516006);
    const payloads = [
      '中文搜索',
      '👨‍👩‍👧‍👦🦀',
      'e\u0301cafe\u0301',
      '\x1b[31mred\n\r\0',
      '中文\n\r\x1b[32m'.repeat(40),
      '@lang:rust fn router',
    ];
    let badCapBypass = 0;
    let badControlLeak = 0;
    let badMidUtf8 = 0;

    for (let trial = 0; trial < 250; trial++) {
      const good = new DeterministicSanitizedSearchBox(128);
      const bad = new DefectiveSearchBox(128);
      let sawMisalign = false;

      for (let step = 0; step < 48; step++) {
        const op = Math.floor(rng() * 5);
        const payload = payloads[Math.floor(rng() * payloads.length)]!;
        if (op === 0) {
          good.insertText(payload);
          bad.insertText(payload);
        } else if (op === 1) {
          const bigYank = payload.repeat(12);
          good.pasteSelection(bigYank);
          bad.pasteSelectionUncapped(bigYank);
        } else if (op === 2) {
          good.setInput(payload);
          bad.setInputUnstripped(payload);
        } else if (op === 3) {
          good.moveLeftGrapheme();
          bad.moveLeftByteBlind();
          if (!bad.cursorAligned) sawMisalign = true;
        } else {
          good.clear();
          bad.clear();
        }

        expect(good.byteLen()).toBeLessThanOrEqual(good.maxBytes);
        expect(good.cursorBytes).toBeLessThanOrEqual(good.byteLen());
        expect(good.cursorAligned).toBe(true);
        CONTROL_RE.lastIndex = 0;
        expect(CONTROL_RE.test(good.text)).toBe(false);
        CONTROL_RE.lastIndex = 0;
      }

      if (bad.capBypassCount > 0) badCapBypass += 1;
      if (bad.controlLeakCount > 0) badControlLeak += 1;
      if (sawMisalign) badMidUtf8 += 1;
    }

    expect(badCapBypass).toBeGreaterThan(220);
    expect(badControlLeak).toBeGreaterThan(200);
    expect(badMidUtf8).toBeGreaterThan(150);
  });

  test('Live Quint ITF MBT Replay for SM16 SearchBoxInputSanitizationEnvelope (6 live traces, 100% parity)', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'sm16-mbt-'));
    try {
      const proc = Bun.spawnSync(
        [
          'bun',
          RESOLVER_CLI,
          'mbt-audit',
          SM16_SPEC,
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
        const sut = new DeterministicSm16AbstractSut();
        for (let i = 1; i < itf.states.length; i++) {
          const st = itf.states[i]!;
          const act = st['mbt::actionTaken'];
          if (act === 'insertCleanChunk') sut.insertCleanChunk();
          else if (act === 'pasteLargeYank') sut.pasteLargeYank();
          else if (act === 'setDirtyInput') sut.setDirtyInput();
          else if (act === 'moveCursorGrapheme') sut.moveCursorGrapheme();
          else if (act === 'clearAndReclaim') sut.clearAndReclaim();
          else throw new Error(`unexpected SM16 action: ${act}`);

          const h = st.h;
          expect(sut.state.inputBytes).toBe(normalizeInt(h.inputBytes));
          expect(sut.state.cursor).toBe(normalizeInt(h.cursor));
          expect(sut.state.cursorAligned).toBe(Boolean(h.cursorAligned));
          expect(sut.state.editorSynced).toBe(Boolean(h.editorSynced));
          expect(sut.state.capBypassCount).toBe(0);
          expect(sut.state.controlLeakCount).toBe(0);
          expect(sut.state.dirtyPasted).toBe(Boolean(h.dirtyPasted));
        }
      }
    } finally {
      rmSync(outDir, {recursive: true, force: true});
    }
  }, 30000);
});
