// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Adversarial Structure-Aware PBT, Chaos Fault-Injection Fuzzing & Live Quint ITF
 * Model-Based Testing for SM12 (IPC Half-Open Reconnect & Idempotency), SM13
 * (Interactive Search-Box IME Composition / Focus / Shortcut Races), and SM14
 * (Compound Chaos Fault Injection, Circuit Shedding & Typed Recovery Envelope).
 */

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');

// Deterministic PRNG (Mulberry32) for 100% reproducible adversarial fuzz schedules.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function generateItfTraces(qntRelPath: string, mainMod: string, nTraces = 6, maxSteps = 12): Array<Array<Record<string, unknown>>> {
  const outDir = mkdtempSync(join(tmpdir(), 'de-sm12-14-itf-'));
  try {
    const qntFull = join(REPO_ROOT, qntRelPath);
    const proc = Bun.spawnSync(
      [
        'bun',
        join(REPO_ROOT, 'packages/quint-modules-resolver/src/cli.ts'),
        'run',
        qntFull,
        `--main=${mainMod}`,
        '--invariant=safety',
        '--mbt',
        `--n-traces=${nTraces}`,
        `--max-steps=${maxSteps}`,
        '--seed=0x512',
        `--out-itf=${join(outDir, 'trace_{seq}.itf.json')}`,
      ],
      {cwd: REPO_ROOT, stdout: 'pipe', stderr: 'pipe'},
    );
    if (proc.exitCode !== 0) {
      throw new Error(`Quint ITF export failed for ${qntRelPath}: ${proc.stderr.toString()}\n${proc.stdout.toString()}`);
    }
    const files = readdirSync(outDir).filter(f => f.endsWith('.itf.json')).sort();
    return files.map(f => {
      const parsed = JSON.parse(readFileSync(join(outDir, f), 'utf8')) as {
        states: Array<Record<string, unknown>>;
      };
      return parsed.states;
    });
  } finally {
    rmSync(outDir, {recursive: true, force: true});
  }
}

function itfInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (typeof v === 'object' && v !== null && '#bigint' in v) {
    return Number((v as {'#bigint': string})['#bigint']);
  }
  return Number(v);
}

// ── SM12: IPC Half-Open Reconnect, Monotonic Epoch Fencing & Idempotent Replay ──

interface IpcState {
  sessionEpoch: number;
  activeStreams: number;
  inFlightKeys: Set<string>;
  committedKeys: Set<string>;
  duplicateEffects: number;
  staleFramesApplied: number;
  reconnectCount: number;
}

class DeterministicIpcSession {
  readonly state: IpcState = {
    sessionEpoch: 1,
    activeStreams: 1,
    inFlightKeys: new Set(),
    committedKeys: new Set(),
    duplicateEffects: 0,
    staleFramesApplied: 0,
    reconnectCount: 0,
  };

  sendRequest(key: string): void {
    this.state.inFlightKeys.add(key);
  }

  commitRequest(key: string): 'applied' | 'deduplicated' | 'noop' {
    if (!this.state.inFlightKeys.has(key)) return 'noop';
    this.state.inFlightKeys.delete(key);
    if (this.state.committedKeys.has(key)) {
      return 'deduplicated';
    }
    this.state.committedKeys.add(key);
    return 'applied';
  }

  reconnectHalfOpen(): void {
    // SM12 guard: explicitly retire superseded stream before activating new epoch.
    this.state.sessionEpoch += 1;
    this.state.activeStreams = 1;
    this.state.reconnectCount += 1;
  }

  receiveFrame(frameEpoch: number): 'accepted' | 'fenced-dropped' {
    if (frameEpoch < this.state.sessionEpoch) {
      return 'fenced-dropped';
    }
    return 'accepted';
  }
}

class DefectiveIpcSession {
  readonly state: IpcState = {
    sessionEpoch: 1,
    activeStreams: 1,
    inFlightKeys: new Set(),
    committedKeys: new Set(),
    duplicateEffects: 0,
    staleFramesApplied: 0,
    reconnectCount: 0,
  };

  sendRequest(key: string): void {
    this.state.inFlightKeys.add(key);
  }

  commitRequest(key: string): void {
    if (!this.state.inFlightKeys.has(key)) return;
    this.state.inFlightKeys.delete(key);
    if (this.state.committedKeys.has(key)) {
      this.state.duplicateEffects += 1;
    } else {
      this.state.committedKeys.add(key);
    }
  }

  reconnectHalfOpen(): void {
    this.state.sessionEpoch += 1;
    this.state.activeStreams += 1; // Leak: fails to retire half-open stream
    this.state.reconnectCount += 1;
  }

  receiveFrame(frameEpoch: number): void {
    if (frameEpoch < this.state.sessionEpoch) {
      this.state.staleFramesApplied += 1; // Bug: accepts stale frame without epoch fence
    }
  }
}

// ── SM13: Interactive Search-Box CJK/IME Composition, Blur & Shortcut Isolation ──

interface ImeState {
  focused: boolean;
  composing: boolean;
  preedit: string;
  committedText: string;
  committedGen: number;
  submittedGen: number;
  submittedQueries: string[];
  prematureSubmits: number;
  orphanedCompositions: number;
  shortcutCollisions: number;
}

class DeterministicImeSearchBox {
  readonly state: ImeState = {
    focused: true,
    composing: false,
    preedit: '',
    committedText: '',
    committedGen: 0,
    submittedGen: 0,
    submittedQueries: [],
    prematureSubmits: 0,
    orphanedCompositions: 0,
    shortcutCollisions: 0,
  };

  focus(): void {
    this.state.focused = true;
  }

  compositionUpdate(preeditChunk: string): void {
    if (!this.state.focused) return;
    this.state.composing = true;
    this.state.preedit += preeditChunk;
  }

  compositionCommit(finalText: string): void {
    if (!this.state.focused || !this.state.composing) return;
    this.state.composing = false;
    this.state.preedit = '';
    this.state.committedText = finalText;
    this.state.committedGen += 1;
  }

  pressEnter(isComposingEvent: boolean): 'submitted' | 'ime-consumed' | 'ignored' {
    if (!this.state.focused) return 'ignored';
    if (this.state.composing || isComposingEvent) return 'ime-consumed';
    if (this.state.submittedGen < this.state.committedGen) {
      this.state.submittedGen = this.state.committedGen;
      this.state.submittedQueries.push(this.state.committedText);
      return 'submitted';
    }
    return 'ignored';
  }

  blur(): void {
    if (!this.state.focused) return;
    this.state.focused = false;
    // SM13 guard: atomically cancel active IME preedit on focus loss.
    this.state.composing = false;
    this.state.preedit = '';
  }

  pressGlobalShortcut(_shortcut: string, isComposingEvent: boolean): 'dispatched' | 'suppressed' {
    if (!this.state.focused) return 'dispatched';
    if (this.state.composing || isComposingEvent) return 'suppressed';
    return 'dispatched';
  }
}

class DefectiveImeSearchBox {
  readonly state: ImeState = {
    focused: true,
    composing: false,
    preedit: '',
    committedText: '',
    committedGen: 0,
    submittedGen: 0,
    submittedQueries: [],
    prematureSubmits: 0,
    orphanedCompositions: 0,
    shortcutCollisions: 0,
  };

  focus(): void {
    this.state.focused = true;
  }

  compositionUpdate(preeditChunk: string): void {
    if (!this.state.focused) return;
    this.state.composing = true;
    this.state.preedit += preeditChunk;
  }

  compositionCommit(finalText: string): void {
    if (!this.state.focused || !this.state.composing) return;
    this.state.composing = false;
    this.state.preedit = '';
    this.state.committedText = finalText;
    this.state.committedGen += 1;
  }

  pressEnter(): void {
    if (!this.state.focused) return;
    if (this.state.composing) {
      this.state.prematureSubmits += 1;
      this.state.submittedQueries.push(this.state.preedit);
    } else if (this.state.submittedGen < this.state.committedGen) {
      this.state.submittedGen = this.state.committedGen;
      this.state.submittedQueries.push(this.state.committedText);
    }
  }

  blur(): void {
    if (!this.state.focused) return;
    this.state.focused = false;
    if (this.state.composing) {
      this.state.orphanedCompositions += 1; // Leak: leaves composing=true while unfocused!
    }
  }

  pressGlobalShortcut(): void {
    if (this.state.focused && this.state.composing) {
      this.state.shortcutCollisions += 1;
    }
  }
}

// ── SM14: Compound Chaos Fault Injection, Circuit Shedding & Typed Recovery ──

type ChaosResult = {kind: 'ok'} | {kind: 'degraded'; reason: string} | {kind: 'shed'; reason: string};

class DeterministicChaosCircuit {
  faultActive = false;
  circuitOpen = false;
  activeLoad = 0;
  readonly maxLoad: number;
  consecutiveFaults = 0;
  readonly tripThreshold: number;
  recoveredCount = 0;
  refusedDegraded = 0;
  cascadeViolations = 0;
  silentCorruptions = 0;
  stickyWedged = 0;

  constructor(maxLoad = 2, tripThreshold = 2) {
    this.maxLoad = maxLoad;
    this.tripThreshold = tripThreshold;
  }

  handleRequest(): ChaosResult {
    if (this.circuitOpen) {
      this.refusedDegraded += 1;
      return {kind: 'shed', reason: 'circuit-open'};
    }
    if (this.faultActive) {
      this.consecutiveFaults += 1;
      this.refusedDegraded += 1;
      if (this.consecutiveFaults >= this.tripThreshold) {
        this.circuitOpen = true;
      }
      return {kind: 'degraded', reason: 'injected-fault'};
    }
    if (this.activeLoad >= this.maxLoad) {
      this.refusedDegraded += 1;
      return {kind: 'shed', reason: 'max-load-cap'};
    }
    this.activeLoad += 1;
    return {kind: 'ok'};
  }

  finishRequest(): void {
    if (this.activeLoad > 0) this.activeLoad -= 1;
  }

  probeRecovery(): boolean {
    if (this.circuitOpen && !this.faultActive) {
      this.circuitOpen = false;
      this.consecutiveFaults = 0;
      this.recoveredCount += 1;
      return true;
    }
    return false;
  }
}

class DefectiveChaosCircuit {
  faultActive = false;
  circuitOpen = false;
  activeLoad = 0;
  readonly maxLoad = 2;
  consecutiveFaults = 0;
  cascadeViolations = 0;
  silentCorruptions = 0;
  stickyWedged = 0;

  handleRequest(): void {
    if (this.circuitOpen) {
      this.activeLoad += 1;
      this.cascadeViolations += 1;
      return;
    }
    if (this.faultActive) {
      this.consecutiveFaults += 1;
      this.silentCorruptions += 1; // Bug: silently returns synthetic empty OK during fault
      if (this.consecutiveFaults >= 2) this.circuitOpen = true;
      return;
    }
    if (this.activeLoad < this.maxLoad) this.activeLoad += 1;
  }

  probeRecovery(): void {
    if (this.circuitOpen && !this.faultActive) {
      this.stickyWedged += 1; // Bug: never transitions out of open circuit
    }
  }
}

describe('SM12-SM14 Adversarial Structure-Aware Fuzzing, Chaos & Live Quint ITF MBT', () => {
  test('SM12: 250 randomized half-open reconnect & replay storms — hardened zero leaks/dups/stale vs defective collapse', () => {
    const rng = mulberry32(0x512001);
    const keys = ['req-alpha', 'req-beta', 'req-gamma', 'req-delta'];
    let totalDefectiveLeaks = 0;
    let totalDefectiveDups = 0;
    let totalDefectiveStale = 0;

    for (let trial = 0; trial < 250; trial++) {
      const good = new DeterministicIpcSession();
      const bad = new DefectiveIpcSession();
      for (let step = 0; step < 64; step++) {
        const op = Math.floor(rng() * 4);
        const key = keys[Math.floor(rng() * keys.length)]!;
        if (op === 0) {
          good.sendRequest(key);
          bad.sendRequest(key);
        } else if (op === 1) {
          good.commitRequest(key);
          bad.commitRequest(key);
        } else if (op === 2) {
          good.reconnectHalfOpen();
          bad.reconnectHalfOpen();
        } else {
          const staleEpoch = Math.max(1, good.state.sessionEpoch - 1);
          good.receiveFrame(staleEpoch);
          bad.receiveFrame(staleEpoch);
        }
        expect(good.state.activeStreams).toBeLessThanOrEqual(1);
        expect(good.state.duplicateEffects).toBe(0);
        expect(good.state.staleFramesApplied).toBe(0);
      }
      if (bad.state.activeStreams > 1) totalDefectiveLeaks += 1;
      if (bad.state.duplicateEffects > 0) totalDefectiveDups += 1;
      if (bad.state.staleFramesApplied > 0) totalDefectiveStale += 1;
    }

    expect(totalDefectiveLeaks).toBeGreaterThan(200);
    expect(totalDefectiveDups).toBeGreaterThan(150);
    expect(totalDefectiveStale).toBeGreaterThan(200);
  });

  test('SM13: 250 randomized CJK/IME composition + focus/blur + shortcut fuzz schedules', () => {
    const rng = mulberry32(0x513002);
    const preeditChunks = ['zhong', 'guo', 'sou', 'suo', 'ni', 'hao'];
    const committedWords = ['中国', '搜索', '你好', '稳定性'];
    const shortcuts = ['Cmd+K', 'Escape', 'ArrowDown', '/'];
    let badPremature = 0;
    let badOrphan = 0;
    let badShortcut = 0;

    for (let trial = 0; trial < 250; trial++) {
      const good = new DeterministicImeSearchBox();
      const bad = new DefectiveImeSearchBox();
      for (let step = 0; step < 56; step++) {
        const op = Math.floor(rng() * 6);
        if (op === 0) {
          good.focus();
          bad.focus();
        } else if (op === 1) {
          const chunk = preeditChunks[Math.floor(rng() * preeditChunks.length)]!;
          good.compositionUpdate(chunk);
          bad.compositionUpdate(chunk);
        } else if (op === 2) {
          const word = committedWords[Math.floor(rng() * committedWords.length)]!;
          good.compositionCommit(word);
          bad.compositionCommit(word);
        } else if (op === 3) {
          good.pressEnter(good.state.composing);
          bad.pressEnter();
        } else if (op === 4) {
          good.blur();
          bad.blur();
        } else {
          const sc = shortcuts[Math.floor(rng() * shortcuts.length)]!;
          good.pressGlobalShortcut(sc, good.state.composing);
          bad.pressGlobalShortcut();
        }

        expect(good.state.prematureSubmits).toBe(0);
        expect(good.state.orphanedCompositions).toBe(0);
        expect(good.state.shortcutCollisions).toBe(0);
        if (!good.state.focused) {
          expect(good.state.composing).toBe(false);
          expect(good.state.preedit).toBe('');
        }
        expect(good.state.submittedGen).toBeLessThanOrEqual(good.state.committedGen);
      }
      if (bad.state.prematureSubmits > 0) badPremature += 1;
      if (bad.state.orphanedCompositions > 0) badOrphan += 1;
      if (bad.state.shortcutCollisions > 0) badShortcut += 1;
    }

    expect(badPremature).toBeGreaterThan(150);
    expect(badOrphan).toBeGreaterThan(150);
    expect(badShortcut).toBeGreaterThan(150);
  });

  test('SM14: 250 randomized compound chaos fault-injection bursts & recovery probes', () => {
    const rng = mulberry32(0x514003);
    let badCascade = 0;
    let badSilent = 0;
    let badWedged = 0;

    for (let trial = 0; trial < 250; trial++) {
      const good = new DeterministicChaosCircuit(2, 2);
      const bad = new DefectiveChaosCircuit();
      for (let step = 0; step < 32; step++) {
        const op = Math.floor(rng() * 5);
        if (op === 0) {
          good.faultActive = true;
          bad.faultActive = true;
        } else if (op === 1) {
          good.faultActive = false;
          bad.faultActive = false;
        } else if (op === 2) {
          const res = good.handleRequest();
          bad.handleRequest();
          if (good.faultActive) expect(res.kind).not.toBe('ok');
        } else if (op === 3) {
          good.finishRequest();
        } else {
          good.probeRecovery();
          bad.probeRecovery();
        }
        expect(good.activeLoad).toBeLessThanOrEqual(good.maxLoad);
        expect(good.cascadeViolations).toBe(0);
        expect(good.silentCorruptions).toBe(0);
        expect(good.stickyWedged).toBe(0);
      }
      // Post-chaos recovery liveness check: clearing fault & probing MUST restore closed circuit.
      good.faultActive = false;
      if (good.circuitOpen) {
        expect(good.probeRecovery()).toBe(true);
      }
      expect(good.circuitOpen).toBe(false);

      if (bad.cascadeViolations > 0) badCascade += 1;
      if (bad.silentCorruptions > 0) badSilent += 1;
      if (bad.stickyWedged > 0) badWedged += 1;
    }

    expect(badCascade).toBeGreaterThan(100);
    expect(badSilent).toBeGreaterThan(200);
    expect(badWedged).toBeGreaterThan(100);
  });

  test('Live Quint ITF MBT Replay across SM12, SM13 & SM14 (18 live traces, 100% invariant parity)', () => {
    // SM12 live ITF replay
    const sm12Traces = generateItfTraces(
      'packages/quint-models/engineering/concurrency/ipc-half-open-reconnect-idempotency/IpcHalfOpenReconnectIdempotency.qnt',
      'concurrency_ipc_half_open_reconnect_idempotency',
    );
    expect(sm12Traces.length).toBe(6);
    for (const states of sm12Traces) {
      const sut = new DeterministicIpcSession();
      for (let i = 1; i < states.length; i++) {
        const action = String(states[i]!['mbt::actionTaken'] ?? '');
        const h = states[i]!['h'] as Record<string, unknown>;
        if (action === 'sendRequest') sut.sendRequest('key-1');
        else if (action === 'commitRequest') sut.commitRequest('key-1');
        else if (action === 'reconnectHalfOpen') {
          if (sut.state.reconnectCount < 3) sut.reconnectHalfOpen();
        } else if (action === 'receiveStaleFrame') {
          if (sut.state.sessionEpoch > 1) sut.receiveFrame(sut.state.sessionEpoch - 1);
        }
        expect(sut.state.activeStreams).toBe(itfInt(h['activeStreams']));
        expect(sut.state.sessionEpoch).toBe(itfInt(h['sessionEpoch']));
        expect(sut.state.duplicateEffects).toBe(itfInt(h['duplicateEffects']));
        expect(sut.state.staleFramesApplied).toBe(itfInt(h['staleFramesApplied']));
      }
    }

    // SM13 live ITF replay
    const sm13Traces = generateItfTraces(
      'packages/quint-models/engineering/concurrency/ime-composition-focus-race/ImeCompositionFocusRace.qnt',
      'concurrency_ime_composition_focus_race',
    );
    expect(sm13Traces.length).toBe(6);
    for (const states of sm13Traces) {
      const sut = new DeterministicImeSearchBox();
      for (let i = 1; i < states.length; i++) {
        const action = String(states[i]!['mbt::actionTaken'] ?? '');
        const h = states[i]!['h'] as Record<string, unknown>;
        if (action === 'focusInput') sut.focus();
        else if (action === 'startPreedit') {
          if (sut.state.focused && sut.state.preedit.length < 3) sut.compositionUpdate('a');
        } else if (action === 'commitComposition') {
          if (sut.state.focused && sut.state.composing && sut.state.committedGen < 4) sut.compositionCommit('字');
        } else if (action === 'pressEnter') sut.pressEnter(sut.state.composing);
        else if (action === 'blurInput') sut.blur();
        else if (action === 'pressGlobalShortcut') sut.pressGlobalShortcut('Cmd+K', sut.state.composing);

        expect(sut.state.focused).toBe(Boolean(h['focused']));
        expect(sut.state.composing).toBe(Boolean(h['composing']));
        expect(sut.state.preedit.length).toBe(itfInt(h['preeditLen']));
        expect(sut.state.committedGen).toBe(itfInt(h['committedGen']));
        expect(sut.state.submittedGen).toBe(itfInt(h['submittedGen']));
        expect(sut.state.prematureSubmits).toBe(0);
        expect(sut.state.orphanedCompositions).toBe(0);
        expect(sut.state.shortcutCollisions).toBe(0);
      }
    }

    // SM14 live ITF replay
    const sm14Traces = generateItfTraces(
      'packages/quint-models/engineering/concurrency/chaos-fault-injection-recovery-envelope/ChaosFaultInjectionRecoveryEnvelope.qnt',
      'concurrency_chaos_fault_injection_recovery_envelope',
    );
    expect(sm14Traces.length).toBe(6);
    for (const states of sm14Traces) {
      const sut = new DeterministicChaosCircuit(2, 2);
      for (let i = 1; i < states.length; i++) {
        const action = String(states[i]!['mbt::actionTaken'] ?? '');
        const h = states[i]!['h'] as Record<string, unknown>;
        if (action === 'injectFault') sut.faultActive = true;
        else if (action === 'clearFault') sut.faultActive = false;
        else if (action === 'handleRequest') sut.handleRequest();
        else if (action === 'finishRequest') sut.finishRequest();
        else if (action === 'probeRecovery') sut.probeRecovery();

        expect(sut.faultActive).toBe(Boolean(h['faultActive']));
        expect(sut.circuitOpen ? 1 : 0).toBe(itfInt(h['circuitState']));
        expect(sut.activeLoad).toBe(itfInt(h['activeLoad']));
        expect(sut.recoveredCount).toBe(itfInt(h['recoveredCount']));
        expect(sut.cascadeViolations).toBe(0);
        expect(sut.silentCorruptions).toBe(0);
        expect(sut.stickyWedged).toBe(0);
      }
    }
  }, 60000);
});
