// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm36State {
  activeModules: number;
  activeTimers: number;
  otlpTlsEnforced: boolean;
  observerEnvScrubbed: boolean;
  watchdogClockBounded: boolean;
  deckVmBoundsEnforced: boolean;
  otlpExfilBreaches: number;
  observerEnvBreaches: number;
  watchdogBlindBreaches: number;
  deckVmExhaustionBreaches: number;
  cleanVerifiedOps: number;
  stepCount: number;
}

function initState(): Sm36State {
  return {
    activeModules: 1,
    activeTimers: 0,
    otlpTlsEnforced: true,
    observerEnvScrubbed: true,
    watchdogClockBounded: true,
    deckVmBoundsEnforced: true,
    otlpExfilBreaches: 0,
    observerEnvBreaches: 0,
    watchdogBlindBreaches: 0,
    deckVmExhaustionBreaches: 0,
    cleanVerifiedOps: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm36State, action: string): Sm36State {
  const s = {...state};
  switch (action) {
    case 'exportTlsBoundedOtlpTrace':
      if (s.stepCount < 12 && s.otlpTlsEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'spawnScrubbedHostObserver':
      if (s.stepCount < 12 && s.observerEnvScrubbed) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'sampleValidatedWatchdogPulse':
      if (s.stepCount < 12 && s.watchdogClockBounded) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'activateBoundedDeckModule':
      if (s.stepCount < 12 && s.deckVmBoundsEnforced && s.activeModules < 12) {
        s.activeModules += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'armBoundedDeckTimer':
      if (s.stepCount < 12 && s.deckVmBoundsEnforced && s.activeTimers < 12) {
        s.activeTimers += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'retireBoundedDeckTimer':
      if (s.stepCount < 12 && s.deckVmBoundsEnforced && s.activeTimers > 0) {
        s.activeTimers -= 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM36 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm36State): boolean {
  return (
    s.otlpExfilBreaches === 0 &&
    s.observerEnvBreaches === 0 &&
    s.watchdogBlindBreaches === 0 &&
    s.deckVmExhaustionBreaches === 0 &&
    s.otlpTlsEnforced &&
    s.observerEnvScrubbed &&
    s.watchdogClockBounded &&
    s.deckVmBoundsEnforced &&
    s.activeModules >= 1 &&
    s.activeModules <= 12 &&
    s.activeTimers >= 0 &&
    s.activeTimers <= 12 &&
    s.stepCount <= 12
  );
}

function isLoopbackHost(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === 'localhost' || lower === '127.0.0.1' || lower === '[::1]' || lower === '::1';
}

function validateOtlpEndpoint(raw: string): boolean {
  if (raw.length === 0 || raw.length > 2048) return false;
  if (/[\x00-\x20\x7f?#]/.test(raw)) return false;
  if (raw.includes('@') || raw.toLowerCase().includes('%40')) return false;
  if (!URL.canParse(raw)) return false;
  const parsed = new URL(raw);
  if (!parsed.hostname) return false;
  if (parsed.protocol === 'https:') return true;
  if (parsed.protocol === 'http:') return isLoopbackHost(parsed.hostname);
  return false;
}

function acceptWatchdogPulse(
  lastTs: number | null,
  pulseTs: number,
  nowNs: number,
): number | null {
  if (pulseTs <= 0 || pulseTs > nowNs) {
    return lastTs;
  }
  return lastTs === null ? pulseTs : Math.max(lastTs, pulseTs);
}

const MAX_TIMER_DELAY_US = 86_400 * 1_000_000;

function admitDeckVmTimer(
  activeTimers: number,
  maxTimers: number,
  delayUs: number,
): boolean {
  return activeTimers < maxTimers && delayUs > 0 && delayUs <= MAX_TIMER_DELAY_US;
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

function parseItfState(raw: Record<string, unknown>): Sm36State {
  const h = raw.h as Record<string, unknown>;
  return {
    activeModules: bigintFromItf(h.activeModules),
    activeTimers: bigintFromItf(h.activeTimers),
    otlpTlsEnforced: Boolean(h.otlpTlsEnforced),
    observerEnvScrubbed: Boolean(h.observerEnvScrubbed),
    watchdogClockBounded: Boolean(h.watchdogClockBounded),
    deckVmBoundsEnforced: Boolean(h.deckVmBoundsEnforced),
    otlpExfilBreaches: bigintFromItf(h.otlpExfilBreaches),
    observerEnvBreaches: bigintFromItf(h.observerEnvBreaches),
    watchdogBlindBreaches: bigintFromItf(h.watchdogBlindBreaches),
    deckVmExhaustionBreaches: bigintFromItf(h.deckVmExhaustionBreaches),
    cleanVerifiedOps: bigintFromItf(h.cleanVerifiedOps),
    stepCount: bigintFromItf(h.stepCount),
  };
}

describe('SM36 (ADV-L4): Telemetry/Watchdog & Deck Single-VM Confinement', () => {
  test('500-trial ADV-L4 hostile fuzz refutes cleartext OTLP exfil, future-timestamp watchdog blinding & Deck VM module/timer exhaustion', () => {
    const rand = makePrng(0x534d3336);
    const hostileOtlp = [
      'http://evil-collector.example:4318/v1/traces',
      'http://10.0.0.5:4318/v1/traces',
      'http://169.254.169.254/latest/meta-data',
      'https://user@collector.example/v1/traces',
      'https://user%40evil.example/v1/traces',
      'https://collector.example/v1/traces?token=leak',
      'https://collector.example/v1/traces#frag',
      'http://:4318/v1/traces',
      'https://collector.example/\r\nX-Inject: 1',
      'ftp://localhost/v1/traces',
    ];
    const safeOtlp = [
      'https://otel.internal.example/v1/traces',
      'http://127.0.0.1:4318/v1/traces',
      'http://localhost:4318/v1/traces',
      'http://[::1]:4318/v1/traces',
    ];

    for (let trial = 0; trial < 500; trial++) {
      // 1. OTLP TLS-mandatory remote / loopback-only HTTP confinement.
      expect(validateOtlpEndpoint(hostileOtlp[trial % hostileOtlp.length]!)).toBe(false);
      expect(validateOtlpEndpoint(safeOtlp[trial % safeOtlp.length]!)).toBe(true);

      // 2. Watchdog future-timestamp & zero-timestamp rejection prevents HeartbeatMissed blinding.
      const nowNs = 1_000_000_000 + Math.floor(rand() * 5_000_000_000);
      const validLast = acceptWatchdogPulse(null, nowNs - 50_000, nowNs);
      expect(validLast).toBe(nowNs - 50_000);
      const blindedAttempt = acceptWatchdogPulse(validLast, nowNs + 1_000_000_000, nowNs);
      expect(blindedAttempt).toBe(validLast);
      expect(acceptWatchdogPulse(validLast, 0, nowNs)).toBe(validLast);
      expect(nowNs - blindedAttempt!).toBeGreaterThanOrEqual(50_000);

      // 3. Deck VM timer capacity & finite delay bounds.
      expect(admitDeckVmTimer(1024, 1024, 1000)).toBe(false);
      expect(admitDeckVmTimer(0, 1024, 0)).toBe(false);
      expect(admitDeckVmTimer(0, 1024, MAX_TIMER_DELAY_US + 1)).toBe(false);
      expect(admitDeckVmTimer(trial % 1024, 1024, 1 + (trial % 60_000_000))).toBe(true);
    }
  });

  test('6 live Quint --mbt ITF traces refine SM36 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const qntPath = resolve(
      repoRoot,
      'packages/quint-models/threat/execution/telemetry-watchdog-and-deck-vm-confinement/TelemetryWatchdogAndDeckVmConfinement.qnt',
    );
    const resolverCli = resolve(repoRoot, 'packages/quint-modules-resolver/src/cli.ts');
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm36-mbt-'));
    try {
      for (let seed = 1; seed <= 6; seed++) {
        const itfPath = join(tmpDir, `sm36-seed-${seed}.itf.json`);
        execFileSync(
          'bun',
          [
            'run',
            resolverCli,
            'run',
            qntPath,
            '--main=execution_telemetry_watchdog_and_deck_vm_confinement',
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
