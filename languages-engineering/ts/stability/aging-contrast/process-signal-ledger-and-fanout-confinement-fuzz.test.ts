// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm37State {
  activeFanout: number;
  ledgerEntries: number;
  signalTargetGuarded: boolean;
  startFingerprintRequired: boolean;
  ledgerConfinementEnforced: boolean;
  fanoutBoundsAndDrainEnforced: boolean;
  signalScopeBreaches: number;
  pidReuseBreaches: number;
  ledgerIntegrityBreaches: number;
  fanoutConfinementBreaches: number;
  cleanVerifiedOps: number;
  stepCount: number;
}

function initState(): Sm37State {
  return {
    activeFanout: 0,
    ledgerEntries: 0,
    signalTargetGuarded: true,
    startFingerprintRequired: true,
    ledgerConfinementEnforced: true,
    fanoutBoundsAndDrainEnforced: true,
    signalScopeBreaches: 0,
    pidReuseBreaches: 0,
    ledgerIntegrityBreaches: 0,
    fanoutConfinementBreaches: 0,
    cleanVerifiedOps: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm37State, action: string): Sm37State {
  const s = {...state};
  switch (action) {
    case 'signalValidatedProcessGroup':
      if (s.stepCount < 12 && s.signalTargetGuarded) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'reconcileFingerprintedOrphan':
      if (s.stepCount < 12 && s.startFingerprintRequired) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'persistBoundedSymlinkSafeLedger':
      if (s.stepCount < 12 && s.ledgerConfinementEnforced && s.ledgerEntries < 12) {
        s.ledgerEntries += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'admitBoundedFanoutWorker':
      if (s.stepCount < 12 && s.fanoutBoundsAndDrainEnforced && s.activeFanout < 12) {
        s.activeFanout += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'completeFanoutWorker':
      if (s.stepCount < 12 && s.fanoutBoundsAndDrainEnforced && s.activeFanout > 0) {
        s.activeFanout -= 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'drainAbortedFanoutWorkers':
      if (s.stepCount < 12 && s.fanoutBoundsAndDrainEnforced && s.activeFanout > 0) {
        s.activeFanout = 0;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM37 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm37State): boolean {
  return (
    s.signalScopeBreaches === 0 &&
    s.pidReuseBreaches === 0 &&
    s.ledgerIntegrityBreaches === 0 &&
    s.fanoutConfinementBreaches === 0 &&
    s.signalTargetGuarded &&
    s.startFingerprintRequired &&
    s.ledgerConfinementEnforced &&
    s.fanoutBoundsAndDrainEnforced &&
    s.activeFanout >= 0 &&
    s.activeFanout <= 12 &&
    s.ledgerEntries >= 0 &&
    s.ledgerEntries <= 12 &&
    s.stepCount <= 12
  );
}

const I32_MAX = 0x7fff_ffff;
const MAX_LEDGER_FILE_BYTES = 4 * 1024 * 1024;
const FILE_LEDGER_SCHEMA_VERSION = 1;
const MAX_ACTIVE_LEDGER_ENTRIES = 1024;
const MAX_WORKING_COPY_FANOUT_PARALLELISM = 64;

function validateSignalTarget(
  pid: number,
  pgid: number | null,
  hostPid: number,
  hostPgid: number,
): boolean {
  const targetPgid = pgid ?? pid;
  if (!Number.isInteger(pid) || !Number.isInteger(targetPgid)) return false;
  if (pid <= 1 || pid > I32_MAX || pid === hostPid) return false;
  if (targetPgid <= 1 || targetPgid > I32_MAX || targetPgid === hostPgid) return false;
  return true;
}

function verifyOrphanIdentity(
  pid: number,
  pgid: number | null,
  hostPid: number,
  hostPgid: number,
  recordedStartSec: number | null,
  liveStartSec: number,
): boolean {
  if (!validateSignalTarget(pid, pgid, hostPid, hostPgid)) return false;
  if (recordedStartSec === null || recordedStartSec <= 0 || liveStartSec <= 0) return false;
  return Math.abs(liveStartSec - recordedStartSec) <= 1;
}

function admitLedgerSnapshot(
  symlinkFree: boolean,
  fileBytes: number,
  schemaVersion: number,
  activeEntries: number,
): boolean {
  return (
    symlinkFree &&
    fileBytes >= 0 &&
    fileBytes <= MAX_LEDGER_FILE_BYTES &&
    schemaVersion === FILE_LEDGER_SCHEMA_VERSION &&
    activeEntries >= 0 &&
    activeEntries <= MAX_ACTIVE_LEDGER_ENTRIES
  );
}

function clampFanoutParallelism(requested: number | null, itemCount: number): number {
  const raw = requested === null ? Math.max(itemCount, 1) : Math.max(requested, 1);
  return Math.min(raw, MAX_WORKING_COPY_FANOUT_PARALLELISM);
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

function parseItfState(raw: Record<string, unknown>): Sm37State {
  const h = raw.h as Record<string, unknown>;
  return {
    activeFanout: bigintFromItf(h.activeFanout),
    ledgerEntries: bigintFromItf(h.ledgerEntries),
    signalTargetGuarded: Boolean(h.signalTargetGuarded),
    startFingerprintRequired: Boolean(h.startFingerprintRequired),
    ledgerConfinementEnforced: Boolean(h.ledgerConfinementEnforced),
    fanoutBoundsAndDrainEnforced: Boolean(h.fanoutBoundsAndDrainEnforced),
    signalScopeBreaches: bigintFromItf(h.signalScopeBreaches),
    pidReuseBreaches: bigintFromItf(h.pidReuseBreaches),
    ledgerIntegrityBreaches: bigintFromItf(h.ledgerIntegrityBreaches),
    fanoutConfinementBreaches: bigintFromItf(h.fanoutConfinementBreaches),
    cleanVerifiedOps: bigintFromItf(h.cleanVerifiedOps),
    stepCount: bigintFromItf(h.stepCount),
  };
}

describe('SM37 (ADV-L4): Process Signal, Ledger & Fanout Confinement', () => {
  test('500-trial ADV-L4 hostile fuzz refutes kill(0)/kill(-1)/self-kill, PID-reuse reaping, symlink/oversize ledgers & unbounded fanout', () => {
    const rand = makePrng(0x534d3337);

    for (let trial = 0; trial < 500; trial++) {
      const hostPid = 10_000 + Math.floor(rand() * 20_000);
      const hostPgid = 5_000 + Math.floor(rand() * 4_000);
      const childPid = 40_000 + (trial % 10_000);
      const childPgid = 60_000 + (trial % 10_000);

      // 1. POSIX signal target confinement: forbid 0, 1, overflow, self-PID, and host PGID.
      expect(validateSignalTarget(0, null, hostPid, hostPgid)).toBe(false);
      expect(validateSignalTarget(1, null, hostPid, hostPgid)).toBe(false);
      expect(validateSignalTarget(childPid, 0, hostPid, hostPgid)).toBe(false);
      expect(validateSignalTarget(childPid, 1, hostPid, hostPgid)).toBe(false);
      expect(validateSignalTarget(hostPid, childPgid, hostPid, hostPgid)).toBe(false);
      expect(validateSignalTarget(childPid, hostPgid, hostPid, hostPgid)).toBe(false);
      expect(validateSignalTarget(I32_MAX + 1, childPgid, hostPid, hostPgid)).toBe(false);
      expect(validateSignalTarget(childPid, childPgid, hostPid, hostPgid)).toBe(true);

      // 2. Orphan identity verification: missing start-time fingerprint or drift > 1s fails closed.
      const baseStart = 1_700_000_000 + trial;
      expect(verifyOrphanIdentity(childPid, childPgid, hostPid, hostPgid, null, baseStart)).toBe(false);
      expect(verifyOrphanIdentity(childPid, childPgid, hostPid, hostPgid, baseStart, baseStart + 5)).toBe(false);
      expect(verifyOrphanIdentity(1, 1, hostPid, hostPgid, baseStart, baseStart)).toBe(false);
      expect(verifyOrphanIdentity(hostPid, hostPgid, hostPid, hostPgid, baseStart, baseStart)).toBe(false);
      expect(verifyOrphanIdentity(childPid, childPgid, hostPid, hostPgid, baseStart, baseStart + 1)).toBe(true);

      // 3. Process ledger confinement: symlink, oversize, schema mismatch, active cap overflow fail closed.
      expect(admitLedgerSnapshot(false, 1024, 1, 4)).toBe(false);
      expect(admitLedgerSnapshot(true, MAX_LEDGER_FILE_BYTES + 1, 1, 4)).toBe(false);
      expect(admitLedgerSnapshot(true, 1024, 99, 4)).toBe(false);
      expect(admitLedgerSnapshot(true, 1024, 1, MAX_ACTIVE_LEDGER_ENTRIES + 1)).toBe(false);
      expect(admitLedgerSnapshot(true, 1024, 1, trial % (MAX_ACTIVE_LEDGER_ENTRIES + 1))).toBe(true);

      // 4. Fanout parallelism hard ceiling: None or huge requests clamp cleanly to 1..=64.
      expect(clampFanoutParallelism(null, 5_000)).toBe(MAX_WORKING_COPY_FANOUT_PARALLELISM);
      expect(clampFanoutParallelism(10_000, 10_000)).toBe(MAX_WORKING_COPY_FANOUT_PARALLELISM);
      expect(clampFanoutParallelism(0, 10)).toBe(1);
      const small = 1 + (trial % MAX_WORKING_COPY_FANOUT_PARALLELISM);
      expect(clampFanoutParallelism(small, 128)).toBe(small);
    }
  });

  test('6 live Quint --mbt ITF traces refine SM37 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const qntPath = resolve(
      repoRoot,
      'packages/quint-models/threat/execution/process-signal-ledger-and-fanout-confinement/ProcessSignalLedgerAndFanoutConfinement.qnt',
    );
    const resolverCli = resolve(repoRoot, 'packages/quint-modules-resolver/src/cli.ts');
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm37-mbt-'));
    try {
      for (let seed = 1; seed <= 6; seed++) {
        const itfPath = join(tmpDir, `sm37-seed-${seed}.itf.json`);
        execFileSync(
          'bun',
          [
            'run',
            resolverCli,
            'run',
            qntPath,
            '--main=execution_process_signal_ledger_and_fanout_confinement',
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
