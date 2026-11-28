// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm39State {
  probeChunksWritten: number;
  configConfinementEnforced: boolean;
  supervisorIsolationEnforced: boolean;
  probeFileConfinementEnforced: boolean;
  bootstrapTrustOrderEnforced: boolean;
  configConfinementBreaches: number;
  supervisorIsolationBreaches: number;
  probeFileBreaches: number;
  bootstrapTrustBreaches: number;
  cleanVerifiedOps: number;
  stepCount: number;
}

function initState(): Sm39State {
  return {
    probeChunksWritten: 0,
    configConfinementEnforced: true,
    supervisorIsolationEnforced: true,
    probeFileConfinementEnforced: true,
    bootstrapTrustOrderEnforced: true,
    configConfinementBreaches: 0,
    supervisorIsolationBreaches: 0,
    probeFileBreaches: 0,
    bootstrapTrustBreaches: 0,
    cleanVerifiedOps: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm39State, action: string): Sm39State {
  const s = {...state};
  switch (action) {
    case 'loadBoundedSafeTuiConfig':
      if (s.stepCount < 12 && s.configConfinementEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'spawnScrubbedBoundedAspGateway':
      if (s.stepCount < 12 && s.supervisorIsolationEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'writeBoundedNoFollowProbeRow':
      if (s.stepCount < 12 && s.probeFileConfinementEnforced && s.probeChunksWritten < 12) {
        s.probeChunksWritten += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'resolveExeFirstNonSymlinkBootstrap':
      if (s.stepCount < 12 && s.bootstrapTrustOrderEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM39 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm39State): boolean {
  return (
    s.configConfinementBreaches === 0 &&
    s.supervisorIsolationBreaches === 0 &&
    s.probeFileBreaches === 0 &&
    s.bootstrapTrustBreaches === 0 &&
    s.configConfinementEnforced &&
    s.supervisorIsolationEnforced &&
    s.probeFileConfinementEnforced &&
    s.bootstrapTrustOrderEnforced &&
    s.probeChunksWritten >= 0 &&
    s.probeChunksWritten <= 12 &&
    s.stepCount <= 12
  );
}

const MAX_TUI_CONFIG_BYTES = 256 * 1024;
const MAX_TUI_TIMEOUT_SECONDS = 600;
const MAX_RUNTIME_PROBE_BYTES = 4 * 1024 * 1024;
const AMBIENT_FORBIDDEN_EXACT = new Set([
  'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'PWD', 'OLDPWD', 'TMPDIR',
  'TERM', 'BASH_ENV', 'ENV', 'IFS', 'RUSTFLAGS', 'NODE_OPTIONS', 'PYTHONPATH',
]);
const AMBIENT_FORBIDDEN_PREFIXES = ['LD_', 'DYLD_', 'SSH_', 'GIT_', 'XDG_', 'CARGO_', 'GERBIL_'];

function isSafeCredentialEnv(name: string): boolean {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return false;
  const upper = name.toUpperCase();
  if (AMBIENT_FORBIDDEN_EXACT.has(upper)) return false;
  return !AMBIENT_FORBIDDEN_PREFIXES.some((p) => upper.startsWith(p));
}

function validateTuiConfigEnvelope(
  symlinkFree: boolean,
  fileBytes: number,
  timeoutSeconds: number,
  credEnv: string,
): boolean {
  return (
    symlinkFree &&
    fileBytes >= 0 &&
    fileBytes <= MAX_TUI_CONFIG_BYTES &&
    Number.isInteger(timeoutSeconds) &&
    timeoutSeconds >= 1 &&
    timeoutSeconds <= MAX_TUI_TIMEOUT_SECONDS &&
    isSafeCredentialEnv(credEnv)
  );
}

function validateManagedAspEndpoint(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed.startsWith('http://')) return false;
  const rest = trimmed.slice('http://'.length);
  if (/[\s@/?#\\]/.test(rest) || /[\x00-\x1f\x7f]/.test(trimmed)) return false;
  const parts = rest.split(':');
  if (parts.length !== 2) return false;
  const [host, portRaw] = parts as [string, string];
  if (host !== '127.0.0.1' && host !== 'localhost') return false;
  if (!/^\d{1,5}$/.test(portRaw)) return false;
  const port = Number(portRaw);
  return port >= 1 && port <= 65535;
}

function admitRuntimeProbeWrite(symlinkFree: boolean, written: number, rowLen: number): boolean {
  return symlinkFree && written >= 0 && rowLen >= 0 && written + rowLen <= MAX_RUNTIME_PROBE_BYTES;
}

function selectBootstrapPrefix(
  exePrefix: string | null,
  cwdPrefix: string | null,
  exeSymlinkFree: boolean,
  cwdSymlinkFree: boolean,
): string | null {
  if (exePrefix && exeSymlinkFree) return exePrefix;
  if (cwdPrefix && cwdSymlinkFree) return cwdPrefix;
  return null;
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

function parseItfState(raw: Record<string, unknown>): Sm39State {
  const h = raw.h as Record<string, unknown>;
  return {
    probeChunksWritten: bigintFromItf(h.probeChunksWritten),
    configConfinementEnforced: Boolean(h.configConfinementEnforced),
    supervisorIsolationEnforced: Boolean(h.supervisorIsolationEnforced),
    probeFileConfinementEnforced: Boolean(h.probeFileConfinementEnforced),
    bootstrapTrustOrderEnforced: Boolean(h.bootstrapTrustOrderEnforced),
    configConfinementBreaches: bigintFromItf(h.configConfinementBreaches),
    supervisorIsolationBreaches: bigintFromItf(h.supervisorIsolationBreaches),
    probeFileBreaches: bigintFromItf(h.probeFileBreaches),
    bootstrapTrustBreaches: bigintFromItf(h.bootstrapTrustBreaches),
    cleanVerifiedOps: bigintFromItf(h.cleanVerifiedOps),
    stepCount: bigintFromItf(h.stepCount),
  };
}

describe('SM39 (ADV-L4): TUI Config, ASP Supervisor, Diagnostic Probe & Bootstrap Confinement', () => {
  test('500-trial ADV-L4 hostile fuzz refutes TUI config, ASP supervisor, probe & bootstrap bypasses', () => {
    const rand = makePrng(0x534d3339);
    const hostileCreds = ['PATH', 'HOME', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'SSH_AUTH_SOCK', 'GIT_ASKPASS', 'BAD KEY'];

    for (let trial = 0; trial < 500; trial++) {
      // 1. TUI config bounds & credential_env hygiene
      expect(validateTuiConfigEnvelope(false, 1024, 30, 'OPENAI_API_KEY')).toBe(false);
      expect(validateTuiConfigEnvelope(true, MAX_TUI_CONFIG_BYTES + 1, 30, 'OPENAI_API_KEY')).toBe(false);
      expect(validateTuiConfigEnvelope(true, 1024, 0, 'OPENAI_API_KEY')).toBe(false);
      expect(validateTuiConfigEnvelope(true, 1024, MAX_TUI_TIMEOUT_SECONDS + 1, 'OPENAI_API_KEY')).toBe(false);
      expect(validateTuiConfigEnvelope(true, 1024, 30, hostileCreds[trial % hostileCreds.length]!)).toBe(false);
      expect(validateTuiConfigEnvelope(true, 1024, 1 + (trial % MAX_TUI_TIMEOUT_SECONDS), 'ANTHROPIC_API_KEY')).toBe(true);

      // 2. Managed ASP gateway strict loopback endpoint validation
      const port = 1024 + Math.floor(rand() * 50_000);
      expect(validateManagedAspEndpoint(`http://127.0.0.1:${port}@evil.example`)).toBe(false);
      expect(validateManagedAspEndpoint(`http://127.0.0.1:${port}\r\nX-Injected: 1`)).toBe(false);
      expect(validateManagedAspEndpoint(`http://127.0.0.1:${port}/path`)).toBe(false);
      expect(validateManagedAspEndpoint('http://127.0.0.1:0')).toBe(false);
      expect(validateManagedAspEndpoint('http://169.254.169.254:80')).toBe(false);
      expect(validateManagedAspEndpoint(`http://127.0.0.1:${port}`)).toBe(true);
      expect(validateManagedAspEndpoint(`http://localhost:${port}`)).toBe(true);

      // 3. Runtime diagnostic probe O_NOFOLLOW & 4 MiB byte cap
      expect(admitRuntimeProbeWrite(false, 0, 32)).toBe(false);
      expect(admitRuntimeProbeWrite(true, MAX_RUNTIME_PROBE_BYTES, 1)).toBe(false);
      expect(admitRuntimeProbeWrite(true, trial * 32, 32)).toBe(true);

      // 4. Bootstrap executable-first non-symlink precedence
      expect(selectBootstrapPrefix('/repo/scheme/.gerbil', '/untrusted/scheme/.gerbil', true, true)).toBe('/repo/scheme/.gerbil');
      expect(selectBootstrapPrefix('/repo/scheme/.gerbil', '/untrusted/scheme/.gerbil', false, false)).toBeNull();
      expect(selectBootstrapPrefix(null, '/dev/scheme/.gerbil', false, true)).toBe('/dev/scheme/.gerbil');
    }
  });

  test('6 live Quint --mbt ITF traces refine SM39 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const qntPath = resolve(
      repoRoot,
      'packages/quint-models/threat/execution/tui-config-supervisor-probe-confinement/TuiConfigSupervisorProbeConfinement.qnt',
    );
    const resolverCli = resolve(repoRoot, 'packages/quint-modules-resolver/src/cli.ts');
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm39-mbt-'));
    try {
      for (let seed = 1; seed <= 6; seed++) {
        const itfPath = join(tmpDir, `sm39-seed-${seed}.itf.json`);
        execFileSync(
          'bun',
          [
            'run',
            resolverCli,
            'run',
            qntPath,
            '--main=execution_tui_config_supervisor_probe_confinement',
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
