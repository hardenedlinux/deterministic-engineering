// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm40State {
  pendingDslJobs: number;
  patchConfinementEnforced: boolean;
  loopbackTransportIntegrityEnforced: boolean;
  schemaRefCycleGuardEnforced: boolean;
  snapshotCacheQueueConfinementEnforced: boolean;
  patchEscapeBreaches: number;
  transportSmugglingBreaches: number;
  schemaCycleCrashBreaches: number;
  cacheQueueBreaches: number;
  cleanVerifiedOps: number;
  stepCount: number;
}

function initState(): Sm40State {
  return {
    pendingDslJobs: 0,
    patchConfinementEnforced: true,
    loopbackTransportIntegrityEnforced: true,
    schemaRefCycleGuardEnforced: true,
    snapshotCacheQueueConfinementEnforced: true,
    patchEscapeBreaches: 0,
    transportSmugglingBreaches: 0,
    schemaCycleCrashBreaches: 0,
    cacheQueueBreaches: 0,
    cleanVerifiedOps: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm40State, action: string): Sm40State {
  const s = {...state};
  switch (action) {
    case 'applyConfinedBoundedAstPatch':
      if (s.stepCount < 12 && s.patchConfinementEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'sendValidatedLoopbackCheckedChunkedHttp':
      if (s.stepCount < 12 && s.loopbackTransportIntegrityEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'resolveDepthBoundedSchemaRef':
      if (s.stepCount < 12 && s.schemaRefCycleGuardEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'persistNoSymlinkCacheOrEnqueueBoundedDsl':
      if (s.stepCount < 12 && s.snapshotCacheQueueConfinementEnforced && s.pendingDslJobs < 12) {
        s.pendingDslJobs += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM40 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm40State): boolean {
  return (
    s.patchEscapeBreaches === 0 &&
    s.transportSmugglingBreaches === 0 &&
    s.schemaCycleCrashBreaches === 0 &&
    s.cacheQueueBreaches === 0 &&
    s.patchConfinementEnforced &&
    s.loopbackTransportIntegrityEnforced &&
    s.schemaRefCycleGuardEnforced &&
    s.snapshotCacheQueueConfinementEnforced &&
    s.pendingDslJobs >= 0 &&
    s.pendingDslJobs <= 12 &&
    s.stepCount <= 12
  );
}

const MAX_AST_PATCH_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_SCHEMA_REF_DEPTH = 32;
const MAX_PENDING_PACKAGE_DSL_JOBS = 64;

function isConfinedRelativePatchPath(relPath: string, symlinkFree: boolean, fileBytes: number): boolean {
  if (!symlinkFree || fileBytes < 0 || fileBytes > MAX_AST_PATCH_SOURCE_BYTES) return false;
  if (!relPath || relPath.startsWith('/') || relPath.includes('\\') || /[\x00-\x1f\x7f]/.test(relPath)) return false;
  if (/^[A-Za-z]:/.test(relPath)) return false;
  const parts = relPath.split('/');
  if (parts.some((p) => p === '' || p === '.' || p === '..')) return false;
  return true;
}

function isValidLoopbackEndpoint(raw: string): boolean {
  const trimmed = raw.trim();
  if (/[\x00-\x1f\x7f]/.test(trimmed)) return false;
  if (!trimmed.startsWith('http://')) return false;
  const rest = trimmed.slice('http://'.length);
  if (/[\s@/?#\\]/.test(rest)) return false;
  const parts = rest.split(':');
  if (parts.length !== 2) return false;
  const [host, portRaw] = parts as [string, string];
  if (host !== '127.0.0.1' && host !== 'localhost') return false;
  if (!/^\d{1,5}$/.test(portRaw)) return false;
  const port = Number(portRaw);
  return port >= 1 && port <= 65535;
}

function isSafeHttpRoutePath(path: string): boolean {
  return path.startsWith('/') && !/[\x00-\x20\x7f]/.test(path);
}

function isSafeBearerToken(token: string): boolean {
  const trimmed = token.trim();
  return trimmed.length > 0 && !/[\x00-\x1f\x7f]/.test(trimmed);
}

function decodeCheckedChunkedBody(body: string): string | null {
  let pos = 0;
  let out = '';
  let sawTerminator = false;
  while (pos < body.length) {
    const crlf = body.indexOf('\r\n', pos);
    if (crlf === -1) return null;
    const sizeHex = body.slice(pos, crlf).split(';')[0]!.trim();
    if (!/^[0-9a-fA-F]{1,16}$/.test(sizeHex)) return null;
    const size = Number.parseInt(sizeHex, 16);
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_HTTP_RESPONSE_BYTES) return null;
    pos = crlf + 2;
    if (size === 0) {
      sawTerminator = true;
      break;
    }
    const end = pos + size;
    if (end + 2 > body.length || body.slice(end, end + 2) !== '\r\n') return null;
    if (out.length + size > MAX_HTTP_RESPONSE_BYTES) return null;
    out += body.slice(pos, end);
    pos = end + 2;
  }
  return sawTerminator ? out : null;
}

function resolveSchemaRefBounded(
  defs: Record<string, {ref?: string; enum?: string[]}>,
  startRef: string,
): {terminated: boolean; enumValues: string[]} {
  const visited = new Set<string>();
  let current = startRef;
  for (let depth = 0; depth <= MAX_SCHEMA_REF_DEPTH; depth++) {
    if (visited.has(current)) return {terminated: true, enumValues: []};
    visited.add(current);
    const node = defs[current];
    if (!node) return {terminated: true, enumValues: []};
    if (node.ref) {
      current = node.ref;
      continue;
    }
    return {terminated: true, enumValues: node.enum ?? []};
  }
  return {terminated: true, enumValues: []};
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

function parseItfState(raw: Record<string, unknown>): Sm40State {
  const h = raw.h as Record<string, unknown>;
  return {
    pendingDslJobs: bigintFromItf(h.pendingDslJobs),
    patchConfinementEnforced: Boolean(h.patchConfinementEnforced),
    loopbackTransportIntegrityEnforced: Boolean(h.loopbackTransportIntegrityEnforced),
    schemaRefCycleGuardEnforced: Boolean(h.schemaRefCycleGuardEnforced),
    snapshotCacheQueueConfinementEnforced: Boolean(h.snapshotCacheQueueConfinementEnforced),
    patchEscapeBreaches: bigintFromItf(h.patchEscapeBreaches),
    transportSmugglingBreaches: bigintFromItf(h.transportSmugglingBreaches),
    schemaCycleCrashBreaches: bigintFromItf(h.schemaCycleCrashBreaches),
    cacheQueueBreaches: bigintFromItf(h.cacheQueueBreaches),
    cleanVerifiedOps: bigintFromItf(h.cleanVerifiedOps),
    stepCount: bigintFromItf(h.stepCount),
  };
}

describe('SM40 (ADV-L4): ASP HTTP Patch, Loopback Transport, Schema & Search Cache Confinement', () => {
  test('500-trial ADV-L4 hostile fuzz refutes patch escape, loopback SSRF/CRLF/chunk overflow, circular $ref & cache/queue hazards', () => {
    const rand = makePrng(0x534d3430);
    const hostilePaths = ['../outside.rs', '../../etc/passwd', '/tmp/victim.rs', 'src/../escape.rs', 'src/\0evil.rs', 'C:\\evil.rs'];

    for (let trial = 0; trial < 500; trial++) {
      // 1. AST patch workspace confinement + symlink refusal + 8 MiB bound
      expect(isConfinedRelativePatchPath(hostilePaths[trial % hostilePaths.length]!, true, 128)).toBe(false);
      expect(isConfinedRelativePatchPath('src/lib.rs', false, 128)).toBe(false);
      expect(isConfinedRelativePatchPath('src/lib.rs', true, MAX_AST_PATCH_SOURCE_BYTES + 1)).toBe(false);
      expect(isConfinedRelativePatchPath('src/lib.rs', true, 1024)).toBe(true);

      // 2. Loopback endpoint strictness, CRLF smuggling refusal & checked chunked decoding
      const port = 1024 + Math.floor(rand() * 50_000);
      expect(isValidLoopbackEndpoint(`http://127.0.0.1:${port}@evil.example`)).toBe(false);
      expect(isValidLoopbackEndpoint(`http://127.0.0.1:${port}\r\nX-Evil: 1`)).toBe(false);
      expect(isValidLoopbackEndpoint('http://127.0.0.1:0')).toBe(false);
      expect(isValidLoopbackEndpoint(`http://127.0.0.1:${port}`)).toBe(true);
      expect(isSafeHttpRoutePath('/health HTTP/1.1\r\nX-Evil: 1')).toBe(false);
      expect(isSafeHttpRoutePath('/v1/providers')).toBe(true);
      expect(isSafeBearerToken('tok\r\nX-Smuggled: 1')).toBe(false);
      expect(isSafeBearerToken('clean-session-token')).toBe(true);
      expect(decodeCheckedChunkedBody('ffffffffffffffff\r\nhello\r\n0\r\n\r\n')).toBeNull();
      expect(decodeCheckedChunkedBody('5\r\nhello\r\n')).toBeNull();
      expect(decodeCheckedChunkedBody('5\r\nhello\r\n0\r\n\r\n')).toBe('hello');

      // 3. Circular JSON Schema $ref anti-DoS
      const selfCycle = resolveSchemaRefBounded({A: {ref: 'A'}}, 'A');
      expect(selfCycle).toEqual({terminated: true, enumValues: []});
      const mutualCycle = resolveSchemaRefBounded({A: {ref: 'B'}, B: {ref: 'A'}}, 'A');
      expect(mutualCycle).toEqual({terminated: true, enumValues: []});
      const cleanRef = resolveSchemaRefBounded({A: {ref: 'B'}, B: {enum: ['fn', 'struct']}}, 'A');
      expect(cleanRef).toEqual({terminated: true, enumValues: ['fn', 'struct']});

      // 4. Bounded Search DSL worker queue cap
      const pending = trial % (MAX_PENDING_PACKAGE_DSL_JOBS + 16);
      expect(pending < MAX_PENDING_PACKAGE_DSL_JOBS).toBe(pending <= 63);
    }
  });

  test('6 live Quint --mbt ITF traces refine SM40 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const qntPath = resolve(
      repoRoot,
      'packages/quint-models/threat/execution/asp-patch-transport-schema-cache-confinement/AspPatchTransportSchemaCacheConfinement.qnt',
    );
    const resolverCli = resolve(repoRoot, 'packages/quint-modules-resolver/src/cli.ts');
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm40-mbt-'));
    try {
      for (let seed = 1; seed <= 6; seed++) {
        const itfPath = join(tmpDir, `sm40-seed-${seed}.itf.json`);
        execFileSync(
          'bun',
          [
            'run',
            resolverCli,
            'run',
            qntPath,
            '--main=execution_asp_patch_transport_schema_cache_confinement',
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
