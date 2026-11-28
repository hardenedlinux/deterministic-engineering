// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';

/**
 * SM23 Adversarial (ADV-L4) Outbound HTTP Redirect, SSRF & Credential Confinement
 *
 * Hostile Pressure Tier: ADV-L4 (MUST fail on default-redirect HTTP clients,
 * cleartext non-loopback Bearer emission, cross-origin/metadata DownloadURL SSRF,
 * URL userinfo/CRLF smuggling, and os.Stat symlink static HTTP file serving).
 *
 * Mirrors real production bugs caught in:
 * - marlin-agent-core/crates/marlin-agent-stream/src/openai_http.rs
 * - marlin-mygo/control/marketplace/{official_sync.go,registry.go}
 */

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const SM23_QNT = resolve(
  REPO_ROOT,
  'packages/quint-models/threat/protocol/outbound-http-redirect-ssrf-confinement/OutboundHttpRedirectSsrfConfinement.qnt',
);

interface HttpProbe {
  kind:
    | 'pinned-https'
    | 'redirect-3xx'
    | 'cleartext-remote-bearer'
    | 'ssrf-download-url'
    | 'userinfo-or-crlf'
    | 'symlink-static-serve';
  url: string;
  baseOrigin: string;
  hasBearerKey: boolean;
  redirectLocation?: string;
  isSymlinkFile?: boolean;
}

interface HttpBoundaryCounters {
  cleanAdmitted: number;
  hostileBlocked: number;
  redirectLeaks: number;
  schemeDowngrades: number;
  ssrfCrossOriginHits: number;
  userinfoSmuggles: number;
  symlinkServeLeaks: number;
}

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

function parseSafeUrl(raw: string): {ok: true; url: URL} | {ok: false; reason: string} {
  if (!raw || /[\s\x00-\x1f\x7f]/.test(raw)) {
    return {ok: false, reason: 'empty-or-control-chars'};
  }
  const u = URL.parse(raw);
  if (!u) {
    return {ok: false, reason: 'malformed-url'};
  }
  if (u.username !== '' || u.password !== '' || raw.includes('@')) {
    return {ok: false, reason: 'userinfo-forbidden'};
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    return {ok: false, reason: 'non-http-scheme'};
  }
  return {ok: true, url: u};
}

class HardenedOutboundHttpBoundary {
  readonly state: HttpBoundaryCounters = {
    cleanAdmitted: 0,
    hostileBlocked: 0,
    redirectLeaks: 0,
    schemeDowngrades: 0,
    ssrfCrossOriginHits: 0,
    userinfoSmuggles: 0,
    symlinkServeLeaks: 0,
  };

  handle(probe: HttpProbe): 'admitted' | 'blocked' {
    if (probe.kind === 'symlink-static-serve') {
      if (probe.isSymlinkFile) {
        this.state.hostileBlocked += 1;
        return 'blocked';
      }
      this.state.cleanAdmitted += 1;
      return 'admitted';
    }

    const parsedRes = parseSafeUrl(probe.url);
    if (!parsedRes.ok) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    const parsed = parsedRes.url;

    if (probe.hasBearerKey && parsed.protocol === 'http:' && !isLoopbackHost(parsed.hostname)) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }

    if (probe.kind === 'ssrf-download-url') {
      const baseRes = parseSafeUrl(probe.baseOrigin);
      if (!baseRes.ok) {
        this.state.hostileBlocked += 1;
        return 'blocked';
      }
      const base = baseRes.url;
      const downgraded = base.protocol === 'https:' && parsed.protocol !== 'https:';
      const crossOrigin = parsed.origin !== base.origin;
      if (downgraded || crossOrigin) {
        this.state.hostileBlocked += 1;
        return 'blocked';
      }
    }

    if (probe.redirectLocation) {
      // Fail-closed no-redirect policy: NEVER follow 301/302/307/308 redirects.
      this.state.hostileBlocked += 1;
      return 'blocked';
    }

    this.state.cleanAdmitted += 1;
    return 'admitted';
  }
}

class DefectiveOutboundHttpBoundary {
  readonly state: HttpBoundaryCounters = {
    cleanAdmitted: 0,
    hostileBlocked: 0,
    redirectLeaks: 0,
    schemeDowngrades: 0,
    ssrfCrossOriginHits: 0,
    userinfoSmuggles: 0,
    symlinkServeLeaks: 0,
  };

  handle(probe: HttpProbe): 'admitted' | 'blocked' {
    if (probe.kind === 'symlink-static-serve' && probe.isSymlinkFile) {
      this.state.symlinkServeLeaks += 1;
      return 'admitted';
    }
    if (probe.kind === 'userinfo-or-crlf') {
      this.state.userinfoSmuggles += 1;
      return 'admitted';
    }
    if (probe.kind === 'cleartext-remote-bearer') {
      this.state.schemeDowngrades += 1;
      return 'admitted';
    }
    if (probe.kind === 'ssrf-download-url') {
      this.state.ssrfCrossOriginHits += 1;
      return 'admitted';
    }
    if (probe.redirectLocation) {
      this.state.redirectLeaks += 1;
      return 'admitted';
    }
    this.state.cleanAdmitted += 1;
    return 'admitted';
  }
}

function makeRng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

function generateAdvL4Probe(rng: () => number, idx: number): HttpProbe {
  const roll = Math.floor(rng() * 6);
  const baseOrigin = 'https://marketplace.example.com';
  switch (roll) {
    case 0:
      return {
        kind: 'pinned-https',
        url: `https://api.openai.com/v1/chat/completions?req=${idx}`,
        baseOrigin,
        hasBearerKey: true,
      };
    case 1:
      return {
        kind: 'redirect-3xx',
        url: `https://api.example.com/v1/chat/completions`,
        baseOrigin,
        hasBearerKey: true,
        redirectLocation: idx % 2 === 0 ? 'http://169.254.169.254/latest/meta-data/' : 'http://127.0.0.1:9999/admin',
      };
    case 2:
      return {
        kind: 'cleartext-remote-bearer',
        url: `http://api.untrusted-proxy-${idx}.example.com/v1/chat/completions`,
        baseOrigin,
        hasBearerKey: true,
      };
    case 3:
      return {
        kind: 'ssrf-download-url',
        url: idx % 2 === 0 ? 'http://169.254.169.254/latest/meta-data/iam' : 'http://127.0.0.1:8080/internal.marlinpkg',
        baseOrigin,
        hasBearerKey: false,
      };
    case 4:
      return {
        kind: 'userinfo-or-crlf',
        url: idx % 2 === 0 ? 'https://api.openai.com@evil.attacker.example/v1' : 'https://api.openai.com/v1\r\nX-Injected: 1',
        baseOrigin,
        hasBearerKey: true,
      };
    default:
      return {
        kind: 'symlink-static-serve',
        url: `${baseOrigin}/evil-${idx}.marlinpkg`,
        baseOrigin,
        hasBearerKey: false,
        isSymlinkFile: true,
      };
  }
}

interface ItfBigInt {
  '#bigint': string;
}

function itfInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number((v as ItfBigInt)['#bigint']);
  }
  throw new Error(`Unexpected ITF int: ${JSON.stringify(v)}`);
}

describe('SM23 Adversarial (ADV-L4) Outbound HTTP Redirect, SSRF & Credential Confinement Fuzz + ITF MBT', () => {
  test('ADV-L4: 500 hostile HTTP attack trials (3xx redirect SSRF, cleartext Bearer, DownloadURL SSRF, userinfo/CRLF, symlink serve) — hardened 0 escapes vs defective leaks', () => {
    const rng = makeRng(0x5a23_4d04);
    const hardened = new HardenedOutboundHttpBoundary();
    const defective = new DefectiveOutboundHttpBoundary();

    for (let i = 0; i < 500; i += 1) {
      const probe = generateAdvL4Probe(rng, i);
      const hDecision = hardened.handle(probe);
      defective.handle(probe);

      if (probe.kind === 'pinned-https') {
        expect(hDecision).toBe('admitted');
      } else {
        expect(hDecision).toBe('blocked');
      }
    }

    expect(hardened.state.cleanAdmitted).toBeGreaterThan(40);
    expect(hardened.state.hostileBlocked).toBeGreaterThan(350);
    expect(hardened.state.redirectLeaks).toBe(0);
    expect(hardened.state.schemeDowngrades).toBe(0);
    expect(hardened.state.ssrfCrossOriginHits).toBe(0);
    expect(hardened.state.userinfoSmuggles).toBe(0);
    expect(hardened.state.symlinkServeLeaks).toBe(0);

    // Defective baseline MUST fail on every ADV-L4 vector (proving non-gentle pressure!).
    expect(defective.state.redirectLeaks).toBeGreaterThan(40);
    expect(defective.state.schemeDowngrades).toBeGreaterThan(40);
    expect(defective.state.ssrfCrossOriginHits).toBeGreaterThan(40);
    expect(defective.state.userinfoSmuggles).toBeGreaterThan(40);
    expect(defective.state.symlinkServeLeaks).toBeGreaterThan(40);
  });

  test('ADV-L4: Live Quint ITF MBT Replay for 101st Formal Model SM23 OutboundHttpRedirectSsrfConfinement (6 live traces, 100% parity)', () => {
    const fs = require('node:fs') as typeof import('node:fs');
    const outDir = `/tmp/sm23-itf-${process.pid}-${Date.now()}`;
    fs.mkdirSync(outDir, {recursive: true});
    const res = spawnSync(
      'quint',
      [
        'run',
        SM23_QNT,
        '--main=protocol_outbound_http_redirect_ssrf_confinement',
        '--mbt',
        '--max-samples=6',
        '--n-traces=6',
        '--max-steps=12',
        `--out-itf=${outDir}/trace.itf.json`,
      ],
      {encoding: 'utf8', timeout: 60_000},
    );
    expect(res.status, `quint run --mbt failed:\n${res.stdout}\n${res.stderr}`).toBe(0);

    const files = fs
      .readdirSync(outDir)
      .filter((f) => f.endsWith('.itf.json'))
      .sort();
    expect(files.length).toBeGreaterThanOrEqual(6);

    let totalTransitions = 0;
    for (const file of files) {
      const trace = JSON.parse(fs.readFileSync(resolve(outDir, file), 'utf8')) as {
        states: Array<{
          'mbt::actionTaken'?: string;
          h: Record<string, unknown>;
        }>;
      };
      const sut = new HardenedOutboundHttpBoundary();
      for (let i = 1; i < trace.states.length; i += 1) {
        const st = trace.states[i]!;
        const action = st['mbt::actionTaken'] ?? '';
        switch (action) {
          case 'admitPinnedHttpsRequest':
            sut.handle({
              kind: 'pinned-https',
              url: 'https://api.openai.com/v1/chat/completions',
              baseOrigin: 'https://api.openai.com',
              hasBearerKey: true,
            });
            break;
          case 'blockRedirectEscape':
            sut.handle({
              kind: 'redirect-3xx',
              url: 'https://api.openai.com/v1/chat/completions',
              baseOrigin: 'https://api.openai.com',
              hasBearerKey: true,
              redirectLocation: 'http://169.254.169.254/latest/meta-data/',
            });
            break;
          case 'blockSchemeDowngrade':
            sut.handle({
              kind: 'cleartext-remote-bearer',
              url: 'http://api.evil.example/v1/chat/completions',
              baseOrigin: 'https://api.openai.com',
              hasBearerKey: true,
            });
            break;
          case 'blockSsrfDownloadUrl':
            sut.handle({
              kind: 'ssrf-download-url',
              url: 'http://127.0.0.1:9999/secret.marlinpkg',
              baseOrigin: 'https://marketplace.example.com',
              hasBearerKey: false,
            });
            break;
          case 'blockUserinfoOrControlUrl':
            sut.handle({
              kind: 'userinfo-or-crlf',
              url: 'https://api.openai.com@evil.example/v1',
              baseOrigin: 'https://api.openai.com',
              hasBearerKey: true,
            });
            break;
          case 'blockSymlinkHttpServe':
            sut.handle({
              kind: 'symlink-static-serve',
              url: 'https://marketplace.example.com/evil.marlinpkg',
              baseOrigin: 'https://marketplace.example.com',
              hasBearerKey: false,
              isSymlinkFile: true,
            });
            break;
          default:
            throw new Error(`Unexpected SM23 MBT action: ${action}`);
        }
        totalTransitions += 1;
        expect(sut.state.cleanAdmitted).toBe(itfInt(st.h.cleanAdmitted));
        expect(sut.state.hostileBlocked).toBe(itfInt(st.h.hostileBlocked));
        expect(sut.state.redirectLeaks).toBe(itfInt(st.h.redirectLeaks));
        expect(sut.state.schemeDowngrades).toBe(itfInt(st.h.schemeDowngrades));
        expect(sut.state.ssrfCrossOriginHits).toBe(itfInt(st.h.ssrfCrossOriginHits));
        expect(sut.state.userinfoSmuggles).toBe(itfInt(st.h.userinfoSmuggles));
        expect(sut.state.symlinkServeLeaks).toBe(itfInt(st.h.symlinkServeLeaks));
      }
    }
    expect(totalTransitions).toBeGreaterThanOrEqual(6);
    fs.rmSync(outDir, {recursive: true, force: true});
  });
});
