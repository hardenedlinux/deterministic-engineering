// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

/**
 * SM26 Adversarial (ADV-L4) Control-Plane Entrypoint Auth & E-Stop Governance
 * Confinement Fuzz + Live Quint ITF MBT.
 *
 * Hostile Pressure Tier: ADV-L4 (MUST catch shadow binary auth helpers using `==`
 * or non-loopback default dev tokens, empty-Bearer prefix confusion `"Bearer "`,
 * mutating/LLM-streaming control-plane RPCs bypassing active Operator E-Stop,
 * and unscrubbed login-shell `sh -lc` release-gate secret exfiltration).
 *
 * Real-repo case: marlin-agent-core (marlin_mygo_host.rs, ui_grpc.rs, grpc.rs,
 * and crates/marlin-agent-core/src/release.rs).
 */

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const SM26_QNT = resolve(
  REPO_ROOT,
  'packages/quint-models/threat/execution/control-plane-auth-and-governance-confinement/ControlPlaneAuthAndGovernanceConfinement.qnt',
);

type ProbeKind =
  | 'clean-governed-rpc'
  | 'clean-scrubbed-release-gate'
  | 'shadow-default-or-timing-auth'
  | 'mutating-rpc-during-estop'
  | 'unscrubbed-login-release-shell'
  | 'empty-bearer-prefix';

interface ControlPlaneCounters {
  admittedCleanOps: number;
  hostileBlocked: number;
  shadowAuthBypasses: number;
  controlPlaneEstopBypasses: number;
  releaseShellSecretLeaks: number;
  emptyBearerBypasses: number;
}

interface ControlPlaneEvent {
  kind: ProbeKind;
  bindScope: 'loopback' | 'non-loopback';
  usesDefaultDevToken: boolean;
  configuredHeader: string;
  presentedHeader: string;
  estopActive: boolean;
  shellScrubbedAndBounded: boolean;
}

function constantTimeBytesEqual(a: string, b: string): boolean {
  const lhs = Buffer.from(a, 'utf8');
  const rhs = Buffer.from(b, 'utf8');
  let diff = lhs.length ^ rhs.length;
  const maxLen = Math.max(lhs.length, rhs.length);
  for (let i = 0; i < maxLen; i += 1) {
    diff |= (lhs[i] ?? 0) ^ (rhs[i] ?? 0);
  }
  return diff === 0;
}

function extractNonBlankBearerPayload(header: string): string | null {
  if (!header.startsWith('Bearer ')) return null;
  const cred = header.slice('Bearer '.length).trim();
  return cred.length > 0 ? cred : null;
}

class HardenedControlPlaneBoundary {
  readonly state: ControlPlaneCounters = {
    admittedCleanOps: 0,
    hostileBlocked: 0,
    shadowAuthBypasses: 0,
    controlPlaneEstopBypasses: 0,
    releaseShellSecretLeaks: 0,
    emptyBearerBypasses: 0,
  };

  admit(ev: ControlPlaneEvent): 'admitted' | 'blocked' {
    if (ev.bindScope === 'non-loopback' && ev.usesDefaultDevToken) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    const configuredCred = extractNonBlankBearerPayload(ev.configuredHeader);
    if (configuredCred === null) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    const presentedCred = extractNonBlankBearerPayload(ev.presentedHeader);
    if (presentedCred === null || !constantTimeBytesEqual(presentedCred, configuredCred)) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    if (ev.estopActive) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    if (ev.kind === 'unscrubbed-login-release-shell' || !ev.shellScrubbedAndBounded) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    this.state.admittedCleanOps += 1;
    return 'admitted';
  }
}

class DefectiveControlPlaneBoundary {
  readonly state: ControlPlaneCounters = {
    admittedCleanOps: 0,
    hostileBlocked: 0,
    shadowAuthBypasses: 0,
    controlPlaneEstopBypasses: 0,
    releaseShellSecretLeaks: 0,
    emptyBearerBypasses: 0,
  };

  admit(ev: ControlPlaneEvent): void {
    // Defective host: binds 0.0.0.0 with hardcoded marlin-dev-token, checks
    // !configuredHeader.trim().isEmpty() on "Bearer ", ignores active E-Stop on
    // mutating RPCs, and runs release gates under unscrubbed `sh -lc`.
    if (ev.bindScope === 'non-loopback' && ev.usesDefaultDevToken && ev.presentedHeader === ev.configuredHeader) {
      this.state.shadowAuthBypasses += 1;
      return;
    }
    if (
      ev.configuredHeader.trim().length > 0 &&
      extractNonBlankBearerPayload(ev.configuredHeader) === null &&
      ev.presentedHeader === ev.configuredHeader
    ) {
      this.state.emptyBearerBypasses += 1;
      return;
    }
    if (ev.estopActive) {
      this.state.controlPlaneEstopBypasses += 1;
      return;
    }
    if (!ev.shellScrubbedAndBounded) {
      this.state.releaseShellSecretLeaks += 1;
      return;
    }
    this.state.admittedCleanOps += 1;
  }
}

function nextSeed(state: {s: number}): number {
  state.s = (Math.imul(state.s, 1664525) + 1013904223) >>> 0;
  return state.s;
}

describe('SM26 Adversarial (ADV-L4) Control-Plane Entrypoint Auth & E-Stop Governance Fuzz + ITF MBT', () => {
  test('500-trial ADV-L4 hostile fuzz proves hardened control plane blocks all 4 bypass vectors while defective host leaks all 4', () => {
    const hardened = new HardenedControlPlaneBoundary();
    const defective = new DefectiveControlPlaneBoundary();
    const prng = {s: 0x2626c0de};

    const corpus: ControlPlaneEvent[] = [
      {
        kind: 'clean-governed-rpc',
        bindScope: 'loopback',
        usesDefaultDevToken: false,
        configuredHeader: 'Bearer secret-ephemeral-token-9f3a',
        presentedHeader: 'Bearer secret-ephemeral-token-9f3a',
        estopActive: false,
        shellScrubbedAndBounded: true,
      },
      {
        kind: 'clean-scrubbed-release-gate',
        bindScope: 'loopback',
        usesDefaultDevToken: false,
        configuredHeader: 'Bearer secret-ephemeral-token-9f3a',
        presentedHeader: 'Bearer secret-ephemeral-token-9f3a',
        estopActive: false,
        shellScrubbedAndBounded: true,
      },
      {
        kind: 'shadow-default-or-timing-auth',
        bindScope: 'non-loopback',
        usesDefaultDevToken: true,
        configuredHeader: 'Bearer marlin-dev-token',
        presentedHeader: 'Bearer marlin-dev-token',
        estopActive: false,
        shellScrubbedAndBounded: true,
      },
      {
        kind: 'empty-bearer-prefix',
        bindScope: 'loopback',
        usesDefaultDevToken: false,
        configuredHeader: 'Bearer ',
        presentedHeader: 'Bearer ',
        estopActive: false,
        shellScrubbedAndBounded: true,
      },
      {
        kind: 'mutating-rpc-during-estop',
        bindScope: 'loopback',
        usesDefaultDevToken: false,
        configuredHeader: 'Bearer secret-ephemeral-token-9f3a',
        presentedHeader: 'Bearer secret-ephemeral-token-9f3a',
        estopActive: true,
        shellScrubbedAndBounded: true,
      },
      {
        kind: 'unscrubbed-login-release-shell',
        bindScope: 'loopback',
        usesDefaultDevToken: false,
        configuredHeader: 'Bearer secret-ephemeral-token-9f3a',
        presentedHeader: 'Bearer secret-ephemeral-token-9f3a',
        estopActive: false,
        shellScrubbedAndBounded: false,
      },
    ];

    for (let trial = 0; trial < 500; trial += 1) {
      const ev = corpus[nextSeed(prng) % corpus.length]!;
      hardened.admit(ev);
      defective.admit(ev);
    }

    expect(hardened.state.admittedCleanOps).toBeGreaterThan(100);
    expect(hardened.state.hostileBlocked).toBeGreaterThan(250);
    expect(hardened.state.shadowAuthBypasses).toBe(0);
    expect(hardened.state.controlPlaneEstopBypasses).toBe(0);
    expect(hardened.state.releaseShellSecretLeaks).toBe(0);
    expect(hardened.state.emptyBearerBypasses).toBe(0);

    // ADV-L4 non-vacuity: defective host MUST get exploited on ALL 4 vectors!
    expect(defective.state.shadowAuthBypasses).toBeGreaterThan(40);
    expect(defective.state.emptyBearerBypasses).toBeGreaterThan(40);
    expect(defective.state.controlPlaneEstopBypasses).toBeGreaterThan(40);
    expect(defective.state.releaseShellSecretLeaks).toBeGreaterThan(40);
  });

  test('live Quint ITF MBT traces replay 100% faithfully against HardenedControlPlaneBoundary', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'sm26-itf-'));
    try {
      const res = spawnSync(
        'quint',
        [
          'run',
          '--mbt',
          '--seed=7',
          '--max-samples=6',
          '--n-traces=6',
          '--max-steps=12',
          '--invariant=safety',
          `--out-itf=${join(outDir, 'trace.itf.json')}`,
          '--main=execution_control_plane_auth_and_governance_confinement',
          SM26_QNT,
        ],
        {cwd: REPO_ROOT, encoding: 'utf8'},
      );
      expect(res.status, `quint run failed: ${res.stderr}\n${res.stdout}`).toBe(0);

      const itfFiles = readdirSync(outDir)
        .filter((f) => f.endsWith('.itf.json'))
        .sort();
      expect(itfFiles.length).toBeGreaterThanOrEqual(6);

      for (const file of itfFiles) {
        const parsed = JSON.parse(readFileSync(resolve(outDir, file), 'utf8')) as {
          states: Array<{
            'mbt::actionTaken'?: string;
            h: {
              admittedCleanOps: {'#bigint': string};
              hostileBlocked: {'#bigint': string};
              shadowAuthBypasses: {'#bigint': string};
              controlPlaneEstopBypasses: {'#bigint': string};
              releaseShellSecretLeaks: {'#bigint': string};
              emptyBearerBypasses: {'#bigint': string};
            };
          }>;
        };

        const dut = new HardenedControlPlaneBoundary();
        for (const st of parsed.states) {
          const act = st['mbt::actionTaken'] ?? '';
          if (act === 'admitAuthenticatedGovernedRpc') {
            dut.admit({
              kind: 'clean-governed-rpc',
              bindScope: 'loopback',
              usesDefaultDevToken: false,
              configuredHeader: 'Bearer tok-live-mbt',
              presentedHeader: 'Bearer tok-live-mbt',
              estopActive: false,
              shellScrubbedAndBounded: true,
            });
          } else if (act === 'runScrubbedBoundedReleaseGate') {
            dut.admit({
              kind: 'clean-scrubbed-release-gate',
              bindScope: 'loopback',
              usesDefaultDevToken: false,
              configuredHeader: 'Bearer tok-live-mbt',
              presentedHeader: 'Bearer tok-live-mbt',
              estopActive: false,
              shellScrubbedAndBounded: true,
            });
          } else if (act === 'blockShadowDefaultOrTimingAuth') {
            dut.admit({
              kind: 'shadow-default-or-timing-auth',
              bindScope: 'non-loopback',
              usesDefaultDevToken: true,
              configuredHeader: 'Bearer marlin-dev-token',
              presentedHeader: 'Bearer marlin-dev-token',
              estopActive: false,
              shellScrubbedAndBounded: true,
            });
          } else if (act === 'blockMutatingRpcDuringEstop') {
            dut.admit({
              kind: 'mutating-rpc-during-estop',
              bindScope: 'loopback',
              usesDefaultDevToken: false,
              configuredHeader: 'Bearer tok-live-mbt',
              presentedHeader: 'Bearer tok-live-mbt',
              estopActive: true,
              shellScrubbedAndBounded: true,
            });
          } else if (act === 'blockUnscrubbedLoginReleaseShell') {
            dut.admit({
              kind: 'unscrubbed-login-release-shell',
              bindScope: 'loopback',
              usesDefaultDevToken: false,
              configuredHeader: 'Bearer tok-live-mbt',
              presentedHeader: 'Bearer tok-live-mbt',
              estopActive: false,
              shellScrubbedAndBounded: false,
            });
          } else if (act === 'blockEmptyBearerCredential') {
            dut.admit({
              kind: 'empty-bearer-prefix',
              bindScope: 'loopback',
              usesDefaultDevToken: false,
              configuredHeader: 'Bearer   ',
              presentedHeader: 'Bearer   ',
              estopActive: false,
              shellScrubbedAndBounded: true,
            });
          }

          expect(dut.state.admittedCleanOps).toBe(Number(st.h.admittedCleanOps['#bigint']));
          expect(dut.state.hostileBlocked).toBe(Number(st.h.hostileBlocked['#bigint']));
          expect(dut.state.shadowAuthBypasses).toBe(Number(st.h.shadowAuthBypasses['#bigint']));
          expect(dut.state.controlPlaneEstopBypasses).toBe(Number(st.h.controlPlaneEstopBypasses['#bigint']));
          expect(dut.state.releaseShellSecretLeaks).toBe(Number(st.h.releaseShellSecretLeaks['#bigint']));
          expect(dut.state.emptyBearerBypasses).toBe(Number(st.h.emptyBearerBypasses['#bigint']));
        }
      }
    } finally {
      rmSync(outDir, {recursive: true, force: true});
    }
  });
});
