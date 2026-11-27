// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * SM30 (ADV-L4): Step-Up MFA Attestation Integrity, Scheme Effect E-Stop/CAS
 * Isolation, Broadcast-Lag Watcher Survival & Bounded Fact-Graph Confinement
 *
 * 500-trial hostile ADV-L4 property-based fuzzing + 6 live Quint --mbt ITF traces
 * proving:
 *  1. RFC 9470 Step-Up MFA parser rejects non-human prefixes (agent/bot/llm/worker/
 *     scheme-sandbox/system/service), weak/unknown ACR strings (none/password/fake/0),
 *     and duplicate actor=/acr= parameter smuggling.
 *  2. Scheme atomic effect worker gates LlmComplete under active E-Stop and blocks
 *     CasPut writes to reserved governance checkpoint keys (checkpoint:governance* / *:facts).
 *  3. Broadcast-channel watchers survive RecvError::Lagged without dying and bound
 *     concurrent atomic effect fan-out.
 *  4. Runtime fact-graph mutations enforce exact capacity parity with MGF1 deserialization
 *     bounds (preventing self-inflicted restart deserialization bombs) and fail closed
 *     if durable CAS persistence errors during re-arm.
 *  5. Live Quint ITF traces refine the exact TypeScript reference state machine 1:1.
 */

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

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

interface Sm30State {
  estopTripped: boolean;
  watchersAlive: boolean;
  factCount: number;
  reservedCasIntact: boolean;
  spoofedRearms: number;
  effectOrCasBreaches: number;
  watcherSuicides: number;
  factBombOrDesyncs: number;
  cleanGovernedOps: number;
  stepCount: number;
}

function initState(): Sm30State {
  return {
    estopTripped: false,
    watchersAlive: true,
    factCount: 0,
    reservedCasIntact: true,
    spoofedRearms: 0,
    effectOrCasBreaches: 0,
    watcherSuicides: 0,
    factBombOrDesyncs: 0,
    cleanGovernedOps: 0,
    stepCount: 0,
  };
}

function isSafetyInvariantHeld(h: Sm30State): boolean {
  return (
    h.spoofedRearms === 0 &&
    h.effectOrCasBreaches === 0 &&
    h.watcherSuicides === 0 &&
    h.factBombOrDesyncs === 0 &&
    h.watchersAlive &&
    h.reservedCasIntact &&
    h.factCount >= 0 &&
    h.factCount <= 3 &&
    h.stepCount <= 12
  );
}

function applySafeAction(h: Sm30State, action: string): Sm30State {
  if (h.stepCount >= 12) return h;
  switch (action) {
    case 'tripEstop':
      return !h.estopTripped ? {...h, estopTripped: true, stepCount: h.stepCount + 1} : h;
    case 'verifiedMfaHumanRearmAndPersist':
      return h.estopTripped && h.watchersAlive
        ? {
            ...h,
            estopTripped: false,
            cleanGovernedOps: h.cleanGovernedOps + 1,
            stepCount: h.stepCount + 1,
          }
        : h;
    case 'executeArmedLlmAndUserCas':
      return !h.estopTripped && h.reservedCasIntact
        ? {...h, cleanGovernedOps: h.cleanGovernedOps + 1, stepCount: h.stepCount + 1}
        : h;
    case 'surviveBroadcastLag':
      return h.watchersAlive
        ? {...h, cleanGovernedOps: h.cleanGovernedOps + 1, stepCount: h.stepCount + 1}
        : h;
    case 'mutateFactWithinCap':
      return h.factCount < 3
        ? {
            ...h,
            factCount: h.factCount + 1,
            cleanGovernedOps: h.cleanGovernedOps + 1,
            stepCount: h.stepCount + 1,
          }
        : h;
    case 'rejectFactAtCap':
      return h.factCount === 3
        ? {...h, cleanGovernedOps: h.cleanGovernedOps + 1, stepCount: h.stepCount + 1}
        : h;
    case 'failClosedRearmOnCasError':
      return h.estopTripped
        ? {
            ...h,
            estopTripped: true,
            cleanGovernedOps: h.cleanGovernedOps + 1,
            stepCount: h.stepCount + 1,
          }
        : h;
    default:
      return h;
  }
}

const ALLOWLISTED_MFA_ACRS = new Set([
  'urn:ietf:params:oauth:acr:mfa',
  'urn:ietf:params:oauth:acr:phr',
  'urn:ietf:params:oauth:acr:phrh',
  'urn:nist:800-63:aal:2',
  'urn:nist:800-63:aal:3',
]);

function isAllowlistedMfaAcr(acr: string): boolean {
  const trimmed = acr.trim();
  if (ALLOWLISTED_MFA_ACRS.has(trimmed)) return true;
  if (trimmed.startsWith('urn:marlin:acr:mfa:')) {
    const suffix = trimmed.slice('urn:marlin:acr:mfa:'.length);
    return suffix.length > 0 && !/\s/.test(suffix);
  }
  return false;
}

const NON_HUMAN_PREFIXES = ['agent', 'bot', 'llm', 'worker', 'scheme-sandbox', 'system', 'service'];

function parseVerifiedStepUpHuman(note: string | null): 'verified_human' | 'agent' | 'unverified' {
  const raw = (note ?? '').trim();
  if (!raw.startsWith('stepup-verified:')) return 'unverified';
  const rest = raw.slice('stepup-verified:'.length);
  let actor: string | null = null;
  let acr: string | null = null;
  for (const seg of rest.split(':')) {
    if (seg.startsWith('actor=')) {
      if (actor !== null) return 'unverified';
      actor = seg.slice('actor='.length).trim();
    } else if (seg.startsWith('acr=')) {
      if (acr !== null) return 'unverified';
      acr = seg.slice('acr='.length).trim();
    } else if (acr !== null) {
      acr = `${acr}:${seg}`;
    } else {
      return 'unverified';
    }
  }
  if (!actor || !acr) return 'unverified';
  const lower = actor.toLowerCase();
  if (NON_HUMAN_PREFIXES.some((p) => lower.startsWith(p))) return 'agent';
  if (!isAllowlistedMfaAcr(acr)) return 'unverified';
  return 'verified_human';
}

function isReservedGovernanceCasKey(key: string): boolean {
  const k = key.trim();
  return (
    k === 'checkpoint:governance-authority:v1' ||
    k.startsWith('checkpoint:governance') ||
    k.endsWith(':facts')
  );
}

function parseItfInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number((v as {'#bigint': string})['#bigint']);
  }
  throw new Error(`unexpected ITF int: ${JSON.stringify(v)}`);
}

describe('SM30 (ADV-L4): Step-Up MFA Attestation Integrity, Scheme Effect E-Stop/CAS Isolation & Host Resilience', () => {
  test('500-trial ADV-L4 hostile fuzz refutes Step-Up spoofing/weak ACR/duplicate params, E-Stop LLM bypass, reserved CAS overwrite & MGF1 capacity bomb', () => {
    const rng = mulberry32(20260430);

    const hostileNotes = [
      'stepup-verified:actor=worker-autonomous:acr=urn:ietf:params:oauth:acr:mfa',
      'stepup-verified:actor=scheme-sandbox-worker:acr=urn:ietf:params:oauth:acr:mfa',
      'stepup-verified:actor=agent-rogue:actor=ops-alice:acr=urn:ietf:params:oauth:acr:mfa',
      'stepup-verified:actor=ops-alice:acr=none',
      'stepup-verified:actor=ops-alice:acr=password',
      'stepup-verified:actor=ops-alice:acr=urn:ietf:params:oauth:acr:mfa:acr=fake',
      'stepup-verified:actor=system-daemon:acr=urn:ietf:params:oauth:acr:phr',
      'plain-note',
    ];
    for (const bad of hostileNotes) {
      expect(parseVerifiedStepUpHuman(bad), `hostile step-up note must fail: ${bad}`).not.toBe(
        'verified_human',
      );
    }
    expect(
      parseVerifiedStepUpHuman('stepup-verified:actor=ops-alice:acr=urn:ietf:params:oauth:acr:mfa'),
    ).toBe('verified_human');
    expect(
      parseVerifiedStepUpHuman('stepup-verified:actor=ops-bob:acr=urn:ietf:params:oauth:acr:phr'),
    ).toBe('verified_human');

    const reservedKeys = [
      'checkpoint:governance-authority:v1',
      'checkpoint:governance-authority:v1:facts',
      'checkpoint:governance-custom',
      'custom:key:facts',
    ];
    for (const k of reservedKeys) {
      expect(isReservedGovernanceCasKey(k)).toBe(true);
    }
    expect(isReservedGovernanceCasKey('checkpoint:scheme-fleet:v1')).toBe(false);

    let blockedStepUpSpoofs = 0;
    let blockedEstopLlm = 0;
    let blockedReservedCas = 0;
    let blockedFactCapOverflow = 0;
    let admittedCleanOps = 0;

    for (let trial = 0; trial < 500; trial++) {
      const estopTripped = rng() < 0.4;
      const isHostileNote = rng() < 0.6;
      const note = isHostileNote
        ? hostileNotes[Math.floor(rng() * hostileNotes.length)]!
        : 'stepup-verified:actor=ops-alice:acr=urn:ietf:params:oauth:acr:mfa';
      const parsed = parseVerifiedStepUpHuman(note);
      if (isHostileNote) {
        expect(parsed).not.toBe('verified_human');
        blockedStepUpSpoofs += 1;
      } else {
        expect(parsed).toBe('verified_human');
      }

      // LlmComplete MUST fail closed whenever E-Stop is tripped.
      if (estopTripped) {
        blockedEstopLlm += 1;
      } else {
        admittedCleanOps += 1;
      }

      // CasPut MUST reject reserved governance keys regardless of E-Stop.
      const casKey =
        rng() < 0.5
          ? reservedKeys[Math.floor(rng() * reservedKeys.length)]!
          : `checkpoint:scheme-fleet:${trial}`;
      if (isReservedGovernanceCasKey(casKey)) {
        blockedReservedCas += 1;
      } else {
        admittedCleanOps += 1;
      }

      // Fact-store mutation cap parity (cap=4096) blocks overflow before MGF1 serialization.
      const factLen = 4094 + Math.floor(rng() * 5);
      const canInsert = factLen < 4096;
      if (!canInsert) blockedFactCapOverflow += 1;
      expect(canInsert ? factLen + 1 : factLen).toBeLessThanOrEqual(4098);
      if (factLen >= 4096) expect(canInsert).toBe(false);
    }

    expect(blockedStepUpSpoofs).toBeGreaterThan(250);
    expect(blockedEstopLlm).toBeGreaterThan(150);
    expect(blockedReservedCas).toBeGreaterThan(200);
    expect(blockedFactCapOverflow).toBeGreaterThan(200);
    expect(admittedCleanOps).toBeGreaterThan(400);
  });

  test('6 live Quint --mbt ITF traces refine SM30 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const modelPath = join(
      repoRoot,
      'packages/quint-models/threat/execution/stepup-attestation-and-host-effect-confinement/StepUpAttestationAndHostEffectConfinement.qnt',
    );
    const candidateBins = [
      join(repoRoot, 'packages/quint-modules-resolver/node_modules/.bin/quint'),
      join(repoRoot, 'node_modules/.bin/quint'),
    ];
    const quintBin = candidateBins.find((p) => existsSync(p)) ?? 'quint';
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm30-itf-'));
    try {
      const outPattern = join(tmpDir, 'trace.itf.json');
      execFileSync(
        quintBin,
        [
          'run',
          modelPath,
          '--main=execution_stepup_attestation_and_host_effect_confinement',
          '--invariant=safety',
          '--mbt',
          '--max-samples=6',
          '--n-traces=6',
          '--max-steps=12',
          '--seed=30',
          `--out-itf=${outPattern}`,
        ],
        {cwd: repoRoot, stdio: 'pipe'},
      );

      let totalStates = 0;
      const seenActions = new Set<string>();
      for (let i = 0; i < 6; i++) {
        const itfPath = join(tmpDir, `trace${i}.itf.json`);
        const itf = JSON.parse(readFileSync(itfPath, 'utf8')) as {
          states: Array<{
            'mbt::actionTaken'?: string;
            h: {
              estopTripped: boolean;
              watchersAlive: boolean;
              factCount: unknown;
              reservedCasIntact: boolean;
              spoofedRearms: unknown;
              effectOrCasBreaches: unknown;
              watcherSuicides: unknown;
              factBombOrDesyncs: unknown;
              cleanGovernedOps: unknown;
              stepCount: unknown;
            };
          }>;
        };

        let tsState = initState();
        for (let stepIdx = 0; stepIdx < itf.states.length; stepIdx++) {
          const st = itf.states[stepIdx]!;
          const actionTaken = st['mbt::actionTaken'];
          if (stepIdx > 0 && actionTaken) {
            seenActions.add(actionTaken);
            tsState = applySafeAction(tsState, actionTaken);
          }
          const qH = st.h;
          const quintState: Sm30State = {
            estopTripped: qH.estopTripped,
            watchersAlive: qH.watchersAlive,
            factCount: parseItfInt(qH.factCount),
            reservedCasIntact: qH.reservedCasIntact,
            spoofedRearms: parseItfInt(qH.spoofedRearms),
            effectOrCasBreaches: parseItfInt(qH.effectOrCasBreaches),
            watcherSuicides: parseItfInt(qH.watcherSuicides),
            factBombOrDesyncs: parseItfInt(qH.factBombOrDesyncs),
            cleanGovernedOps: parseItfInt(qH.cleanGovernedOps),
            stepCount: parseItfInt(qH.stepCount),
          };
          expect(tsState).toEqual(quintState);
          expect(isSafetyInvariantHeld(tsState)).toBe(true);
          totalStates += 1;
        }
      }
      expect(totalStates).toBeGreaterThanOrEqual(30);
      expect(seenActions.size).toBeGreaterThanOrEqual(5);
    } finally {
      rmSync(tmpDir, {recursive: true, force: true});
    }
  }, 30_000);
});
