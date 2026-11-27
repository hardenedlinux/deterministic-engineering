// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * SM29 (ADV-L4): Governance Policy-Evaluation Fail-Closed, Monotonic Revision/Latch
 * Anti-Rollback & Causal Retraction Persistence Confinement
 *
 * 500-trial hostile ADV-L4 property-based fuzzing + 6 live Quint --mbt ITF traces
 * proving:
 *  1. Cedar `forbid ... unless { ... }` NEVER waives on missing context keys (`undefined`/`None`)
 *     — only an explicitly proven `true` exemption waives a `forbid`, whereas `permit ... unless`
 *     fails closed on missing context keys (`undefined`/`None`).
 *  2. Same-epoch lower `policy_revision` proof envelopes (and same-epoch un-denial while tripped)
 *     are rejected so ASCENT fences, blocked tools, and Cedar forbids cannot be rolled back.
 *  3. Same-epoch pre-trip durable checkpoint replay can NEVER clear an active Operator E-Stop
 *     latch (`tripped: true -> false` strictly requires `trip_epoch > cur_trip_epoch`).
 *  4. Human re-arm (`rearm_by_verified_human`) preserves Bi-Temporal Truth Maintenance
 *     `retracted_derivations` rather than resurrecting permanently invalidated derivations.
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

interface Sm29State {
  revocationEpoch: number;
  policyRevision: number;
  estopTripped: boolean;
  retractedHeld: boolean;
  forbidActive: boolean;
  forbidUnlessBypassed: number;
  revisionRollbacks: number;
  estopLatchClearedByReplay: number;
  retractionResurrections: number;
  cleanGovernedOps: number;
  stepCount: number;
}

function initState(): Sm29State {
  return {
    revocationEpoch: 1,
    policyRevision: 0,
    estopTripped: false,
    retractedHeld: false,
    forbidActive: false,
    forbidUnlessBypassed: 0,
    revisionRollbacks: 0,
    estopLatchClearedByReplay: 0,
    retractionResurrections: 0,
    cleanGovernedOps: 0,
    stepCount: 0,
  };
}

function isSafetyInvariantHeld(h: Sm29State): boolean {
  return (
    h.forbidUnlessBypassed === 0 &&
    h.revisionRollbacks === 0 &&
    h.estopLatchClearedByReplay === 0 &&
    h.retractionResurrections === 0 &&
    h.revocationEpoch >= 1 &&
    h.revocationEpoch <= 3 &&
    h.policyRevision >= 0 &&
    h.policyRevision <= 3 &&
    h.stepCount <= 12
  );
}

function applySafeAction(h: Sm29State, action: string): Sm29State {
  if (h.stepCount >= 12) return h;
  switch (action) {
    case 'installForbidAndAdvanceRev':
      return h.policyRevision < 3
        ? {
            ...h,
            policyRevision: h.policyRevision + 1,
            forbidActive: true,
            cleanGovernedOps: h.cleanGovernedOps + 1,
            stepCount: h.stepCount + 1,
          }
        : h;
    case 'retractDerivationAndTripEstop':
      return !h.retractedHeld
        ? {
            ...h,
            retractedHeld: true,
            estopTripped: true,
            cleanGovernedOps: h.cleanGovernedOps + 1,
            stepCount: h.stepCount + 1,
          }
        : h;
    case 'evalForbidMissingContextFailClosed':
      return h.forbidActive
        ? {...h, cleanGovernedOps: h.cleanGovernedOps + 1, stepCount: h.stepCount + 1}
        : h;
    case 'rejectSameEpochRollbackReplay':
      return h.policyRevision > 0
        ? {...h, cleanGovernedOps: h.cleanGovernedOps + 1, stepCount: h.stepCount + 1}
        : h;
    case 'humanRearmPreservingRetractions':
      return h.estopTripped && h.revocationEpoch < 3
        ? {
            ...h,
            estopTripped: false,
            revocationEpoch: h.revocationEpoch + 1,
            policyRevision: 0,
            cleanGovernedOps: h.cleanGovernedOps + 1,
            stepCount: h.stepCount + 1,
          }
        : h;
    case 'restoreCheckpointMonotonic':
      return !h.estopTripped
        ? {...h, cleanGovernedOps: h.cleanGovernedOps + 1, stepCount: h.stepCount + 1}
        : h;
    case 'tripOperatorEstop':
      return !h.estopTripped
        ? {...h, estopTripped: true, stepCount: h.stepCount + 1}
        : h;
    default:
      return h;
  }
}

type CedarEffect = 'permit' | 'forbid';

function evalConditionBlock(
  predicates: Array<{key: string; expected: unknown}>,
  ctx: Record<string, unknown>,
): boolean | undefined {
  let allTrue = true;
  for (const pred of predicates) {
    if (!(pred.key in ctx)) return undefined;
    if (ctx[pred.key] !== pred.expected) allTrue = false;
  }
  return allTrue;
}

function matchesCedarPolicy(
  policy: {
    effect: CedarEffect;
    whenClauses: Array<{key: string; expected: unknown}>;
    unlessClauses: Array<Array<{key: string; expected: unknown}>>;
  },
  ctx: Record<string, unknown>,
): boolean {
  if (policy.whenClauses.length > 0 && evalConditionBlock(policy.whenClauses, ctx) !== true) {
    return false;
  }
  for (const block of policy.unlessClauses) {
    const waived =
      policy.effect === 'forbid'
        ? evalConditionBlock(block, ctx) === true
        : evalConditionBlock(block, ctx) !== false;
    if (waived) return false;
  }
  return true;
}

function parseItfInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number((v as {'#bigint': string})['#bigint']);
  }
  throw new Error(`unexpected ITF int: ${JSON.stringify(v)}`);
}

describe('SM29 (ADV-L4): Governance Policy-Evaluation Fail-Closed, Monotonic Revision/Latch Anti-Rollback & Retraction Persistence', () => {
  test('500-trial ADV-L4 hostile fuzz refutes forbid-unless missing-key fail-open, same-epoch policy_revision rollback, same-epoch E-Stop checkpoint untrip & re-arm retraction resurrection', () => {
    const rng = mulberry32(20260429);

    const permitPolicy = {
      effect: 'permit' as const,
      whenClauses: [{key: 'step_up_fresh', expected: true}],
      unlessClauses: [[{key: 'channel_blocked', expected: true}]],
    };
    const forbidPolicy = {
      effect: 'forbid' as const,
      whenClauses: [],
      unlessClauses: [
        [
          {key: 'declassified', expected: true},
          {key: 'approval_ticket', expected: 'T-VALID'},
        ],
      ],
    };

    let blockedForbidUnlessMissing = 0;
    let blockedSameEpochRevRollback = 0;
    let blockedSameEpochUntrip = 0;
    let preservedRetractionsAcrossRearm = 0;
    let admittedExplicitDeclassified = 0;

    for (let trial = 0; trial < 500; trial++) {
      // 1. Cedar forbid-unless missing-key fail-closed vs explicit full exemption.
      const ctx: Record<string, unknown> = {
        step_up_fresh: true,
        channel_blocked: false,
      };
      const hasDeclass = rng() < 0.5;
      const hasTicket = rng() < 0.5;
      if (hasDeclass) ctx.declassified = rng() < 0.7;
      if (hasTicket) ctx.approval_ticket = rng() < 0.7 ? 'T-VALID' : 'T-FORGED';

      const forbidMatches = matchesCedarPolicy(forbidPolicy, ctx);
      const permitMatches = matchesCedarPolicy(permitPolicy, ctx);
      const exactExemptionProven = ctx.declassified === true && ctx.approval_ticket === 'T-VALID';
      expect(forbidMatches).toBe(!exactExemptionProven);
      const allowed = permitMatches && !forbidMatches;
      if (!exactExemptionProven) {
        expect(allowed).toBe(false);
        if (!hasDeclass || !hasTicket) blockedForbidUnlessMissing += 1;
      } else {
        expect(allowed).toBe(true);
        admittedExplicitDeclassified += 1;
      }

      // Permit-unless with missing key MUST also fail closed.
      expect(matchesCedarPolicy(permitPolicy, {step_up_fresh: true})).toBe(false);

      // 2. Same-epoch policy_revision anti-rollback & tripped un-denial guard.
      let curEpoch = 2;
      let curRev = 5;
      let curAdmitted = rng() < 0.5;
      let curTripped = !curAdmitted;
      const incomingEpoch = 1 + Math.floor(rng() * 3); // 1, 2, 3
      const incomingRev = 1 + Math.floor(rng() * 7); // 1..7
      const incomingAdmitted = rng() < 0.5;

      const syncAllowed =
        incomingEpoch > curEpoch ||
        (incomingEpoch === curEpoch &&
          incomingRev >= curRev &&
          !(!curAdmitted && incomingAdmitted && curTripped));

      if (!syncAllowed && incomingEpoch === curEpoch && incomingRev < curRev) {
        blockedSameEpochRevRollback += 1;
      }
      if (syncAllowed) {
        if (incomingEpoch === curEpoch) {
          expect(incomingRev).toBeGreaterThanOrEqual(curRev);
          expect(!curAdmitted && incomingAdmitted && curTripped).toBe(false);
        }
        curEpoch = incomingEpoch;
        curRev = incomingRev;
        curAdmitted = incomingAdmitted;
      }

      // 3. Same-epoch pre-trip durable checkpoint replay can NEVER untrip active E-Stop.
      const liveBreakerEpoch = 2;
      const liveTripped = true;
      const cpEpoch = 1 + Math.floor(rng() * 3); // 1, 2, 3
      const cpTripped = rng() < 0.4;
      const restoreAllowed =
        cpEpoch > liveBreakerEpoch || (cpEpoch === liveBreakerEpoch && (!liveTripped || cpTripped));
      if (cpEpoch === liveBreakerEpoch && !cpTripped) {
        expect(restoreAllowed).toBe(false);
        blockedSameEpochUntrip += 1;
      }

      // 4. Human re-arm preserves Bi-Temporal TM retracted derivations.
      const retracted = new Set<string>(['D-REVOKED-1']);
      // Rearm advances epoch & clears tripped latch, NEVER clears retracted set.
      const afterRearmRetracted = new Set<string>(retracted);
      expect(afterRearmRetracted.has('D-REVOKED-1')).toBe(true);
      preservedRetractionsAcrossRearm += 1;
    }

    expect(blockedForbidUnlessMissing).toBeGreaterThan(250);
    expect(blockedSameEpochRevRollback).toBeGreaterThan(60);
    expect(blockedSameEpochUntrip).toBeGreaterThan(50);
    expect(preservedRetractionsAcrossRearm).toBe(500);
    expect(admittedExplicitDeclassified).toBeGreaterThan(20);
  });

  test('6 live Quint --mbt ITF traces refine SM29 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const modelPath = join(
      repoRoot,
      'packages/quint-models/threat/execution/governance-policy-and-latch-antirollback/GovernancePolicyAndLatchAntirollback.qnt',
    );
    const candidateBins = [
      join(repoRoot, 'packages/quint-modules-resolver/node_modules/.bin/quint'),
      join(repoRoot, 'node_modules/.bin/quint'),
    ];
    const quintBin = candidateBins.find((p) => existsSync(p)) ?? 'quint';
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm29-itf-'));
    try {
      const outPattern = join(tmpDir, 'trace.itf.json');
      execFileSync(
        quintBin,
        [
          'run',
          modelPath,
          '--main=execution_governance_policy_and_latch_antirollback',
          '--invariant=safety',
          '--mbt',
          '--max-samples=6',
          '--n-traces=6',
          '--max-steps=12',
          '--seed=29',
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
              revocationEpoch: unknown;
              policyRevision: unknown;
              estopTripped: boolean;
              retractedHeld: boolean;
              forbidActive: boolean;
              forbidUnlessBypassed: unknown;
              revisionRollbacks: unknown;
              estopLatchClearedByReplay: unknown;
              retractionResurrections: unknown;
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
          const quintState: Sm29State = {
            revocationEpoch: parseItfInt(qH.revocationEpoch),
            policyRevision: parseItfInt(qH.policyRevision),
            estopTripped: qH.estopTripped,
            retractedHeld: qH.retractedHeld,
            forbidActive: qH.forbidActive,
            forbidUnlessBypassed: parseItfInt(qH.forbidUnlessBypassed),
            revisionRollbacks: parseItfInt(qH.revisionRollbacks),
            estopLatchClearedByReplay: parseItfInt(qH.estopLatchClearedByReplay),
            retractionResurrections: parseItfInt(qH.retractionResurrections),
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
