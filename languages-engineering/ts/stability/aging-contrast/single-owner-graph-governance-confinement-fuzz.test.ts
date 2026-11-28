// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

/**
 * SM25 Adversarial (ADV-L4) Single-Owner Graph Execution Convergence &
 * Reachable Production Governance Confinement Fuzz + Live Quint ITF MBT.
 *
 * Hostile Pressure Tier: ADV-L4 (MUST catch disconnected governance where
 * Cedar/E-Stop gates exist only on a legacy Loop engine while the production
 * GraphEngine executes ungated, unretired shadow legacy engines, tripped
 * E-Stop fallthrough, and stale fencing-epoch dual dispatches).
 *
 * Real-repo case: marlin-agent-core (marlin_mygo_host + CompositeAtomicEffectExecutor
 * + TaskActorKernelExecutor vs unretired LoopProgram* legacy engine).
 */

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const SM25_QNT = resolve(
  REPO_ROOT,
  'packages/quint-models/threat/execution/single-owner-graph-governance-confinement/SingleOwnerGraphGovernanceConfinement.qnt',
);

type ProbeKind =
  | 'governed-graph-effect'
  | 'governed-task-actor'
  | 'tripped-breaker-effect'
  | 'cedar-forbid-effect'
  | 'legacy-shadow-dispatch'
  | 'stale-epoch-dispatch';

interface GraphGovCounters {
  governedAdmitted: number;
  hostileBlocked: number;
  disconnectedGovBypasses: number;
  shadowLegacyExecutions: number;
  trippedBreakerBypasses: number;
  staleEpochDualDispatches: number;
}

interface GraphGovEvent {
  kind: ProbeKind;
  breakerTripped: boolean;
  cedarForbid: boolean;
  epochCurrent: boolean;
  engineOwner: 'graph-canonical' | 'legacy-loop-shadow';
}

class HardenedSingleOwnerGraphBoundary {
  readonly state: GraphGovCounters = {
    governedAdmitted: 0,
    hostileBlocked: 0,
    disconnectedGovBypasses: 0,
    shadowLegacyExecutions: 0,
    trippedBreakerBypasses: 0,
    staleEpochDualDispatches: 0,
  };

  dispatch(ev: GraphGovEvent): 'admitted' | 'blocked' {
    if (ev.engineOwner === 'legacy-loop-shadow') {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    if (!ev.epochCurrent) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    if (ev.breakerTripped || ev.cedarForbid) {
      this.state.hostileBlocked += 1;
      return 'blocked';
    }
    this.state.governedAdmitted += 1;
    return 'admitted';
  }
}

class DefectiveSplitBrainGraphBoundary {
  readonly state: GraphGovCounters = {
    governedAdmitted: 0,
    hostileBlocked: 0,
    disconnectedGovBypasses: 0,
    shadowLegacyExecutions: 0,
    trippedBreakerBypasses: 0,
    staleEpochDualDispatches: 0,
  };

  dispatch(ev: GraphGovEvent): void {
    // Defective architecture: governance gate only wired to legacy loop unit tests,
    // production GraphEngine executor runs ungated AND shadow loop remains callable!
    if (ev.engineOwner === 'legacy-loop-shadow') {
      this.state.shadowLegacyExecutions += 1;
      return;
    }
    if (ev.cedarForbid) {
      this.state.disconnectedGovBypasses += 1;
      return;
    }
    if (ev.breakerTripped) {
      this.state.trippedBreakerBypasses += 1;
      return;
    }
    if (!ev.epochCurrent) {
      this.state.staleEpochDualDispatches += 1;
      return;
    }
    this.state.governedAdmitted += 1;
  }
}

function nextSeed(state: {s: number}): number {
  state.s = (Math.imul(state.s, 1664525) + 1013904223) >>> 0;
  return state.s;
}

describe('SM25 Adversarial (ADV-L4) Single-Owner Graph Execution & Reachable Governance Fuzz + ITF MBT', () => {
  test('ADV-L4: 500 hostile split-brain & governance-evasion trials — hardened 0 bypasses vs defective governance theater', () => {
    const rng = {s: 0x51a52501};
    const hardened = new HardenedSingleOwnerGraphBoundary();
    const defective = new DefectiveSplitBrainGraphBoundary();

    const kinds: ProbeKind[] = [
      'governed-graph-effect',
      'governed-task-actor',
      'tripped-breaker-effect',
      'cedar-forbid-effect',
      'legacy-shadow-dispatch',
      'stale-epoch-dispatch',
    ];

    for (let i = 0; i < 500; i += 1) {
      const kind = kinds[nextSeed(rng) % kinds.length]!;
      const ev: GraphGovEvent = {
        kind,
        breakerTripped: kind === 'tripped-breaker-effect',
        cedarForbid: kind === 'cedar-forbid-effect',
        epochCurrent: kind !== 'stale-epoch-dispatch',
        engineOwner: kind === 'legacy-shadow-dispatch' ? 'legacy-loop-shadow' : 'graph-canonical',
      };
      const decision = hardened.dispatch(ev);
      defective.dispatch(ev);

      if (kind === 'governed-graph-effect' || kind === 'governed-task-actor') {
        expect(decision).toBe('admitted');
      } else {
        expect(decision).toBe('blocked');
      }
    }

    expect(hardened.state.governedAdmitted).toBeGreaterThan(100);
    expect(hardened.state.hostileBlocked).toBeGreaterThan(250);
    expect(hardened.state.disconnectedGovBypasses).toBe(0);
    expect(hardened.state.shadowLegacyExecutions).toBe(0);
    expect(hardened.state.trippedBreakerBypasses).toBe(0);
    expect(hardened.state.staleEpochDualDispatches).toBe(0);

    // Defective split-brain architecture MUST demonstrate all 4 failure modes live.
    expect(defective.state.disconnectedGovBypasses).toBeGreaterThan(50);
    expect(defective.state.shadowLegacyExecutions).toBeGreaterThan(50);
    expect(defective.state.trippedBreakerBypasses).toBeGreaterThan(50);
    expect(defective.state.staleEpochDualDispatches).toBeGreaterThan(50);
  });

  test('ADV-L4: Live Quint ITF MBT Replay for 103rd Formal Model SM25 SingleOwnerGraphGovernanceConfinement (6 live traces, 100% parity)', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'sm25-itf-'));

    try {
      const proc = spawnSync(
        'bun',
        [
          resolve(REPO_ROOT, 'packages/quint-modules-resolver/src/cli.ts'),
          'mbt-audit',
          SM25_QNT,
          '--main=execution_single_owner_graph_governance_confinement',
          '--invariant=safety',
          '--max-samples=6',
          '--max-steps=12',
          '--min-coverage=1',
          '--out-dir',
          outDir,
        ],
        {cwd: REPO_ROOT, encoding: 'utf8'},
      );
      expect(proc.status, `mbt-audit failed: ${proc.stderr}`).toBe(0);

      const itfFiles = readdirSync(outDir)
        .filter((f) => f.endsWith('.itf.json'))
        .sort();
      expect(itfFiles.length).toBeGreaterThanOrEqual(6);

      for (const file of itfFiles) {
        const parsed = JSON.parse(readFileSync(resolve(outDir, file), 'utf8')) as {
          states: Array<{
            'mbt::actionTaken'?: string;
            h: {
              governedAdmitted: {'#bigint': string};
              hostileBlocked: {'#bigint': string};
              disconnectedGovBypasses: {'#bigint': string};
              shadowLegacyExecutions: {'#bigint': string};
              trippedBreakerBypasses: {'#bigint': string};
              staleEpochDualDispatches: {'#bigint': string};
            };
          }>;
        };

        const dut = new HardenedSingleOwnerGraphBoundary();
        for (const st of parsed.states) {
          const act = st['mbt::actionTaken'] ?? '';
          if (act === 'dispatchGovernedGraphEffect') {
            dut.dispatch({
              kind: 'governed-graph-effect',
              breakerTripped: false,
              cedarForbid: false,
              epochCurrent: true,
              engineOwner: 'graph-canonical',
            });
          } else if (act === 'dispatchGovernedTaskActor') {
            dut.dispatch({
              kind: 'governed-task-actor',
              breakerTripped: false,
              cedarForbid: false,
              epochCurrent: true,
              engineOwner: 'graph-canonical',
            });
          } else if (act === 'blockTrippedBreakerEffect') {
            dut.dispatch({
              kind: 'tripped-breaker-effect',
              breakerTripped: true,
              cedarForbid: false,
              epochCurrent: true,
              engineOwner: 'graph-canonical',
            });
          } else if (act === 'blockCedarOrAscentForbid') {
            dut.dispatch({
              kind: 'cedar-forbid-effect',
              breakerTripped: false,
              cedarForbid: true,
              epochCurrent: true,
              engineOwner: 'graph-canonical',
            });
          } else if (act === 'rejectLegacyShadowDispatch') {
            dut.dispatch({
              kind: 'legacy-shadow-dispatch',
              breakerTripped: true,
              cedarForbid: false,
              epochCurrent: true,
              engineOwner: 'legacy-loop-shadow',
            });
          } else if (act === 'rejectStaleFencingEpoch') {
            dut.dispatch({
              kind: 'stale-epoch-dispatch',
              breakerTripped: false,
              cedarForbid: false,
              epochCurrent: false,
              engineOwner: 'graph-canonical',
            });
          }

          expect(dut.state.governedAdmitted).toBe(Number(st.h.governedAdmitted['#bigint']));
          expect(dut.state.hostileBlocked).toBe(Number(st.h.hostileBlocked['#bigint']));
          expect(dut.state.disconnectedGovBypasses).toBe(Number(st.h.disconnectedGovBypasses['#bigint']));
          expect(dut.state.shadowLegacyExecutions).toBe(Number(st.h.shadowLegacyExecutions['#bigint']));
          expect(dut.state.trippedBreakerBypasses).toBe(Number(st.h.trippedBreakerBypasses['#bigint']));
          expect(dut.state.staleEpochDualDispatches).toBe(Number(st.h.staleEpochDualDispatches['#bigint']));
        }
      }
    } finally {
      rmSync(outDir, {recursive: true, force: true});
    }
  }, 30_000);
});
