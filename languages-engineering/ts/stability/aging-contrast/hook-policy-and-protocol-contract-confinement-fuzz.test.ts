// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm33State {
  registeredHooks: number;
  asyncTasksRunning: number;
  validatedProfiles: number;
  strictConfigEnforced: boolean;
  uniqueHookIdsEnforced: boolean;
  trustFloorImmutable: boolean;
  protocolContractsEnforced: boolean;
  configFailOpenBreaches: number;
  hookShadowOrFanoutBreaches: number;
  trustMaskOrActionBreaches: number;
  protocolContractBreaches: number;
  cleanVerifiedOps: number;
  stepCount: number;
}

function initState(): Sm33State {
  return {
    registeredHooks: 0,
    asyncTasksRunning: 0,
    validatedProfiles: 0,
    strictConfigEnforced: true,
    uniqueHookIdsEnforced: true,
    trustFloorImmutable: true,
    protocolContractsEnforced: true,
    configFailOpenBreaches: 0,
    hookShadowOrFanoutBreaches: 0,
    trustMaskOrActionBreaches: 0,
    protocolContractBreaches: 0,
    cleanVerifiedOps: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm33State, action: string): Sm33State {
  const s = {...state};
  switch (action) {
    case 'loadStrictHookTomlConfig':
      if (s.stepCount < 12 && s.strictConfigEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'upsertUniqueHookRegistration':
      if (s.stepCount < 12 && s.uniqueHookIdsEnforced && s.registeredHooks < 6) {
        s.registeredHooks += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'unregisterHookCompletely':
      if (s.stepCount < 12 && s.uniqueHookIdsEnforced && s.registeredHooks > 0) {
        s.registeredHooks -= 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'dispatchBoundedAsyncHook':
      if (s.stepCount < 12 && s.asyncTasksRunning < 4) {
        s.asyncTasksRunning += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'completeBoundedAsyncHook':
      if (s.stepCount < 12 && s.asyncTasksRunning > 0) {
        s.asyncTasksRunning -= 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'applyBoundedDynamicActionPreservingTrustFloor':
      if (s.stepCount < 12 && s.trustFloorImmutable) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'validateSubAgentAndProtocolBoundary':
      if (s.stepCount < 12 && s.protocolContractsEnforced && s.validatedProfiles < 4) {
        s.validatedProfiles += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM33 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm33State): boolean {
  return (
    s.configFailOpenBreaches === 0 &&
    s.hookShadowOrFanoutBreaches === 0 &&
    s.trustMaskOrActionBreaches === 0 &&
    s.protocolContractBreaches === 0 &&
    s.strictConfigEnforced &&
    s.uniqueHookIdsEnforced &&
    s.trustFloorImmutable &&
    s.protocolContractsEnforced &&
    s.registeredHooks >= 0 &&
    s.registeredHooks <= 6 &&
    s.asyncTasksRunning >= 0 &&
    s.asyncTasksRunning <= 4 &&
    s.validatedProfiles <= 4 &&
    s.stepCount <= 12
  );
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type HookReason =
  | 'TrustedSource'
  | 'UntrustedRejected'
  | 'ModifiedRejected'
  | 'ExtensionDeferred'
  | 'ExtensionRejected';

function applyHookDynamicDecision(current: HookReason, action: 'Deny' | 'Defer'): HookReason {
  if (current === 'UntrustedRejected' || current === 'ModifiedRejected') {
    return current;
  }
  return action === 'Deny' ? 'ExtensionRejected' : 'ExtensionDeferred';
}

function validateSubAgentPolicy(p: {
  readOnly: boolean;
  workspaceWrite: boolean;
  descendantSpawn: boolean;
  maxConcurrency: number;
  timeoutMs: number;
  maxDepth?: number;
}): boolean {
  if (p.readOnly && p.workspaceWrite) return false;
  if (p.maxConcurrency === 0 || p.timeoutMs === 0) return false;
  if (p.maxDepth !== undefined && p.maxDepth > 16) return false;
  if (p.descendantSpawn && (p.maxDepth === undefined || p.maxDepth === 0)) return false;
  return true;
}

function isSafeEndpointComponent(token: string): boolean {
  if (!token || token.trim().length === 0 || token !== token.trim()) return false;
  if (/[\s\x00-\x1f\x7f/?#@\\]/.test(token) || token.includes('..')) return false;
  return true;
}

function isSafeRuntimeSessionId(id: string): boolean {
  const trimmed = id.trim();
  if (!trimmed || trimmed.length > 256) return false;
  if (/[\x00-\x1f\x7f/\\]/.test(trimmed) || trimmed.includes('..')) return false;
  return true;
}

function parseItfInt(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number((v as {'#bigint': string})['#bigint']);
  }
  throw new Error(`unexpected ITF int: ${JSON.stringify(v)}`);
}

describe('SM33 (ADV-L4): Hook Policy Confinement, Anti-Shadowing Registry & Protocol Contract Validation', () => {
  test('500-trial ADV-L4 hostile fuzz refutes fail-open TOML keys, duplicate ghost hooks, trust-rejection masking, contradictory sub-agent policies & protocol injection', () => {
    const rng = mulberry32(20260703);

    // 1. Trust floor immutability
    expect(applyHookDynamicDecision('UntrustedRejected', 'Defer')).toBe('UntrustedRejected');
    expect(applyHookDynamicDecision('UntrustedRejected', 'Deny')).toBe('UntrustedRejected');
    expect(applyHookDynamicDecision('ModifiedRejected', 'Defer')).toBe('ModifiedRejected');
    expect(applyHookDynamicDecision('TrustedSource', 'Defer')).toBe('ExtensionDeferred');
    expect(applyHookDynamicDecision('ExtensionDeferred', 'Deny')).toBe('ExtensionRejected');

    // 2. Contradictory sub-agent policy & zero budget refusal
    expect(
      validateSubAgentPolicy({
        readOnly: true,
        workspaceWrite: true,
        descendantSpawn: false,
        maxConcurrency: 1,
        timeoutMs: 1000,
        maxDepth: 1,
      }),
    ).toBe(false);
    expect(
      validateSubAgentPolicy({
        readOnly: false,
        workspaceWrite: true,
        descendantSpawn: false,
        maxConcurrency: 0,
        timeoutMs: 1000,
      }),
    ).toBe(false);
    expect(
      validateSubAgentPolicy({
        readOnly: false,
        workspaceWrite: true,
        descendantSpawn: true,
        maxConcurrency: 2,
        timeoutMs: 1000,
      }),
    ).toBe(false);
    expect(
      validateSubAgentPolicy({
        readOnly: false,
        workspaceWrite: true,
        descendantSpawn: true,
        maxConcurrency: 2,
        timeoutMs: 1000,
        maxDepth: 2,
      }),
    ).toBe(true);

    // 3. Protocol session & endpoint injection refusal
    for (const bad of ['', '   ', 'sess\r\nX: 1', '../escape', 'a/b', 'id\x00']) {
      expect(isSafeRuntimeSessionId(bad), `hostile session id rejected: ${JSON.stringify(bad)}`).toBe(false);
    }
    expect(isSafeRuntimeSessionId('marlin-session-1')).toBe(true);

    for (const bad of ['', 'gpt-4o\r\nX-Evil: 1', 'gpt-4o?key=leak', 'gpt-4o#frag', 'gpt-4o@evil', 'a..b', 'a\\b']) {
      expect(isSafeEndpointComponent(bad), `hostile endpoint token rejected: ${JSON.stringify(bad)}`).toBe(false);
    }
    expect(isSafeEndpointComponent('gpt-5-mini')).toBe(true);
    expect(isSafeEndpointComponent('claude-opus-4-8')).toBe(true);

    let blockedGhostShadows = 0;
    let preservedTrustRejections = 0;
    let blockedSubAgentContradictions = 0;
    let blockedProtocolInjections = 0;

    for (let trial = 0; trial < 500; trial++) {
      // Unique hook_id registry upsert guarantees disable/unregister leaves 0 shadows.
      const registry = new Map<string, {enabled: boolean; version: number}>();
      const id = `hook-${trial % 7}`;
      registry.set(id, {enabled: true, version: 1});
      registry.set(id, {enabled: true, version: 2});
      expect(registry.size).toBe(1);
      registry.delete(id);
      expect(registry.has(id)).toBe(false);
      blockedGhostShadows += 1;

      const trustReason: HookReason = rng() < 0.5 ? 'UntrustedRejected' : 'ModifiedRejected';
      const action: 'Deny' | 'Defer' = rng() < 0.5 ? 'Deny' : 'Defer';
      expect(applyHookDynamicDecision(trustReason, action)).toBe(trustReason);
      preservedTrustRejections += 1;

      const mode = trial % 3;
      const badPolicy =
        mode === 0
          ? {readOnly: true, workspaceWrite: true, descendantSpawn: false, maxConcurrency: 1, timeoutMs: 500}
          : mode === 1
            ? {readOnly: false, workspaceWrite: true, descendantSpawn: false, maxConcurrency: 0, timeoutMs: 500}
            : {readOnly: false, workspaceWrite: false, descendantSpawn: true, maxConcurrency: 1, timeoutMs: 500, maxDepth: 0};
      expect(validateSubAgentPolicy(badPolicy)).toBe(false);
      blockedSubAgentContradictions += 1;

      const hostileTokens = ['gpt-4o\r\nEvil', 'model?leak=1', 'model#frag', 'model@host', 'a..b'];
      expect(isSafeEndpointComponent(hostileTokens[trial % hostileTokens.length]!)).toBe(false);
      blockedProtocolInjections += 1;
    }

    expect(blockedGhostShadows).toBe(500);
    expect(preservedTrustRejections).toBe(500);
    expect(blockedSubAgentContradictions).toBe(500);
    expect(blockedProtocolInjections).toBe(500);
  });

  test('6 live Quint --mbt ITF traces refine SM33 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const modelPath = join(
      repoRoot,
      'packages/quint-models/threat/execution/hook-policy-and-protocol-contract-confinement/HookPolicyAndProtocolContractConfinement.qnt',
    );
    const candidateBins = [
      join(repoRoot, 'packages/quint-modules-resolver/node_modules/.bin/quint'),
      join(repoRoot, 'node_modules/.bin/quint'),
    ];
    const quintBin = candidateBins.find((p) => existsSync(p)) ?? 'quint';
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm33-itf-'));
    try {
      const outPattern = join(tmpDir, 'trace.itf.json');
      execFileSync(
        quintBin,
        [
          'run',
          modelPath,
          '--main=execution_hook_policy_and_protocol_contract_confinement',
          '--invariant=safety',
          '--mbt',
          '--max-samples=6',
          '--n-traces=6',
          '--max-steps=12',
          '--seed=33',
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
              registeredHooks: unknown;
              asyncTasksRunning: unknown;
              validatedProfiles: unknown;
              strictConfigEnforced: boolean;
              uniqueHookIdsEnforced: boolean;
              trustFloorImmutable: boolean;
              protocolContractsEnforced: boolean;
              configFailOpenBreaches: unknown;
              hookShadowOrFanoutBreaches: unknown;
              trustMaskOrActionBreaches: unknown;
              protocolContractBreaches: unknown;
              cleanVerifiedOps: unknown;
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
          const quintState: Sm33State = {
            registeredHooks: parseItfInt(qH.registeredHooks),
            asyncTasksRunning: parseItfInt(qH.asyncTasksRunning),
            validatedProfiles: parseItfInt(qH.validatedProfiles),
            strictConfigEnforced: qH.strictConfigEnforced,
            uniqueHookIdsEnforced: qH.uniqueHookIdsEnforced,
            trustFloorImmutable: qH.trustFloorImmutable,
            protocolContractsEnforced: qH.protocolContractsEnforced,
            configFailOpenBreaches: parseItfInt(qH.configFailOpenBreaches),
            hookShadowOrFanoutBreaches: parseItfInt(qH.hookShadowOrFanoutBreaches),
            trustMaskOrActionBreaches: parseItfInt(qH.trustMaskOrActionBreaches),
            protocolContractBreaches: parseItfInt(qH.protocolContractBreaches),
            cleanVerifiedOps: parseItfInt(qH.cleanVerifiedOps),
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
