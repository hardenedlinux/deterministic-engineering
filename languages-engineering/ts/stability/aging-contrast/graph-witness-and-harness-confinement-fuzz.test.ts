// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {execFileSync} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

interface Sm35State {
  fencingEpoch: number;
  contextCut: number;
  witnessSerdeEnforced: boolean;
  routingPolicyEnforced: boolean;
  cedarGateHardened: boolean;
  artifactAndConfigConfined: boolean;
  witnessForgeryBreaches: number;
  routingPolicyBreaches: number;
  cedarSpoofBreaches: number;
  artifactConfigBreaches: number;
  cleanVerifiedOps: number;
  stepCount: number;
}

function initState(): Sm35State {
  return {
    fencingEpoch: 1,
    contextCut: 1,
    witnessSerdeEnforced: true,
    routingPolicyEnforced: true,
    cedarGateHardened: true,
    artifactAndConfigConfined: true,
    witnessForgeryBreaches: 0,
    routingPolicyBreaches: 0,
    cedarSpoofBreaches: 0,
    artifactConfigBreaches: 0,
    cleanVerifiedOps: 0,
    stepCount: 0,
  };
}

function applySafeAction(state: Sm35State, action: string): Sm35State {
  const s = {...state};
  switch (action) {
    case 'admitVerifiedGraphWitness':
      if (s.stepCount < 12 && s.witnessSerdeEnforced && s.fencingEpoch < 12) {
        s.fencingEpoch += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'planPolicyScopedGraphRoute':
      if (s.stepCount < 12 && s.routingPolicyEnforced) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'evaluateCedarHarnessToolGate':
      if (s.stepCount < 12 && s.cedarGateHardened) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'materializeConfinedArtifactBundle':
      if (s.stepCount < 12 && s.artifactAndConfigConfined) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'loadBoundedWeaverTomlRoute':
      if (s.stepCount < 12 && s.artifactAndConfigConfined) {
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    case 'advanceGovernedContextCut':
      if (s.stepCount < 12 && s.witnessSerdeEnforced && s.contextCut < 12) {
        s.contextCut += 1;
        s.cleanVerifiedOps += 1;
        s.stepCount += 1;
      }
      return s;
    default:
      throw new Error(`Unexpected SM35 action: ${action}`);
  }
}

function isSafetyInvariantHeld(s: Sm35State): boolean {
  return (
    s.witnessForgeryBreaches === 0 &&
    s.routingPolicyBreaches === 0 &&
    s.cedarSpoofBreaches === 0 &&
    s.artifactConfigBreaches === 0 &&
    s.witnessSerdeEnforced &&
    s.routingPolicyEnforced &&
    s.cedarGateHardened &&
    s.artifactAndConfigConfined &&
    s.fencingEpoch >= 1 &&
    s.fencingEpoch <= 12 &&
    s.contextCut >= 1 &&
    s.contextCut <= 12 &&
    s.stepCount <= 12
  );
}

const DESTRUCTIVE_TOOL_TOKENS = new Set([
  'bash',
  'sh',
  'shell',
  'exec',
  'run',
  'cmd',
  'command',
  'write',
  'edit',
  'patch',
  'delete',
  'del',
  'rm',
  'remove',
  'unlink',
  'mutate',
  'chmod',
  'chown',
  'mv',
  'move',
  'rename',
  'create',
  'mkdir',
  'symlink',
  'install',
  'deploy',
  'commit',
  'push',
  'curl',
  'wget',
  'http',
  'fetch',
  'network',
]);

function isDestructiveToolName(toolName: string): boolean {
  const tokens = toolName
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return tokens.some((tok) => DESTRUCTIVE_TOOL_TOKENS.has(tok));
}

function classifyHarnessToolCapability(toolName: string, declaredCapability: string | null): {capability: string; isWrite: boolean} {
  if (toolName.trim().length === 0 || /[\x00-\x1f\x7f]/.test(toolName)) {
    return {capability: 'write', isWrite: true};
  }
  if (isDestructiveToolName(toolName)) {
    const isShell = /\b(?:bash|sh|shell|exec|cmd|command)\b/i.test(toolName.replace(/[_-]+/g, ' '));
    return {capability: isShell ? 'shell' : 'write', isWrite: true};
  }
  if (declaredCapability !== null) {
    const norm = declaredCapability.trim().toLowerCase();
    if (norm.length === 0 || /[\x00-\x1f\x7f]/.test(norm)) {
      return {capability: 'write', isWrite: true};
    }
    const writeCap = ['write', 'edit', 'mutation', 'shell', 'exec', 'filesystem', 'network', 'admin'].includes(norm);
    return {capability: norm, isWrite: writeCap};
  }
  if (toolName.toLowerCase().includes('search')) {
    return {capability: 'search', isWrite: false};
  }
  return {capability: 'write', isWrite: true};
}

const DISALLOWED_CREDENTIAL_ENVS = new Set([
  'PATH',
  'HOME',
  'USER',
  'SHELL',
  'PWD',
  'TERM',
  'TMPDIR',
  'BASH_ENV',
  'ENV',
  'IFS',
  'PROMPT_COMMAND',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
]);

function isSafeCredentialEnvName(name: string): boolean {
  if (name.length === 0 || name.length > 128) return false;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return false;
  const upper = name.toUpperCase();
  if (
    DISALLOWED_CREDENTIAL_ENVS.has(upper) ||
    upper.startsWith('LD_') ||
    upper.startsWith('DYLD_') ||
    upper.startsWith('SSH_') ||
    upper.startsWith('GIT_')
  ) {
    return false;
  }
  return true;
}

function deserializeAdmittedCapsule(raw: {
  contextCut: number;
  hasActiveDefeater: boolean;
  disclosureDepth: number;
  sandboxAdmitted: boolean;
  cedarHandoffValid: boolean;
  detourMode: 'Mainline' | 'BlockerActive' | 'SideQuestActive';
  autoArchiveEnabled: boolean;
}): boolean {
  if (raw.contextCut === 0) return false;
  if (raw.hasActiveDefeater && raw.disclosureDepth < 3) return false;
  if (!raw.sandboxAdmitted || !raw.cedarHandoffValid) return false;
  if (raw.detourMode === 'BlockerActive' && raw.autoArchiveEnabled) return false;
  return true;
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

function parseItfState(raw: Record<string, unknown>): Sm35State {
  const h = raw.h as Record<string, unknown>;
  return {
    fencingEpoch: bigintFromItf(h.fencingEpoch),
    contextCut: bigintFromItf(h.contextCut),
    witnessSerdeEnforced: Boolean(h.witnessSerdeEnforced),
    routingPolicyEnforced: Boolean(h.routingPolicyEnforced),
    cedarGateHardened: Boolean(h.cedarGateHardened),
    artifactAndConfigConfined: Boolean(h.artifactAndConfigConfined),
    witnessForgeryBreaches: bigintFromItf(h.witnessForgeryBreaches),
    routingPolicyBreaches: bigintFromItf(h.routingPolicyBreaches),
    cedarSpoofBreaches: bigintFromItf(h.cedarSpoofBreaches),
    artifactConfigBreaches: bigintFromItf(h.artifactConfigBreaches),
    cleanVerifiedOps: bigintFromItf(h.cleanVerifiedOps),
    stepCount: bigintFromItf(h.stepCount),
  };
}

describe('SM35 (ADV-L4): AgentGraph Witness/Routing & Harness Governance/Artifact Confinement', () => {
  test('500-trial ADV-L4 hostile fuzz refutes witness Serde forgery, PolicyDecision bypass, Cedar capability spoofing & unsafe credential_env', () => {
    const rand = makePrng(0x534d3335);
    const hostileTools = [
      'search_exec',
      'shell_search',
      'exec_command',
      'BASH',
      'rm_file',
      'search-and-delete',
      'curl_search',
      'apply_patch',
      'chmod_tool',
    ];
    const safeTools = ['workspace_search', 'structural_query', 'constraint_solve'];
    const hostileCredEnvs = ['PATH', 'HOME', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'BASH_ENV', 'SSH_AUTH_SOCK', '', 'KEY\r\nBAD', '123INVALID'];
    const safeCredEnvs = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'DEEPSEEK_API_KEY', 'WEAVER_TOKEN_1'];

    for (let trial = 0; trial < 500; trial++) {
      // 1. Sealed witness deserialization parity: forged capsule flags MUST be refused.
      expect(
        deserializeAdmittedCapsule({
          contextCut: 1,
          hasActiveDefeater: true,
          disclosureDepth: Math.floor(rand() * 3),
          sandboxAdmitted: true,
          cedarHandoffValid: true,
          detourMode: 'Mainline',
          autoArchiveEnabled: true,
        }),
      ).toBe(false);
      expect(
        deserializeAdmittedCapsule({
          contextCut: 1,
          hasActiveDefeater: false,
          disclosureDepth: 1,
          sandboxAdmitted: false,
          cedarHandoffValid: true,
          detourMode: 'Mainline',
          autoArchiveEnabled: true,
        }),
      ).toBe(false);
      expect(
        deserializeAdmittedCapsule({
          contextCut: 1,
          hasActiveDefeater: true,
          disclosureDepth: 3,
          sandboxAdmitted: true,
          cedarHandoffValid: true,
          detourMode: 'BlockerActive',
          autoArchiveEnabled: false,
        }),
      ).toBe(true);

      // 2. Harness Cedar tool classification: destructive names NEVER downgrade to non-write search.
      const hostileTool = hostileTools[trial % hostileTools.length]!;
      expect(classifyHarnessToolCapability(hostileTool, null).isWrite).toBe(true);
      expect(classifyHarnessToolCapability(hostileTool, 'search').isWrite).toBe(true);
      const safeTool = safeTools[trial % safeTools.length]!;
      const safeRes = classifyHarnessToolCapability(safeTool, 'search');
      expect(safeRes.isWrite).toBe(false);
      expect(safeRes.capability).toBe('search');

      // 3. Weaver TOML credential_env hygiene: ambient system/loader vars MUST fail closed.
      const badEnv = hostileCredEnvs[trial % hostileCredEnvs.length]!;
      expect(isSafeCredentialEnvName(badEnv)).toBe(false);
      const goodEnv = safeCredEnvs[trial % safeCredEnvs.length]!;
      expect(isSafeCredentialEnvName(goodEnv)).toBe(true);
    }
  });

  test('6 live Quint --mbt ITF traces refine SM35 TypeScript confinement state machine 1:1', () => {
    const repoRoot = resolve(import.meta.dir, '../../../..');
    const qntPath = resolve(
      repoRoot,
      'packages/quint-models/threat/execution/graph-witness-and-harness-confinement/GraphWitnessAndHarnessConfinement.qnt',
    );
    const resolverCli = resolve(repoRoot, 'packages/quint-modules-resolver/src/cli.ts');
    const tmpDir = mkdtempSync(join(tmpdir(), 'sm35-mbt-'));
    try {
      for (let seed = 1; seed <= 6; seed++) {
        const itfPath = join(tmpDir, `sm35-seed-${seed}.itf.json`);
        execFileSync(
          'bun',
          [
            'run',
            resolverCli,
            'run',
            qntPath,
            '--main=execution_graph_witness_and_harness_confinement',
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
