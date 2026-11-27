// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from '../src/durable-merkle-store.ts';
import {arbitrateConcurrentWorkspaces} from '../src/symbol-ssi-arbitrator.ts';

describe('Phase 13 Automated AST Symbol-Level ReadSet x WriteSet SSI Arbitrator (10.161 / 30.05 AG71-AG75)', () => {
  test('AG71: Automatic TS AST extraction catches disjoint-file semantic write-skew with zero manual ReadSet declarations', () => {
    const kv = new ContentAddressedKvStore();
    const baseFiles = {
      'src/auth-types.ts': `
        export interface AuthSession {
          userId: string;
          expiresAt: number;
        }
      `,
      'src/session-handler.ts': `
        import {AuthSession} from './auth-types';
        export function isExpired(s: AuthSession, now: number): boolean {
          return now > s.expiresAt;
        }
      `,
    };

    // Agent A renames `expiresAt` -> `expiresAtMs` in `src/auth-types.ts`
    const agentA = {
      agentId: 'agent-types-refactor',
      fencingEpoch: 5,
      modifiedFiles: {
        'src/auth-types.ts': `
          export interface AuthSession {
            userId: string;
            expiresAtMs: number;
          }
        `,
      },
    };

    // Agent B concurrently modifies `src/session-handler.ts` reading old `AuthSession`!
    // Git 3-way merge sees 0 file overlap, yet symbol SSI catches `rw` write-skew!
    const agentB = {
      agentId: 'agent-session-feature',
      fencingEpoch: 5,
      modifiedFiles: {
        'src/session-handler.ts': `
          import {AuthSession} from './auth-types';
          export function isExpired(s: AuthSession, now: number): boolean {
            return now >= s.expiresAt;
          }
        `,
      },
    };

    const res = arbitrateConcurrentWorkspaces({
      baseFiles,
      proposals: [agentA, agentB],
      activeLeaseEpoch: 5,
      kv,
    });

    expect(res.verdict).toBe('PartialAdmitWithBoundedRevalidation');
    expect(res.wwConflicts).toEqual([]);
    expect(res.admittedAgents).toEqual(['agent-types-refactor']);
    expect(res.rwEdges.length).toBe(1);
    expect(res.rwEdges[0]?.symbolId).toBe('src/auth-types.ts::AuthSession');
    expect(res.rwEdges[0]?.changeKind).toBe('signature-or-contract');
    expect(res.rwEdges[0]?.staleReaderAgent).toBe('agent-session-feature');
    expect(res.revalidationPackets.length).toBe(1);
    expect(res.revalidationPackets[0]?.targetAgentId).toBe('agent-session-feature');
    expect(kv.hasBlob(res.revalidationPackets[0]!.packetMerkleHash)).toBe(true);
  });

  test('AG72: Cyclic SSI write-skew (A reads B & writes A; B reads A & writes B) blocks both sides cleanly', () => {
    const kv = new ContentAddressedKvStore();
    const baseFiles = {
      'src/pricing.ts': `
        import {computeTax} from './tax';
        export function calcTotal(net: number): number {
          return net + computeTax(net);
        }
      `,
      'src/tax.ts': `
        import {calcTotal} from './pricing';
        export function computeTax(net: number): number {
          return Math.round(net * 0.1);
        }
        export function effectiveRate(net: number): number {
          return computeTax(net) / calcTotal(net);
        }
      `,
    };

    const agentPricing = {
      agentId: 'agent-pricing',
      fencingEpoch: 2,
      modifiedFiles: {
        'src/pricing.ts': `
          import {computeTax} from './tax';
          export function calcTotal(net: number, discount: number): number {
            return net - discount + computeTax(net - discount);
          }
        `,
      },
    };

    const agentTax = {
      agentId: 'agent-tax',
      fencingEpoch: 2,
      modifiedFiles: {
        'src/tax.ts': `
          import {calcTotal} from './pricing';
          export function computeTax(net: number, region: string): number {
            return region === 'EU' ? Math.round(net * 0.2) : Math.round(net * 0.1);
          }
          export function effectiveRate(net: number): number {
            return computeTax(net, 'US') / calcTotal(net);
          }
        `,
      },
    };

    const res = arbitrateConcurrentWorkspaces({
      baseFiles,
      proposals: [agentPricing, agentTax],
      activeLeaseEpoch: 2,
      kv,
    });

    expect(res.verdict).toBe('ConflictOrCycleBlocked');
    expect(res.admittedAgents).toEqual([]);
    expect(res.cyclicAgents).toEqual(['agent-pricing', 'agent-tax']);
    expect(res.rwEdges.every(e => e.cyclic)).toBe(true);
    expect(res.revalidationPackets.length).toBe(2);
    expect(res.revalidationPackets.every(p => p.reason === 'cyclic-semantic-write-skew')).toBe(true);
  });

  test('AG73: Bounded DE01 partial admission in 3-agent swarm admits independent Agent C and upstream A while revalidating ONLY B', () => {
    const kv = new ContentAddressedKvStore();
    const baseFiles = {
      'src/config.ts': `export const MAX_RETRIES = 3;`,
      'src/worker.ts': `
        import {MAX_RETRIES} from './config';
        export function retryLimit(): number { return MAX_RETRIES; }
      `,
      'src/docs-renderer.ts': `export function renderTitle(s: string): string { return s; }`,
    };

    const agentA = {
      agentId: 'agent-config',
      fencingEpoch: 7,
      modifiedFiles: {
        'src/config.ts': `export const MAX_RETRIES = 0;`,
      },
    };
    const agentB = {
      agentId: 'agent-worker',
      fencingEpoch: 7,
      modifiedFiles: {
        'src/worker.ts': `
          import {MAX_RETRIES} from './config';
          export function retryLimit(): number { return MAX_RETRIES + 1; }
        `,
      },
    };
    const agentC = {
      agentId: 'agent-docs',
      fencingEpoch: 7,
      modifiedFiles: {
        'src/docs-renderer.ts': `export function renderTitle(s: string): string { return s.toUpperCase(); }`,
      },
    };

    const res = arbitrateConcurrentWorkspaces({
      baseFiles,
      proposals: [agentA, agentB, agentC],
      activeLeaseEpoch: 7,
      kv,
    });

    expect(res.verdict).toBe('PartialAdmitWithBoundedRevalidation');
    expect(res.admittedAgents).toEqual(['agent-config', 'agent-docs']);
    expect(res.revalidationPackets.map(p => p.targetAgentId)).toEqual(['agent-worker']);
    // Independent Agent C's change is cleanly merged without unnecessary purge!
    expect(res.mergedFiles['src/docs-renderer.ts']).toContain('toUpperCase');
    // Stale Agent B's change is held back pending revalidation against MAX_RETRIES = 0
    expect(res.mergedFiles['src/worker.ts']).not.toContain('MAX_RETRIES + 1');
  });

  test('AG74: Gerbil Scheme POO automatic extractor detects cross-file .ss symbol write-skew', () => {
    const kv = new ContentAddressedKvStore();
    const baseFiles = {
      'lib/types.ss': `
        (export PolicyFloor)
        (.def PolicyFloor
          require-witness?: #t
          max-depth: 6)
      `,
      'lib/checker.ss': `
        (import (only-in "types.ss" PolicyFloor))
        (export check-policy)
        (def (check-policy cfg)
          (.get PolicyFloor require-witness?))
      `,
    };

    const agentSchema = {
      agentId: 'scheme-schema-agent',
      fencingEpoch: 3,
      modifiedFiles: {
        'lib/types.ss': `
          (export PolicyFloor)
          (.def PolicyFloor
            require-use-time-witness?: #t
            max-depth: 10)
        `,
      },
    };

    const agentChecker = {
      agentId: 'scheme-checker-agent',
      fencingEpoch: 3,
      modifiedFiles: {
        'lib/checker.ss': `
          (import (only-in "types.ss" PolicyFloor))
          (export check-policy)
          (def (check-policy cfg)
            (and cfg (.get PolicyFloor require-witness?)))
        `,
      },
    };

    const res = arbitrateConcurrentWorkspaces({
      baseFiles,
      proposals: [agentSchema, agentChecker],
      activeLeaseEpoch: 3,
      kv,
    });

    expect(res.verdict).toBe('PartialAdmitWithBoundedRevalidation');
    expect(res.admittedAgents).toEqual(['scheme-schema-agent']);
    expect(res.rwEdges.length).toBe(1);
    expect(res.rwEdges[0]?.symbolId).toBe('lib/types.ss::PolicyFloor');
    expect(res.revalidationPackets[0]?.targetAgentId).toBe('scheme-checker-agent');
  });

  test('AG75: Stale M3 lease fencing isolates zombie workers and direct ww edits refuse silent LWW', () => {
    const kv = new ContentAddressedKvStore();
    const baseFiles = {
      'src/shared.ts': `export const VERSION = 1;`,
      'src/clean.ts': `export const FLAG = false;`,
    };

    const zombieWorker = {
      agentId: 'zombie-epoch-1',
      fencingEpoch: 1, // stale epoch!
      modifiedFiles: {
        'src/clean.ts': `export const FLAG = true;`,
      },
    };
    const peerA = {
      agentId: 'peer-a',
      fencingEpoch: 4,
      modifiedFiles: {
        'src/shared.ts': `export const VERSION = 2;`,
      },
    };
    const peerB = {
      agentId: 'peer-b',
      fencingEpoch: 4,
      modifiedFiles: {
        'src/shared.ts': `export const VERSION = 3;`,
      },
    };

    const res = arbitrateConcurrentWorkspaces({
      baseFiles,
      proposals: [zombieWorker, peerA, peerB],
      activeLeaseEpoch: 4,
      kv,
    });

    expect(res.verdict).toBe('ConflictOrCycleBlocked');
    expect(res.fencedAgents).toEqual([
      {agentId: 'zombie-epoch-1', expectedEpoch: 4, actualEpoch: 1},
    ]);
    expect(res.wwConflicts).toEqual([
      {filePath: 'src/shared.ts', agents: ['peer-a', 'peer-b']},
    ]);
    // Neither silent LWW nor zombie overwrite mutates `mergedFiles`:
    expect(res.mergedFiles['src/shared.ts']).toBe('export const VERSION = 1;');
    expect(res.mergedFiles['src/clean.ts']).toBe('export const FLAG = false;');
  });
});
