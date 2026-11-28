// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 34 (B11, 10.182): Deterministic MCP / Tool-Sandbox & RPC Schema-Boundary Engine.
 *
 * Runtime implementation paired with `ToolSandboxAndRpcBoundary.lean`:
 *   1. Immutable M1 Tool Manifest Pinning (blocks shadow tools & MCP schema rug-pulls).
 *   2. 10th R3 Non-Leakable M3 Capability (`ToolSandboxCapability`, narrowed scopes & epoch).
 *   3. Side-Effecting Idempotency Enforcement & `PendingUnknownEffect` RPC Timeout Fence.
 *   4. Response-Size Ceiling & Mandatory `B7` `UntrustedExternal` Taint Tagging.
 */

import {
  assertM1Persistable,
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

/**
 * 10th R3 non-serializable M3 capability class: live sandbox handle confining an
 * agent's MCP/RPC egress & filesystem scopes. Mechanically blocked from entering M1.
 */
export class ToolSandboxCapability {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly allowedScopes: readonly string[];

  constructor(
    readonly agentId: string,
    allowedScopes: readonly string[],
    readonly revocationEpoch: number,
  ) {
    this.capabilityId = `tool-sandbox:${agentId}:ep${revocationEpoch}`;
    this.allowedScopes = [...allowedScopes].sort();
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: ToolSandboxCapability '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export interface PinnedMcpToolEntry {
  toolId: string;
  pinnedSchemaHash: string;
  allowedScopes: string[];
  maxOutputBytes: number;
  isSideEffecting: boolean;
  manifestMerkleHash: string;
}

export interface ToolExecutionOutcome {
  kind: 'Completed' | 'TimedOutAmbiguous';
  outputText?: string;
}

export type ToolInvocationVerdict =
  | {
      kind: 'Proven';
      toolId: string;
      outputText: string;
      outputBytes: number;
      integrityLabel: 'UntrustedExternal';
      receiptMerkleHash: string;
    }
  | {
      kind: 'PendingUnknownEffect';
      toolId: string;
      idempotencyKey: string;
      reason: 'rpc-timeout-unreconciled';
    }
  | {
      kind: 'Refuted';
      reason:
        | 'unpinned-shadow-tool'
        | 'mcp-schema-rug-pull-detected'
        | 'sandbox-capability-revoked'
        | 'sandbox-scope-escalation'
        | 'missing-idempotency-key-for-side-effect'
        | 'oversized-tool-output-blocked';
      detail?: string;
    };

export class DeterministicToolSandboxEngine {
  private readonly pinnedTools = new Map<string, PinnedMcpToolEntry>();
  private readonly unreconciledTimeouts = new Map<string, string>(); // key: toolId::idempotencyKey
  private minActiveLeaseEpoch = 1;

  constructor(private readonly kv: ContentAddressedKvStore) {}

  advanceMinLeaseEpoch(nextEpoch: number): void {
    if (nextEpoch > this.minActiveLeaseEpoch) {
      this.minActiveLeaseEpoch = nextEpoch;
    }
  }

  pinToolManifest(params: {
    toolId: string;
    schemaDefinition: Record<string, unknown>;
    allowedScopes: readonly string[];
    maxOutputBytes: number;
    isSideEffecting: boolean;
  }): PinnedMcpToolEntry {
    assertM1Persistable(params.schemaDefinition, `mcp-schema(${params.toolId})`);
    const pinnedSchemaHash = sha256Digest({
      toolId: params.toolId,
      schemaDefinition: params.schemaDefinition,
    });
    const allowedScopes = [...params.allowedScopes].sort();
    const manifestMerkleHash = this.kv.putBlob(
      'pinned-mcp-tool-manifest',
      {
        toolId: params.toolId,
        pinnedSchemaHash,
        allowedScopes,
        maxOutputBytes: params.maxOutputBytes,
        isSideEffecting: params.isSideEffecting,
      },
      [],
    );
    this.kv.pinHistoricalCut(manifestMerkleHash);

    const entry: PinnedMcpToolEntry = {
      toolId: params.toolId,
      pinnedSchemaHash,
      allowedScopes,
      maxOutputBytes: params.maxOutputBytes,
      isSideEffecting: params.isSideEffecting,
      manifestMerkleHash,
    };
    this.pinnedTools.set(params.toolId, entry);
    return {...entry};
  }

  reconcileTimedOutCall(params: {
    toolId: string;
    idempotencyKey: string;
    reconciliationEvidenceDigest: string;
  }): {reconciled: boolean; receiptMerkleHash: string} {
    const key = `${params.toolId}::${params.idempotencyKey}`;
    const existed = this.unreconciledTimeouts.delete(key);
    const receiptMerkleHash = this.kv.putBlob(
      'rpc-timeout-reconciliation',
      {
        toolId: params.toolId,
        idempotencyKey: params.idempotencyKey,
        reconciliationEvidenceDigest: params.reconciliationEvidenceDigest,
        clearedPendingFence: existed,
      },
      [],
    );
    this.kv.pinHistoricalCut(receiptMerkleHash);
    return {reconciled: existed, receiptMerkleHash};
  }

  invokeTool(params: {
    toolId: string;
    observedSchemaDefinition: Record<string, unknown>;
    requestedScopes: readonly string[];
    sandboxCap: ToolSandboxCapability;
    idempotencyKey?: string;
    executeRpc: () => ToolExecutionOutcome;
  }): ToolInvocationVerdict {
    const pinned = this.pinnedTools.get(params.toolId);
    if (!pinned) {
      return {kind: 'Refuted', reason: 'unpinned-shadow-tool', detail: params.toolId};
    }

    const observedSchemaHash = sha256Digest({
      toolId: params.toolId,
      schemaDefinition: params.observedSchemaDefinition,
    });
    if (observedSchemaHash !== pinned.pinnedSchemaHash) {
      return {
        kind: 'Refuted',
        reason: 'mcp-schema-rug-pull-detected',
        detail: `expected=${pinned.pinnedSchemaHash.slice(0, 12)} observed=${observedSchemaHash.slice(0, 12)}`,
      };
    }

    if (params.sandboxCap.revocationEpoch < this.minActiveLeaseEpoch) {
      return {kind: 'Refuted', reason: 'sandbox-capability-revoked'};
    }

    // Requested scopes must be contained in BOTH the pinned tool manifest AND the agent's M3 sandbox cap:
    for (const s of params.requestedScopes) {
      if (!pinned.allowedScopes.includes(s) || !params.sandboxCap.allowedScopes.includes(s)) {
        return {kind: 'Refuted', reason: 'sandbox-scope-escalation', detail: s};
      }
    }

    if (pinned.isSideEffecting && !params.idempotencyKey) {
      return {kind: 'Refuted', reason: 'missing-idempotency-key-for-side-effect'};
    }

    const effectiveKey = params.idempotencyKey ?? 'read-only';
    const timeoutKey = `${params.toolId}::${effectiveKey}`;
    if (this.unreconciledTimeouts.has(timeoutKey)) {
      return {
        kind: 'PendingUnknownEffect',
        toolId: params.toolId,
        idempotencyKey: effectiveKey,
        reason: 'rpc-timeout-unreconciled',
      };
    }

    const outcome = params.executeRpc();
    if (outcome.kind === 'TimedOutAmbiguous') {
      this.unreconciledTimeouts.set(timeoutKey, 'rpc-timeout-unreconciled');
      return {
        kind: 'PendingUnknownEffect',
        toolId: params.toolId,
        idempotencyKey: effectiveKey,
        reason: 'rpc-timeout-unreconciled',
      };
    }

    const outputText = outcome.outputText ?? '';
    const outputBytes = Buffer.byteLength(outputText, 'utf8');
    if (outputBytes > pinned.maxOutputBytes) {
      return {
        kind: 'Refuted',
        reason: 'oversized-tool-output-blocked',
        detail: `${outputBytes} > ${pinned.maxOutputBytes}`,
      };
    }

    const receiptMerkleHash = this.kv.putBlob(
      'mcp-tool-invocation-receipt',
      {
        toolId: params.toolId,
        pinnedSchemaHash: pinned.pinnedSchemaHash,
        requestedScopes: [...params.requestedScopes].sort(),
        outputBytes,
        outputDigest: sha256Digest(outputText),
        integrityLabel: 'UntrustedExternal' as const,
      },
      [pinned.manifestMerkleHash],
    );
    this.kv.pinHistoricalCut(receiptMerkleHash);

    return {
      kind: 'Proven',
      toolId: params.toolId,
      outputText,
      outputBytes,
      integrityLabel: 'UntrustedExternal',
      receiptMerkleHash,
    };
  }
}
