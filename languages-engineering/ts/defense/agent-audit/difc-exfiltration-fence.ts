// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 16 (Business Extension B7, 10.164):
 * Decentralized Information Flow Control (DIFC), CaMeL Control-Flow Integrity,
 * and Exfiltration Confinement for Tool-Calling AI Agents.
 *
 * Grounded in:
 *   - Bell-LaPadula (1973) Confidentiality Lattice & Biba (1977) Integrity Lattice
 *   - A. C. Myers & B. Liskov (SOSP 1997) — Decentralized IFC (DIFC)
 *   - N. Zeldovich et al. (OSDI 2006) — HiStar explicit declassification capabilities
 *   - E. Debenedetti et al. (Google DeepMind 2025) — CaMeL (Defeating Prompt Injections by Design)
 *
 * Closes the "Lethal Trifecta" (Private Data + Untrusted External Input + External Sink)
 * that capability checks alone cannot stop:
 *   1. Immutable M1 `TaintedValue<T>` envelopes carry monotonic `secrecyTags` (union)
 *      and `integrity` (meet: TrustedSystem > VerifiedInternal > UntrustedExternal).
 *   2. Sink Clearance Gate enforces BOTH:
 *        - Confidentiality (`payload.secrecyTags ⊆ sink.allowedSecrecyTags`),
 *        - CaMeL Control-Flow Integrity (`controlArg.integrity >= sink.minControlIntegrity`).
 *   3. Non-Serializable M3 `DeclassificationCapability` (R3 branded) is required to clear
 *      any secrecy tag, paired with a mandatory deterministic redaction sanitizer and an
 *      immutable M1 `DeclassificationAuditReceipt`.
 */

import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
} from './durable-merkle-store.ts';

export type IntegrityLevel = 'UntrustedExternal' | 'VerifiedInternal' | 'TrustedSystem';

const INTEGRITY_RANK: Record<IntegrityLevel, number> = {
  UntrustedExternal: 0,
  VerifiedInternal: 1,
  TrustedSystem: 2,
};

function meetIntegrity(levels: IntegrityLevel[]): IntegrityLevel {
  let minRank = 2;
  let result: IntegrityLevel = 'TrustedSystem';
  for (const lvl of levels) {
    const r = INTEGRITY_RANK[lvl];
    if (r < minRank) {
      minRank = r;
      result = lvl;
    }
  }
  return result;
}

export interface TaintedValue<T = unknown> {
  readonly valueId: string;
  readonly value: T;
  /** Confidentiality tags (Bell-LaPadula set; empty = Public) */
  readonly secrecyTags: readonly string[];
  /** Integrity tier (Biba / CaMeL) */
  readonly integrity: IntegrityLevel;
  readonly sourcePrincipal: string;
  readonly parentValueHashes: readonly string[];
  readonly valueMerkleHash: string;
}

export interface ToolSinkPolicy {
  sinkId: string;
  /** Secrecy tags permitted to leave via this sink (empty = Public sink) */
  allowedSecrecyTags: readonly string[];
  /** Minimum integrity required for control parameters (URL, recipient, command, path) */
  minControlIntegrity: IntegrityLevel;
}

/**
 * R3 Non-Serializable live M3 capability granting narrow declassification authority
 * over an explicit set of secrecy tags. Cannot be serialized into M1 Merkle blobs!
 */
export class DeclassificationCapability {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;
  readonly removableTags: ReadonlySet<string>;

  constructor(
    readonly authorityId: string,
    removableTags: readonly string[],
  ) {
    this.capabilityId = `difc-declassify-cap:${authorityId}`;
    this.removableTags = new Set(removableTags);
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: DeclassificationCapability '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

export type DeclassificationVerdict<T> =
  | {
      kind: 'Declassified';
      value: TaintedValue<T>;
      auditReceiptHash: string;
      removedTags: string[];
    }
  | {
      kind: 'Refuted';
      reason: 'unauthorized-declassification-tag' | 'declassification-sanitizer-failed';
      blockedTags?: string[];
      sanitizerDetail?: string;
    };

export type SinkDispatchVerdict =
  | {
      kind: 'Allowed';
      sinkAuditReceiptHash: string;
      sinkId: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'secret-exfiltration-blocked'
        | 'cross-tenant-flow-blocked'
        | 'untrusted-control-flow-hijack';
      disallowedTags?: string[];
      actualControlIntegrity?: IntegrityLevel;
      requiredControlIntegrity?: IntegrityLevel;
    };

export class DifcAgentMonitor {
  constructor(private readonly kv: ContentAddressedKvStore) {}

  ingestData<T>(params: {
    valueId: string;
    value: T;
    secrecyTags: readonly string[];
    integrity: IntegrityLevel;
    sourcePrincipal: string;
  }): TaintedValue<T> {
    const sortedTags = [...new Set(params.secrecyTags)].sort();
    const valueMerkleHash = this.kv.putBlob(
      'difc-tainted-value',
      {
        valueId: params.valueId,
        secrecyTags: sortedTags,
        integrity: params.integrity,
        sourcePrincipal: params.sourcePrincipal,
        parentValueHashes: [],
      },
      [],
    );
    this.kv.pinHistoricalCut(valueMerkleHash);

    return {
      valueId: params.valueId,
      value: params.value,
      secrecyTags: sortedTags,
      integrity: params.integrity,
      sourcePrincipal: params.sourcePrincipal,
      parentValueHashes: [],
      valueMerkleHash,
    };
  }

  /**
   * Monotonic dual-lattice join across multiple inputs (e.g. LLM synthesis combining
   * a private repo secret and an untrusted web issue):
   *   - Secrecy = Union of all input secrecy tags (never drops a secret tag!)
   *   - Integrity = Meet (minimum) of all input integrity levels (never upgrades untrusted!)
   */
  deriveValue<T>(params: {
    valueId: string;
    inputs: readonly TaintedValue<unknown>[];
    derivedValue: T;
    derivedBy: string;
  }): TaintedValue<T> {
    const unionTags = new Set<string>();
    const integrities: IntegrityLevel[] = [];
    const parentHashes: string[] = [];

    for (const inp of params.inputs) {
      for (const tag of inp.secrecyTags) unionTags.add(tag);
      integrities.push(inp.integrity);
      parentHashes.push(inp.valueMerkleHash);
    }

    const sortedTags = [...unionTags].sort();
    const integrity = integrities.length > 0 ? meetIntegrity(integrities) : 'TrustedSystem';
    const valueMerkleHash = this.kv.putBlob(
      'difc-derived-value',
      {
        valueId: params.valueId,
        secrecyTags: sortedTags,
        integrity,
        derivedBy: params.derivedBy,
        parentValueHashes: parentHashes,
      },
      parentHashes,
    );
    this.kv.pinHistoricalCut(valueMerkleHash);

    return {
      valueId: params.valueId,
      value: params.derivedValue,
      secrecyTags: sortedTags,
      integrity,
      sourcePrincipal: params.derivedBy,
      parentValueHashes: parentHashes,
      valueMerkleHash,
    };
  }

  /**
   * Explicit audited declassification (Myers & Liskov 1997 / HiStar):
   * Requires a live M3 `DeclassificationCapability` authorizing EVERY tag being removed
   * PLUS a deterministic sanitizer predicate verifying no forbidden secret tokens remain.
   */
  declassify<T>(params: {
    source: TaintedValue<unknown>;
    redactedValue: T;
    tagsToRemove: readonly string[];
    capability: DeclassificationCapability;
    deterministicSanitizer: (candidate: T) => {clean: boolean; detail?: string};
  }): DeclassificationVerdict<T> {
    const unauthorized = params.tagsToRemove.filter(t => !params.capability.removableTags.has(t));
    if (unauthorized.length > 0) {
      return {
        kind: 'Refuted',
        reason: 'unauthorized-declassification-tag',
        blockedTags: [...unauthorized].sort(),
      };
    }

    const check = params.deterministicSanitizer(params.redactedValue);
    if (!check.clean) {
      return {
        kind: 'Refuted',
        reason: 'declassification-sanitizer-failed',
        sanitizerDetail: check.detail ?? 'sanitizer-rejected-candidate',
      };
    }

    const removeSet = new Set(params.tagsToRemove);
    const remainingTags = params.source.secrecyTags.filter(t => !removeSet.has(t));
    const removedTags = params.source.secrecyTags.filter(t => removeSet.has(t));

    const newHash = this.kv.putBlob(
      'difc-declassified-value',
      {
        valueId: `${params.source.valueId}:declassified`,
        remainingSecrecyTags: remainingTags,
        removedTags,
        integrity: params.source.integrity,
        declassifiedBy: params.capability.authorityId,
        sourceValueHash: params.source.valueMerkleHash,
      },
      [params.source.valueMerkleHash],
    );
    this.kv.pinHistoricalCut(newHash);

    const auditReceiptHash = this.kv.putBlob(
      'difc-declassification-audit-receipt',
      {
        sourceValueHash: params.source.valueMerkleHash,
        declassifiedValueHash: newHash,
        authorityId: params.capability.authorityId,
        removedTags,
      },
      [params.source.valueMerkleHash, newHash],
    );
    this.kv.pinHistoricalCut(auditReceiptHash);

    return {
      kind: 'Declassified',
      auditReceiptHash,
      removedTags,
      value: {
        valueId: `${params.source.valueId}:declassified`,
        value: params.redactedValue,
        secrecyTags: remainingTags,
        integrity: params.source.integrity,
        sourcePrincipal: params.capability.authorityId,
        parentValueHashes: [params.source.valueMerkleHash],
        valueMerkleHash: newHash,
      },
    };
  }

  /**
   * Sink Clearance Gate enforcing BOTH:
   *   1. CaMeL Control-Flow Integrity (`controlArg.integrity >= sink.minControlIntegrity`),
   *   2. Bell-LaPadula / DIFC No-Write-Down (`payload.secrecyTags ⊆ sink.allowedSecrecyTags`).
   */
  dispatchToToolSink(params: {
    sink: ToolSinkPolicy;
    controlArg: TaintedValue<unknown>;
    payload: TaintedValue<unknown>;
    agentId: string;
  }): SinkDispatchVerdict {
    // 1. CaMeL Control-Flow Integrity check:
    const actualRank = INTEGRITY_RANK[params.controlArg.integrity];
    const reqRank = INTEGRITY_RANK[params.sink.minControlIntegrity];
    if (actualRank < reqRank) {
      return {
        kind: 'Refuted',
        reason: 'untrusted-control-flow-hijack',
        actualControlIntegrity: params.controlArg.integrity,
        requiredControlIntegrity: params.sink.minControlIntegrity,
      };
    }

    // 2. Confidentiality No-Write-Down check (both payload AND controlArg cannot carry secret tags out!):
    const allowedSet = new Set(params.sink.allowedSecrecyTags);
    const allFlowingTags = new Set([
      ...params.payload.secrecyTags,
      ...params.controlArg.secrecyTags,
    ]);
    const disallowed = [...allFlowingTags].filter(t => !allowedSet.has(t)).sort();
    if (disallowed.length > 0) {
      const isCrossTenant =
        params.sink.allowedSecrecyTags.some(t => t.startsWith('tenant:')) &&
        disallowed.some(t => t.startsWith('tenant:'));
      return {
        kind: 'Refuted',
        reason: isCrossTenant ? 'cross-tenant-flow-blocked' : 'secret-exfiltration-blocked',
        disallowedTags: disallowed,
      };
    }

    const sinkAuditReceiptHash = this.kv.putBlob(
      'difc-sink-dispatch-receipt',
      {
        sinkId: params.sink.sinkId,
        agentId: params.agentId,
        controlValueHash: params.controlArg.valueMerkleHash,
        payloadValueHash: params.payload.valueMerkleHash,
        controlIntegrity: params.controlArg.integrity,
        flowingSecrecyTags: [...allFlowingTags].sort(),
      },
      [params.controlArg.valueMerkleHash, params.payload.valueMerkleHash],
    );
    this.kv.pinHistoricalCut(sinkAuditReceiptHash);

    return {
      kind: 'Allowed',
      sinkAuditReceiptHash,
      sinkId: params.sink.sinkId,
    };
  }
}
