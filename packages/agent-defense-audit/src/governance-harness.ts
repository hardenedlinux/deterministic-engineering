// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * G5 / E5: Scope-Fenced Closed-Loop AI Agent Patch Governance Harness.
 *
 * Implements the exact bounded repair & admission state machine formally verified in
 * `packages/quint-models/engineering/defense/agent-patch-governance/AgentPatchGovernance.qnt`:
 *
 *   1. H1 Scope & Protected-File Fencing (blocks unauthorized mutation of CI gates,
 *      Band-5 profile floors, governance auditors, or out-of-scope files).
 *   2. L1/L2 Multi-Language AST + Diff-Delta Obligation Deletion Audit across TS/C/C++/Rust/Go/Scheme.
 *   3. Independent Mechanical Oracle (Agent prose claims are logged as untrusted data, never evidence).
 *   4. Structured C2 Repair Packet feedback (`AgentRepairPacket`) with bounded retries;
 *      exhausting the retry budget strictly transitions to `EscalatedToHuman`.
 *   5. Deterministic SHA-256 attempt receipts & ASCENT fact projection for cross-layer auditing.
 */

import {createHash} from 'node:crypto';
import type {AstAuditFinding} from './ts-ast-auditor.ts';
import {
  auditUnifiedDiff,
  detectAuditLanguage,
  type MultiLangAuditReport,
} from './multi-lang-auditor.ts';
import {
  formatAgentRepairPacket,
  type AgentRepairPacket,
} from './remediation-catalog.ts';

export const DEFAULT_PROTECTED_GOVERNANCE_PATHS: readonly string[] = [
  '.github/workflows/**',
  'library/defense-profiles/**',
  'library/defensive-governance/**',
  't/support/quint-model-qualification.ss',
  'packages/agent-defense-audit/**',
];

export interface ScopeFencePolicy {
  allowedPaths?: readonly string[];
  protectedGovernancePaths?: readonly string[];
  allowGovernanceMutation?: boolean;
}

export function matchGlob(path: string, pattern: string): boolean {
  const normPath = path.replaceAll('\\', '/').replace(/^\.\//, '');
  const normPat = pattern.replaceAll('\\', '/').replace(/^\.\//, '');
  const escaped = normPat
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*\//g, '(?:.*/)?')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*');
  return new RegExp(`^${escaped}$`).test(normPath);
}

export function evaluateScopeFence(
  touchedFiles: readonly string[],
  policy: ScopeFencePolicy,
): MultiLangAuditReport[] {
  const protectedGlobs = policy.protectedGovernancePaths ?? DEFAULT_PROTECTED_GOVERNANCE_PATHS;
  const allowedGlobs = policy.allowedPaths ?? [];
  const reports: MultiLangAuditReport[] = [];

  for (const file of touchedFiles) {
    const findings: AstAuditFinding[] = [];
    if (
      !policy.allowGovernanceMutation &&
      protectedGlobs.some(glob => matchGlob(file, glob))
    ) {
      findings.push({
        hallucinationClass: 'floor-weakening',
        rule: 'unauthorized-governance-file-mutation',
        line: 1,
        column: 1,
        detail: `Agent patch touches protected governance file '${file}' without explicit human authorization`,
      });
    }
    if (
      allowedGlobs.length > 0 &&
      !allowedGlobs.some(glob => matchGlob(file, glob))
    ) {
      findings.push({
        hallucinationClass: 'floor-weakening',
        rule: 'out-of-scope-file-mutation',
        line: 1,
        column: 1,
        detail: `Agent patch mutates '${file}' outside declared allowed scope [${allowedGlobs.join(', ')}]`,
      });
    }
    if (findings.length > 0) {
      reports.push({
        fileName: file,
        language: detectAuditLanguage(file) ?? 'typescript',
        passed: false,
        findings,
        countsByClass: {
          'silent-fallback': 0,
          'floor-weakening': findings.length,
          'redundant-defensive-glue': 0,
          'fabricated-evidence': 0,
        },
        scopedToAddedLines: true,
      });
    }
  }
  return reports;
}

/**
 * Computes a minimal deterministic unified diff between two line-oriented snapshots
 * of a single file so in-memory governed loops feed the exact same diff parser as git.
 */
export function buildFileUnifiedDiff(filePath: string, beforeText: string, afterText: string): string {
  if (beforeText === afterText) return '';
  const a = beforeText === '' ? [] : beforeText.split('\n');
  const b = afterText === '' ? [] : afterText.split('\n');

  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++;

  let suffix = 0;
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  ) {
    suffix++;
  }

  const removed = a.slice(prefix, a.length - suffix);
  const added = b.slice(prefix, b.length - suffix);
  const oldStart = removed.length === 0 ? prefix : prefix + 1;
  const newStart = added.length === 0 ? prefix : prefix + 1;

  const lines = [
    `diff --git a/${filePath} b/${filePath}`,
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    `@@ -${oldStart},${removed.length} +${newStart},${added.length} @@`,
    ...removed.map(l => `-${l}`),
    ...added.map(l => `+${l}`),
  ];
  return lines.join('\n') + '\n';
}

export interface AgentPatchProposal {
  /** Map of repo-relative file path -> full proposed file text */
  files: Record<string, string>;
  /** Agent's prose claim — recorded strictly as untrusted telemetry, NEVER evidence */
  proseClaim: string;
}

export interface IndependentOracleResult {
  passed: boolean;
  detail: string;
}

export interface AttemptAuditReceipt {
  attempt: number;
  patchDigest: string;
  agentProseClaim: string;
  touchedFiles: string[];
  scopeViolationCount: number;
  astAndDiffFindingCount: number;
  obligationDeletionCount: number;
  oraclePassed: boolean;
  oracleDetail: string;
  decision: 'ADMIT' | 'REFUSE' | 'ESCALATED_TO_HUMAN';
  repairPacket: AgentRepairPacket;
}

export interface GovernanceTranscript {
  patchId: string;
  finalDecision: 'ADMIT' | 'ESCALATED_TO_HUMAN';
  maxRepairAttempts: number;
  attemptsUsed: number;
  receipts: AttemptAuditReceipt[];
}

export interface GovernedRepairLoopOptions {
  patchId: string;
  baseFiles: Record<string, string>;
  scopePolicy: ScopeFencePolicy;
  maxRepairAttempts?: number;
  proposeAttempt: (attempt: number, previousPacket: AgentRepairPacket | null) => AgentPatchProposal;
  runIndependentOracle: (effectiveFiles: Record<string, string>) => IndependentOracleResult;
}

export function runGovernedAgentRepairLoop(options: GovernedRepairLoopOptions): GovernanceTranscript {
  const maxRetries = options.maxRepairAttempts ?? 2;
  const receipts: AttemptAuditReceipt[] = [];
  let prevPacket: AgentRepairPacket | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const proposal = options.proposeAttempt(attempt, prevPacket);
    const effectiveFiles: Record<string, string> = {...options.baseFiles, ...proposal.files};

    const touchedFiles: string[] = [];
    const diffChunks: string[] = [];
    for (const filePath of Object.keys(proposal.files).sort()) {
      const before = options.baseFiles[filePath] ?? '';
      const after = proposal.files[filePath]!;
      if (before !== after) {
        touchedFiles.push(filePath);
        diffChunks.push(buildFileUnifiedDiff(filePath, before, after));
      }
    }
    const unifiedDiff = diffChunks.join('\n');
    const patchDigest = createHash('sha256').update(unifiedDiff).digest('hex').slice(0, 16);

    // Gate 1: Scope & Protected-File Fence
    const scopeReports = evaluateScopeFence(touchedFiles, options.scopePolicy);

    // Gate 2: Multi-Language Added-Line AST + Diff-Delta Obligation Deletion Audit
    const astAndDiffReports = auditUnifiedDiff(unifiedDiff, rel => effectiveFiles[rel] ?? null);

    const allAuditReports = [...scopeReports, ...astAndDiffReports];
    const scopeViolationCount = scopeReports.reduce((acc, r) => acc + r.findings.length, 0);
    const astAndDiffFindingCount = astAndDiffReports.reduce((acc, r) => acc + r.findings.length, 0);
    const obligationDeletionCount = astAndDiffReports.reduce(
      (acc, r) => acc + r.findings.filter(f => f.rule.startsWith('diff-deleted-')).length,
      0,
    );

    // Gate 3: Independent Mechanical Behavioral Oracle (ignores proposal.proseClaim!)
    const oracle =
      scopeViolationCount === 0
        ? options.runIndependentOracle(effectiveFiles)
        : {passed: false, detail: 'Oracle skipped: protected/out-of-scope file mutation refused before execution'};

    const repairPacket = formatAgentRepairPacket(allAuditReports);
    repairPacket.boundedRetryPolicy.maxRepairAttempts = maxRetries;
    if (!oracle.passed) {
      repairPacket.decision = 'REFUSE';
      repairPacket.requiredBeforeRetry.push(`Fix independent behavioral oracle failure: ${oracle.detail}`);
    }

    const admitted =
      scopeViolationCount === 0 &&
      astAndDiffFindingCount === 0 &&
      oracle.passed;

    if (admitted) {
      receipts.push({
        attempt,
        patchDigest,
        agentProseClaim: proposal.proseClaim,
        touchedFiles,
        scopeViolationCount,
        astAndDiffFindingCount,
        obligationDeletionCount,
        oraclePassed: true,
        oracleDetail: oracle.detail,
        decision: 'ADMIT',
        repairPacket,
      });
      return {
        patchId: options.patchId,
        finalDecision: 'ADMIT',
        maxRepairAttempts: maxRetries,
        attemptsUsed: attempt + 1,
        receipts,
      };
    }

    const exhausted = attempt === maxRetries;
    receipts.push({
      attempt,
      patchDigest,
      agentProseClaim: proposal.proseClaim,
      touchedFiles,
      scopeViolationCount,
      astAndDiffFindingCount,
      obligationDeletionCount,
      oraclePassed: oracle.passed,
      oracleDetail: oracle.detail,
      decision: exhausted ? 'ESCALATED_TO_HUMAN' : 'REFUSE',
      repairPacket,
    });
    prevPacket = repairPacket;
  }

  return {
    patchId: options.patchId,
    finalDecision: 'ESCALATED_TO_HUMAN',
    maxRepairAttempts: maxRetries,
    attemptsUsed: receipts.length,
    receipts,
  };
}
