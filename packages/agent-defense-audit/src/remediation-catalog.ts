// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * G2 / G5 Structured Remediation Catalog, SARIF 2.1.0 Exporter, and AI Agent Repair Packet Generator.
 *
 * Binds every AST / diff-delta hallucination finding back to:
 *   - Its canonical C1 anti-pattern identity in `library/defensive-boundaries/objects.ss`
 *   - Its C2 deterministic trust-boundary replacement contract
 *   - Its G1 5-tuple guard-admission obligations
 *   - Explicit anti-evasion prohibitions so AI Agents cannot placate the gate via
 *     log-and-swallow, @ts-ignore, conditional assertions, or silent assertion deletion.
 */

import type {AstAuditFinding, HallucinationClass} from './ts-ast-auditor.ts';
import type {MultiLangAuditReport} from './multi-lang-auditor.ts';

export interface RemediationDirective {
  hallucinationClass: HallucinationClass;
  antiPatternId: string;
  taxonomyRef: string;
  c2Replacement: string;
  requiredFiveTuple: readonly ['obligation', 'owner', 'scoped_failure', 'witness', 'affected_consumer'];
  antiEvasionWarning: string;
}

const FIVE_TUPLE = [
  'obligation',
  'owner',
  'scoped_failure',
  'witness',
  'affected_consumer',
] as const;

const CLASS_DIRECTIVES: Record<HallucinationClass, RemediationDirective> = {
  'silent-fallback': {
    hallucinationClass: 'silent-fallback',
    antiPatternId: 'c1.silent-fallback-on-defect',
    taxonomyRef: 'docs/10-19-design/10-architecture/10.153-defensive-engineering-taxonomy-and-modular-organization.org#de153-taxonomy',
    c2Replacement:
      'Return a typed epistemic boundary result separating SetupDefect, PendingMethod, PendingScope, Conflict, Refuted, and Proven (TS discriminated union / C de_boundary_status_t / C++ std::variant / Rust Epistemic<T> / Go typed error+status / Scheme POO verdict).',
    requiredFiveTuple: FIVE_TUPLE,
    antiEvasionWarning:
      'Do NOT evade by adding console.error/std::cerr/eprintln before returning null/0/[]/Ok(())/default. The failure state must remain visible in the return type.',
  },
  'floor-weakening': {
    hallucinationClass: 'floor-weakening',
    antiPatternId: 'c1.global-purge-on-negative-change',
    taxonomyRef: 'docs/10-19-design/10-architecture/10.155-ai-agent-coding-governance-and-anti-evasion-architecture.org#ag155-evasion',
    c2Replacement:
      'Restore monotonic Band-5 verification floors (requireCountermodels, requireUseTimeWitness, allowGlobalPurge=false, minCoverage=1.0), keep all assertions unconditional, and fix the underlying defect rather than weakening or deleting checks.',
    requiredFiveTuple: FIVE_TUPLE,
    antiEvasionWarning:
      'Do NOT evade by deleting failing assertions, adding test.skip/#[ignore]/#define NDEBUG/@ts-ignore/as any, or wrapping expect() inside if (res.ok).',
  },
  'redundant-defensive-glue': {
    hallucinationClass: 'redundant-defensive-glue',
    antiPatternId: 'c1.redundant-internal-revalidation',
    taxonomyRef: 'docs/10-19-design/10-architecture/10.153-defensive-engineering-taxonomy-and-modular-organization.org#de153-taxonomy',
    c2Replacement:
      'Parse once into sealed nominal types at the single trust boundary; remove no-op catch-rethrow, duplicate null checks, and vacuous guards, or discharge a genuine obligation via F3 guard-probe counterexample + G1 5-tuple.',
    requiredFiveTuple: FIVE_TUPLE,
    antiEvasionWarning:
      'Do NOT rename or rearrange a redundant guard without proving necessity via Apalache guard-probe or an executable counterexample.',
  },
  'fabricated-evidence': {
    hallucinationClass: 'fabricated-evidence',
    antiPatternId: 'c1.unknown-as-violation',
    taxonomyRef: 'docs/10-19-design/10-architecture/10.155-ai-agent-coding-governance-and-anti-evasion-architecture.org#ag155-evasion',
    c2Replacement:
      'Execute the real verification oracle or emit PendingMethod/PendingScope when evidence is not yet collected; never emit verified:true/passed:true/return true stubs or TODO-backed positive verdicts.',
    requiredFiveTuple: FIVE_TUPLE,
    antiEvasionWarning:
      'Do NOT evade by removing the TODO comment while keeping an ungrounded constant true/verified:true return.',
  },
};

export function getRemediationDirective(finding: AstAuditFinding): RemediationDirective {
  if (finding.rule === 'unauthorized-governance-file-mutation' || finding.rule === 'out-of-scope-file-mutation') {
    return {
      ...CLASS_DIRECTIVES['floor-weakening'],
      antiPatternId: 'g5.scope-or-governance-boundary-tampering',
      c2Replacement:
        'Restrict edits strictly to the authorized task scope and never modify CI workflows, Band-5 profile floors, or audit harnesses without explicit human authorization.',
    };
  }
  if (finding.rule.startsWith('diff-deleted-')) {
    return {
      ...CLASS_DIRECTIVES['floor-weakening'],
      antiPatternId: 'g2.silent-obligation-deletion',
      c2Replacement:
        'Preserve existing assertions, Band-5 governance floors, formal (guard ...) declarations, and @countermodel witnesses. Removing an obligation requires an explicit admitted replacement witness in the same change.',
    };
  }
  return CLASS_DIRECTIVES[finding.hallucinationClass];
}

export interface AgentRepairFinding {
  file: string;
  language: string;
  line: number;
  column: number;
  hallucinationClass: HallucinationClass;
  rule: string;
  detail: string;
  remediation: RemediationDirective;
}

export interface AgentRepairPacket {
  schemaVersion: '1.0.0';
  decision: 'ADMIT' | 'REFUSE';
  boundedRetryPolicy: {
    maxRepairAttempts: number;
    onBudgetExhausted: 'EscalateToHuman';
    forbidFloorWeakening: true;
    forbidUnwitnessedObligationDeletion: true;
  };
  auditedFiles: number;
  totalFindings: number;
  findings: AgentRepairFinding[];
  requiredBeforeRetry: string[];
}

export function formatAgentRepairPacket(reports: MultiLangAuditReport[]): AgentRepairPacket {
  const flatFindings: AgentRepairFinding[] = [];
  for (const r of reports) {
    for (const f of r.findings) {
      flatFindings.push({
        file: r.fileName,
        language: r.language,
        line: f.line,
        column: f.column,
        hallucinationClass: f.hallucinationClass,
        rule: f.rule,
        detail: f.detail,
        remediation: getRemediationDirective(f),
      });
    }
  }
  const passed = flatFindings.length === 0;
  return {
    schemaVersion: '1.0.0',
    decision: passed ? 'ADMIT' : 'REFUSE',
    boundedRetryPolicy: {
      maxRepairAttempts: 3,
      onBudgetExhausted: 'EscalateToHuman',
      forbidFloorWeakening: true,
      forbidUnwitnessedObligationDeletion: true,
    },
    auditedFiles: reports.length,
    totalFindings: flatFindings.length,
    findings: flatFindings,
    requiredBeforeRetry: passed
      ? []
      : [
          'Replace every flagged site with its C2 deterministic trust-boundary contract.',
          'Do not delete assertions, weaken Band-5 floors, add @ts-ignore/as any, or log-and-swallow errors.',
          'Re-run `just audit-agent-patch` and `just check-defense` to produce fresh independent verification evidence.',
        ],
  };
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          shortDescription: {text: string};
          help: {text: string};
          properties: {
            hallucinationClass: HallucinationClass;
            antiPatternId: string;
          };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: 'error';
      message: {text: string};
      locations: Array<{
        physicalLocation: {
          artifactLocation: {uri: string};
          region: {startLine: number; startColumn: number};
        };
      }>;
      properties: {
        hallucinationClass: HallucinationClass;
        antiPatternId: string;
        c2Replacement: string;
        antiEvasionWarning: string;
      };
    }>;
  }>;
}

export function formatSarifReport(reports: MultiLangAuditReport[]): SarifLog {
  const ruleMap = new Map<
    string,
    {
      id: string;
      shortDescription: {text: string};
      help: {text: string};
      properties: {hallucinationClass: HallucinationClass; antiPatternId: string};
    }
  >();
  const results: SarifLog['runs'][0]['results'] = [];

  for (const r of reports) {
    for (const f of r.findings) {
      const rem = getRemediationDirective(f);
      if (!ruleMap.has(f.rule)) {
        ruleMap.set(f.rule, {
          id: f.rule,
          shortDescription: {text: `[${f.hallucinationClass}] ${f.rule}`},
          help: {text: `${rem.c2Replacement} | Anti-evasion: ${rem.antiEvasionWarning}`},
          properties: {
            hallucinationClass: f.hallucinationClass,
            antiPatternId: rem.antiPatternId,
          },
        });
      }
      results.push({
        ruleId: f.rule,
        level: 'error',
        message: {text: `${f.detail} — C2 replacement: ${rem.c2Replacement}`},
        locations: [
          {
            physicalLocation: {
              artifactLocation: {uri: r.fileName},
              region: {startLine: Math.max(1, f.line), startColumn: Math.max(1, f.column)},
            },
          },
        ],
        properties: {
          hallucinationClass: f.hallucinationClass,
          antiPatternId: rem.antiPatternId,
          c2Replacement: rem.c2Replacement,
          antiEvasionWarning: rem.antiEvasionWarning,
        },
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'deterministic-engineering-agent-defense-audit',
            version: '2.0.0',
            informationUri:
              'https://github.com/hardenedlinux/deterministic-engineering-qnt/blob/main/docs/10-19-design/10-architecture/10.155-ai-agent-coding-governance-and-anti-evasion-architecture.org',
            rules: [...ruleMap.values()],
          },
        },
        results,
      },
    ],
  };
}
