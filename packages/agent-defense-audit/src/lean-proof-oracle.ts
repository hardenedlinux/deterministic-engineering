// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 24 (10.172): Live Lean 4 Proof-Carrying Oracle & Anti-Fabrication Gate.
 *
 * Bridges unbounded Lean 4 machine-checked proofs (`DurableGovernanceQuorum.lean`)
 * into our G2 / M1 proof-carrying governance boundary:
 *   1. `auditLeanSourceAntiFabrication`: rejects `sorry`, `admit`, `axiom`, `unsafe`,
 *      or `implemented_by` backdoors in `.lean` sources before trust admission.
 *   2. `parseLeanPrintAxiomsOutput`: parses Lean 4 `#print axioms` output and verifies
 *      that every audited theorem depends ONLY on Lean's standard foundational axioms
 *      (`propext`, `Classical.choice`, `Quot.sound`) with ZERO `sorryAx` or custom axioms.
 *   3. `verifyLeanModuleAxiomsLive`: runs live `lake env lean --stdin` against compiled
 *      `.olean` artifacts, failing closed as epistemic `PendingMethod` when `lake` is
 *      unavailable (never silently returning ok:true!).
 */

import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {ContentAddressedKvStore, sha256Digest} from './durable-merkle-store.ts';

export const STANDARD_LEAN_AXIOMS = new Set(['propext', 'Classical.choice', 'Quot.sound']);

export interface LeanSourceFinding {
  line: number;
  kind: 'sorry' | 'admit' | 'custom-axiom' | 'unsafe-escape';
  snippet: string;
}

export function auditLeanSourceAntiFabrication(sourceText: string): {
  passed: boolean;
  findings: LeanSourceFinding[];
} {
  const findings: LeanSourceFinding[] = [];
  const lines = sourceText.split('\n');
  let inBlockComment = false;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]!;
    if (inBlockComment) {
      const closeIdx = line.indexOf('-/');
      if (closeIdx === -1) continue;
      line = line.slice(closeIdx + 2);
      inBlockComment = false;
    }
    const openIdx = line.indexOf('/-');
    if (openIdx !== -1) {
      const closeIdx = line.indexOf('-/', openIdx + 2);
      if (closeIdx === -1) {
        line = line.slice(0, openIdx);
        inBlockComment = true;
      } else {
        line = line.slice(0, openIdx) + line.slice(closeIdx + 2);
      }
    }
    const lineCommentIdx = line.indexOf('--');
    const code = (lineCommentIdx === -1 ? line : line.slice(0, lineCommentIdx)).trim();
    if (!code) continue;

    if (/\bsorry\b/.test(code)) {
      findings.push({line: i + 1, kind: 'sorry', snippet: code});
    }
    if (/\badmit\b/.test(code)) {
      findings.push({line: i + 1, kind: 'admit', snippet: code});
    }
    if (/^\s*axiom\b/.test(code)) {
      findings.push({line: i + 1, kind: 'custom-axiom', snippet: code});
    }
    if (/\b(?:unsafe|implemented_by)\b/.test(code)) {
      findings.push({line: i + 1, kind: 'unsafe-escape', snippet: code});
    }
  }

  return {passed: findings.length === 0, findings};
}

export type LeanAxiomAuditVerdict =
  | {
      kind: 'Proven';
      theoremAxioms: Record<string, string[]>;
      proofCertificateDigest: string;
    }
  | {
      kind: 'Refuted';
      reason: 'unverified-sorry-or-custom-axiom' | 'missing-theorem-axiom-report';
      offendingTheorems: Array<{theorem: string; disallowedAxioms: string[]}>;
    }
  | {kind: 'PendingMethod'; reason: 'lean-toolchain-unavailable'}
  | {kind: 'SetupDefect'; reason: string};

export function parseLeanPrintAxiomsOutput(
  stdout: string,
  expectedTheorems: readonly string[],
): LeanAxiomAuditVerdict {
  const theoremAxioms: Record<string, string[]> = {};
  // Lean 4 `#print axioms` prints either:
  //   '<name>' depends on axioms: [a, b]
  //   '<name>' does not depend on any axioms
  const depRegex = /'([^']+)'\s+depends on axioms:\s*\[([^\]]*)\]/g;
  for (const m of stdout.matchAll(depRegex)) {
    const fullName = m[1]!;
    const rawList = m[2]!.trim();
    const axioms = rawList
      ? rawList
          .split(',')
          .map(s => s.trim())
          .filter(Boolean)
      : [];
    theoremAxioms[fullName] = axioms;
  }
  const zeroRegex = /'([^']+)'\s+does not depend on any axioms/g;
  for (const m of stdout.matchAll(zeroRegex)) {
    theoremAxioms[m[1]!] = [];
  }

  const offending: Array<{theorem: string; disallowedAxioms: string[]}> = [];
  const missing: Array<{theorem: string; disallowedAxioms: string[]}> = [];

  for (const thm of expectedTheorems) {
    const matchedKey = Object.keys(theoremAxioms).find(
      k => k === thm || k.endsWith(`.${thm}`),
    );
    if (!matchedKey) {
      missing.push({theorem: thm, disallowedAxioms: ['missing-from-print-axioms']});
      continue;
    }
    const disallowed = theoremAxioms[matchedKey]!.filter(ax => !STANDARD_LEAN_AXIOMS.has(ax));
    if (disallowed.length > 0) {
      offending.push({theorem: matchedKey, disallowedAxioms: disallowed});
    }
  }

  if (offending.length > 0) {
    return {
      kind: 'Refuted',
      reason: 'unverified-sorry-or-custom-axiom',
      offendingTheorems: offending,
    };
  }
  if (missing.length > 0) {
    return {
      kind: 'Refuted',
      reason: 'missing-theorem-axiom-report',
      offendingTheorems: missing,
    };
  }

  return {
    kind: 'Proven',
    theoremAxioms,
    proofCertificateDigest: sha256Digest({expectedTheorems, theoremAxioms}),
  };
}

const DEFAULT_LEAN_DIR = resolve(import.meta.dir, '../../lean-models');

export function isLeanToolchainAvailable(leanDir = DEFAULT_LEAN_DIR): boolean {
  if (!existsSync(resolve(leanDir, 'lakefile.toml'))) return false;
  const probe = spawnSync('lake', ['--version'], {cwd: leanDir, encoding: 'utf8'});
  return !probe.error && probe.status === 0;
}

export function verifyLeanModuleAxiomsLive(params: {
  moduleName: string;
  namespacePrefix: string;
  expectedTheorems: readonly string[];
  kv?: ContentAddressedKvStore;
  leanDir?: string;
  lakeBinary?: string;
}): LeanAxiomAuditVerdict & {pinnedCertificateHash?: string} {
  const leanDir = params.leanDir ?? DEFAULT_LEAN_DIR;
  const lakeBin = params.lakeBinary ?? 'lake';
  if (!existsSync(resolve(leanDir, 'lakefile.toml'))) {
    return {kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'};
  }

  const stdinScript = [
    `import ${params.moduleName}`,
    `open ${params.namespacePrefix}`,
    ...params.expectedTheorems.map(t => `#print axioms ${t}`),
    '',
  ].join('\n');

  const proc = spawnSync(lakeBin, ['env', 'lean', '--stdin'], {
    cwd: leanDir,
    input: stdinScript,
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  });

  if (proc.error) {
    const code = (proc.error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return {kind: 'PendingMethod', reason: 'lean-toolchain-unavailable'};
    }
    return {kind: 'SetupDefect', reason: `lake-spawn-error: ${proc.error.message}`};
  }
  if (proc.status !== 0) {
    return {
      kind: 'SetupDefect',
      reason: `lean-exit-${proc.status}: ${(proc.stderr || proc.stdout).slice(0, 300)}`,
    };
  }

  const verdict = parseLeanPrintAxiomsOutput(proc.stdout, params.expectedTheorems);
  if (verdict.kind === 'Proven' && params.kv) {
    const pinnedCertificateHash = params.kv.putBlob(
      'lean4-unbounded-proof-certificate',
      {
        moduleName: params.moduleName,
        theoremAxioms: verdict.theoremAxioms,
        proofCertificateDigest: verdict.proofCertificateDigest,
      },
      [],
    );
    params.kv.pinHistoricalCut(pinnedCertificateHash);
    return {...verdict, pinnedCertificateHash};
  }
  return verdict;
}
