// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * E3.3: Multi-Language Structural AST & Unified-Diff AI Agent Defensive Auditor.
 *
 * Covers 5 languages used in this repository with zero external parser dependencies
 * and exact 1-based line/column locations:
 *   - TypeScript / JavaScript (.ts, .tsx, .js, .mjs) -> delegates to ts-ast-auditor.ts
 *   - C / C++ (.c, .h, .cc, .cpp, .hpp)             -> balanced C-family lexer & block auditor
 *   - Rust (.rs)                                     -> nested-comment Rust lexer & structural auditor
 *   - Gerbil / Gambit Scheme (.ss, .scm)             -> S-expression datum parser mirroring library/defensive-governance/func.ss
 *
 * Also parses unified git diffs so AI Agent PRs/patches are audited strictly on
 * newly added/changed lines without false positives from untouched legacy code.
 */

import {extname} from 'node:path';
import {
  auditTypeScriptSource,
  type AstAuditFinding,
  type HallucinationClass,
  type TsAgentAuditReport,
} from './ts-ast-auditor.ts';

export type SupportedAuditLanguage = 'typescript' | 'c-cpp' | 'rust' | 'scheme';

export interface MultiLangAuditReport extends TsAgentAuditReport {
  language: SupportedAuditLanguage;
  scopedToAddedLines: boolean;
}

interface Tok {
  kind: 'ident' | 'str' | 'num' | 'punct' | 'comment';
  value: string;
  line: number;
  column: number;
}

function makeReport(
  fileName: string,
  language: SupportedAuditLanguage,
  findings: AstAuditFinding[],
  scopedToAddedLines = false,
): MultiLangAuditReport {
  const countsByClass: Record<HallucinationClass, number> = {
    'silent-fallback': 0,
    'floor-weakening': 0,
    'redundant-defensive-glue': 0,
    'fabricated-evidence': 0,
  };
  for (const f of findings) countsByClass[f.hallucinationClass]++;
  return {
    fileName,
    language,
    passed: findings.length === 0,
    findings,
    countsByClass,
    scopedToAddedLines,
  };
}

export function detectAuditLanguage(fileName: string): SupportedAuditLanguage | null {
  const ext = extname(fileName).toLowerCase();
  if (ext === '.ts' || ext === '.tsx' || ext === '.js' || ext === '.mjs' || ext === '.cjs') {
    return 'typescript';
  }
  if (ext === '.c' || ext === '.h' || ext === '.cc' || ext === '.cpp' || ext === '.cxx' || ext === '.hpp' || ext === '.hh') {
    return 'c-cpp';
  }
  if (ext === '.rs') return 'rust';
  if (ext === '.ss' || ext === '.scm') return 'scheme';
  return null;
}

function findMatching(toks: Tok[], openIdx: number, openCh: string, closeCh: string): number {
  let depth = 0;
  for (let i = openIdx; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.kind === 'punct' && t.value === openCh) depth++;
    else if (t.kind === 'punct' && t.value === closeCh) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// ── Shared C/C++ & Rust Lexer ───────────────────────────────────────────────

function tokenizeCLike(src: string, nestedBlockComments: boolean): {code: Tok[]; comments: Tok[]} {
  const code: Tok[] = [];
  const comments: Tok[] = [];
  let i = 0;
  let line = 1;
  let col = 1;

  const advance = (n = 1) => {
    for (let k = 0; k < n && i < src.length; k++) {
      if (src[i] === '\n') {
        line++;
        col = 1;
      } else {
        col++;
      }
      i++;
    }
  };

  while (i < src.length) {
    const ch = src[i]!;
    if (/\s/.test(ch)) {
      advance();
      continue;
    }
    const startLine = line;
    const startCol = col;

    if (ch === '/' && src[i + 1] === '/') {
      const start = i;
      while (i < src.length && src[i] !== '\n') advance();
      comments.push({kind: 'comment', value: src.slice(start, i), line: startLine, column: startCol});
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      const start = i;
      advance(2);
      let depth = 1;
      while (i < src.length && depth > 0) {
        if (nestedBlockComments && src[i] === '/' && src[i + 1] === '*') {
          depth++;
          advance(2);
        } else if (src[i] === '*' && src[i + 1] === '/') {
          depth--;
          advance(2);
        } else {
          advance();
        }
      }
      comments.push({kind: 'comment', value: src.slice(start, i), line: startLine, column: startCol});
      continue;
    }
    if (ch === '"') {
      let val = '';
      advance();
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < src.length) {
          val += src[i + 1];
          advance(2);
        } else {
          val += src[i];
          advance();
        }
      }
      if (i < src.length) advance();
      code.push({kind: 'str', value: val, line: startLine, column: startCol});
      continue;
    }
    // Char literal (avoid breaking Rust lifetimes like 'static)
    if (ch === "'" && (src[i + 1] === '\\' || src[i + 2] === "'")) {
      let val = '';
      advance();
      if (src[i] === '\\' && i + 1 < src.length) {
        val += src[i + 1];
        advance(2);
      } else if (i < src.length) {
        val += src[i];
        advance();
      }
      if (src[i] === "'") advance();
      code.push({kind: 'str', value: val, line: startLine, column: startCol});
      continue;
    }
    if (/[0-9]/.test(ch)) {
      const start = i;
      while (i < src.length && /[0-9a-zA-Z_.]/.test(src[i]!)) advance();
      code.push({kind: 'num', value: src.slice(start, i), line: startLine, column: startCol});
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      const start = i;
      while (i < src.length && /[A-Za-z0-9_]/.test(src[i]!)) advance();
      code.push({kind: 'ident', value: src.slice(start, i), line: startLine, column: startCol});
      continue;
    }
    const three = src.slice(i, i + 3);
    if (three === '...') {
      advance(3);
      code.push({kind: 'punct', value: three, line: startLine, column: startCol});
      continue;
    }
    const two = src.slice(i, i + 2);
    if (['==', '!=', '<=', '>=', '=>', '->', '::', '&&', '||'].includes(two)) {
      advance(2);
      code.push({kind: 'punct', value: two, line: startLine, column: startCol});
      continue;
    }
    advance();
    code.push({kind: 'punct', value: ch, line: startLine, column: startCol});
  }
  return {code, comments};
}

// ── C / C++ Auditor ─────────────────────────────────────────────────────────

export function auditCCppAgentSource(sourceText: string, fileName = 'input.cpp'): MultiLangAuditReport {
  const {code, comments} = tokenizeCLike(sourceText, false);
  const findings: AstAuditFinding[] = [];
  const add = (hallucinationClass: HallucinationClass, rule: string, tok: Tok, detail: string) => {
    findings.push({hallucinationClass, rule, line: tok.line, column: tok.column, detail});
  };

  // Preprocessor #define NDEBUG (strips all assert() checks!)
  for (let i = 0; i + 2 < code.length; i++) {
    if (
      code[i]!.value === '#' &&
      code[i + 1]!.value === 'define' &&
      code[i + 2]!.value === 'NDEBUG'
    ) {
      add('floor-weakening', 'c-define-ndebug', code[i]!, '#define NDEBUG disables runtime assert() checks');
    }
  }

  for (let i = 0; i < code.length; i++) {
    const t = code[i]!;

    // 1. C++ catch (...) / catch (...) { return 0/true; } / empty catch / noop rethrow
    if (t.kind === 'ident' && t.value === 'catch' && code[i + 1]?.value === '(') {
      const closeParen = findMatching(code, i + 1, '(', ')');
      if (closeParen > i && code[closeParen + 1]?.value === '{') {
        const bodyOpen = closeParen + 1;
        const bodyClose = findMatching(code, bodyOpen, '{', '}');
        if (bodyClose > bodyOpen) {
          const inner = code.slice(bodyOpen + 1, bodyClose);
          if (inner.length === 0) {
            add('silent-fallback', 'cpp-empty-catch', t, 'Empty catch block silently swallows exceptions');
          } else if (
            (inner.length === 2 && inner[0]!.value === 'throw' && inner[1]!.value === ';') ||
            (inner.length === 3 && inner[0]!.value === 'throw' && inner[2]!.value === ';')
          ) {
            add('redundant-defensive-glue', 'cpp-noop-catch-rethrow', t, 'catch block only rethrows without transforming or logging');
          } else {
            for (let k = 0; k < inner.length; k++) {
              if (inner[k]!.value === 'return') {
                const next = inner[k + 1];
                if (
                  next &&
                  ((next.kind === 'num' && next.value === '0') ||
                    (next.kind === 'ident' && (next.value === 'true' || next.value === 'nullptr')) ||
                    (next.kind === 'str' && next.value === '') ||
                    (next.value === '{' && inner[k + 2]?.value === '}'))
                ) {
                  add(
                    'silent-fallback',
                    'cpp-catch-constant-fallback',
                    inner[k]!,
                    `catch block masks exception by returning fallback constant '${next.value}'`,
                  );
                }
              }
            }
          }
        }
      }
    }

    // 2. C/C++ NULL/nullptr/SIZE_MAX defect guard returning silent 0 or true
    if (t.kind === 'ident' && t.value === 'if' && code[i + 1]?.value === '(') {
      const closeParen = findMatching(code, i + 1, '(', ')');
      if (closeParen > i) {
        const condSlice = code.slice(i + 2, closeParen);
        const testsDefect = condSlice.some(
          ct =>
            ct.value === 'NULL' ||
            ct.value === 'nullptr' ||
            ct.value === 'SIZE_MAX' ||
            ct.value === 'UINT64_MAX',
        );
        if (testsDefect) {
          let retTok: Tok | null = null;
          let retValTok: Tok | null = null;
          if (code[closeParen + 1]?.value === '{') {
            const bodyClose = findMatching(code, closeParen + 1, '{', '}');
            const inner = code.slice(closeParen + 2, bodyClose);
            if (
              inner.length === 3 &&
              inner[0]!.value === 'return' &&
              inner[2]!.value === ';'
            ) {
              retTok = inner[0]!;
              retValTok = inner[1]!;
            }
          } else if (
            code[closeParen + 1]?.value === 'return' &&
            code[closeParen + 3]?.value === ';'
          ) {
            retTok = code[closeParen + 1]!;
            retValTok = code[closeParen + 2]!;
          }
          if (
            retTok &&
            retValTok &&
            ((retValTok.kind === 'num' && retValTok.value === '0') ||
              (retValTok.kind === 'ident' && retValTok.value === 'true'))
          ) {
            add(
              'silent-fallback',
              'c-defect-guard-constant-fallback',
              retTok,
              `NULL/overflow defect guard returns silent fallback '${retValTok.value}' instead of typed defect status`,
            );
          }
        }
      }
    }

    // 3. Floor weakening: tautological assert(true) / assert(1) / static_assert(true) / GTEST_SKIP()
    if (
      t.kind === 'ident' &&
      (t.value === 'assert' || t.value === 'static_assert' || t.value === 'REQUIRE') &&
      code[i + 1]?.value === '('
    ) {
      const closeParen = findMatching(code, i + 1, '(', ')');
      if (closeParen > i + 2) {
        const arg = code[i + 2]!;
        if (
          (arg.value === 'true' || arg.value === '1') &&
          (closeParen === i + 3 || code[i + 3]?.value === ',')
        ) {
          add('floor-weakening', 'c-tautological-assert', t, `Tautological ${t.value}(${arg.value}) weakens verification`);
        }
      }
    }
    if (t.kind === 'ident' && t.value === 'GTEST_SKIP' && code[i + 1]?.value === '(') {
      add('floor-weakening', 'cpp-gtest-skip', t, 'GTEST_SKIP() disables test gate');
    }

    // 4. Zero-check verify/validate/check/audit stub returning true
    if (
      t.kind === 'ident' &&
      /^(verify|validate|check|audit)[A-Z_]/i.test(t.value) &&
      code[i + 1]?.value === '('
    ) {
      const closeParen = findMatching(code, i + 1, '(', ')');
      if (closeParen > i) {
        let braceIdx = closeParen + 1;
        while (braceIdx < code.length && (code[braceIdx]!.value === 'noexcept' || code[braceIdx]!.value === 'const')) {
          braceIdx++;
        }
        if (code[braceIdx]?.value === '{') {
          const bodyClose = findMatching(code, braceIdx, '{', '}');
          if (bodyClose > braceIdx) {
            const inner = code.slice(braceIdx + 1, bodyClose);
            if (
              inner.length === 3 &&
              inner[0]!.value === 'return' &&
              (inner[1]!.value === 'true' || inner[1]!.value === '1') &&
              inner[2]!.value === ';'
            ) {
              add(
                'fabricated-evidence',
                'c-stub-verify-returns-true',
                t,
                `Verification function '${t.value}' unconditionally returns '${inner[1]!.value}' without checking`,
              );
            }
          }
        }
      }
    }
  }

  // 5. TODO verify comment near bare return true
  for (const c of comments) {
    if (/(?:TODO|FIXME|HACK).*(?:verify|validate|check|auth|signature|proof)/i.test(c.value)) {
      const nearReturnTrue = code.find(
        (tk, idx) =>
          tk.value === 'return' &&
          tk.line >= c.line &&
          tk.line <= c.line + 4 &&
          code[idx + 1]?.value === 'true',
      );
      if (nearReturnTrue) {
        add('fabricated-evidence', 'c-todo-verify-return-true', nearReturnTrue, 'TODO verification comment paired with bare return true');
      }
    }
  }

  return makeReport(fileName, 'c-cpp', findings);
}

// ── Rust Auditor ────────────────────────────────────────────────────────────

export function auditRustAgentSource(sourceText: string, fileName = 'input.rs'): MultiLangAuditReport {
  const {code, comments} = tokenizeCLike(sourceText, true);
  const findings: AstAuditFinding[] = [];
  const add = (hallucinationClass: HallucinationClass, rule: string, tok: Tok, detail: string) => {
    findings.push({hallucinationClass, rule, line: tok.line, column: tok.column, detail});
  };

  for (let i = 0; i < code.length; i++) {
    const t = code[i]!;

    // 1. Silent fallback: .unwrap_or_default() or .unwrap_or(0|true|false|""|Vec::new())
    if (t.value === '.' && code[i + 1]?.kind === 'ident') {
      const m = code[i + 1]!;
      if (m.value === 'unwrap_or_default' && code[i + 2]?.value === '(') {
        add(
          'silent-fallback',
          'rust-unwrap-or-default',
          m,
          '.unwrap_or_default() silently collapses Err/None into a default value',
        );
      } else if (m.value === 'unwrap_or' && code[i + 2]?.value === '(') {
        const closeParen = findMatching(code, i + 2, '(', ')');
        if (closeParen === i + 4) {
          const arg = code[i + 3]!;
          if (
            (arg.kind === 'num' && arg.value === '0') ||
            arg.value === 'true' ||
            (arg.kind === 'str' && arg.value === '')
          ) {
            add(
              'silent-fallback',
              'rust-unwrap-or-constant',
              m,
              `.unwrap_or(${arg.value}) silently masks Err/None as constant '${arg.value}'`,
            );
          }
        }
      }
    }

    // 2. Silent fallback or noop glue in `Err(...) => ...`
    if (t.kind === 'ident' && t.value === 'Err' && code[i + 1]?.value === '(') {
      const closeParen = findMatching(code, i + 1, '(', ')');
      if (closeParen > i && code[closeParen + 1]?.value === '=>') {
        const errVar = closeParen === i + 3 ? code[i + 2]!.value : null;
        let rhsIdx = closeParen + 2;
        if (code[rhsIdx]?.value === 'return') rhsIdx++;
        const rhs = code[rhsIdx];
        if (rhs?.value === 'Ok' && code[rhsIdx + 1]?.value === '(') {
          add('silent-fallback', 'rust-err-arm-returns-ok', t, 'Match arm Err(_) silently converts error into Ok(...)');
        } else if (
          errVar &&
          errVar !== '_' &&
          rhs?.value === 'Err' &&
          code[rhsIdx + 1]?.value === '(' &&
          code[rhsIdx + 2]?.value === errVar &&
          code[rhsIdx + 3]?.value === ')'
        ) {
          add('redundant-defensive-glue', 'rust-noop-err-rethrow', t, `Redundant Err(${errVar}) => Err(${errVar}) glue`);
        }
      }
    }

    // 3. Floor weakening: #[ignore] on tests, assert!(true)
    if (
      t.value === '#' &&
      code[i + 1]?.value === '[' &&
      code[i + 2]?.value === 'ignore'
    ) {
      add('floor-weakening', 'rust-test-ignore', t, '#[ignore] disables verification test');
    }
    if (
      t.kind === 'ident' &&
      (t.value === 'assert' || t.value === 'debug_assert') &&
      code[i + 1]?.value === '!' &&
      code[i + 2]?.value === '(' &&
      code[i + 3]?.value === 'true' &&
      code[i + 4]?.value === ')'
    ) {
      add('floor-weakening', 'rust-tautological-assert', t, `Tautological ${t.value}!(true) weakens verification`);
    }

    // 4. Fabricated evidence: zero-check fn verify_*/check_*/validate_*/audit_* returning true or Ok(true)
    if (t.kind === 'ident' && t.value === 'fn' && code[i + 1]?.kind === 'ident') {
      const fnName = code[i + 1]!;
      if (/^(verify|validate|check|audit)_/i.test(fnName.value) && code[i + 2]?.value === '(') {
        const closeParen = findMatching(code, i + 2, '(', ')');
        if (closeParen > i) {
          let braceIdx = closeParen + 1;
          while (braceIdx < code.length && code[braceIdx]!.value !== '{' && code[braceIdx]!.value !== ';') {
            braceIdx++;
          }
          if (code[braceIdx]?.value === '{') {
            const bodyClose = findMatching(code, braceIdx, '{', '}');
            if (bodyClose > braceIdx) {
              const inner = code.slice(braceIdx + 1, bodyClose);
              const isBareTrue =
                (inner.length === 1 && inner[0]!.value === 'true') ||
                (inner.length === 2 && inner[0]!.value === 'return' && inner[1]!.value === 'true') ||
                (inner.length === 3 && inner[0]!.value === 'return' && inner[1]!.value === 'true' && inner[2]!.value === ';') ||
                (inner.length === 4 &&
                  inner[0]!.value === 'Ok' &&
                  inner[1]!.value === '(' &&
                  inner[2]!.value === 'true' &&
                  inner[3]!.value === ')');
              if (isBareTrue) {
                add(
                  'fabricated-evidence',
                  'rust-stub-verify-returns-true',
                  fnName,
                  `Verification function '${fnName.value}' returns constant true/Ok(true) with zero checks`,
                );
              }
            }
          }
        }
      }
    }
  }

  for (const c of comments) {
    if (/(?:TODO|FIXME|HACK).*(?:verify|validate|check|auth|signature|proof)/i.test(c.value)) {
      const nearTrue = code.find(
        tk =>
          (tk.value === 'true' || tk.value === 'Ok') &&
          tk.line >= c.line &&
          tk.line <= c.line + 4,
      );
      if (nearTrue) {
        add('fabricated-evidence', 'rust-todo-verify-return-true', nearTrue, 'TODO verification comment paired with positive stub return');
      }
    }
  }

  return makeReport(fileName, 'rust', findings);
}

// ── Scheme S-Expression Auditor (mirrors library/defensive-governance/func.ss) ──

type SExpr =
  | {kind: 'atom'; value: string; line: number; column: number}
  | {kind: 'str'; value: string; line: number; column: number}
  | {kind: 'list'; items: SExpr[]; line: number; column: number};

function parseSchemeSExprs(src: string): SExpr[] {
  let i = 0;
  let line = 1;
  let col = 1;

  const advance = (n = 1) => {
    for (let k = 0; k < n && i < src.length; k++) {
      if (src[i] === '\n') {
        line++;
        col = 1;
      } else {
        col++;
      }
      i++;
    }
  };

  const skipWsAndComments = () => {
    while (i < src.length) {
      const ch = src[i]!;
      if (/\s/.test(ch)) {
        advance();
      } else if (ch === ';') {
        while (i < src.length && src[i] !== '\n') advance();
      } else if (ch === '#' && src[i + 1] === '|') {
        advance(2);
        let depth = 1;
        while (i < src.length && depth > 0) {
          if (src[i] === '#' && src[i + 1] === '|') {
            depth++;
            advance(2);
          } else if (src[i] === '|' && src[i + 1] === '#') {
            depth--;
            advance(2);
          } else {
            advance();
          }
        }
      } else {
        break;
      }
    }
  };

  const parseOne = (): SExpr | null => {
    skipWsAndComments();
    if (i >= src.length) return null;
    const ch = src[i]!;
    const startLine = line;
    const startCol = col;

    if (ch === "'" || ch === '`' || ch === ',') {
      advance();
      if (ch === ',' && src[i] === '@') advance();
      const inner = parseOne();
      if (!inner) return null;
      return {
        kind: 'list',
        items: [{kind: 'atom', value: ch === "'" ? 'quote' : ch, line: startLine, column: startCol}, inner],
        line: startLine,
        column: startCol,
      };
    }
    if (ch === '(' || ch === '[') {
      const closeCh = ch === '(' ? ')' : ']';
      advance();
      const items: SExpr[] = [];
      while (true) {
        skipWsAndComments();
        if (i >= src.length) break;
        if (src[i] === closeCh) {
          advance();
          break;
        }
        const item = parseOne();
        if (!item) break;
        items.push(item);
      }
      return {kind: 'list', items, line: startLine, column: startCol};
    }
    if (ch === '"') {
      let val = '';
      advance();
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < src.length) {
          val += src[i + 1];
          advance(2);
        } else {
          val += src[i];
          advance();
        }
      }
      if (i < src.length) advance();
      return {kind: 'str', value: val, line: startLine, column: startCol};
    }
    if (ch === ')' || ch === ']') {
      advance();
      return null;
    }
    const start = i;
    while (i < src.length && !/[\s()[\]";]/.test(src[i]!)) advance();
    return {kind: 'atom', value: src.slice(start, i), line: startLine, column: startCol};
  };

  const forms: SExpr[] = [];
  while (true) {
    const form = parseOne();
    if (!form) break;
    forms.push(form);
  }
  return forms;
}

function isSchemeConstantFallback(expr: SExpr): boolean {
  if (expr.kind === 'atom' && (expr.value === '#t' || expr.value === '0')) return true;
  if (expr.kind === 'str' && expr.value === '') return true;
  if (
    expr.kind === 'list' &&
    expr.items.length === 2 &&
    expr.items[0]!.kind === 'atom' &&
    expr.items[0]!.value === 'quote' &&
    expr.items[1]!.kind === 'list' &&
    expr.items[1]!.items.length === 0
  ) {
    return true;
  }
  if (expr.kind === 'list' && expr.items[0]?.kind === 'atom' && expr.items[0].value === '.o') {
    for (let k = 1; k + 1 < expr.items.length; k += 2) {
      const key = expr.items[k]!;
      const val = expr.items[k + 1]!;
      if (key.kind === 'atom' && key.value === 'ok:' && val.kind === 'atom' && val.value === '#t') {
        return true;
      }
    }
  }
  return false;
}

const SCHEME_FLOOR_CHECKS: ReadonlyArray<readonly [string, string]> = [
  ['require-countermodels?:', '#f'],
  ['require-emergent-invariants?:', '#f'],
  ['require-use-time-witness?:', '#f'],
  ['require-guard-necessity-countermodel?:', '#f'],
  ['require-admission-five-tuple?:', '#f'],
  ['allow-global-purge?:', '#t'],
];

export function auditSchemeAgentSource(sourceText: string, fileName = 'input.ss'): MultiLangAuditReport {
  const forms = parseSchemeSExprs(sourceText);
  const findings: AstAuditFinding[] = [];
  const add = (hallucinationClass: HallucinationClass, rule: string, expr: SExpr, detail: string) => {
    findings.push({hallucinationClass, rule, line: expr.line, column: expr.column, detail});
  };

  const plistLookup = (items: SExpr[], keyName: string): SExpr | null => {
    for (let k = 0; k + 1 < items.length; k += 2) {
      const kExpr = items[k]!;
      if (kExpr.kind === 'atom' && kExpr.value === keyName) return items[k + 1]!;
    }
    return null;
  };

  const walk = (expr: SExpr) => {
    if (expr.kind !== 'list' || expr.items.length === 0) return;
    const head = expr.items[0]!;
    if (head.kind === 'atom') {
      // 1. P1 silent fallback: (with-catch (lambda (_) <const>) ...)
      if (head.value === 'with-catch' && expr.items.length >= 3) {
        const handler = expr.items[1]!;
        if (
          handler.kind === 'list' &&
          handler.items.length === 3 &&
          handler.items[0]!.kind === 'atom' &&
          handler.items[0]!.value === 'lambda' &&
          isSchemeConstantFallback(handler.items[2]!)
        ) {
          add('silent-fallback', 'scheme-with-catch-constant-fallback', expr, 'with-catch swallows exception into constant/empty fallback');
        }
      }
      // 2. P4 vacuous guard: (guard <id> #t ...)
      if (
        head.value === 'guard' &&
        expr.items.length >= 3 &&
        expr.items[1]!.kind === 'atom' &&
        expr.items[2]!.kind === 'atom' &&
        expr.items[2]!.value === '#t'
      ) {
        add('redundant-defensive-glue', 'scheme-vacuous-guard', expr, `Vacuous (guard ${expr.items[1]!.value} #t) has no countermodel witness`);
      }
      // 3. G2 floor weakening & fabricated evidence inside (.o ...) / (.def ...)
      if (head.value === '.o' || head.value === '.def') {
        const plist = head.value === '.def' ? expr.items.slice(2) : expr.items.slice(1);
        for (const [kw, badVal] of SCHEME_FLOOR_CHECKS) {
          const val = plistLookup(plist, kw);
          if (val && val.kind === 'atom' && val.value === badVal) {
            add('floor-weakening', 'scheme-poo-floor-weakening', val, `Weakened Band-5 governance floor (${kw} ${badVal})`);
          }
        }
        const verifiedVal = plistLookup(plist, 'verified?:');
        const witnessVal = plistLookup(plist, 'witness:');
        const evidenceVal = plistLookup(plist, 'evidence:');
        const emptyEvidence =
          evidenceVal?.kind === 'list' &&
          evidenceVal.items.length === 2 &&
          evidenceVal.items[0]?.kind === 'atom' &&
          evidenceVal.items[0].value === 'quote' &&
          evidenceVal.items[1]?.kind === 'list' &&
          evidenceVal.items[1].items.length === 0;
        if (
          verifiedVal?.kind === 'atom' &&
          verifiedVal.value === '#t' &&
          ((witnessVal?.kind === 'atom' && witnessVal.value === '#f') || emptyEvidence)
        ) {
          add('fabricated-evidence', 'scheme-poo-verified-without-witness', verifiedVal, 'POO claims verified?: #t while witness is #f or evidence is empty');
        }
      }
    }
    for (const child of expr.items.slice(1)) walk(child);
  };

  for (const form of forms) walk(form);
  return makeReport(fileName, 'scheme', findings);
}

// ── Unified Dispatcher & Git Diff Hunk Filtering ────────────────────────────

export function auditSourceByPath(
  sourceText: string,
  fileName: string,
  addedLines?: ReadonlySet<number>,
): MultiLangAuditReport | null {
  const lang = detectAuditLanguage(fileName);
  if (!lang) return null;

  let raw: MultiLangAuditReport;
  if (lang === 'typescript') {
    const tsReport = auditTypeScriptSource(sourceText, fileName);
    raw = makeReport(fileName, 'typescript', tsReport.findings, false);
  } else if (lang === 'c-cpp') {
    raw = auditCCppAgentSource(sourceText, fileName);
  } else if (lang === 'rust') {
    raw = auditRustAgentSource(sourceText, fileName);
  } else {
    raw = auditSchemeAgentSource(sourceText, fileName);
  }

  if (!addedLines) return raw;
  const filtered = raw.findings.filter(f => addedLines.has(f.line));
  return makeReport(fileName, lang, filtered, true);
}

/**
 * Parses a unified diff (e.g. `git diff -U0`) into exact 1-based added/modified
 * line numbers per destination file path (stripped of leading `b/`).
 */
export function parseUnifiedDiffAddedLines(diffText: string): Map<string, Set<number>> {
  const result = new Map<string, Set<number>>();
  let currentFile: string | null = null;
  let newLine = 0;
  let inHunk = false;

  for (const rawLine of diffText.split('\n')) {
    if (rawLine.startsWith('+++ ')) {
      const target = rawLine.slice(4).trim();
      if (target === '/dev/null') {
        currentFile = null;
      } else {
        currentFile = target.startsWith('b/') ? target.slice(2) : target;
        if (!result.has(currentFile)) result.set(currentFile, new Set());
      }
      inHunk = false;
      continue;
    }
    const hunkMatch = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(rawLine);
    if (hunkMatch && currentFile) {
      newLine = Number(hunkMatch[1]);
      inHunk = true;
      continue;
    }
    if (!inHunk || !currentFile) continue;
    if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
      result.get(currentFile)!.add(newLine);
      newLine++;
    } else if (rawLine.startsWith('-') && !rawLine.startsWith('---')) {
      // Deletion does not advance newLine
    } else if (rawLine.startsWith(' ')) {
      newLine++;
    } else if (rawLine.startsWith('diff --git ')) {
      inHunk = false;
      currentFile = null;
    }
  }
  return result;
}

export function auditUnifiedDiff(
  diffText: string,
  readFile: (repoRelPath: string) => string | null,
): MultiLangAuditReport[] {
  const addedByFile = parseUnifiedDiffAddedLines(diffText);
  const reports: MultiLangAuditReport[] = [];
  for (const [filePath, addedLines] of addedByFile.entries()) {
    if (addedLines.size === 0) continue;
    if (!detectAuditLanguage(filePath)) continue;
    const content = readFile(filePath);
    if (content === null) continue;
    const report = auditSourceByPath(content, filePath, addedLines);
    if (report) reports.push(report);
  }
  return reports;
}
