// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * E3.3: Multi-Language Structural AST & Unified-Diff AI Agent Defensive Auditor.
 *
 * Covers 6 languages used across this repository and consuming production repos
 * with zero external parser dependencies and exact 1-based line/column locations:
 *   - TypeScript / JavaScript (.ts, .tsx, .js, .mjs) -> delegates to ts-ast-auditor.ts
 *   - C / C++ (.c, .h, .cc, .cpp, .hpp)             -> balanced C-family lexer & block auditor
 *   - Rust (.rs)                                     -> nested-comment Rust lexer & structural auditor
 *   - Go (.go)                                       -> Go lexer (incl. raw backtick strings) & err/recover/stub auditor
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

export type SupportedAuditLanguage = 'typescript' | 'c-cpp' | 'rust' | 'go' | 'scheme';

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
  if (ext === '.go') return 'go';
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
    if (ch === '`') {
      advance();
      const start = i;
      while (i < src.length && src[i] !== '`') advance();
      const val = src.slice(start, i);
      if (src[i] === '`') advance();
      code.push({kind: 'str', value: val, line: startLine, column: startCol});
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
      while (
        i < src.length &&
        (/[0-9a-zA-Z_]/.test(src[i]!) || (src[i] === '.' && /[0-9]/.test(src[i + 1] ?? '')))
      ) {
        advance();
      }
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
            let hasThrow = false;
            let hasReturn = false;
            let hasLog = false;
            for (let k = 0; k < inner.length; k++) {
              if (inner[k]!.value === 'throw') hasThrow = true;
              if (
                inner[k]!.value === 'cerr' ||
                inner[k]!.value === 'clog' ||
                inner[k]!.value === 'fprintf' ||
                inner[k]!.value === 'printf'
              ) {
                hasLog = true;
              }
              if (inner[k]!.value === 'return') {
                hasReturn = true;
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
                    hasLog ? 'cpp-catch-log-and-swallow' : 'cpp-catch-constant-fallback',
                    inner[k]!,
                    `catch block masks exception by returning fallback constant '${next.value}'`,
                  );
                }
              }
            }
            if (hasLog && !hasThrow && !hasReturn) {
              add('silent-fallback', 'cpp-catch-log-and-swallow', t, 'catch block logs exception and swallows control flow without rethrow or error return');
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

const RUST_OPTION_ACCESSOR_METHODS = new Set([
  'as_deref',
  'as_ref',
  'as_str',
  'as_array',
  'as_object',
  'as_u64',
  'as_i64',
  'as_bool',
  'get',
  'next',
  'first',
  'last',
  'find',
  'position',
  'rposition',
  'pointer',
  'pop',
  'peek',
  'cloned',
  'copied',
  'strip_prefix',
  'strip_suffix',
  'file_name',
  'extension',
  'parent',
  'max',
  'min',
  'saturating_sub',
  'checked_sub',
  'checked_div',
  'checked_add',
  'checked_mul',
  'checked_rem',
  'started_at_ms',
  'width',
]);

const RUST_FAIL_CLOSED_PREDICATE_RE =
  /^is_.*(fenced|retracted|blocked|revoked|tripped|denied|quarantined|expired|stale|corrupt|disabled)/i;

function isRustOptionAccessorChain(code: readonly Tok[], dotIdx: number): boolean {
  // Scan backwards across the receiver expression up to statement/delimiter boundary.
  // If `.ok()` appears anywhere in the chain (except `duration_since(UNIX_EPOCH)`),
  // a Result::Err is being collapsed into Option::None -> NOT a pure Option accessor!
  const start = Math.max(0, dotIdx - 80);
  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;
  let sawOptionAccessor = false;
  let sawDurationSinceEpoch = false;
  let sawTryPropagated = false;
  let sawDotOk = false;
  for (let k = dotIdx - 1; k >= start; k--) {
    const tk = code[k]!;
    if (tk.value === ')') {
      depthParen++;
      continue;
    }
    if (tk.value === '(') {
      if (depthParen > 0) {
        depthParen--;
        continue;
      }
      break;
    }
    if (tk.value === ']') {
      depthBracket++;
      continue;
    }
    if (tk.value === '[') {
      if (depthBracket > 0) {
        depthBracket--;
        continue;
      }
      break;
    }
    if (tk.value === '}') {
      depthBrace++;
      continue;
    }
    if (tk.value === '{') {
      if (depthBrace > 0) {
        depthBrace--;
        continue;
      }
      break;
    }
    if (
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0 &&
      (tk.value === ';' || tk.value === '=' || tk.value === ',' || tk.value === '&&' || tk.value === '||' || tk.value === '=>')
    ) {
      break;
    }
    // `expr?.unwrap_or_default()` already propagated Err via `?` (only Option remains).
    if (depthParen === 0 && depthBracket === 0 && depthBrace === 0 && tk.value === '?' && k === dotIdx - 1) {
      sawTryPropagated = true;
    }
    if (tk.kind === 'ident' && tk.value === 'ok' && code[k - 1]?.value === '.' && code[k + 1]?.value === '(') {
      sawDotOk = true;
    }
    if (tk.kind === 'ident' && tk.value === 'UNIX_EPOCH') {
      sawDurationSinceEpoch = true;
    }
    if (
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0 &&
      tk.kind === 'ident' &&
      code[k - 1]?.value === '.' &&
      RUST_OPTION_ACCESSOR_METHODS.has(tk.value)
    ) {
      sawOptionAccessor = true;
    }
  }
  if (sawDurationSinceEpoch) return true;
  if (sawDotOk) return false;
  return sawOptionAccessor || sawTryPropagated;
}

function inspectEnclosingMatch(
  code: readonly Tok[],
  errTokIdx: number,
): {hasOtherErrArm: boolean; hasGuardedReturnErrArm: boolean; hasAwait: boolean} {
  // Walk backwards to find the opening `{` of the enclosing match body.
  let depth = 0;
  let matchOpen = -1;
  for (let k = errTokIdx - 1; k >= 0; k--) {
    const v = code[k]!.value;
    if (v === '}') depth++;
    else if (v === '{') {
      if (depth === 0) {
        matchOpen = k;
        break;
      }
      depth--;
    }
  }
  if (matchOpen < 0) return {hasOtherErrArm: false, hasGuardedReturnErrArm: false, hasAwait: false};
  const matchClose = findMatching(code, matchOpen, '{', '}');
  if (matchClose <= matchOpen) return {hasOtherErrArm: false, hasGuardedReturnErrArm: false, hasAwait: false};

  // Count top-level `Err(...) =>` arms directly inside this match block and check for guarded return Err / `.await`.
  let innerDepth = 0;
  let errArmCount = 0;
  let hasGuardedReturnErrArm = false;
  let hasAwait = false;
  for (let k = matchOpen + 1; k < matchClose; k++) {
    const v = code[k]!.value;
    if (code[k]!.kind === 'ident' && v === 'await' && code[k - 1]?.value === '.') {
      hasAwait = true;
    }
    if (v === '{' || v === '(' || v === '[') {
      innerDepth++;
      continue;
    }
    if (v === '}' || v === ')' || v === ']') {
      if (innerDepth > 0) innerDepth--;
      continue;
    }
    if (innerDepth === 0 && code[k]!.kind === 'ident' && v === 'Err' && code[k + 1]?.value === '(') {
      const cp = findMatching(code, k + 1, '(', ')');
      if (cp > k) {
        let arrowIdx = cp + 1;
        let isGuarded = false;
        if (code[arrowIdx]?.value === 'if') {
          isGuarded = true;
          let gDepth = 0;
          while (arrowIdx < matchClose) {
            const gv = code[arrowIdx]!.value;
            if (gv === '(' || gv === '{' || gv === '[') gDepth++;
            else if (gv === ')' || gv === '}' || gv === ']') {
              if (gDepth > 0) gDepth--;
            } else if (gDepth === 0 && gv === '=>') {
              break;
            }
            arrowIdx++;
          }
        }
        if (code[arrowIdx]?.value === '=>') {
          errArmCount++;
          if (isGuarded && code[arrowIdx + 1]?.value === 'return' && code[arrowIdx + 2]?.value === 'Err') {
            hasGuardedReturnErrArm = true;
          }
        }
      }
    }
  }
  return {hasOtherErrArm: errArmCount > 1, hasGuardedReturnErrArm, hasAwait};
}

export function auditRustAgentSource(sourceText: string, fileName = 'input.rs'): MultiLangAuditReport {
  const {code, comments} = tokenizeCLike(sourceText, true);
  const findings: AstAuditFinding[] = [];
  const add = (hallucinationClass: HallucinationClass, rule: string, tok: Tok, detail: string) => {
    findings.push({hallucinationClass, rule, line: tok.line, column: tok.column, detail});
  };

  // Identify inline `#[cfg(test)] mod <name> { ... }` token ranges so production unwrap/Err
  // heuristics do not spam test helpers (while #[ignore] & assert!(true) remain enforced everywhere).
  const cfgTestRanges: Array<[number, number]> = [];
  for (let i = 0; i + 5 < code.length; i++) {
    if (code[i]!.value === '#' && code[i + 1]?.value === '[') {
      const attrClose = findMatching(code, i + 1, '[', ']');
      if (attrClose > i + 1) {
        const attrSlice = code.slice(i + 2, attrClose);
        const isCfgTest =
          attrSlice[0]?.value === 'cfg' &&
          attrSlice[1]?.value === '(' &&
          attrSlice.some(tk => tk.value === 'test');
        if (isCfgTest && code[attrClose + 1]?.value === 'mod') {
          let braceIdx = attrClose + 2;
          while (braceIdx < code.length && code[braceIdx]!.value !== '{' && code[braceIdx]!.value !== ';') {
            braceIdx++;
          }
          if (code[braceIdx]?.value === '{') {
            const modClose = findMatching(code, braceIdx, '{', '}');
            if (modClose > braceIdx) {
              cfgTestRanges.push([braceIdx, modClose]);
            }
          }
        }
      }
    }
  }
  const inCfgTest = (idx: number): boolean => cfgTestRanges.some(([s, e]) => idx >= s && idx <= e);

  // Track enclosing `fn <name>` scope for fail-closed predicate detection.
  const fnRanges: Array<{name: string; start: number; end: number}> = [];
  for (let i = 0; i + 2 < code.length; i++) {
    if (code[i]!.kind === 'ident' && code[i]!.value === 'fn' && code[i + 1]?.kind === 'ident') {
      const fnName = code[i + 1]!.value;
      let braceIdx = i + 2;
      while (braceIdx < code.length && code[braceIdx]!.value !== '{' && code[braceIdx]!.value !== ';') {
        braceIdx++;
      }
      if (code[braceIdx]?.value === '{') {
        const bodyClose = findMatching(code, braceIdx, '{', '}');
        if (bodyClose > braceIdx) {
          fnRanges.push({name: fnName, start: braceIdx, end: bodyClose});
        }
      }
    }
  }
  const enclosingFnName = (idx: number): string | null => {
    let best: {name: string; span: number} | null = null;
    for (const r of fnRanges) {
      if (idx >= r.start && idx <= r.end) {
        const span = r.end - r.start;
        if (!best || span < best.span) best = {name: r.name, span};
      }
    }
    return best?.name ?? null;
  };

  for (let i = 0; i < code.length; i++) {
    const t = code[i]!;
    const insideTestMod = inCfgTest(i);

    // 1. Silent fallback: .unwrap_or_default() or .unwrap_or(0|true|"") on Result/unqualified chains
    if (!insideTestMod && t.value === '.' && code[i + 1]?.kind === 'ident') {
      const m = code[i + 1]!;
      if (m.value === 'unwrap_or_default' && code[i + 2]?.value === '(') {
        if (!isRustOptionAccessorChain(code, i)) {
          add(
            'silent-fallback',
            'rust-unwrap-or-default',
            m,
            '.unwrap_or_default() silently collapses Err/None into a default value',
          );
        }
      } else if (m.value === 'unwrap_or' && code[i + 2]?.value === '(') {
        const closeParen = findMatching(code, i + 2, '(', ')');
        if (closeParen === i + 4) {
          const arg = code[i + 3]!;
          const isFailClosedPredicate =
            arg.value === 'true' &&
            (() => {
              const fnName = enclosingFnName(i);
              return fnName !== null && RUST_FAIL_CLOSED_PREDICATE_RE.test(fnName);
            })();
          if (
            !isFailClosedPredicate &&
            !isRustOptionAccessorChain(code, i) &&
            ((arg.kind === 'num' && arg.value === '0') ||
              arg.value === 'true' ||
              (arg.kind === 'str' && arg.value === ''))
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
    if (!insideTestMod && t.kind === 'ident' && t.value === 'Err' && code[i + 1]?.value === '(') {
      const closeParen = findMatching(code, i + 1, '(', ')');
      if (closeParen > i && code[closeParen + 1]?.value === '=>') {
        const patTokens = code.slice(i + 2, closeParen);
        const isSpecificErrorVariant = patTokens.some(tk => tk.value === '::');
        const errVar = closeParen === i + 3 ? code[i + 2]!.value : null;
        let rhsIdx = closeParen + 2;
        if (code[rhsIdx]?.value === 'return') rhsIdx++;
        const rhs = code[rhsIdx];
        if (rhs?.value === 'Ok' && code[rhsIdx + 1]?.value === '(') {
          const okClose = findMatching(code, rhsIdx + 1, '(', ')');
          const okInner = okClose > rhsIdx + 1 ? code.slice(rhsIdx + 2, okClose) : [];
          const isGrpcResponsePayload =
            okInner[0]?.value === 'Response' && okInner[1]?.value === '::' && okInner[2]?.value === 'new';
          if (!isSpecificErrorVariant && !isGrpcResponsePayload) {
            add('silent-fallback', 'rust-err-arm-returns-ok', t, 'Match arm Err(_) silently converts error into Ok(...)');
          }
        } else if (rhs?.value === '{') {
          const armClose = findMatching(code, rhsIdx, '{', '}');
          if (armClose > rhsIdx) {
            const armBody = code.slice(rhsIdx + 1, armClose);
            // Require macro `!` so a variable named `error` is never mistaken for `error!(...)`.
            const logsErr = armBody.some(
              (tk, idx) =>
                (tk.value === 'eprintln' || tk.value === 'println' || tk.value === 'error' || tk.value === 'warn') &&
                armBody[idx + 1]?.value === '!',
            );
            const returnsOkOrDefault = armBody.some(
              (tk, idx) =>
                (tk.value === 'Ok' && armBody[idx + 1]?.value === '(') ||
                tk.value === 'default',
            );
            const exitsProcess = armBody.some(
              (tk, idx) =>
                tk.value === 'exit' &&
                armBody[idx + 1]?.value === '(' &&
                armBody[idx + 2]?.value !== '0',
            );
            const returnsTypedFailure = armBody.some(
              (tk, idx) =>
                ((tk.value === 'failed' || tk.value === 'denied' || tk.value === 'rejected') &&
                  armBody[idx - 1]?.value === '::' &&
                  armBody[idx + 1]?.value === '(') ||
                tk.value === 'failed_join_summary' ||
                tk.value === 'rejected_with_actions' ||
                (tk.value === 'Rejected' && armBody[idx - 1]?.value === '::'),
            );
            const returnsErr = armBody.some(tk => tk.value === 'Err' || tk.value === 'panic');
            const matchInfo = inspectEnclosingMatch(code, i);
            const hasScopedErrorRouting =
              matchInfo.hasOtherErrArm && (isSpecificErrorVariant || matchInfo.hasGuardedReturnErrArm);
            if (logsErr && !exitsProcess && !returnsTypedFailure && !hasScopedErrorRouting && (returnsOkOrDefault || !returnsErr)) {
              add(
                'silent-fallback',
                'rust-err-log-and-swallow',
                t,
                'Err match arm logs error and swallows failure via Ok/default/unit fallthrough',
              );
            }
          }
        } else if (
          errVar &&
          errVar !== '_' &&
          rhs?.value === 'Err' &&
          code[rhsIdx + 1]?.value === '(' &&
          code[rhsIdx + 2]?.value === errVar &&
          code[rhsIdx + 3]?.value === ')'
        ) {
          const matchInfo = inspectEnclosingMatch(code, i);
          if (!matchInfo.hasOtherErrArm && !matchInfo.hasAwait) {
            add('redundant-defensive-glue', 'rust-noop-err-rethrow', t, `Redundant Err(${errVar}) => Err(${errVar}) glue`);
          }
        }
      }
    }

    // 3. Floor weakening: #[ignore] on tests, #[allow(unused_must_use|unused_results)], assert!(true)
    if (t.value === '#' && code[i + 1]?.value === '[') {
      const attrClose = findMatching(code, i + 1, '[', ']');
      if (attrClose > i + 1) {
        const attrSlice = code.slice(i + 2, attrClose);
        if (attrSlice[0]?.value === 'ignore') {
          add('floor-weakening', 'rust-test-ignore', t, '#[ignore] disables verification test');
        } else if (
          attrSlice[0]?.value === 'allow' &&
          attrSlice.some(tk => tk.value === 'unused_must_use' || tk.value === 'unused_results')
        ) {
          add(
            'floor-weakening',
            'rust-allow-unused-must-use',
            t,
            '#[allow(unused_must_use/unused_results)] suppresses Result/error boundary handling',
          );
        }
      }
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

// ── Go Auditor ──────────────────────────────────────────────────────────────

function findEnclosingGoFuncReturnError(code: readonly Tok[], idx: number): {
  fnName: string | null;
  returnsError: boolean;
  returnsMulti: boolean;
} {
  // Scan enclosing func declarations that contain `idx`.
  let bestSpan = Infinity;
  let best: {fnName: string | null; returnsError: boolean; returnsMulti: boolean} = {
    fnName: null,
    returnsError: false,
    returnsMulti: false,
  };
  for (let i = 0; i < idx; i++) {
    if (code[i]!.kind !== 'ident' || code[i]!.value !== 'func') continue;
    let cursor = i + 1;
    // Skip optional method receiver `func (r *Recv) Name(...)` — only when an identifier follows `)`.
    // Anonymous closures `func(a T, err error) {` start directly with `(` and have NO following name!
    if (code[cursor]?.value === '(') {
      const recvClose = findMatching(code, cursor, '(', ')');
      if (recvClose < 0) continue;
      if (code[recvClose + 1]?.kind === 'ident') {
        cursor = recvClose + 1;
      }
    }
    let fnName: string | null = null;
    if (code[cursor]?.kind === 'ident') {
      fnName = code[cursor]!.value;
      cursor++;
    }
    // Skip optional type parameters `[T any]`
    if (code[cursor]?.value === '[') {
      const tpClose = findMatching(code, cursor, '[', ']');
      if (tpClose < 0) continue;
      cursor = tpClose + 1;
    }
    if (code[cursor]?.value !== '(') continue;
    const paramClose = findMatching(code, cursor, '(', ')');
    if (paramClose < 0) continue;
    let braceIdx = paramClose + 1;
    while (braceIdx < code.length && code[braceIdx]!.value !== '{' && code[braceIdx]!.value !== ';') {
      braceIdx++;
    }
    if (code[braceIdx]?.value !== '{') continue;
    const bodyClose = findMatching(code, braceIdx, '{', '}');
    if (bodyClose <= braceIdx || idx < braceIdx || idx > bodyClose) continue;
    const span = bodyClose - braceIdx;
    if (span < bestSpan) {
      bestSpan = span;
      const retSlice = code.slice(paramClose + 1, braceIdx);
      const returnsMulti = retSlice[0]?.value === '(' && retSlice.some(tk => tk.value === ',');
      const returnsError = retSlice.some(tk => tk.kind === 'ident' && tk.value === 'error');
      best = {fnName, returnsError, returnsMulti};
    }
  }
  return best;
}

export function auditGoAgentSource(sourceText: string, fileName = 'input.go'): MultiLangAuditReport {
  const {code, comments} = tokenizeCLike(sourceText, false);
  const findings: AstAuditFinding[] = [];
  const add = (hallucinationClass: HallucinationClass, rule: string, tok: Tok, detail: string) => {
    findings.push({hallucinationClass, rule, line: tok.line, column: tok.column, detail});
  };

  for (let i = 0; i < code.length; i++) {
    const t = code[i]!;

    // 1. `if ... err != nil { ... }` silent fallback / log-and-swallow / empty block
    if (t.kind === 'ident' && t.value === 'if') {
      let braceIdx = i + 1;
      let pDepth = 0;
      while (braceIdx < code.length) {
        const v = code[braceIdx]!.value;
        if (v === '(' || v === '[') pDepth++;
        else if (v === ')' || v === ']') {
          if (pDepth > 0) pDepth--;
        } else if (pDepth === 0 && v === '{') {
          break;
        } else if (pDepth === 0 && v === '}' && braceIdx > i + 1) {
          braceIdx = -1;
          break;
        }
        braceIdx++;
      }
      if (braceIdx > i + 1 && code[braceIdx]?.value === '{') {
        const condSlice = code.slice(i + 1, braceIdx);
        const checksErrNotNil = condSlice.some(
          (tk, idx) =>
            tk.kind === 'ident' &&
            /^(err\d*|[a-zA-Z0-9_]+Err)$/.test(tk.value) &&
            condSlice[idx + 1]?.value === '!=' &&
            condSlice[idx + 2]?.value === 'nil',
        );
        const hasNarrowExpectedErrGuard = condSlice.some(
          tk =>
            tk.value === 'Is' ||
            tk.value === 'As' ||
            tk.value === 'EOF' ||
            tk.value === 'ErrNotExist' ||
            tk.value === 'ErrClosed' ||
            tk.value === 'Canceled' ||
            tk.value === 'IsNotExist',
        );
        if (checksErrNotNil && !hasNarrowExpectedErrGuard) {
          const bodyClose = findMatching(code, braceIdx, '{', '}');
          if (bodyClose > braceIdx) {
            const body = code.slice(braceIdx + 1, bodyClose);
            if (body.length === 0) {
              add('silent-fallback', 'go-empty-if-err', t, 'Empty `if err != nil {}` silently swallows error');
            } else {
              const fnInfo = findEnclosingGoFuncReturnError(code, i);
              const logsErr = body.some(
                (tk, idx) =>
                  (tk.value === 'log' || tk.value === 'slog' || tk.value === 'fmt') &&
                  body[idx + 1]?.value === '.' &&
                  /^(Print|Printf|Println|Warn|Error|Fprint|Fprintf|Fprintln)/.test(body[idx + 2]?.value ?? ''),
              );
              const surfacesUiError = body.some(
                tk =>
                  tk.value === 'SeverityError' ||
                  tk.value === 'SeverityWarning' ||
                  tk.value === 'publishError' ||
                  tk.value === 'PublishError',
              );
              const propagatesErr =
                surfacesUiError ||
                body.some(
                (tk, idx) =>
                  tk.value === 'panic' ||
                  tk.value === 'Fatal' ||
                  tk.value === 'Fatalf' ||
                  tk.value === 'Error' ||
                  tk.value === 'Errorf' ||
                  (tk.value === 'Exit' &&
                    body[idx - 1]?.value === '.' &&
                    body[idx + 1]?.value === '(' &&
                    body[idx + 2]?.value !== '0') ||
                  (tk.value === 'return' &&
                    body.slice(idx + 1).some(
                      rt =>
                        rt.value === 'err' ||
                        rt.value.endsWith('Err') ||
                        rt.value === 'Errorf' ||
                        rt.value === 'New' ||
                        rt.value === 'Wrap' ||
                        rt.value === 'Status' ||
                        rt.value === 'Error' ||
                        rt.value === 'Refuted' ||
                        rt.value === 'Denied',
                    )),
              );
              // Detect `return nil` or `return ..., nil` where the function returns `error`
              let returnsNilError = false;
              let retTok: Tok | null = null;
              for (let k = 0; k < body.length; k++) {
                if (body[k]!.value !== 'return') continue;
                // Find end of return statement (same line or next `;` / `}`)
                const retLine = body[k]!.line;
                let end = k + 1;
                let d = 0;
                while (end < body.length) {
                  const ev = body[end]!.value;
                  if (ev === '(' || ev === '{' || ev === '[') d++;
                  else if (ev === ')' || ev === '}' || ev === ']') {
                    if (d > 0) d--;
                  } else if (d === 0 && (ev === ';' || (body[end]!.line > retLine && body[end - 1]!.value !== ','))) {
                    break;
                  }
                  end++;
                }
                const retExpr = body.slice(k + 1, end);
                if (retExpr.length > 0 && retExpr[retExpr.length - 1]!.value === 'nil') {
                  if (fnInfo.returnsError) {
                    returnsNilError = true;
                    retTok = body[k]!;
                    break;
                  }
                }
              }
              const handlesExpectedInside = body.some(
                tk =>
                  tk.value === 'Is' ||
                  tk.value === 'As' ||
                  tk.value === 'EOF' ||
                  tk.value === 'ErrNotExist' ||
                  tk.value === 'ErrClosed' ||
                  tk.value === 'Canceled' ||
                  tk.value === 'DeadlineExceeded',
              );
              if (!handlesExpectedInside) {
                if (logsErr && !propagatesErr && (returnsNilError || body.every(tk => tk.value !== 'return') || fnInfo.returnsError)) {
                  add(
                    'silent-fallback',
                    'go-if-err-log-and-swallow',
                    t,
                    '`if err != nil` logs error and swallows failure without propagating error',
                  );
                } else if (returnsNilError && !propagatesErr) {
                  add(
                    'silent-fallback',
                    'go-if-err-return-nil',
                    retTok ?? t,
                    '`if err != nil` returns nil error, silently masking defect',
                  );
                }
              }
            }
          }
        }
      }
    }

    // 2. `recover()` swallow or redundant `if r := recover(); r != nil { panic(r) }`
    if (t.kind === 'ident' && t.value === 'recover' && code[i + 1]?.value === '(' && code[i + 2]?.value === ')') {
      // Check `defer func() { recover() }()` bare swallow
      if (code[i - 1]?.value === '{' && code[i + 3]?.value === '}') {
        add('silent-fallback', 'go-recover-swallow', t, 'Bare `recover()` silently swallows panic without recording or returning error');
      } else if (code[i + 3]?.value === ';') {
        // `if r := recover(); r != nil { ... }`
        let braceIdx = i + 4;
        while (braceIdx < code.length && code[braceIdx]!.value !== '{' && braceIdx < i + 12) braceIdx++;
        if (code[braceIdx]?.value === '{') {
          const bodyClose = findMatching(code, braceIdx, '{', '}');
          if (bodyClose > braceIdx) {
            const inner = code.slice(braceIdx + 1, bodyClose);
            if (inner.length === 0) {
              add('silent-fallback', 'go-recover-swallow', t, 'Empty `if r := recover(); r != nil {}` silently swallows panic');
            } else if (
              inner.length === 4 &&
              inner[0]!.value === 'panic' &&
              inner[1]!.value === '(' &&
              inner[3]!.value === ')'
            ) {
              add('redundant-defensive-glue', 'go-noop-recover-repanic', t, 'Redundant recover() that immediately re-panics unchanged value');
            }
          }
        }
      }
    }

    // 3. Floor weakening: t.Skip / t.Skipf / t.SkipNow
    if (
      t.value === '.' &&
      (code[i + 1]?.value === 'Skip' || code[i + 1]?.value === 'Skipf' || code[i + 1]?.value === 'SkipNow') &&
      code[i + 2]?.value === '('
    ) {
      add('floor-weakening', 'go-test-skip', code[i + 1]!, `Test skip call .${code[i + 1]!.value}() weakens verification gate`);
    }

    // 4. Fabricated evidence: zero-check Verify*/Validate*/Check*/Audit* stub returning bare true or nil
    if (t.kind === 'ident' && t.value === 'func') {
      let cursor = i + 1;
      if (code[cursor]?.value === '(') {
        const rc = findMatching(code, cursor, '(', ')');
        if (rc > cursor) cursor = rc + 1;
      }
      const fnName = code[cursor];
      if (
        fnName?.kind === 'ident' &&
        /^(verify|validate|check|audit)[A-Z_]/i.test(fnName.value) &&
        code[cursor + 1]?.value === '('
      ) {
        const pc = findMatching(code, cursor + 1, '(', ')');
        if (pc > cursor) {
          let braceIdx = pc + 1;
          while (braceIdx < code.length && code[braceIdx]!.value !== '{' && code[braceIdx]!.value !== ';') {
            braceIdx++;
          }
          if (code[braceIdx]?.value === '{') {
            const bodyClose = findMatching(code, braceIdx, '{', '}');
            if (bodyClose > braceIdx) {
              const inner = code.slice(braceIdx + 1, bodyClose);
              if (
                inner.length === 2 &&
                inner[0]!.value === 'return' &&
                (inner[1]!.value === 'true' || inner[1]!.value === 'nil')
              ) {
                add(
                  'fabricated-evidence',
                  'go-stub-verify-returns-true',
                  fnName,
                  `Verification function '${fnName.value}' unconditionally returns '${inner[1]!.value}' with zero checks`,
                );
              }
            }
          }
        }
      }
    }
  }

  for (const c of comments) {
    if (/nolint:[^\n]*\berrcheck\b/i.test(c.value)) {
      add('floor-weakening', 'go-nolint-errcheck', c, '//nolint:errcheck suppresses Go error-checking boundary enforcement');
    }
    if (/(?:TODO|FIXME|HACK).*(?:verify|validate|check|auth|signature|proof)/i.test(c.value)) {
      const nearReturn = code.find(
        (tk, idx) =>
          tk.value === 'return' &&
          tk.line >= c.line &&
          tk.line <= c.line + 4 &&
          (code[idx + 1]?.value === 'true' || code[idx + 1]?.value === 'nil'),
      );
      if (nearReturn) {
        add('fabricated-evidence', 'go-todo-verify-return-true', nearReturn, 'TODO verification comment paired with bare return true/nil');
      }
    }
  }

  return makeReport(fileName, 'go', findings);
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
      // 1. P1 silent fallback: (with-catch (lambda (_) <const>) ...) and Gerbil (try ... (catch (_) <const>))
      if (head.value === 'with-catch' && expr.items.length >= 3) {
        const handler = expr.items[1]!;
        if (
          handler.kind === 'list' &&
          handler.items.length >= 3 &&
          handler.items[0]!.kind === 'atom' &&
          handler.items[0]!.value === 'lambda'
        ) {
          const bodyForms = handler.items.slice(2);
          const lastForm = bodyForms[bodyForms.length - 1]!;
          const logsErr = bodyForms.some(
            bf =>
              bf.kind === 'list' &&
              bf.items[0]?.kind === 'atom' &&
              ['displayln', 'display', 'eprintf', 'fprintf', 'errorf', 'log-error'].includes(bf.items[0].value),
          );
          if (bodyForms.length === 1 && isSchemeConstantFallback(lastForm)) {
            add('silent-fallback', 'scheme-with-catch-constant-fallback', expr, 'with-catch swallows exception into constant/empty fallback');
          } else if (logsErr && isSchemeConstantFallback(lastForm)) {
            add('silent-fallback', 'scheme-with-catch-log-and-swallow', expr, 'with-catch logs exception and swallows failure into constant fallback');
          }
        }
      }
      if (head.value === 'try' && expr.items.length >= 3) {
        for (const clause of expr.items.slice(2)) {
          if (
            clause.kind === 'list' &&
            clause.items.length >= 3 &&
            clause.items[0]?.kind === 'atom' &&
            clause.items[0].value === 'catch'
          ) {
            const catchBody = clause.items.slice(2);
            const lastForm = catchBody[catchBody.length - 1]!;
            if (isSchemeConstantFallback(lastForm)) {
              add('silent-fallback', 'scheme-try-catch-constant-fallback', clause, 'Gerbil (try ... (catch ...)) swallows exception into constant/empty fallback');
            }
          }
        }
      }
      // 2. P4 vacuous guard: 2-arg `(guard <id> #t)` with no countermodel branch,
      //    or 3-arg `(guard <id> #t #t)` whose dropped branch is identical to healthy.
      //    A 3-arg `(guard <id> #t #f)` explicitly declares `#f` as its countermodel witness.
      if (
        head.value === 'guard' &&
        expr.items.length >= 3 &&
        expr.items[1]!.kind === 'atom' &&
        expr.items[2]!.kind === 'atom' &&
        expr.items[2]!.value === '#t' &&
        (expr.items.length === 3 ||
          (expr.items[3]!.kind === 'atom' && expr.items[3]!.value === '#t'))
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
  const fileLines = sourceText.split('\n');
  const filteredFindings = findings.filter(f => {
    const cur = fileLines[f.line - 1] ?? '';
    const prev = f.line >= 2 ? (fileLines[f.line - 2] ?? '') : '';
    return !cur.includes('defense-audit:allow-negative-control') && !prev.includes('defense-audit:allow-negative-control');
  });
  return makeReport(fileName, 'scheme', filteredFindings);
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
  } else if (lang === 'go') {
    raw = auditGoAgentSource(sourceText, fileName);
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

export interface DiffHunkDelta {
  filePath: string;
  newStartLine: number;
  removedLines: string[];
  addedLines: string[];
}

export function parseUnifiedDiffHunks(diffText: string): DiffHunkDelta[] {
  const hunks: DiffHunkDelta[] = [];
  let currentFile: string | null = null;
  let currentHunk: DiffHunkDelta | null = null;

  const flush = () => {
    if (currentHunk && (currentHunk.removedLines.length > 0 || currentHunk.addedLines.length > 0)) {
      hunks.push(currentHunk);
    }
    currentHunk = null;
  };

  for (const rawLine of diffText.split('\n')) {
    if (rawLine.startsWith('diff --git ')) {
      flush();
      currentFile = null;
      continue;
    }
    if (rawLine.startsWith('+++ ')) {
      flush();
      const target = rawLine.slice(4).trim();
      currentFile = target === '/dev/null' ? null : target.startsWith('b/') ? target.slice(2) : target;
      continue;
    }
    const hunkMatch = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(rawLine);
    if (hunkMatch && currentFile) {
      flush();
      currentHunk = {
        filePath: currentFile,
        newStartLine: Math.max(1, Number(hunkMatch[1])),
        removedLines: [],
        addedLines: [],
      };
      continue;
    }
    if (!currentHunk) continue;
    if (rawLine.startsWith('-') && !rawLine.startsWith('---')) {
      currentHunk.removedLines.push(rawLine.slice(1));
    } else if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
      currentHunk.addedLines.push(rawLine.slice(1));
    }
  }
  flush();
  return hunks;
}

const ASSERTION_RE =
  /\b(?:expect|assert|assert_eq|assert_ne|static_assert|check-equal\?)\s*(?:!\s*)?\(|\(check-equal\?|\bt\.(?:Fatal|Fatalf|Error|Errorf)\s*\(|\b(?:require|assert)\.[A-Z][A-Za-z0-9_]*\s*\(/;
const FLOOR_OBLIGATION_RE =
  /(?:require-countermodels\?:\s*#t|require-use-time-witness\?:\s*#t|require-guard-necessity-countermodel\?:\s*#t|require-admission-five-tuple\?:\s*#t|allow-global-purge\?:\s*#f|requireCountermodels:\s*true|requireUseTimeWitness:\s*true|allowGlobalPurge:\s*false|minCoverage:\s*1(?:\.0)?\b|--min-coverage=1\.0\b)/;
const FORMAL_GUARD_OR_COUNTERMODEL_RE = /\(guard\s+[A-Za-z0-9_-]+|\/\/\s*@countermodel\b/;

/**
 * E3 Anti-Evasion: Detects net uncompensated deletion of assertions, Band-5 governance
 * floors, or formal Quint guards/countermodels inside a unified diff.
 */
export function auditDiffObligationDeletions(diffText: string): MultiLangAuditReport[] {
  const hunks = parseUnifiedDiffHunks(diffText);
  const findingsByFile = new Map<string, AstAuditFinding[]>();

  interface FileTotals {
    removedAsserts: number;
    addedAsserts: number;
    firstAssertLine: number;
    removedFloors: number;
    addedFloors: number;
    firstFloorLine: number;
    removedGuards: number;
    addedGuards: number;
    firstGuardLine: number;
  }
  const totalsByFile = new Map<string, FileTotals>();
  for (const h of hunks) {
    let t = totalsByFile.get(h.filePath);
    if (!t) {
      t = {
        removedAsserts: 0, addedAsserts: 0, firstAssertLine: h.newStartLine,
        removedFloors: 0, addedFloors: 0, firstFloorLine: h.newStartLine,
        removedGuards: 0, addedGuards: 0, firstGuardLine: h.newStartLine,
      };
      totalsByFile.set(h.filePath, t);
    }
    const rA = h.removedLines.filter(l => ASSERTION_RE.test(l)).length;
    const aA = h.addedLines.filter(l => ASSERTION_RE.test(l)).length;
    if (rA > 0 && t.removedAsserts === 0) t.firstAssertLine = h.newStartLine;
    t.removedAsserts += rA;
    t.addedAsserts += aA;

    const rF = h.removedLines.filter(l => FLOOR_OBLIGATION_RE.test(l)).length;
    const aF = h.addedLines.filter(l => FLOOR_OBLIGATION_RE.test(l)).length;
    if (rF > 0 && t.removedFloors === 0) t.firstFloorLine = h.newStartLine;
    t.removedFloors += rF;
    t.addedFloors += aF;

    const rG = h.removedLines.filter(l => FORMAL_GUARD_OR_COUNTERMODEL_RE.test(l)).length;
    const aG = h.addedLines.filter(l => FORMAL_GUARD_OR_COUNTERMODEL_RE.test(l)).length;
    if (rG > 0 && t.removedGuards === 0) t.firstGuardLine = h.newStartLine;
    t.removedGuards += rG;
    t.addedGuards += aG;
  }

  const pushFinding = (filePath: string, f: AstAuditFinding) => {
    if (!findingsByFile.has(filePath)) findingsByFile.set(filePath, []);
    findingsByFile.get(filePath)!.push(f);
  };

  for (const [filePath, t] of totalsByFile.entries()) {
    if (t.removedAsserts > t.addedAsserts) {
      pushFinding(filePath, {
        hallucinationClass: 'floor-weakening',
        rule: 'diff-deleted-assertion',
        line: t.firstAssertLine,
        column: 1,
        detail: `Diff deletes ${t.removedAsserts - t.addedAsserts} verification assertion(s) without replacement in file`,
      });
    }
    if (t.removedFloors > t.addedFloors) {
      pushFinding(filePath, {
        hallucinationClass: 'floor-weakening',
        rule: 'diff-deleted-governance-floor',
        line: t.firstFloorLine,
        column: 1,
        detail: `Diff removes ${t.removedFloors - t.addedFloors} Band-5 governance floor requirement(s) without preserving them`,
      });
    }
    if (t.removedGuards > t.addedGuards) {
      pushFinding(filePath, {
        hallucinationClass: 'floor-weakening',
        rule: 'diff-deleted-formal-guard-or-countermodel',
        line: t.firstGuardLine,
        column: 1,
        detail: `Diff deletes ${t.removedGuards - t.addedGuards} formal (guard ...) or @countermodel witness(es) without replacement`,
      });
    }
  }

  const reports: MultiLangAuditReport[] = [];
  for (const [filePath, findings] of findingsByFile.entries()) {
    const lang = detectAuditLanguage(filePath) ?? 'typescript';
    reports.push(makeReport(filePath, lang, findings, true));
  }
  return reports;
}

export function auditUnifiedDiff(
  diffText: string,
  readFile: (repoRelPath: string) => string | null,
): MultiLangAuditReport[] {
  const addedByFile = parseUnifiedDiffAddedLines(diffText);
  const deletionReports = auditDiffObligationDeletions(diffText);
  const deletionsByFile = new Map(deletionReports.map(r => [r.fileName, r]));
  const reports: MultiLangAuditReport[] = [];
  const seen = new Set<string>();

  for (const [filePath, addedLines] of addedByFile.entries()) {
    const delRep = deletionsByFile.get(filePath);
    const lang = detectAuditLanguage(filePath);
    if (!lang && !delRep) continue;
    const content = addedLines.size > 0 && lang ? readFile(filePath) : null;
    const addedRep = content !== null ? auditSourceByPath(content, filePath, addedLines) : null;
    const mergedFindings: AstAuditFinding[] = [
      ...(addedRep?.findings ?? []),
      ...(delRep?.findings ?? []),
    ];
    if (addedRep || delRep) {
      reports.push(makeReport(filePath, addedRep?.language ?? delRep!.language, mergedFindings, true));
      seen.add(filePath);
    }
  }
  for (const [filePath, delRep] of deletionsByFile.entries()) {
    if (!seen.has(filePath)) reports.push(delRep);
  }
  return reports;
}
