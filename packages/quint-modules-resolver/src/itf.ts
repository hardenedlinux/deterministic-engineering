// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Pure, zero-eval recursive-descent evaluator for `expectedItfPredicate`
 * expressions over Informal Trace Format (ITF) JSON states.
 *
 * Grammar:
 *   expr := orExpr
 *   orExpr := andExpr ('or' andExpr)*
 *   andExpr := notExpr ('and' notExpr)*
 *   notExpr := 'not' '(' expr ')' | cmpExpr
 *   cmpExpr := addExpr (('==' | '!=' | '>=' | '<=' | '>' | '<') addExpr)?
 *   addExpr := atom (('+' | '-') atom)*
 *   atom := '(' expr ')'
 *         | '-' atom
 *         | 'size' '(' addExpr ')'
 *         | 'contains' '(' addExpr ',' addExpr ')'
 *         | 'subseteq' '(' addExpr ',' addExpr ')'
 *         | 'true' | 'false' | INT | IDENT ('.' IDENT)*
 */

export interface ItfTrace {
  vars: string[];
  states: Record<string, unknown>[];
}

type Token =
  | {kind: 'lparen'}
  | {kind: 'rparen'}
  | {kind: 'comma'}
  | {kind: 'arith'; value: '+' | '-'}
  | {kind: 'op'; value: '==' | '!=' | '>=' | '<=' | '>' | '<'}
  | {kind: 'kw'; value: 'and' | 'or' | 'not' | 'true' | 'false' | 'size' | 'contains' | 'subseteq'}
  | {kind: 'int'; value: bigint}
  | {kind: 'ident'; value: string};

const KEYWORDS = new Set(['and', 'or', 'not', 'true', 'false', 'size', 'contains', 'subseteq']);

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i]!;
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '(') {
      tokens.push({kind: 'lparen'});
      i++;
      continue;
    }
    if (ch === ')') {
      tokens.push({kind: 'rparen'});
      i++;
      continue;
    }
    if (ch === ',') {
      tokens.push({kind: 'comma'});
      i++;
      continue;
    }
    const two = input.slice(i, i + 2);
    if (two === '==' || two === '!=' || two === '>=' || two === '<=') {
      tokens.push({kind: 'op', value: two});
      i += 2;
      continue;
    }
    if (ch === '>' || ch === '<') {
      tokens.push({kind: 'op', value: ch});
      i++;
      continue;
    }
    if (ch === '+' || ch === '-') {
      tokens.push({kind: 'arith', value: ch});
      i++;
      continue;
    }
    if (/[0-9]/.test(ch)) {
      let end = i + 1;
      while (end < input.length && /[0-9]/.test(input[end]!)) end++;
      tokens.push({kind: 'int', value: BigInt(input.slice(i, end))});
      i = end;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let end = i + 1;
      while (end < input.length && /[A-Za-z0-9_.]/.test(input[end]!)) end++;
      const word = input.slice(i, end);
      if (KEYWORDS.has(word)) {
        tokens.push({kind: 'kw', value: word as Extract<Token, {kind: 'kw'}>['value']});
      } else {
        tokens.push({kind: 'ident', value: word});
      }
      i = end;
      continue;
    }
    throw new Error(`Unexpected character in ITF predicate at ${i}: ${JSON.stringify(ch)}`);
  }
  return tokens;
}

type NormalizedVal = boolean | bigint | string | NormalizedVal[] | null;

function normalizeItfValue(v: unknown): NormalizedVal {
  if (typeof v === 'boolean' || typeof v === 'string') return v;
  if (typeof v === 'number') return BigInt(Math.trunc(v));
  if (Array.isArray(v)) return v.map(normalizeItfValue);
  if (v && typeof v === 'object') {
    if ('#bigint' in v) {
      return BigInt(String((v as {'#bigint': string})['#bigint']));
    }
    if ('#set' in v && Array.isArray((v as {'#set': unknown[]})['#set'])) {
      return (v as {'#set': unknown[]})['#set'].map(normalizeItfValue);
    }
  }
  return null;
}

function resolvePath(state: Record<string, unknown>, vars: string[], dotted: string): unknown {
  const parts = dotted.split('.');
  const root = parts[0]!;
  // Match either exact variable name ("h") or module-qualified ITF variable ("mod::sub::h").
  let cur: unknown = state[root];
  if (cur === undefined) {
    const qualified = vars.find(v => v === root || v.endsWith(`::${root}`));
    if (qualified !== undefined) {
      cur = state[qualified];
    }
  }
  for (let i = 1; i < parts.length; i++) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[parts[i]!];
  }
  return cur;
}

export function evaluateItfPredicateOnState(
  predicate: string,
  state: Record<string, unknown>,
  vars: string[],
): boolean {
  const tokens = tokenize(predicate);
  let pos = 0;

  const peek = () => tokens[pos];
  const consume = () => tokens[pos++];

  function expectKind(kind: Token['kind'], ctx: string): void {
    const t = consume();
    if (t?.kind !== kind) throw new Error(`Expected '${kind}' in ${ctx}`);
  }

  function parseOr(): unknown {
    let left = Boolean(parseAnd());
    while (peek()?.kind === 'kw' && (peek() as {kind: 'kw'; value: string}).value === 'or') {
      consume();
      const right = Boolean(parseAnd());
      left = left || right;
    }
    return left;
  }

  function parseAnd(): unknown {
    let left = Boolean(parseNot());
    while (peek()?.kind === 'kw' && (peek() as {kind: 'kw'; value: string}).value === 'and') {
      consume();
      const right = Boolean(parseNot());
      left = left && right;
    }
    return left;
  }

  function parseNot(): unknown {
    if (peek()?.kind === 'kw' && (peek() as {kind: 'kw'; value: string}).value === 'not') {
      consume();
      expectKind('lparen', 'not(...)');
      const val = parseOr();
      expectKind('rparen', 'not(...)');
      return !Boolean(val);
    }
    return parseCmp();
  }

  function parseCmp(): unknown {
    const left = parseAdd();
    if (peek()?.kind === 'op') {
      const op = (consume() as {kind: 'op'; value: '==' | '!=' | '>=' | '<=' | '>' | '<'}).value;
      const right = parseAdd();
      switch (op) {
        case '==': return left === right;
        case '!=': return left !== right;
        case '>=': return typeof left === 'bigint' && typeof right === 'bigint' && left >= right;
        case '<=': return typeof left === 'bigint' && typeof right === 'bigint' && left <= right;
        case '>': return typeof left === 'bigint' && typeof right === 'bigint' && left > right;
        case '<': return typeof left === 'bigint' && typeof right === 'bigint' && left < right;
      }
    }
    return left;
  }

  function parseAdd(): unknown {
    let left = parseAtom();
    while (peek()?.kind === 'arith') {
      const op = (consume() as {kind: 'arith'; value: '+' | '-'}).value;
      const right = parseAtom();
      if (typeof left !== 'bigint' || typeof right !== 'bigint') return null;
      left = op === '+' ? left + right : left - right;
    }
    return left;
  }

  function parseAtom(): unknown {
    const tok = consume();
    if (!tok) throw new Error(`Unexpected end of ITF predicate: ${predicate}`);
    if (tok.kind === 'arith' && tok.value === '-') {
      const inner = parseAtom();
      return typeof inner === 'bigint' ? -inner : null;
    }
    if (tok.kind === 'lparen') {
      const val = parseOr();
      expectKind('rparen', '(...)');
      return val;
    }
    if (tok.kind === 'kw' && tok.value === 'true') return true;
    if (tok.kind === 'kw' && tok.value === 'false') return false;
    if (tok.kind === 'kw' && tok.value === 'size') {
      expectKind('lparen', 'size(...)');
      const arg = parseAdd();
      expectKind('rparen', 'size(...)');
      return Array.isArray(arg) ? BigInt(arg.length) : null;
    }
    if (tok.kind === 'kw' && tok.value === 'contains') {
      expectKind('lparen', 'contains(...)');
      const setVal = parseAdd();
      expectKind('comma', 'contains(set, item)');
      const itemVal = parseAdd();
      expectKind('rparen', 'contains(...)');
      return Array.isArray(setVal) && setVal.some(el => el === itemVal);
    }
    if (tok.kind === 'kw' && tok.value === 'subseteq') {
      expectKind('lparen', 'subseteq(...)');
      const sub = parseAdd();
      expectKind('comma', 'subseteq(a, b)');
      const sup = parseAdd();
      expectKind('rparen', 'subseteq(...)');
      return Array.isArray(sub) && Array.isArray(sup) && sub.every(el => sup.some(s => s === el));
    }
    if (tok.kind === 'int') return tok.value;
    if (tok.kind === 'ident') {
      return normalizeItfValue(resolvePath(state, vars, tok.value));
    }
    throw new Error(`Unexpected token in ITF predicate: ${JSON.stringify(tok)}`);
  }

  const result = Boolean(parseOr());
  if (pos !== tokens.length) {
    throw new Error(`Trailing tokens in ITF predicate: ${predicate}`);
  }
  return result;
}

export function traceSatisfiesItfPredicate(trace: ItfTrace, predicate: string): boolean {
  return trace.states.some(state => evaluateItfPredicateOnState(predicate, state, trace.vars));
}
