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
 *   cmpExpr := atom (('==' | '!=' | '>=' | '<=' | '>' | '<') atom)?
 *   atom := '(' expr ')' | 'true' | 'false' | INT | IDENT ('.' IDENT)*
 */

export interface ItfTrace {
  vars: string[];
  states: Record<string, unknown>[];
}

type Token =
  | {kind: 'lparen'}
  | {kind: 'rparen'}
  | {kind: 'op'; value: '==' | '!=' | '>=' | '<=' | '>' | '<'}
  | {kind: 'kw'; value: 'and' | 'or' | 'not' | 'true' | 'false'}
  | {kind: 'int'; value: bigint}
  | {kind: 'ident'; value: string};

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
    if (/[0-9]/.test(ch) || (ch === '-' && /[0-9]/.test(input[i + 1] ?? ''))) {
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
      if (word === 'and' || word === 'or' || word === 'not' || word === 'true' || word === 'false') {
        tokens.push({kind: 'kw', value: word});
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

function normalizeItfValue(v: unknown): boolean | bigint | string | null {
  if (typeof v === 'boolean' || typeof v === 'string') return v;
  if (typeof v === 'number') return BigInt(Math.trunc(v));
  if (v && typeof v === 'object' && '#bigint' in v) {
    return BigInt(String((v as {'#bigint': string})['#bigint']));
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
      const lp = consume();
      if (lp?.kind !== 'lparen') throw new Error('Expected "(" after not');
      const val = parseOr();
      const rp = consume();
      if (rp?.kind !== 'rparen') throw new Error('Expected ")" after not(...)');
      return !Boolean(val);
    }
    return parseCmp();
  }

  function parseCmp(): unknown {
    const left = parseAtom();
    if (peek()?.kind === 'op') {
      const op = (consume() as {kind: 'op'; value: '==' | '!=' | '>=' | '<=' | '>' | '<'}).value;
      const right = parseAtom();
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

  function parseAtom(): unknown {
    const tok = consume();
    if (!tok) throw new Error(`Unexpected end of ITF predicate: ${predicate}`);
    if (tok.kind === 'lparen') {
      const val = parseOr();
      const rp = consume();
      if (rp?.kind !== 'rparen') throw new Error('Expected closing ")" in ITF predicate');
      return val;
    }
    if (tok.kind === 'kw' && tok.value === 'true') return true;
    if (tok.kind === 'kw' && tok.value === 'false') return false;
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
