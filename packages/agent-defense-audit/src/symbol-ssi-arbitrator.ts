// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 13 (Business Extension B4, 10.161):
 * Automated AST Symbol-Level ReadSet x WriteSet Extraction & Multi-Agent SSI
 * Conflict Arbitration Engine (In-Process Coordinator Commit-Gate).
 *
 * Lifts Cahill / Rohm / Fekete (SIGMOD 2008) Serializable Snapshot Isolation (SSI)
 * from SQL rows to codebase symbol dependency graphs (TypeScript & Gerbil Scheme):
 *   1. Automatically extracts exported symbol definitions (interfaces, types, functions,
 *      constants, classes, Scheme `def`/`.def` objects) and cross-file imported/consumed
 *      symbol references with zero manual ReadSet/WriteSet annotations.
 *   2. Separates three distinct concurrency failure modes:
 *        - Stale M3 lease fencing (`fencedAgents`),
 *        - Direct file/symbol Write-Write conflict (`wwConflicts`, refuses silent LWW),
 *        - Disjoint-file Semantic Write-Skew (`rwEdges`, including cyclic `A <-> B`
 *          mutual skew vs. acyclic producer-consumer skew).
 *   3. Bounded DE01 Partial Admission: in an N-agent swarm, independent agents and
 *      upstream producers commit cleanly while ONLY affected downstream consumers
 *      receive a cold M1 `RevalidationPacket` pinned in `ContentAddressedKvStore`.
 */

import {dirname, posix} from 'node:path';
import {ContentAddressedKvStore, sha256Digest} from './durable-merkle-store.ts';

export type SymbolChangeKind =
  | 'signature-or-contract'
  | 'implementation'
  | 'added'
  | 'removed';

export interface ExtractedSymbolDef {
  symbolId: string; // canonical `normalizedFile::symbolName`
  name: string;
  kind: 'interface' | 'type' | 'function' | 'const' | 'class' | 'scheme-def' | 'scheme-poo';
  signatureDigest: string;
  bodyDigest: string;
}

export interface FileSymbolProfile {
  filePath: string;
  exports: Map<string, ExtractedSymbolDef>; // keyed by symbol name
  readSymbols: Set<string>; // canonical `targetFile::symbolName`
}

export interface SymbolWriteRecord {
  symbolId: string;
  filePath: string;
  symbolName: string;
  changeKind: SymbolChangeKind;
  oldDigest: string | null;
  newDigest: string | null;
}

export interface ConcurrentAgentWorkspace {
  agentId: string;
  fencingEpoch: number;
  /**
   * Files modified or added by this agent relative to `baseFiles`.
   * Map of normalized workspace-relative file path -> full updated source text.
   */
  modifiedFiles: Record<string, string>;
}

export interface DirectWwConflict {
  filePath: string;
  agents: string[];
}

export interface SymbolRwAntidependency {
  staleReaderAgent: string;
  writerAgent: string;
  symbolId: string;
  changeKind: SymbolChangeKind;
  oldDigest: string | null;
  newDigest: string | null;
  cyclic: boolean;
}

export interface BoundedRevalidationPacket {
  packetMerkleHash: string;
  targetAgentId: string;
  reason: 'acyclic-semantic-write-skew' | 'cyclic-semantic-write-skew';
  conflictingDependencies: SymbolRwAntidependency[];
}

export interface FencedAgentRecord {
  agentId: string;
  expectedEpoch: number;
  actualEpoch: number;
}

export interface MultiAgentArbitrationResult {
  verdict:
    | 'CleanSerializableMerge'
    | 'PartialAdmitWithBoundedRevalidation'
    | 'ConflictOrCycleBlocked';
  arbitrationReceiptHash: string;
  admittedAgents: string[];
  fencedAgents: FencedAgentRecord[];
  wwConflicts: DirectWwConflict[];
  rwEdges: SymbolRwAntidependency[];
  cyclicAgents: string[];
  revalidationPackets: BoundedRevalidationPacket[];
  mergedFiles: Record<string, string>;
}

// ── Path Normalization & Cross-File Import Resolution ──

function normFile(p: string): string {
  return posix.normalize(p.replace(/\\/g, '/')).replace(/^\.\//, '');
}

function resolveRelativeImport(
  fromFile: string,
  specifier: string,
  knownFiles: Set<string>,
): string | null {
  if (!specifier.startsWith('.')) return null;
  const baseDir = dirname(normFile(fromFile));
  const raw = normFile(baseDir === '.' ? specifier : posix.join(baseDir, specifier));
  const candidates = [
    raw,
    `${raw}.ts`,
    `${raw}.tsx`,
    `${raw}.ss`,
    posix.join(raw, 'index.ts'),
    raw.replace(/\.js$/, '.ts'),
  ];
  for (const c of candidates) {
    if (knownFiles.has(c)) return c;
  }
  return raw;
}

// ── Zero-Dependency TypeScript Structural Lexer & Symbol Extractor ──

interface LexTok {
  kind: 'ident' | 'str' | 'num' | 'punct';
  value: string;
}

function lexTsCodeOnly(src: string): LexTok[] {
  const out: LexTok[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      const q = ch;
      i++;
      let s = '';
      while (i < src.length && src[i] !== q) {
        if (src[i] === '\\' && i + 1 < src.length) {
          s += src[i + 1]!;
          i += 2;
        } else {
          s += src[i]!;
          i++;
        }
      }
      i++;
      out.push({kind: 'str', value: s});
      continue;
    }
    if (/[0-9]/.test(ch)) {
      const start = i;
      while (i < src.length && /[0-9a-zA-Z._]/.test(src[i]!)) i++;
      out.push({kind: 'num', value: src.slice(start, i)});
      continue;
    }
    if (/[a-zA-Z_$]/.test(ch)) {
      const start = i;
      while (i < src.length && /[a-zA-Z0-9_$]/.test(src[i]!)) i++;
      out.push({kind: 'ident', value: src.slice(start, i)});
      continue;
    }
    out.push({kind: 'punct', value: ch});
    i++;
  }
  return out;
}

function skipBalanced(tokens: LexTok[], startIdx: number, open: string, close: string): number {
  let depth = 0;
  for (let i = startIdx; i < tokens.length; i++) {
    const v = tokens[i]!.value;
    if (v === open) depth++;
    else if (v === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return tokens.length - 1;
}

function sliceSig(tokens: LexTok[], from: number, to: number): string {
  return tokens
    .slice(from, to + 1)
    .map(t => (t.kind === 'str' ? JSON.stringify(t.value) : t.value))
    .join(' ');
}

export function extractTsSymbolProfile(
  filePath: string,
  src: string,
  knownFiles: Set<string>,
): FileSymbolProfile {
  const file = normFile(filePath);
  const tokens = lexTsCodeOnly(src);
  const exports = new Map<string, ExtractedSymbolDef>();
  const importedLocalToCanonical = new Map<string, string>();
  const readSymbols = new Set<string>();

  // Pass 1: Extract imports & exported declarations
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;

    // `import [type] { A, B as C } from './mod'`
    if (t.kind === 'ident' && t.value === 'import') {
      let j = i + 1;
      if (tokens[j]?.value === 'type') j++;
      const namedPairs: Array<{orig: string; local: string}> = [];
      let wildcardLocal: string | null = null;

      if (tokens[j]?.value === '{') {
        const endBrace = skipBalanced(tokens, j, '{', '}');
        for (let k = j + 1; k < endBrace; k++) {
          if (tokens[k]?.value === 'type') continue;
          if (tokens[k]?.kind === 'ident') {
            const orig = tokens[k]!.value;
            let local = orig;
            if (tokens[k + 1]?.value === 'as' && tokens[k + 2]?.kind === 'ident') {
              local = tokens[k + 2]!.value;
              k += 2;
            }
            namedPairs.push({orig, local});
          }
        }
        j = endBrace + 1;
      } else if (tokens[j]?.value === '*' && tokens[j + 1]?.value === 'as') {
        wildcardLocal = tokens[j + 2]?.value ?? null;
        j += 3;
      }

      if (tokens[j]?.value === 'from' && tokens[j + 1]?.kind === 'str') {
        const resolved = resolveRelativeImport(file, tokens[j + 1]!.value, knownFiles);
        if (resolved) {
          for (const pair of namedPairs) {
            const canonical = `${resolved}::${pair.orig}`;
            importedLocalToCanonical.set(pair.local, canonical);
            // Importing a symbol explicitly establishes a dependency even in type position
            readSymbols.add(canonical);
          }
          if (wildcardLocal) {
            importedLocalToCanonical.set(wildcardLocal, `${resolved}::*`);
          }
        }
        i = j + 1;
      }
      continue;
    }

    // `export interface | type | function | async function | const | let | class`
    if (t.kind === 'ident' && t.value === 'export') {
      let j = i + 1;
      if (tokens[j]?.value === 'async') j++;
      const kw = tokens[j]?.value;
      const nameTok = tokens[j + 1];
      if (!kw || !nameTok || nameTok.kind !== 'ident') continue;

      if (kw === 'interface' || kw === 'class') {
        let braceIdx = j + 2;
        while (braceIdx < tokens.length && tokens[braceIdx]!.value !== '{') braceIdx++;
        const endIdx = braceIdx < tokens.length ? skipBalanced(tokens, braceIdx, '{', '}') : j + 2;
        const text = sliceSig(tokens, j, endIdx);
        const digest = sha256Digest(text);
        exports.set(nameTok.value, {
          symbolId: `${file}::${nameTok.value}`,
          name: nameTok.value,
          kind: kw,
          signatureDigest: digest,
          bodyDigest: digest,
        });
        i = endIdx;
      } else if (kw === 'type') {
        let endIdx = j + 2;
        let depth = 0;
        while (endIdx < tokens.length) {
          const v = tokens[endIdx]!.value;
          if (v === '{' || v === '(' || v === '[') depth++;
          else if (v === '}' || v === ')' || v === ']') depth = Math.max(0, depth - 1);
          else if (v === ';' && depth === 0) break;
          endIdx++;
        }
        const text = sliceSig(tokens, j, endIdx);
        const digest = sha256Digest(text);
        exports.set(nameTok.value, {
          symbolId: `${file}::${nameTok.value}`,
          name: nameTok.value,
          kind: 'type',
          signatureDigest: digest,
          bodyDigest: digest,
        });
        i = endIdx;
      } else if (kw === 'function') {
        let parenIdx = j + 2;
        while (parenIdx < tokens.length && tokens[parenIdx]!.value !== '(') parenIdx++;
        const closeParen =
          parenIdx < tokens.length ? skipBalanced(tokens, parenIdx, '(', ')') : j + 2;
        let braceIdx = closeParen + 1;
        let angleDepth = 0;
        while (braceIdx < tokens.length) {
          const v = tokens[braceIdx]!.value;
          if (v === '<') angleDepth++;
          else if (v === '>') angleDepth = Math.max(0, angleDepth - 1);
          else if (v === '{' && angleDepth === 0) {
            // Skip inline object return type `{ ... }` when preceded by `:`
            const prev = tokens[braceIdx - 1]?.value;
            if (prev === ':' || prev === '|') {
              braceIdx = skipBalanced(tokens, braceIdx, '{', '}') + 1;
              continue;
            }
            break;
          }
          braceIdx++;
        }
        const endIdx =
          braceIdx < tokens.length ? skipBalanced(tokens, braceIdx, '{', '}') : closeParen;
        const sigText = sliceSig(tokens, j, Math.max(closeParen, braceIdx - 1));
        const fullText = sliceSig(tokens, j, endIdx);
        exports.set(nameTok.value, {
          symbolId: `${file}::${nameTok.value}`,
          name: nameTok.value,
          kind: 'function',
          signatureDigest: sha256Digest(sigText),
          bodyDigest: sha256Digest(fullText),
        });
        i = endIdx;
      } else if (kw === 'const' || kw === 'let') {
        let endIdx = j + 2;
        let depth = 0;
        while (endIdx < tokens.length) {
          const v = tokens[endIdx]!.value;
          if (v === '{' || v === '(' || v === '[') depth++;
          else if (v === '}' || v === ')' || v === ']') depth = Math.max(0, depth - 1);
          else if (v === ';' && depth === 0) break;
          endIdx++;
        }
        const fullText = sliceSig(tokens, j, endIdx);
        const digest = sha256Digest(fullText);
        exports.set(nameTok.value, {
          symbolId: `${file}::${nameTok.value}`,
          name: nameTok.value,
          kind: 'const',
          signatureDigest: digest,
          bodyDigest: digest,
        });
        i = endIdx;
      }
    }
  }

  // Pass 2: Resolve wildcard namespace reads `ns.Symbol`
  for (let i = 0; i + 2 < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.kind === 'ident' && tokens[i + 1]?.value === '.' && tokens[i + 2]?.kind === 'ident') {
      const target = importedLocalToCanonical.get(t.value);
      if (target && target.endsWith('::*')) {
        const modFile = target.slice(0, -3);
        readSymbols.add(`${modFile}::${tokens[i + 2]!.value}`);
      }
    }
  }

  return {filePath: file, exports, readSymbols};
}

// ── Zero-Dependency Gerbil Scheme S-Expression Symbol Extractor ──

type SExpr = string | SExpr[];

function parseSchemeForms(src: string): SExpr[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === ';') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '"') {
      const start = i;
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < src.length) i += 2;
        else i++;
      }
      i++;
      tokens.push(src.slice(start, i));
      continue;
    }
    if (ch === '(' || ch === ')' || ch === '[' || ch === ']') {
      tokens.push(ch);
      i++;
      continue;
    }
    const start = i;
    while (i < src.length && !/[\s()\[\];"]/.test(src[i]!)) i++;
    tokens.push(src.slice(start, i));
  }

  let pos = 0;
  const readOne = (): SExpr | null => {
    if (pos >= tokens.length) return null;
    const tok = tokens[pos++]!;
    if (tok === '(' || tok === '[') {
      const close = tok === '(' ? ')' : ']';
      const list: SExpr[] = [];
      while (pos < tokens.length && tokens[pos] !== close) {
        const item = readOne();
        if (item !== null) list.push(item);
      }
      if (pos < tokens.length && tokens[pos] === close) pos++;
      return list;
    }
    return tok;
  };

  const forms: SExpr[] = [];
  while (pos < tokens.length) {
    const f = readOne();
    if (f !== null) forms.push(f);
  }
  return forms;
}

function unquoteStr(s: string): string | null {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1);
  }
  return null;
}

export function extractSchemeSymbolProfile(
  filePath: string,
  src: string,
  knownFiles: Set<string>,
): FileSymbolProfile {
  const file = normFile(filePath);
  const forms = parseSchemeForms(src);
  const exportedNames = new Set<string>();
  const allDefs = new Map<string, ExtractedSymbolDef>();
  const readSymbols = new Set<string>();

  for (const form of forms) {
    if (!Array.isArray(form) || form.length === 0) continue;
    const head = form[0];

    if (head === 'export') {
      for (let i = 1; i < form.length; i++) {
        const sym = form[i];
        if (typeof sym === 'string') exportedNames.add(sym);
      }
    } else if (head === 'import') {
      for (let i = 1; i < form.length; i++) {
        const spec = form[i];
        if (typeof spec === 'string') {
          const rel = unquoteStr(spec);
          if (rel) {
            const resolved = resolveRelativeImport(file, rel.startsWith('.') ? rel : `./${rel}`, knownFiles);
            if (resolved) readSymbols.add(`${resolved}::*`);
          }
        } else if (Array.isArray(spec) && spec[0] === 'only-in' && typeof spec[1] === 'string') {
          const rel = unquoteStr(spec[1]);
          if (rel) {
            const resolved = resolveRelativeImport(file, rel.startsWith('.') ? rel : `./${rel}`, knownFiles);
            if (resolved) {
              for (let k = 2; k < spec.length; k++) {
                const sym = spec[k];
                if (typeof sym === 'string') {
                  readSymbols.add(`${resolved}::${sym}`);
                }
              }
            }
          }
        }
      }
    } else if (head === 'def' && form.length >= 2) {
      const target = form[1];
      const name = typeof target === 'string' ? target : Array.isArray(target) && typeof target[0] === 'string' ? target[0] : null;
      if (name) {
        const sigDigest = sha256Digest(target);
        const bodyDigest = sha256Digest(form);
        allDefs.set(name, {
          symbolId: `${file}::${name}`,
          name,
          kind: 'scheme-def',
          signatureDigest: sigDigest,
          bodyDigest,
        });
      }
    } else if (head === '.def' && form.length >= 2) {
      const target = form[1];
      const name = typeof target === 'string' ? target : Array.isArray(target) && typeof target[0] === 'string' ? target[0] : null;
      if (name) {
        const bodyDigest = sha256Digest(form);
        allDefs.set(name, {
          symbolId: `${file}::${name}`,
          name,
          kind: 'scheme-poo',
          signatureDigest: bodyDigest,
          bodyDigest,
        });
      }
    }
  }

  const exports = new Map<string, ExtractedSymbolDef>();
  for (const [name, def] of allDefs.entries()) {
    if (exportedNames.size === 0 || exportedNames.has(name)) {
      exports.set(name, def);
    }
  }
  return {filePath: file, exports, readSymbols};
}

export function extractFileSymbolProfile(
  filePath: string,
  src: string,
  knownFiles: Set<string>,
): FileSymbolProfile {
  if (filePath.endsWith('.ss') || filePath.endsWith('.scm')) {
    return extractSchemeSymbolProfile(filePath, src, knownFiles);
  }
  return extractTsSymbolProfile(filePath, src, knownFiles);
}

// ── Automated N-Agent Symbol-Level SSI Arbitrator ──

function computeAgentSymbolSets(
  baseFiles: Record<string, string>,
  modifiedFiles: Record<string, string>,
): {
  changedFiles: Set<string>;
  writes: Map<string, SymbolWriteRecord>;
  reads: Set<string>;
} {
  const knownFiles = new Set<string>([
    ...Object.keys(baseFiles).map(normFile),
    ...Object.keys(modifiedFiles).map(normFile),
  ]);

  const changedFiles = new Set<string>();
  const writes = new Map<string, SymbolWriteRecord>();
  const reads = new Set<string>();

  for (const [rawPath, newSrc] of Object.entries(modifiedFiles)) {
    const file = normFile(rawPath);
    const oldSrc = baseFiles[file] ?? baseFiles[rawPath];
    if (oldSrc === newSrc) continue;
    changedFiles.add(file);

    const newProf = extractFileSymbolProfile(file, newSrc, knownFiles);
    const oldProf =
      oldSrc !== undefined ? extractFileSymbolProfile(file, oldSrc, knownFiles) : null;

    // Collect every cross-file symbol read by this modified file:
    for (const r of newProf.readSymbols) {
      if (!r.startsWith(`${file}::`)) reads.add(r);
    }

    // Diff exported symbols (added / removed / signature-or-contract / implementation):
    const oldExports = oldProf?.exports ?? new Map<string, ExtractedSymbolDef>();
    for (const [symName, newDef] of newProf.exports.entries()) {
      const oldDef = oldExports.get(symName);
      if (!oldDef) {
        writes.set(newDef.symbolId, {
          symbolId: newDef.symbolId,
          filePath: file,
          symbolName: symName,
          changeKind: 'added',
          oldDigest: null,
          newDigest: newDef.bodyDigest,
        });
      } else if (oldDef.signatureDigest !== newDef.signatureDigest) {
        writes.set(newDef.symbolId, {
          symbolId: newDef.symbolId,
          filePath: file,
          symbolName: symName,
          changeKind: 'signature-or-contract',
          oldDigest: oldDef.signatureDigest,
          newDigest: newDef.signatureDigest,
        });
      } else if (oldDef.bodyDigest !== newDef.bodyDigest) {
        writes.set(newDef.symbolId, {
          symbolId: newDef.symbolId,
          filePath: file,
          symbolName: symName,
          changeKind: 'implementation',
          oldDigest: oldDef.bodyDigest,
          newDigest: newDef.bodyDigest,
        });
      }
    }
    for (const [symName, oldDef] of oldExports.entries()) {
      if (!newProf.exports.has(symName)) {
        writes.set(oldDef.symbolId, {
          symbolId: oldDef.symbolId,
          filePath: file,
          symbolName: symName,
          changeKind: 'removed',
          oldDigest: oldDef.bodyDigest,
          newDigest: null,
        });
      }
    }
  }

  return {changedFiles, writes, reads};
}

function findCyclicNodes(adj: Map<string, Set<string>>): Set<string> {
  const cyclic = new Set<string>();
  const nodes = [...adj.keys()];
  for (const start of nodes) {
    // BFS from start's neighbors to check if start is reachable back from itself
    const visited = new Set<string>();
    const queue = [...(adj.get(start) ?? [])];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      if (cur === start) {
        cyclic.add(start);
        break;
      }
      if (visited.has(cur)) continue;
      visited.add(cur);
      for (const nxt of adj.get(cur) ?? []) {
        queue.push(nxt);
      }
    }
  }
  return cyclic;
}

export function arbitrateConcurrentWorkspaces(params: {
  baseFiles: Record<string, string>;
  proposals: ConcurrentAgentWorkspace[];
  activeLeaseEpoch: number;
  kv: ContentAddressedKvStore;
}): MultiAgentArbitrationResult {
  const normalizedBase: Record<string, string> = {};
  for (const [k, v] of Object.entries(params.baseFiles)) {
    normalizedBase[normFile(k)] = v;
  }

  // 1. M3 Monotonic Lease Fencing: isolate stalled agents immediately.
  const fencedAgents: FencedAgentRecord[] = [];
  const liveProposals: ConcurrentAgentWorkspace[] = [];
  for (const p of params.proposals) {
    if (p.fencingEpoch !== params.activeLeaseEpoch) {
      fencedAgents.push({
        agentId: p.agentId,
        expectedEpoch: params.activeLeaseEpoch,
        actualEpoch: p.fencingEpoch,
      });
    } else {
      liveProposals.push(p);
    }
  }

  // 2. Automatic AST Symbol ReadSet / WriteSet extraction per live agent.
  const extracted = new Map<
    string,
    {changedFiles: Set<string>; writes: Map<string, SymbolWriteRecord>; reads: Set<string>}
  >();
  const fileWriters = new Map<string, Array<{agentId: string; content: string}>>();

  for (const p of liveProposals) {
    const sets = computeAgentSymbolSets(normalizedBase, p.modifiedFiles);
    extracted.set(p.agentId, sets);
    for (const file of sets.changedFiles) {
      const content = p.modifiedFiles[file] ?? p.modifiedFiles[`./${file}`] ?? '';
      const arr = fileWriters.get(file) ?? [];
      arr.push({agentId: p.agentId, content});
      fileWriters.set(file, arr);
    }
  }

  // 3. Direct Write-Write conflict detection (divergent edits to the same file).
  const wwConflicts: DirectWwConflict[] = [];
  const wwBlockedAgents = new Set<string>();
  for (const [filePath, writers] of fileWriters.entries()) {
    if (writers.length > 1) {
      const distinctContents = new Set(writers.map(w => w.content));
      if (distinctContents.size > 1) {
        const agents = writers.map(w => w.agentId).sort();
        wwConflicts.push({filePath, agents});
        for (const a of agents) wwBlockedAgents.add(a);
      }
    }
  }

  // 4. Symbol-Level SSI rw Anti-Dependency Graph across disjoint files!
  const rawEdges: Omit<SymbolRwAntidependency, 'cyclic'>[] = [];
  const rwAdj = new Map<string, Set<string>>();

  for (const reader of liveProposals) {
    const readerSets = extracted.get(reader.agentId)!;
    for (const writer of liveProposals) {
      if (reader.agentId === writer.agentId) continue;
      const writerSets = extracted.get(writer.agentId)!;

      for (const readSym of readerSets.reads) {
        // Exact symbol match OR wildcard module import (`file::*`)
        if (readSym.endsWith('::*')) {
          const targetPrefix = readSym.slice(0, -1); // `file::`
          for (const writeRec of writerSets.writes.values()) {
            if (writeRec.symbolId.startsWith(targetPrefix)) {
              rawEdges.push({
                staleReaderAgent: reader.agentId,
                writerAgent: writer.agentId,
                symbolId: writeRec.symbolId,
                changeKind: writeRec.changeKind,
                oldDigest: writeRec.oldDigest,
                newDigest: writeRec.newDigest,
              });
              const s = rwAdj.get(reader.agentId) ?? new Set<string>();
              s.add(writer.agentId);
              rwAdj.set(reader.agentId, s);
            }
          }
        } else {
          const writeRec = writerSets.writes.get(readSym);
          if (writeRec) {
            rawEdges.push({
              staleReaderAgent: reader.agentId,
              writerAgent: writer.agentId,
              symbolId: writeRec.symbolId,
              changeKind: writeRec.changeKind,
              oldDigest: writeRec.oldDigest,
              newDigest: writeRec.newDigest,
            });
            const s = rwAdj.get(reader.agentId) ?? new Set<string>();
            s.add(writer.agentId);
            rwAdj.set(reader.agentId, s);
          }
        }
      }
    }
  }

  // 5. Detect cyclic rw write-skew vs. acyclic producer-consumer skew.
  const cyclicSet = findCyclicNodes(rwAdj);
  const rwEdges: SymbolRwAntidependency[] = rawEdges.map(e => ({
    ...e,
    cyclic: cyclicSet.has(e.staleReaderAgent) && cyclicSet.has(e.writerAgent),
  }));

  const edgesByStaleReader = new Map<string, SymbolRwAntidependency[]>();
  for (const e of rwEdges) {
    const arr = edgesByStaleReader.get(e.staleReaderAgent) ?? [];
    arr.push(e);
    edgesByStaleReader.set(e.staleReaderAgent, arr);
  }

  // 6. Bounded DE01 Admission:
  //    - Blocked: fenced agents, ww-conflicting agents, cyclic rw agents, and acyclic stale readers.
  //    - Admitted: independent agents AND non-cyclic upstream producers!
  const admittedAgents: string[] = [];
  const revalidationPackets: BoundedRevalidationPacket[] = [];
  const mergedFiles: Record<string, string> = {...normalizedBase};

  for (const p of liveProposals) {
    const id = p.agentId;
    if (wwBlockedAgents.has(id)) continue;

    const staleDeps = edgesByStaleReader.get(id);
    if (staleDeps && staleDeps.length > 0) {
      const reason = cyclicSet.has(id)
        ? 'cyclic-semantic-write-skew'
        : 'acyclic-semantic-write-skew';
      const packetMerkleHash = params.kv.putBlob(
        'ssi-revalidation-packet',
        {
          targetAgentId: id,
          reason,
          conflictingDependencies: staleDeps,
          epoch: params.activeLeaseEpoch,
        },
        [],
      );
      params.kv.pinHistoricalCut(packetMerkleHash);
      revalidationPackets.push({
        packetMerkleHash,
        targetAgentId: id,
        reason,
        conflictingDependencies: staleDeps,
      });
      continue;
    }

    admittedAgents.push(id);
    for (const [rawPath, content] of Object.entries(p.modifiedFiles)) {
      mergedFiles[normFile(rawPath)] = content;
    }
  }

  let verdict: MultiAgentArbitrationResult['verdict'];
  if (
    wwConflicts.length === 0 &&
    rwEdges.length === 0 &&
    fencedAgents.length === 0
  ) {
    verdict = 'CleanSerializableMerge';
  } else if (admittedAgents.length > 0 && wwConflicts.length === 0 && cyclicSet.size === 0) {
    verdict = 'PartialAdmitWithBoundedRevalidation';
  } else {
    verdict = 'ConflictOrCycleBlocked';
  }

  const arbitrationReceiptHash = params.kv.putBlob(
    'ssi-arbitration-receipt',
    {
      verdict,
      activeLeaseEpoch: params.activeLeaseEpoch,
      admittedAgents: [...admittedAgents].sort(),
      fencedAgents,
      wwConflicts,
      rwEdgeCount: rwEdges.length,
      cyclicAgents: [...cyclicSet].sort(),
      revalidationPacketHashes: revalidationPackets.map(r => r.packetMerkleHash),
    },
    revalidationPackets.map(r => r.packetMerkleHash),
  );
  params.kv.pinHistoricalCut(arbitrationReceiptHash);

  return {
    verdict,
    arbitrationReceiptHash,
    admittedAgents: [...admittedAgents].sort(),
    fencedAgents,
    wwConflicts,
    rwEdges,
    cyclicAgents: [...cyclicSet].sort(),
    revalidationPackets,
    mergedFiles,
  };
}
