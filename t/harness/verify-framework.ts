#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Zero-Hardcoding Graph-Driven Multi-Language Verification Framework
 *
 * Portable Bun execution plane sharing the exact same declarative discovery model
 * and query algebra as the native Scheme Yuanxu + Functional Fun-Flow engine
 * (`t/harness/funflow-exec.ss`).
 *
 * ZERO hardcoded test lists, domain switches, Scheme scopes, or example scripts:
 *   1. Parses `init.ss` + every `<mod>/interface.ss` S-expression (`identity:`, `tags:`)
 *      plus `library/` import edges and `t/integration/*` suites.
 *   2. Discovers `languages-engineering/<lang>/<domain>/...` purely from directory grammar.
 *   3. Discovers all Lean 4 modules under `packages/lean-models/DeterministicEngineering/` + dynamic `#print axioms`.
 *   4. Discovers workspace `package.json` & root `package.json` scripts dynamically.
 *   5. Supports composable query algebra (`--tag`, `--all-tags`, `--mount`, `--lang`,
 *      `--domain`, `--module`, `--only`, `--skip`, `--portable`), change-impact slicing
 *      (`--impact`, `--changed=...`), SHA-256 content-addressed caching (`--cache=<dir>`),
 *      conflict-free parallel wave execution (`--jobs=<N>`), dry-run planning (`--plan`),
 *      and structured JSON reporting (`--report=<path>`).
 */

import {createHash} from 'node:crypto';
import {existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync} from 'node:fs';
import {basename, dirname, join, relative, resolve} from 'node:path';

const REPO_ROOT = resolve(import.meta.dir, '../..');
const BUILD_DIR = join(REPO_ROOT, '.data/test-runs/verify-framework');
const AUTO_EXPORTED_ENV_PREFIXES = ['RESOURCE_CARGO', 'RESOURCE_RUSTC', 'SOURCE_CONTRACT_'];
const SKIP_WALK_DIRS = new Set(['node_modules', 'target', '.lake', '.devenv', 'vendor', '.git', '.gerbil', '.data']);

type UnitKind = 'scheme' | 'ts' | 'c' | 'cbmc' | 'cpp' | 'rust' | 'go' | 'lean' | 'pkg' | 'quint';

interface VerificationUnit {
  id: string;
  kind: UnitKind;
  mount: string;
  module: string;
  domain: string;
  tags: string[];
  inputs: string[];
  conflictKey: string | null;
  timeoutSec: number;
  meta: Record<string, unknown>;
}

interface QueryOptions {
  tagGroups: string[][];
  allTags: string[];
  mounts: Set<string>;
  langs: Set<string>;
  domains: Set<string>;
  modules: Set<string>;
  only: Set<string>;
  skip: Set<string>;
  portable: boolean;
  includeExternal: boolean;
  impact: boolean;
  changedFiles: string[];
  cacheDir: string | null;
  jobs: number;
  planOnly: boolean;
  reportPath: string | null;
  limit: number | null;
  checkAxioms: boolean;
}

interface UnitOutcome {
  id: string;
  kind: UnitKind;
  status: 'pass' | 'cached' | 'fail';
  digest: string;
  durationMs: number;
  detail: string;
}

interface CacheEntry {
  digest: string;
  passedAt: string;
  detail: string;
}

interface CacheFile {
  schema: string;
  entries: Record<string, CacheEntry>;
}

// ── 1. Filesystem & Minimal S-Expression Reader (Zero External Deps) ──

function listDirSorted(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).sort();
}

function findFiles(dir: string, predicate: (fullPath: string, name: string) => boolean): string[] {
  if (!existsSync(dir)) return [];
  const results: string[] = [];
  const walk = (current: string) => {
    for (const name of listDirSorted(current)) {
      if (SKIP_WALK_DIRS.has(name)) continue;
      const full = join(current, name);
      const st = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else if (predicate(full, name)) {
        results.push(full);
      }
    }
  };
  walk(dir);
  return results;
}

function collectInputFiles(paths: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const addFile = (full: string) => {
    const rel = relative(REPO_ROOT, full);
    if (!seen.has(rel)) {
      seen.add(rel);
      out.push(rel);
    }
  };
  for (const p of paths) {
    const full = resolve(REPO_ROOT, p);
    if (!existsSync(full)) continue;
    const st = statSync(full);
    if (st.isDirectory()) {
      for (const f of findFiles(full, () => true)) addFile(f);
    } else if (st.isFile()) {
      addFile(full);
    }
  }
  return out.sort();
}

type SExpr = string | SExpr[];

function tokenizeSexpr(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const ch = src[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      i++;
      continue;
    }
    if (ch === ';') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '(' || ch === ')' || ch === "'") {
      tokens.push(ch);
      i++;
      continue;
    }
    if (ch === '"') {
      let s = '"';
      i++;
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < n) {
          s += src[i]! + src[i + 1]!;
          i += 2;
        } else {
          s += src[i]!;
          i++;
        }
      }
      if (i < n) {
        s += '"';
        i++;
      }
      tokens.push(s);
      continue;
    }
    let atom = '';
    while (i < n && !' \t\n\r()"\';'.includes(src[i]!)) {
      atom += src[i]!;
      i++;
    }
    if (atom.length > 0) tokens.push(atom);
  }
  return tokens;
}

function parseSexprs(src: string): SExpr[] {
  const tokens = tokenizeSexpr(src);
  let pos = 0;
  const parseOne = (): SExpr => {
    const tok = tokens[pos++];
    if (tok === undefined) return '';
    if (tok === "'") {
      return ['quote', parseOne()];
    }
    if (tok === '(') {
      const list: SExpr[] = [];
      while (pos < tokens.length && tokens[pos] !== ')') {
        list.push(parseOne());
      }
      if (tokens[pos] === ')') pos++;
      return list;
    }
    return tok;
  };
  const forms: SExpr[] = [];
  while (pos < tokens.length) {
    if (tokens[pos] === ')') {
      pos++;
      continue;
    }
    forms.push(parseOne());
  }
  return forms;
}

function unquoteString(atom: SExpr | undefined): string | null {
  if (typeof atom !== 'string') return null;
  if (atom.startsWith('"') && atom.endsWith('"') && atom.length >= 2) {
    return atom.slice(1, -1);
  }
  return null;
}

function extractSymbolList(expr: SExpr | undefined): string[] {
  if (!Array.isArray(expr)) return [];
  const inner = expr[0] === 'quote' && Array.isArray(expr[1]) ? expr[1] : expr;
  return inner.filter((x): x is string => typeof x === 'string' && !x.startsWith('"'));
}

function extractInterfaceMeta(ifacePath: string): {identity: string | null; tags: string[]} {
  const forms = parseSexprs(readFileSync(ifacePath, 'utf8'));
  let identity: string | null = null;
  const tags: string[] = [];
  const walk = (node: SExpr) => {
    if (!Array.isArray(node)) return;
    for (let i = 0; i < node.length; i++) {
      const cur = node[i];
      if (cur === 'identity:' && i + 1 < node.length) {
        const next = node[i + 1];
        if (Array.isArray(next) && next[0] === 'quote' && typeof next[1] === 'string') {
          identity = next[1];
        } else if (typeof next === 'string') {
          identity = next.replace(/^'/, '');
        }
      } else if (cur === 'tags:' && i + 1 < node.length) {
        for (const t of extractSymbolList(node[i + 1])) {
          if (!tags.includes(t)) tags.push(t);
        }
      } else if (Array.isArray(cur)) {
        walk(cur);
      }
    }
  };
  for (const f of forms) walk(f);
  return {identity, tags};
}

function extractLibraryImportDeps(modDir: string): string[] {
  const deps = new Set<string>();
  const ssFiles = listDirSorted(modDir).filter((f) => f.endsWith('.ss'));
  for (const fname of ssFiles) {
    const src = readFileSync(join(modDir, fname), 'utf8');
    for (const m of src.matchAll(/:deterministic-engineering\/library\/([A-Za-z0-9_-]+)/g)) {
      deps.add(m[1]!);
    }
    for (const m of src.matchAll(/"\.\.\/([A-Za-z0-9_-]+)\//g)) {
      deps.add(m[1]!);
    }
  }
  return [...deps].sort();
}

function computeTransitiveLibraryDeps(directMap: Map<string, string[]>, rootMod: string): string[] {
  const visited = new Set<string>([rootMod]);
  const queue = [rootMod];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const dep of directMap.get(cur) ?? []) {
      if (!visited.has(dep) && directMap.has(dep)) {
        visited.add(dep);
        queue.push(dep);
      }
    }
  }
  return [...visited].sort();
}

function detectMandatoryEnvTags(filePath: string): string[] {
  const src = readFileSync(filePath, 'utf8');
  const tags: string[] = [];
  // Matches 1-argument mandatory `(getenv "FOO")` (without default argument like `#f`).
  for (const m of src.matchAll(/\(getenv\s+"([A-Z0-9_]+)"\s*\)/g)) {
    const envVar = m[1]!;
    const autoPopulated = AUTO_EXPORTED_ENV_PREFIXES.some((p) => envVar.startsWith(p));
    if (!autoPopulated) {
      if (!tags.includes('requires:env')) tags.push('requires:env');
    }
  }
  return tags;
}

// ── 2. Declarative Zero-Hardcoding Discovery Graph ──

interface YuanxuMountDecl {
  relDir: string;
  mount: string;
  testDir: string;
  profiles: string[];
}

function parseInitMounts(): YuanxuMountDecl[] {
  const initPath = join(REPO_ROOT, 'init.ss');
  if (!existsSync(initPath)) return [];
  const forms = parseSexprs(readFileSync(initPath, 'utf8'));
  const yuanxuForm = forms.find((f) => Array.isArray(f) && f[0] === 'yuanxu!') as SExpr[] | undefined;
  if (!yuanxuForm) return [];

  const mounts: YuanxuMountDecl[] = [];
  let i = 1;
  while (i < yuanxuForm.length) {
    if (yuanxuForm[i] === ':load-modules') {
      const target = yuanxuForm[i + 1];
      const relDir = unquoteString(target);
      i += 2;
      let mount = '';
      let testDir = './t';
      let profiles: string[] = [];
      while (i < yuanxuForm.length && yuanxuForm[i] !== ':load-modules') {
        const tok = yuanxuForm[i];
        if (tok === 'mount:' && typeof yuanxuForm[i + 1] === 'string') {
          mount = yuanxuForm[i + 1] as string;
          i += 2;
        } else if (tok === ':test-dir') {
          testDir = unquoteString(yuanxuForm[i + 1]) ?? testDir;
          i += 2;
        } else if (tok === ':profiles' && Array.isArray(yuanxuForm[i + 1])) {
          profiles = extractSymbolList(yuanxuForm[i + 1]);
          i += 2;
        } else {
          i++;
        }
      }
      if (relDir && mount) {
        mounts.push({
          relDir: relDir.replace(/^\.\//, ''),
          mount,
          testDir: testDir.replace(/^\.\//, ''),
          profiles,
        });
      }
    } else {
      i++;
    }
  }
  return mounts;
}

function deriveMountDomain(mount: string, tags: string[]): string {
  const parts = mount.split('.');
  if (parts.length >= 3) return parts[parts.length - 1]!.toLowerCase();
  if (tags.includes('defense') || tags.includes('de.layer.defense')) return 'defense';
  if (tags.includes('funflow') || tags.includes('verification')) return 'multi-method';
  return mount.toLowerCase();
}

function discoverYuanxuUnits(): VerificationUnit[] {
  const units: VerificationUnit[] = [];
  const mounts = parseInitMounts();

  // Precompute Library internal dependency graph for transitive --impact slicing.
  const libDir = join(REPO_ROOT, 'library');
  const libDirectDeps = new Map<string, string[]>();
  if (existsSync(libDir)) {
    for (const mod of listDirSorted(libDir)) {
      const modDir = join(libDir, mod);
      if (statSync(modDir).isDirectory()) {
        libDirectDeps.set(mod, extractLibraryImportDeps(modDir));
      }
    }
  }

  for (const m of mounts) {
    const rootDir = join(REPO_ROOT, m.relDir);
    if (!existsSync(rootDir)) continue;
    for (const mod of listDirSorted(rootDir)) {
      const modDir = join(rootDir, mod);
      if (!statSync(modDir).isDirectory()) continue;
      const ifacePath = join(modDir, 'interface.ss');
      if (!existsSync(ifacePath)) continue;

      const {identity, tags: ifaceTags} = extractInterfaceMeta(ifacePath);
      const modId = identity ?? mod;
      const domain = deriveMountDomain(m.mount, ifaceTags);
      const ownedTestDir = join(REPO_ROOT, m.testDir, 'yanxu', m.mount, mod);
      const testFiles = findFiles(ownedTestDir, (_, name) => name.endsWith('-test.ss'));

      const depDirs =
        m.mount === 'Library'
          ? computeTransitiveLibraryDeps(libDirectDeps, mod).map((d) => join('library', d))
          : [join(m.relDir, mod)];

      for (const tf of testFiles) {
        const relTf = relative(REPO_ROOT, tf);
        const stem = basename(tf, '.ss');
        const envTags = detectMandatoryEnvTags(tf);
        const tagSet = new Set<string>([
          ...ifaceTags,
          ...m.profiles,
          ...envTags,
          'scheme',
          'lang:scheme',
          `mount:${m.mount}`,
          `module:${modId}`,
          `domain:${domain}`,
          domain,
          `scheme:${domain}`,
        ]);
        // Normalize dotted defense/stability markers so pure tag queries match uniformly.
        if (ifaceTags.includes('de.layer.defense') || ifaceTags.includes('quint.engineering.defense')) {
          tagSet.add('defense');
        }
        const timeoutSec =
          ifaceTags.includes('funflow') || stem.includes('fleet') ? 600 : 120;
        const inputs = collectInputFiles(['init.ss', ...depDirs, relTf]);
        units.push({
          id: `scheme:${m.mount}/${mod}/${stem}`,
          kind: 'scheme',
          mount: m.mount,
          module: modId,
          domain,
          tags: [...tagSet].sort(),
          inputs,
          conflictKey: null,
          timeoutSec,
          meta: {testPath: relTf, sourceDir: join(m.relDir, mod)},
        });
      }
    }
  }

  // Auto-discover t/integration/<group>/*-test.ss
  const integrationRoot = join(REPO_ROOT, 't/integration');
  for (const group of listDirSorted(integrationRoot)) {
    const groupDir = join(integrationRoot, group);
    if (!statSync(groupDir).isDirectory()) continue;
    for (const tf of findFiles(groupDir, (_, name) => name.endsWith('-test.ss'))) {
      const relTf = relative(REPO_ROOT, tf);
      const stem = basename(tf, '.ss');
      const envTags = detectMandatoryEnvTags(tf);
      const tagSet = new Set<string>([
        'scheme',
        'lang:scheme',
        'integration',
        `integration.${group}`,
        `mount:Integration`,
        `module:${group}`,
        `domain:${group}`,
        group,
        ...envTags,
      ]);
      units.push({
        id: `scheme:Integration/${group}/${stem}`,
        kind: 'scheme',
        mount: 'Integration',
        module: group,
        domain: group,
        tags: [...tagSet].sort(),
        inputs: collectInputFiles(['init.ss', relTf]),
        conflictKey: null,
        timeoutSec: 180,
        meta: {testPath: relTf},
      });
    }
  }

  return units;
}

function discoverPolyglotUnits(): VerificationUnit[] {
  const units: VerificationUnit[] = [];
  const langRoot = join(REPO_ROOT, 'languages-engineering');
  if (!existsSync(langRoot)) return units;

  for (const lang of listDirSorted(langRoot)) {
    const langDir = join(langRoot, lang);
    if (!statSync(langDir).isDirectory()) continue;

    for (const domain of listDirSorted(langDir)) {
      const domainDir = join(langDir, domain);
      if (!statSync(domainDir).isDirectory()) continue;

      if (lang === 'ts') {
        const subjectDirs = listDirSorted(domainDir)
          .map((e) => join(domainDir, e))
          .filter((p) => statSync(p).isDirectory());
        const candidates = subjectDirs.length > 0 ? subjectDirs : [domainDir];
        for (const sDir of candidates) {
          const tests = findFiles(sDir, (_, n) => n.endsWith('.test.ts'));
          if (tests.length === 0) continue;
          const mod = sDir === domainDir ? domain : basename(sDir);
          const relDir = relative(REPO_ROOT, sDir);
          units.push({
            id: `ts:${domain}/${mod}`,
            kind: 'ts',
            mount: 'Languages',
            module: mod,
            domain,
            tags: ['ts', 'lang:ts', domain, `domain:${domain}`, `ts:${domain}`, 'mount:Languages', `module:${mod}`].sort(),
            inputs: collectInputFiles([relDir]),
            conflictKey: null,
            timeoutSec: 600,
            meta: {dir: relDir, testCount: tests.length},
          });
        }
      } else if (lang === 'c') {
        for (const entry of listDirSorted(domainDir)) {
          const sDir = join(domainDir, entry);
          if (!statSync(sDir).isDirectory()) continue;
          const cFiles = listDirSorted(sDir).filter((f) => f.endsWith('.c')).map((f) => join(sDir, f));
          const testDriver = cFiles.find((f) => basename(f) === 'contrast_test.c' || basename(f) === 'native-test.c');
          const proofFile = cFiles.find((f) => basename(f) === 'proof.c');
          const relDir = relative(REPO_ROOT, sDir);
          const inputs = collectInputFiles([relDir]);
          if (testDriver) {
            units.push({
              id: `c:${domain}/${entry}`,
              kind: 'c',
              mount: 'Languages',
              module: entry,
              domain,
              tags: ['c', 'lang:c', domain, `domain:${domain}`, `c:${domain}`, 'mount:Languages', `module:${entry}`].sort(),
              inputs,
              conflictKey: null,
              timeoutSec: 120,
              meta: {dir: relDir, sources: cFiles.filter((f) => basename(f) !== 'proof.c').map((f) => relative(REPO_ROOT, f))},
            });
          }
          if (proofFile) {
            const implFiles = cFiles.filter((f) => {
              const b = basename(f);
              return b !== 'proof.c' && !b.startsWith('bad_') && !b.endsWith('_test.c') && b !== 'native-test.c';
            });
            units.push({
              id: `cbmc:${domain}/${entry}`,
              kind: 'cbmc',
              mount: 'Languages',
              module: entry,
              domain,
              tags: ['cbmc', 'lang:cbmc', domain, `domain:${domain}`, `cbmc:${domain}`, 'mount:Languages', `module:${entry}`].sort(),
              inputs,
              conflictKey: null,
              timeoutSec: 240,
              meta: {dir: relDir, files: [...implFiles, proofFile].map((f) => relative(REPO_ROOT, f))},
            });
          }
        }
      } else if (lang === 'cpp') {
        for (const entry of listDirSorted(domainDir)) {
          const sDir = join(domainDir, entry);
          if (!statSync(sDir).isDirectory()) continue;
          const driver = ['contrast_test.cpp', 'native-test.cpp']
            .map((f) => join(sDir, f))
            .find((p) => existsSync(p));
          if (!driver) continue;
          const relDir = relative(REPO_ROOT, sDir);
          units.push({
            id: `cpp:${domain}/${entry}`,
            kind: 'cpp',
            mount: 'Languages',
            module: entry,
            domain,
            tags: ['cpp', 'lang:cpp', domain, `domain:${domain}`, `cpp:${domain}`, 'mount:Languages', `module:${entry}`].sort(),
            inputs: collectInputFiles([relDir]),
            conflictKey: null,
            timeoutSec: 120,
            meta: {dir: relDir, driver: relative(REPO_ROOT, driver)},
          });
        }
      } else if (lang === 'rust') {
        // Recursively discover Cargo.toml crates OR standalone contrast.rs files under rust/<domain>/.
        const cargoFiles = findFiles(domainDir, (_, n) => n === 'Cargo.toml');
        const crateDirs = new Set(cargoFiles.map((f) => dirname(f)));
        for (const cDir of [...crateDirs].sort()) {
          const relDir = relative(REPO_ROOT, cDir);
          const relSub = relative(domainDir, cDir);
          const mod = basename(cDir);
          units.push({
            id: `rust:${domain}/${relSub}`,
            kind: 'rust',
            mount: 'Languages',
            module: mod,
            domain,
            tags: ['rust', 'lang:rust', domain, `domain:${domain}`, `rust:${domain}`, 'mount:Languages', `module:${mod}`].sort(),
            inputs: collectInputFiles([relDir]),
            conflictKey: relDir,
            timeoutSec: 300,
            meta: {dir: relDir, mode: 'cargo'},
          });
        }
        const standaloneFiles = findFiles(domainDir, (full, n) => {
          if (n !== 'contrast.rs') return false;
          for (const cDir of crateDirs) {
            if (full.startsWith(cDir + '/')) return false;
          }
          return true;
        });
        for (const sFile of standaloneFiles) {
          const sDir = dirname(sFile);
          const relDir = relative(REPO_ROOT, sDir);
          const relSub = relative(domainDir, sDir);
          const mod = basename(sDir);
          units.push({
            id: `rust:${domain}/${relSub}`,
            kind: 'rust',
            mount: 'Languages',
            module: mod,
            domain,
            tags: ['rust', 'lang:rust', domain, `domain:${domain}`, `rust:${domain}`, 'mount:Languages', `module:${mod}`].sort(),
            inputs: collectInputFiles([relDir]),
            conflictKey: null,
            timeoutSec: 180,
            meta: {dir: relDir, mode: 'standalone', file: relative(REPO_ROOT, sFile)},
          });
        }
      } else if (lang === 'go') {
        const modFiles = findFiles(domainDir, (_, n) => n === 'go.mod');
        for (const mf of modFiles) {
          const mDir = dirname(mf);
          const relDir = relative(REPO_ROOT, mDir);
          const relSub = relative(domainDir, mDir);
          const idSuffix = relSub ? `${domain}/${relSub}` : domain;
          const mod = relSub ? basename(mDir) : domain;
          units.push({
            id: `go:${idSuffix}`,
            kind: 'go',
            mount: 'Languages',
            module: mod,
            domain,
            tags: ['go', 'lang:go', domain, `domain:${domain}`, `go:${domain}`, 'mount:Languages', `module:${mod}`].sort(),
            inputs: collectInputFiles([relDir]),
            conflictKey: relDir,
            timeoutSec: 240,
            meta: {dir: relDir},
          });
        }
      }
    }
  }

  return units;
}

function discoverLeanUnits(): VerificationUnit[] {
  const leanRoot = join(REPO_ROOT, 'packages/lean-models');
  const srcRoot = join(leanRoot, 'DeterministicEngineering');
  if (!existsSync(srcRoot)) return [];

  return findFiles(srcRoot, (_, n) => n.endsWith('.lean')).map((full) => {
    const relFromLean = relative(leanRoot, full);
    const modName = relFromLean.replace(/\.lean$/, '').replaceAll('/', '.');
    const parts = modName.split('.').slice(1).map((p) => p.toLowerCase());
    const tagSet = new Set<string>(['lean', 'lang:lean', 'mount:Lean', 'domain:lean', `module:${modName}`]);
    for (let i = 0; i < parts.length; i++) {
      tagSet.add(`lean.${parts.slice(0, i + 1).join('.')}`);
    }
    return {
      id: `lean:${modName}`,
      kind: 'lean',
      mount: 'Lean',
      module: modName,
      domain: 'lean',
      tags: [...tagSet].sort(),
      inputs: collectInputFiles([
        relative(REPO_ROOT, full),
        'packages/lean-models/lakefile.toml',
        'packages/lean-models/lakefile.lean',
        'packages/lean-models/lean-toolchain',
      ]),
      conflictKey: 'packages/lean-models',
      timeoutSec: 600,
      meta: {modName, file: relative(REPO_ROOT, full)},
    };
  });
}

function discoverPackageUnits(): VerificationUnit[] {
  const units: VerificationUnit[] = [];
  const rootPkgPath = join(REPO_ROOT, 'package.json');
  if (!existsSync(rootPkgPath)) return units;
  const rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf8')) as {
    scripts?: Record<string, string>;
  };
  const rootScripts = rootPkg.scripts ?? {};

  // 1. Discover workspace package scripts directly from packages/*/package.json
  const packagesDir = join(REPO_ROOT, 'packages');
  for (const pkgName of listDirSorted(packagesDir)) {
    const pkgDir = join(packagesDir, pkgName);
    const pkgJsonPath = join(pkgDir, 'package.json');
    if (!existsSync(pkgJsonPath)) continue;
    const pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf8')) as {
      scripts?: Record<string, string>;
    };
    const isQuintPkg = pkgName.startsWith('quint');
    const domain = isQuintPkg ? 'quint' : pkgName;
    const kind: UnitKind = isQuintPkg ? 'quint' : 'pkg';
    const relPkgDir = relative(REPO_ROOT, pkgDir);
    const inputs = collectInputFiles([relPkgDir, 'package.json']);

    for (const [scriptName, scriptCmd] of Object.entries(pkgJson.scripts ?? {})) {
      // Normalize step alias (e.g. `test:export` -> `export`, `test:examples` -> `examples-test`).
      const stepAlias =
        scriptName === 'test:export'
          ? 'export'
          : scriptName === 'test:examples'
            ? 'examples-test'
            : scriptName;
      const isResolverTest = isQuintPkg && scriptName === 'test' && existsSync(join(pkgDir, 'test'));
      units.push({
        id: `${kind}:${domain}/${scriptName}`,
        kind,
        mount: 'Packages',
        module: pkgName,
        domain,
        tags: [
          kind,
          `lang:${kind}`,
          domain,
          `domain:${domain}`,
          `${kind}:${domain}`,
          'mount:Packages',
          `module:${pkgName}`,
          `step:${scriptName}`,
          `step:${stepAlias}`,
          scriptName,
          stepAlias,
        ].sort(),
        inputs,
        conflictKey: relPkgDir,
        timeoutSec: 300,
        meta: {
          mode: isResolverTest ? 'quint-resolver-tests' : 'pkg-script',
          cwd: relPkgDir,
          scriptName,
          scriptCmd,
        },
      });
    }
  }

  // 2. Discover root package.json workflow/example scripts dynamically (ZERO hardcoded script lists!)
  for (const [scriptName, scriptCmd] of Object.entries(rootScripts)) {
    if (scriptName.startsWith('example:')) {
      // Infer owning package from script command path `packages/<owner>/...`
      const ownerMatch = /packages\/([^/\s]+)/.exec(scriptCmd);
      const owner = ownerMatch ? ownerMatch[1]! : 'render';
      const relOwnerDir = `packages/${owner}`;
      units.push({
        id: `pkg:${owner}/${scriptName}`,
        kind: 'pkg',
        mount: 'Packages',
        module: owner,
        domain: owner,
        tags: [
          'pkg',
          'lang:pkg',
          owner,
          `domain:${owner}`,
          `pkg:${owner}`,
          'mount:Packages',
          `module:${owner}`,
          'step:examples',
          'examples',
          `step:${scriptName}`,
          scriptName,
        ].sort(),
        inputs: collectInputFiles([relOwnerDir, 'package.json']),
        conflictKey: relOwnerDir,
        timeoutSec: 180,
        meta: {mode: 'root-script', scriptName, scriptCmd},
      });
    } else if (/^(fleet|mbt):/.test(scriptName)) {
      const [verb, target] = scriptName.split(':') as [string, string];
      const domain = target;
      const kind: UnitKind = domain === 'quint' ? 'quint' : 'pkg';
      units.push({
        id: `${kind}:${domain}/${verb}`,
        kind,
        mount: 'Packages',
        module: scriptName,
        domain,
        tags: [
          kind,
          `lang:${kind}`,
          domain,
          `domain:${domain}`,
          `${kind}:${domain}`,
          'mount:Packages',
          `step:${verb}`,
          verb,
          scriptName,
        ].sort(),
        inputs: collectInputFiles(['packages/quint-models', 'packages/quint-modules-resolver', 'package.json']),
        conflictKey: `root:${domain}`,
        timeoutSec: 600,
        meta: {mode: 'root-script', scriptName, scriptCmd},
      });
    }
  }

  return units;
}

function discoverAllUnits(): VerificationUnit[] {
  return [
    ...discoverYuanxuUnits(),
    ...discoverPolyglotUnits(),
    ...discoverLeanUnits(),
    ...discoverPackageUnits(),
  ];
}

// ── 3. Composable Query Algebra & Change-Impact Slicing ──

function splitCsv(val: string): string[] {
  return val
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function getGitChangedFiles(): string[] {
  const tracked = Bun.spawnSync(['git', 'diff', '--name-only', 'HEAD'], {cwd: REPO_ROOT, stdout: 'pipe', stderr: 'pipe'});
  const untracked = Bun.spawnSync(['git', 'ls-files', '--others', '--exclude-standard'], {
    cwd: REPO_ROOT,
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const lines = [
    ...new TextDecoder().decode(tracked.stdout).split('\n'),
    ...new TextDecoder().decode(untracked.stdout).split('\n'),
  ]
    .map((s) => s.trim().replace(/^\.\//, ''))
    .filter(Boolean);
  return [...new Set(lines)].sort();
}

function matchesToken(unit: VerificationUnit, token: string): boolean {
  return (
    unit.kind === token ||
    unit.domain === token ||
    unit.mount === token ||
    unit.module === token ||
    unit.id === token ||
    unit.tags.includes(token) ||
    unit.tags.includes(`step:${token}`) ||
    unit.tags.includes(`lang:${token}`)
  );
}

function filterUnits(units: VerificationUnit[], opts: QueryOptions): VerificationUnit[] {
  const changedSet = opts.impact
    ? new Set(opts.changedFiles.length > 0 ? opts.changedFiles : getGitChangedFiles())
    : null;

  let filtered = units.filter((u) => {
    if (!opts.includeExternal && u.tags.includes('requires:env')) return false;
    if (opts.portable && (u.tags.includes('requires:gerbil') || u.tags.includes('requires:apalache'))) {
      return false;
    }
    if (opts.mounts.size > 0 && !opts.mounts.has(u.mount)) return false;
    if (opts.langs.size > 0 && !opts.langs.has(u.kind)) return false;
    if (opts.domains.size > 0 && !opts.domains.has(u.domain)) return false;
    if (opts.modules.size > 0 && !opts.modules.has(u.module)) return false;

    for (const group of opts.tagGroups) {
      if (!group.some((t) => matchesToken(u, t))) return false;
    }
    for (const t of opts.allTags) {
      if (!matchesToken(u, t)) return false;
    }
    if (opts.only.size > 0 && ![...opts.only].some((tok) => matchesToken(u, tok))) {
      return false;
    }
    if (opts.skip.size > 0 && [...opts.skip].some((tok) => matchesToken(u, tok))) {
      return false;
    }
    if (changedSet !== null) {
      if (changedSet.size === 0) return false;
      const touched = u.inputs.some((inp) => changedSet.has(inp));
      if (!touched) return false;
    }
    return true;
  });

  if (opts.limit !== null && opts.limit >= 0) {
    filtered = filtered.slice(0, opts.limit);
  }
  return filtered;
}

// ── 4. Content-Addressed SHA-256 Digests & Conflict-Free Parallel Wave Scheduler ──

function computeUnitDigest(unit: VerificationUnit): string {
  const h = createHash('sha256');
  h.update(`unit:${unit.id}\nkind:${unit.kind}\nmeta:${JSON.stringify(unit.meta)}\n`);
  for (const relPath of unit.inputs) {
    const full = join(REPO_ROOT, relPath);
    h.update(`file:${relPath}\n`);
    if (existsSync(full) && statSync(full).isFile()) {
      h.update(readFileSync(full));
    }
    h.update('\n');
  }
  return h.digest('hex');
}

function loadCache(cacheDir: string | null): CacheFile {
  if (!cacheDir) return {schema: 'de.verify-framework-cache.v1', entries: {}};
  const cachePath = resolve(REPO_ROOT, cacheDir, 'verify-framework-cache.v1.json');
  if (!existsSync(cachePath)) return {schema: 'de.verify-framework-cache.v1', entries: {}};
  try {
    return JSON.parse(readFileSync(cachePath, 'utf8')) as CacheFile;
  } catch {
    return {schema: 'de.verify-framework-cache.v1', entries: {}};
  }
}

function saveCache(cacheDir: string | null, cache: CacheFile): void {
  if (!cacheDir) return;
  const absDir = resolve(REPO_ROOT, cacheDir);
  mkdirSync(absDir, {recursive: true});
  writeFileSync(join(absDir, 'verify-framework-cache.v1.json'), JSON.stringify(cache, null, 2) + '\n');
}

function partitionParallelWaves(units: VerificationUnit[], maxJobs: number): VerificationUnit[][] {
  const waves: VerificationUnit[][] = [];
  const remaining = [...units];
  while (remaining.length > 0) {
    const wave: VerificationUnit[] = [];
    const usedKeys = new Set<string>();
    const deferred: VerificationUnit[] = [];
    for (const u of remaining) {
      const conflicts = u.conflictKey !== null && usedKeys.has(u.conflictKey);
      if (!conflicts && wave.length < maxJobs) {
        wave.push(u);
        if (u.conflictKey !== null) usedKeys.add(u.conflictKey);
      } else {
        deferred.push(u);
      }
    }
    waves.push(wave);
    remaining.length = 0;
    remaining.push(...deferred);
  }
  return waves;
}

// ── 5. Atomic Tool Resolvers & Unit Executors ──

function whichTool(candidates: string[]): string | null {
  for (const name of candidates) {
    const found = Bun.which(name);
    if (found) return found;
  }
  return null;
}

function resolveRustTool(tool: 'rustc' | 'cargo'): string {
  const envOverride = tool === 'cargo' ? process.env.RESOURCE_CARGO : process.env.RESOURCE_RUSTC;
  if (envOverride && existsSync(envOverride)) return envOverride;
  const rustup = join(process.env.HOME ?? '', '.cargo/bin/rustup');
  if (existsSync(rustup)) {
    const proc = Bun.spawnSync([rustup, 'which', tool], {stdout: 'pipe', stderr: 'pipe'});
    if (proc.exitCode === 0) {
      const p = new TextDecoder().decode(proc.stdout).trim();
      if (p) return p;
    }
  }
  const homeBin = join(process.env.HOME ?? '', '.cargo/bin', tool);
  if (existsSync(homeBin)) return homeBin;
  const found = whichTool([tool]);
  if (!found) throw new Error(`${tool} not found on PATH or via rustup`);
  return found;
}

async function execAsync(
  cmd: string[],
  opts: {cwd?: string; env?: Record<string, string | undefined>; inherit?: boolean} = {},
): Promise<{exitCode: number; output: string}> {
  const proc = Bun.spawn(cmd, {
    cwd: opts.cwd ?? REPO_ROOT,
    env: {...process.env, ...opts.env},
    stdout: opts.inherit ? 'inherit' : 'pipe',
    stderr: opts.inherit ? 'inherit' : 'pipe',
  });
  let output = '';
  if (!opts.inherit) {
    const [out, err] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    output = out + (err ? `\n${err}` : '');
  }
  const exitCode = await proc.exited;
  return {exitCode, output};
}

function extractLeanTheorems(filePath: string): {fullName: string}[] {
  const src = readFileSync(filePath, 'utf8');
  const results: {fullName: string}[] = [];
  const nsStack: string[] = [];
  for (const line of src.split('\n')) {
    const nsOpen = /^\s*namespace\s+([A-Za-z0-9_.]+)/.exec(line);
    if (nsOpen) {
      nsStack.push(nsOpen[1]!);
      continue;
    }
    const nsClose = /^\s*end\s+([A-Za-z0-9_.]+)/.exec(line);
    if (nsClose && nsStack.length > 0 && nsStack[nsStack.length - 1] === nsClose[1]) {
      nsStack.pop();
      continue;
    }
    const thm = /^\s*(?:private\s+)?(?:theorem|lemma)\s+([A-Za-z_][A-Za-z0-9_']*)\b/.exec(line);
    if (thm && !line.trimStart().startsWith('private ')) {
      const prefix = nsStack.join('.');
      results.push({fullName: prefix ? `${prefix}.${thm[1]!}` : thm[1]!});
    }
  }
  return results;
}

const ALLOWED_LEAN_AXIOMS = new Set(['propext', 'Classical.choice', 'Quot.sound']);

function checkLeanAxiomOutput(modName: string, stdout: string): void {
  if (stdout.includes('sorryAx')) {
    throw new Error(`CRITICAL: sorryAx detected in ${modName}:\n${stdout}`);
  }
  const axiomBlockRe = /depends on axioms:\s*\[([^\]]+)\]/g;
  let m: RegExpExecArray | null;
  while ((m = axiomBlockRe.exec(stdout)) !== null) {
    for (const ax of m[1]!.split(',').map((s) => s.trim()).filter(Boolean)) {
      if (!ALLOWED_LEAN_AXIOMS.has(ax)) {
        throw new Error(`CRITICAL: disallowed axiom '${ax}' in ${modName}:\n${stdout}`);
      }
    }
  }
}

async function runLeanBatch(
  leanUnits: VerificationUnit[],
  digests: Map<string, string>,
  checkAxioms: boolean,
): Promise<UnitOutcome[]> {
  const leanDir = join(REPO_ROOT, 'packages/lean-models');
  const modNames = leanUnits.map((u) => String(u.meta.modName));
  const t0 = performance.now();
  console.log(`\n▶ [lean] Building ${modNames.length} auto-discovered Lean 4 modules`);
  const build = await execAsync(['lake', 'build', ...modNames], {cwd: leanDir, inherit: true});
  if (build.exitCode !== 0) {
    throw new Error(`lake build failed (${build.exitCode})`);
  }

  let totalTheorems = 0;
  let auditedMods = 0;
  if (checkAxioms) {
    for (const u of leanUnits) {
      const mod = String(u.meta.modName);
      const fullPath = join(REPO_ROOT, String(u.meta.file));
      const theorems = extractLeanTheorems(fullPath);
      if (theorems.length === 0) continue;
      totalTheorems += theorems.length;
      auditedMods++;
      const stdinLines = [`import ${mod}`, ...theorems.map((t) => `#print axioms ${t.fullName}`)].join('\n');
      const proc = Bun.spawnSync(['lake', 'env', 'lean', '--stdin'], {
        cwd: leanDir,
        stdin: new TextEncoder().encode(stdinLines + '\n'),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const out = new TextDecoder().decode(proc.stdout);
      const err = new TextDecoder().decode(proc.stderr);
      if (proc.exitCode !== 0) {
        throw new Error(`Lean axiom audit failed on ${mod}:\n${err}\n${out}`);
      }
      checkLeanAxiomOutput(mod, out);
    }
    console.log(
      `  ✓ [lean-axioms] Audited ${totalTheorems} theorems across ${auditedMods} Lean modules (0 sorryAx, standard kernel axioms only)`,
    );
  }
  const dt = Math.round(performance.now() - t0);
  return leanUnits.map((u) => ({
    id: u.id,
    kind: 'lean',
    status: 'pass',
    digest: digests.get(u.id) ?? '',
    durationMs: Math.round(dt / Math.max(1, leanUnits.length)),
    detail: `lake build + axioms OK`,
  }));
}

async function runSingleUnit(
  unit: VerificationUnit,
  digest: string,
  opts: QueryOptions,
  inheritOutput: boolean,
): Promise<UnitOutcome> {
  const t0 = performance.now();
  mkdirSync(BUILD_DIR, {recursive: true});

  const fail = (detail: string): UnitOutcome => ({
    id: unit.id,
    kind: unit.kind,
    status: 'fail',
    digest,
    durationMs: Math.round(performance.now() - t0),
    detail,
  });

  const ok = (detail: string): UnitOutcome => ({
    id: unit.id,
    kind: unit.kind,
    status: 'pass',
    digest,
    durationMs: Math.round(performance.now() - t0),
    detail,
  });

  if (unit.kind === 'ts') {
    const dir = String(unit.meta.dir);
    console.log(`\n▶ [${unit.id}] Running ${unit.meta.testCount} Bun tests under ${dir}`);
    const r = await execAsync(['bun', 'test', dir], {inherit: inheritOutput});
    return r.exitCode === 0 ? ok(`bun test ${dir} (${unit.meta.testCount} files)`) : fail(r.output || `exit ${r.exitCode}`);
  }

  if (unit.kind === 'c') {
    const cc = whichTool(['clang', 'cc', 'gcc']);
    if (!cc) return fail('No C compiler found');
    const sources = (unit.meta.sources as string[]).map((s) => join(REPO_ROOT, s));
    const binOut = join(BUILD_DIR, `c_${unit.domain}_${unit.module}`);
    console.log(`\n▶ [${unit.id}] Compiling & running native C contrast (${sources.length} units)`);
    const comp = await execAsync([cc, '-Wall', '-Wextra', '-Werror', ...sources, '-o', binOut], {inherit: inheritOutput});
    if (comp.exitCode !== 0) return fail(comp.output || `cc exit ${comp.exitCode}`);
    const run = await execAsync([binOut], {inherit: inheritOutput});
    return run.exitCode === 0 ? ok('C native contrast PASS') : fail(run.output || `exit ${run.exitCode}`);
  }

  if (unit.kind === 'cbmc') {
    const cbmc = whichTool(['cbmc']);
    if (!cbmc) return fail('cbmc not found on PATH');
    const files = (unit.meta.files as string[]).map((f) => join(REPO_ROOT, f));
    console.log(`\n▶ [${unit.id}] Bounded model checking ${files.map((f) => basename(f)).join(', ')}`);
    const r = await execAsync(
      [cbmc, ...files, '--bounds-check', '--pointer-check', '--unsigned-overflow-check'],
      {inherit: inheritOutput},
    );
    return r.exitCode === 0 ? ok('CBMC VERIFICATION SUCCESSFUL') : fail(r.output || `exit ${r.exitCode}`);
  }

  if (unit.kind === 'cpp') {
    const cxx = whichTool(['clang++', 'c++', 'g++']);
    if (!cxx) return fail('No C++ compiler found');
    const driver = join(REPO_ROOT, String(unit.meta.driver));
    const binOut = join(BUILD_DIR, `cpp_${unit.domain}_${unit.module}`);
    console.log(`\n▶ [${unit.id}] Compiling & running C++20 contrast`);
    const comp = await execAsync([cxx, '-std=c++20', '-Wall', '-Wextra', '-Werror', driver, '-o', binOut], {
      inherit: inheritOutput,
    });
    if (comp.exitCode !== 0) return fail(comp.output || `cxx exit ${comp.exitCode}`);
    const run = await execAsync([binOut], {inherit: inheritOutput});
    return run.exitCode === 0 ? ok('C++20 contrast PASS') : fail(run.output || `exit ${run.exitCode}`);
  }

  if (unit.kind === 'rust') {
    const dir = join(REPO_ROOT, String(unit.meta.dir));
    if (unit.meta.mode === 'cargo') {
      const cargo = resolveRustTool('cargo');
      const cargoEnv = {PATH: `${join(process.env.HOME ?? '', '.cargo/bin')}:${process.env.PATH ?? ''}`};
      console.log(`\n▶ [${unit.id}] Running Cargo clippy + lib + integration tests`);
      for (const args of [
        ['clippy', '--all-targets', '--', '-D', 'warnings'],
        ['test', '--lib', '--', '--nocapture'],
      ]) {
        const r = await execAsync([cargo, ...args], {cwd: dir, env: cargoEnv, inherit: inheritOutput});
        if (r.exitCode !== 0) return fail(r.output || `cargo ${args[0]} exit ${r.exitCode}`);
      }
      const testsDir = join(dir, 'tests');
      for (const tf of listDirSorted(testsDir).filter((f) => f.endsWith('.rs'))) {
        const stem = tf.replace(/\.rs$/, '');
        const r = await execAsync([cargo, 'test', '--test', stem, '--', '--nocapture', '--test-threads=1'], {
          cwd: dir,
          env: cargoEnv,
          inherit: inheritOutput,
        });
        if (r.exitCode !== 0) return fail(r.output || `cargo test --test ${stem} exit ${r.exitCode}`);
      }
      return ok('Cargo clippy + tests PASS');
    }
    const rustc = resolveRustTool('rustc');
    const file = join(REPO_ROOT, String(unit.meta.file));
    const binOut = join(BUILD_DIR, `rust_${unit.domain}_${unit.module}`);
    console.log(`\n▶ [${unit.id}] Compiling & running standalone Rust contrast`);
    const comp = await execAsync([rustc, '--test', file, '-o', binOut], {inherit: inheritOutput});
    if (comp.exitCode !== 0) return fail(comp.output || `rustc exit ${comp.exitCode}`);
    const run = await execAsync([binOut], {inherit: inheritOutput});
    return run.exitCode === 0 ? ok('Rust contrast PASS') : fail(run.output || `exit ${run.exitCode}`);
  }

  if (unit.kind === 'go') {
    const dir = join(REPO_ROOT, String(unit.meta.dir));
    const hasGo = Boolean(whichTool(['go']));
    const devenv =
      whichTool(['devenv']) ??
      (existsSync(join(process.env.HOME ?? '', '.nix-profile/bin/devenv'))
        ? join(process.env.HOME ?? '', '.nix-profile/bin/devenv')
        : null);
    const nixShell = whichTool(['nix-shell']);
    const script = `cd ${JSON.stringify(dir)} && go vet ./... && go test -race -v ./...`;
    console.log(`\n▶ [${unit.id}] Running go vet + go test -race`);
    const cmd = hasGo
      ? ['bash', '-euo', 'pipefail', '-c', script]
      : devenv
        ? [devenv, 'shell', '--', 'bash', '-euo', 'pipefail', '-c', script]
        : nixShell
          ? [nixShell, '-p', 'go', '--run', script]
          : null;
    if (!cmd) return fail('Neither go, devenv, nor nix-shell available');
    const r = await execAsync(cmd, {inherit: inheritOutput});
    return r.exitCode === 0 ? ok('Go vet + race tests PASS') : fail(r.output || `exit ${r.exitCode}`);
  }

  if (unit.kind === 'scheme') {
    const runner = join(REPO_ROOT, 't/harness/run-gxtest.sh');
    const testPath = String(unit.meta.testPath);
    console.log(`\n▶ [${unit.id}] Running Gerbil/Yuanxu test ${testPath}`);
    const r = await execAsync([runner, 'file', testPath, '.*', `${unit.timeoutSec}s`], {inherit: inheritOutput});
    return r.exitCode === 0 ? ok(`gxtest PASS ${testPath}`) : fail(r.output || `exit ${r.exitCode}`);
  }

  if (unit.kind === 'pkg' || unit.kind === 'quint') {
    const mode = String(unit.meta.mode);
    if (mode === 'quint-resolver-tests') {
      const testDir = join(REPO_ROOT, String(unit.meta.cwd), 'test');
      const allTests = findFiles(testDir, (_, n) => n.endsWith('.test.ts'));
      const hasGerbil = Boolean(whichTool(['gerbil']));
      const hasApalache = Boolean(whichTool(['apalache-mc', 'java']));
      const selected: string[] = [];
      const skipped: string[] = [];
      for (const file of allTests) {
        const src = readFileSync(file, 'utf8');
        const needsGerbil = /['"]gerbil['"]/.test(src);
        const needsApalache = /(?:['"]verify['"]|--verify|guard-probe|auditGuardNecessity|probeGuards)/.test(src);
        if (opts.portable && (needsGerbil || needsApalache)) {
          skipped.push(`${basename(file)} (${[needsGerbil && 'gerbil', needsApalache && 'apalache'].filter(Boolean).join('+')})`);
          continue;
        }
        if ((needsGerbil && !hasGerbil) || (needsApalache && !hasApalache)) {
          skipped.push(`${basename(file)} (missing host engine)`);
          continue;
        }
        selected.push(relative(REPO_ROOT, file));
      }
      console.log(
        `\n▶ [${unit.id}] Running ${selected.length}/${allTests.length} resolver tests${skipped.length ? ` (skipped: ${skipped.join(', ')})` : ''}`,
      );
      const r = await execAsync(['bun', 'test', ...selected], {inherit: inheritOutput});
      return r.exitCode === 0 ? ok(`resolver tests (${selected.length}/${allTests.length}) PASS`) : fail(r.output || `exit ${r.exitCode}`);
    }
    if (mode === 'pkg-script') {
      const cwd = join(REPO_ROOT, String(unit.meta.cwd));
      const scriptName = String(unit.meta.scriptName);
      console.log(`\n▶ [${unit.id}] bun run --cwd ${unit.meta.cwd} ${scriptName}`);
      const r = await execAsync(['bun', 'run', scriptName], {cwd, inherit: inheritOutput});
      return r.exitCode === 0 ? ok(`pkg script ${scriptName} PASS`) : fail(r.output || `exit ${r.exitCode}`);
    }
    const scriptName = String(unit.meta.scriptName);
    console.log(`\n▶ [${unit.id}] bun run ${scriptName}`);
    const r = await execAsync(['bun', 'run', scriptName], {inherit: inheritOutput});
    return r.exitCode === 0 ? ok(`root script ${scriptName} PASS`) : fail(r.output || `exit ${r.exitCode}`);
  }

  return fail(`Unsupported unit kind: ${unit.kind}`);
}

// ── 6. Inventory Printer & CLI Driver ──

function printInventory(units: VerificationUnit[]): void {
  const byMount = new Map<string, number>();
  const byKind = new Map<string, number>();
  const byDomain = new Map<string, number>();
  for (const u of units) {
    byMount.set(u.mount, (byMount.get(u.mount) ?? 0) + 1);
    byKind.set(u.kind, (byKind.get(u.kind) ?? 0) + 1);
    byDomain.set(u.domain, (byDomain.get(u.domain) ?? 0) + 1);
  }
  console.log(`=== Deterministic Engineering Zero-Hardcoding Verification Graph (${units.length} units) ===`);
  console.log('\nBy Mount (discovered from init.ss + filesystem grammar):');
  for (const [k, v] of [...byMount.entries()].sort()) {
    console.log(`  ${k.padEnd(32)} ${v}`);
  }
  console.log('\nBy Language / Kind:');
  for (const [k, v] of [...byKind.entries()].sort()) {
    console.log(`  ${k.padEnd(32)} ${v}`);
  }
  console.log('\nBy Domain:');
  for (const [k, v] of [...byDomain.entries()].sort()) {
    console.log(`  ${k.padEnd(32)} ${v}`);
  }
}

function parseQueryFlags(args: string[]): QueryOptions {
  const opts: QueryOptions = {
    tagGroups: [],
    allTags: [],
    mounts: new Set(),
    langs: new Set(),
    domains: new Set(),
    modules: new Set(),
    only: new Set(),
    skip: new Set(),
    portable: false,
    includeExternal: false,
    impact: false,
    changedFiles: [],
    cacheDir: null,
    jobs: 1,
    planOnly: false,
    reportPath: null,
    limit: null,
    checkAxioms: true,
  };
  let cbmcFlag = false;
  let cbmcOnlyFlag = false;

  for (const arg of args) {
    if (arg.startsWith('--tag=')) opts.tagGroups.push(splitCsv(arg.slice(6)));
    else if (arg.startsWith('--all-tags=')) opts.allTags.push(...splitCsv(arg.slice(11)));
    else if (arg.startsWith('--mount=')) splitCsv(arg.slice(8)).forEach((x) => opts.mounts.add(x));
    else if (arg.startsWith('--lang=')) splitCsv(arg.slice(7)).forEach((x) => opts.langs.add(x));
    else if (arg.startsWith('--domain=')) splitCsv(arg.slice(9)).forEach((x) => opts.domains.add(x));
    else if (arg.startsWith('--module=')) splitCsv(arg.slice(9)).forEach((x) => opts.modules.add(x));
    else if (arg.startsWith('--only=')) splitCsv(arg.slice(7)).forEach((x) => opts.only.add(x));
    else if (arg.startsWith('--skip=')) splitCsv(arg.slice(7)).forEach((x) => opts.skip.add(x));
    else if (arg === '--portable') opts.portable = true;
    else if (arg === '--include-external') opts.includeExternal = true;
    else if (arg === '--impact') opts.impact = true;
    else if (arg.startsWith('--changed=')) {
      opts.impact = true;
      opts.changedFiles.push(...splitCsv(arg.slice(10)).map((p) => p.replace(/^\.\//, '')));
    } else if (arg.startsWith('--cache=')) opts.cacheDir = arg.slice(8);
    else if (arg.startsWith('--jobs=')) opts.jobs = Math.max(1, Number.parseInt(arg.slice(7), 10) || 1);
    else if (arg === '--plan') opts.planOnly = true;
    else if (arg.startsWith('--report=')) opts.reportPath = arg.slice(9);
    else if (arg.startsWith('--limit=')) opts.limit = Number.parseInt(arg.slice(8), 10);
    else if (arg === '--no-axioms') opts.checkAxioms = false;
    else if (arg === '--axioms') opts.checkAxioms = true;
    else if (arg === '--cbmc') cbmcFlag = true;
    else if (arg === '--cbmc-only') cbmcOnlyFlag = true;
  }

  if (cbmcOnlyFlag) {
    opts.langs.delete('c');
    opts.langs.add('cbmc');
  } else if (cbmcFlag && opts.langs.has('c')) {
    opts.langs.add('cbmc');
  }
  return opts;
}

async function main(): Promise<void> {
  const rawArgs = process.argv.slice(2);
  const cmd = rawArgs[0] ?? 'list';
  const tStart = performance.now();
  const allUnits = discoverAllUnits();

  if (cmd === 'list' || cmd === '--list' || cmd === '--help' || cmd === '-h') {
    printInventory(allUnits);
    return;
  }

  const flagArgs = cmd === 'run' ? rawArgs.slice(1) : rawArgs;
  const opts = parseQueryFlags(flagArgs);
  const selected = filterUnits(allUnits, opts);

  if (selected.length === 0) {
    if (opts.impact) {
      console.log('✓ VERIFY-IMPACT-OK (0 affected units)');
      return;
    }
    throw new Error(`Query matched 0 verification units (out of ${allUnits.length} discovered). Flags: ${flagArgs.join(' ')}`);
  }

  const cache = loadCache(opts.cacheDir);
  const digests = new Map<string, string>();
  const cachedUnits: VerificationUnit[] = [];
  const pendingUnits: VerificationUnit[] = [];

  for (const u of selected) {
    const digest = opts.cacheDir || opts.planOnly || opts.reportPath ? computeUnitDigest(u) : '';
    digests.set(u.id, digest);
    const hit = opts.cacheDir ? cache.entries[u.id] : undefined;
    if (hit && hit.digest === digest) {
      cachedUnits.push(u);
    } else {
      pendingUnits.push(u);
    }
  }

  const pendingNonLean = pendingUnits.filter((u) => u.kind !== 'lean');
  const pendingLean = pendingUnits.filter((u) => u.kind === 'lean');
  const waves = partitionParallelWaves(pendingNonLean, opts.jobs);
  if (pendingLean.length > 0) waves.push(pendingLean);

  if (opts.planOnly) {
    console.log(
      `=== Verification Execution Plan (selected=${selected.length}/${allUnits.length}, cached=${cachedUnits.length}, pending=${pendingUnits.length}, waves=${waves.length}, jobs=${opts.jobs}) ===`,
    );
    for (const u of cachedUnits) {
      console.log(`  [CACHE-HIT] ${u.id} (${digests.get(u.id)?.slice(0, 12)})`);
    }
    waves.forEach((w, idx) => {
      console.log(`  [WAVE ${idx + 1}] (${w.length} units): ${w.map((u) => u.id).join(', ')}`);
    });
    console.log(`✓ VERIFY-PLAN-OK (${Math.round(performance.now() - tStart)}ms)`);
    return;
  }

  const outcomes: UnitOutcome[] = cachedUnits.map((u) => ({
    id: u.id,
    kind: u.kind,
    status: 'cached',
    digest: digests.get(u.id) ?? '',
    durationMs: 0,
    detail: cache.entries[u.id]?.detail ?? 'cached pass',
  }));

  if (cachedUnits.length > 0) {
    console.log(`▶ [cache] Reused ${cachedUnits.length}/${selected.length} unchanged verification units`);
  }

  const failures: UnitOutcome[] = [];
  for (const wave of waves) {
    if (wave.length > 0 && wave.every((u) => u.kind === 'lean')) {
      const leanResults = await runLeanBatch(wave, digests, opts.checkAxioms);
      outcomes.push(...leanResults);
      for (const r of leanResults) {
        if (opts.cacheDir && r.status === 'pass') {
          cache.entries[r.id] = {digest: r.digest, passedAt: new Date().toISOString(), detail: r.detail};
        }
      }
      continue;
    }

    const inherit = wave.length === 1;
    const waveResults = await Promise.all(
      wave.map((u) => runSingleUnit(u, digests.get(u.id) ?? '', opts, inherit)),
    );
    for (const r of waveResults) {
      outcomes.push(r);
      if (r.status === 'fail') {
        failures.push(r);
        if (!inherit) console.error(`\n✗ FAILED ${r.id}:\n${r.detail}`);
      } else if (opts.cacheDir) {
        cache.entries[r.id] = {digest: r.digest, passedAt: new Date().toISOString(), detail: r.detail};
      }
    }
    if (failures.length > 0) break;
  }

  if (opts.cacheDir) saveCache(opts.cacheDir, cache);

  if (opts.reportPath) {
    const absReport = resolve(REPO_ROOT, opts.reportPath);
    mkdirSync(dirname(absReport), {recursive: true});
    writeFileSync(
      absReport,
      JSON.stringify(
        {
          schema: 'deterministic-engineering.verify-framework-report.v1',
          totalDiscovered: allUnits.length,
          selectedCount: selected.length,
          executedCount: outcomes.filter((o) => o.status === 'pass').length,
          cachedCount: outcomes.filter((o) => o.status === 'cached').length,
          failedCount: failures.length,
          durationMs: Math.round(performance.now() - tStart),
          outcomes,
        },
        null,
        2,
      ) + '\n',
    );
  }

  if (failures.length > 0) {
    throw new Error(`${failures.length} verification unit(s) failed: ${failures.map((f) => f.id).join(', ')}`);
  }

  const totalMs = Math.round(performance.now() - tStart);
  const execCount = outcomes.filter((o) => o.status === 'pass').length;
  console.log(
    `\n✓ VERIFY-FRAMEWORK-OK (selected=${selected.length}, executed=${execCount}, cached=${cachedUnits.length}, ${totalMs}ms)`,
  );
}

main().catch((err) => {
  console.error(`\n✗ VERIFY-FRAMEWORK-FAILED: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
