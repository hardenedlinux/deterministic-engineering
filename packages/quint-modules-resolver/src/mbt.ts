// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {createHash} from 'node:crypto';
import {existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {dirname, join, relative, resolve} from 'node:path';
import {
  newIdGenerator,
  parsePhase1fromText,
  type QuintEx,
  type QuintModule,
} from '@informalsystems/quint';
import {parseQntHeaderDirectives} from './plan.ts';
import {expandExtendedQntFile} from './compose.ts';
import {resolveQuintSpec} from './spec.ts';

export interface MbtAuditOptions {
  main?: string;
  invariant?: string;
  nTraces?: number;
  maxSteps?: number;
  maxSamples?: number;
  seed?: string;
  minCoverage?: number;
  outDir?: string;
  cliPath?: string;
  timeoutMs?: number;
}

export interface MbtAuditReport {
  file: string;
  module: string;
  modelIdentity?: string;
  tracesGenerated: number;
  totalTransitions: number;
  uniqueStates: number;
  declaredStepActions: string[];
  coveredActions: string[];
  uncoveredActions: string[];
  actionCounts: Record<string, number>;
  actionCoverage: number;
  minCoverage: number;
  passed: boolean;
  outDir?: string;
  traceFiles?: string[];
  manifestPath?: string;
}

export interface FleetOptions {
  domain?: string;
  subdomain?: string;
  verify?: boolean;
  mbtAudit?: boolean;
  minCoverage?: number;
  nTraces?: number;
  seed?: string;
  concurrency?: number;
  cliPath?: string;
  cacheDir?: string;
}

export interface FleetModelResult {
  file: string;
  modelIdentity?: string;
  passed: boolean;
  cached?: boolean;
  skipped?: boolean;
  skippedReason?: string;
  actionCoverage?: number;
  coveredActions?: number;
  declaredStepActions?: number;
  durationMs: number;
  output: string;
}

export interface FleetReport {
  root: string;
  verify: boolean;
  mbtAudit: boolean;
  concurrency: number;
  total: number;
  passed: number;
  cached?: number;
  skipped: number;
  failed: number;
  minActionCoverage?: number;
  avgActionCoverage?: number;
  durationMs: number;
  results: FleetModelResult[];
}

function collectActionRefs(ex: QuintEx, declaredActions: Set<string>, out: Set<string>): void {
  if (ex.kind === 'name') {
    if (declaredActions.has(ex.name)) {
      out.add(ex.name);
    }
    return;
  }
  if (ex.kind === 'app') {
    if (declaredActions.has(ex.opcode)) {
      out.add(ex.opcode);
    }
    for (const arg of ex.args) {
      collectActionRefs(arg, declaredActions, out);
    }
    return;
  }
  if (ex.kind === 'let') {
    collectActionRefs(ex.opdef.expr, declaredActions, out);
    collectActionRefs(ex.expr, declaredActions, out);
    return;
  }
  if (ex.kind === 'lambda') {
    collectActionRefs(ex.expr, declaredActions, out);
  }
}

export function extractDeclaredStepActions(mod: QuintModule, stepName: string = 'step'): string[] {
  const declaredActions = new Set<string>();
  let stepExpr: QuintEx | undefined;
  for (const decl of mod.declarations) {
    if (decl.kind === 'def' && decl.qualifier === 'action') {
      declaredActions.add(decl.name);
      if (decl.name === stepName) {
        stepExpr = decl.expr;
      }
    }
  }
  if (!stepExpr) return [];
  const referenced = new Set<string>();
  collectActionRefs(stepExpr, declaredActions, referenced);
  return [...referenced].sort();
}

function extractStepActionsWithImports(
  mod: QuintModule,
  filePath: string,
  stepName: string = 'step',
  visited: Set<string> = new Set(),
): string[] {
  const direct = extractDeclaredStepActions(mod, stepName);
  if (direct.length > 0) return direct;
  if (visited.has(filePath)) return [];
  visited.add(filePath);

  for (const decl of mod.declarations) {
    const isWildcardImport = decl.kind === 'import' && decl.defName === '*' && decl.fromSource;
    const isInstance = decl.kind === 'instance' && decl.fromSource;
    if (!isWildcardImport && !isInstance) continue;
    try {
      const target = resolveQuintSpec(decl.fromSource!, dirname(filePath));
      const targetSource = expandExtendedQntFile(target.fullPath).expandedText;
      const parsed = parsePhase1fromText(newIdGenerator(), targetSource, target.fullPath);
      const targetMod = parsed.modules.find(m => m.name === decl.protoName) ?? parsed.modules[0];
      if (!targetMod) continue;
      const nested = extractStepActionsWithImports(targetMod, target.fullPath, stepName, visited);
      if (nested.length > 0) return nested;
    } catch (err) {
      // Built-in / virtual Quint modules (e.g. basicSpells) have no local source file; continue searching other imports.
      if (!(err instanceof Error && err.message.startsWith('Could not resolve Quint module'))) {
        throw err;
      }
    }
  }
  return [];
}

function parseConstBindingPairs(constBindings: string): Array<{name: string; expr: string}> {
  return constBindings
    .split(',')
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => {
      const eq = part.indexOf('=');
      if (eq < 0) {
        throw new Error(`Invalid @verify const binding '${part}'; expected Name=Expr`);
      }
      return {name: part.slice(0, eq).trim(), expr: part.slice(eq + 1).trim()};
    });
}

export interface MbtEligibility {
  eligible: boolean;
  module: string;
  declaredStepActions: string[];
  reason?: 'no-step-action' | 'unbound-const';
}

export function inspectModuleMbtEligibility(qntPath: string, main?: string): MbtEligibility {
  const fullPath = resolve(process.cwd(), qntPath);
  const source = expandExtendedQntFile(fullPath).expandedText;
  const directives = parseQntHeaderDirectives(source);
  const parsed = parsePhase1fromText(newIdGenerator(), source, fullPath);
  if (parsed.errors.length > 0 || parsed.modules.length === 0) {
    throw new Error(`Failed to parse Quint module '${fullPath}' for MBT inspection`);
  }
  const mod = main ? parsed.modules.find(m => m.name === main) : parsed.modules[0];
  if (!mod) {
    throw new Error(`Module '${main}' not found in '${fullPath}'`);
  }
  const declaredStepActions = extractStepActionsWithImports(mod, fullPath, 'step');
  if (declaredStepActions.length === 0) {
    return {eligible: false, module: mod.name, declaredStepActions: [], reason: 'no-step-action'};
  }
  const hasConst = mod.declarations.some(d => d.kind === 'const');
  if (hasConst && !directives.verify?.constBindings) {
    return {eligible: false, module: mod.name, declaredStepActions, reason: 'unbound-const'};
  }
  return {eligible: true, module: mod.name, declaredStepActions};
}

export function auditMbtCoverage(qntPath: string, options: MbtAuditOptions = {}): MbtAuditReport {
  const fullPath = resolve(process.cwd(), qntPath);
  const source = expandExtendedQntFile(fullPath).expandedText;
  const directives = parseQntHeaderDirectives(source);
  const parsed = parsePhase1fromText(newIdGenerator(), source, fullPath);
  if (parsed.errors.length > 0 || parsed.modules.length === 0) {
    throw new Error(`Failed to parse Quint module '${fullPath}' for MBT audit`);
  }
  const mod = options.main
    ? parsed.modules.find(m => m.name === options.main)
    : parsed.modules[0];
  if (!mod) {
    throw new Error(`Module '${options.main}' not found in '${fullPath}'`);
  }

  const declaredStepActions = extractStepActionsWithImports(mod, fullPath, 'step');
  if (declaredStepActions.length === 0) {
    throw new Error(`Module '${mod.name}' in '${fullPath}' declares no step actions for MBT audit`);
  }
  const hasUnboundConst = mod.declarations.some(d => d.kind === 'const');
  if (hasUnboundConst && !directives.verify?.constBindings) {
    throw new Error(
      `Module '${mod.name}' in '${fullPath}' declares unbound const(s) without @verify const="..." bindings`,
    );
  }

  const nTraces = options.nTraces ?? 10;
  const maxSteps = options.maxSteps ?? directives.verify?.maxSteps ?? 12;
  const seed = options.seed ?? '7';
  const invariant = options.invariant ?? directives.verify?.invariant ?? 'safety';
  const minCoverage = options.minCoverage ?? 0.5;
  const cliPath = options.cliPath ?? resolve(dirname(new URL(import.meta.url).pathname), 'cli.ts');
  const timeoutMs = options.timeoutMs ?? 120_000;

  const tempDir = mkdtempSync(join(tmpdir(), 'qmr-mbt-audit-'));
  const absOutDir = options.outDir ? resolve(process.cwd(), options.outDir) : undefined;
  const traceDir = absOutDir ?? tempDir;

  try {
    if (absOutDir) {
      mkdirSync(absOutDir, {recursive: true});
      for (const existing of readdirSync(absOutDir)) {
        if (existing.endsWith('.itf.json') || existing === 'mbt-manifest.json') {
          rmSync(join(absOutDir, existing), {force: true});
        }
      }
    }

    let runTargetPath = fullPath;
    if (hasUnboundConst && directives.verify?.constBindings) {
      const pairs = parseConstBindingPairs(directives.verify.constBindings);
      const wrapperLines = [
        `// @quint-extends "${fullPath}"`,
        ...pairs.map(p => `// @quint-const ${p.name} = ${p.expr}`),
        `module ${mod.name} {}`,
        '',
      ];
      runTargetPath = join(tempDir, `${mod.name}__mbt_const_inst.qnt`);
      writeFileSync(runTargetPath, wrapperLines.join('\n'), 'utf8');
    }

    const outItf = join(traceDir, `${mod.name}.itf.json`);
    const cmdArgs = [
      'bun',
      cliPath,
      'run',
      runTargetPath,
      `--main=${mod.name}`,
      `--invariant=${invariant}`,
      '--mbt',
      `--n-traces=${nTraces}`,
      `--max-steps=${maxSteps}`,
      `--seed=${seed}`,
      `--out-itf=${outItf}`,
    ];
    if (options.maxSamples !== undefined) {
      cmdArgs.push(`--max-samples=${options.maxSamples}`);
    }
    const proc = Bun.spawnSync(cmdArgs, {
      cwd: process.cwd(),
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: timeoutMs,
    });
    if (proc.exitCode !== 0) {
      const output = proc.stdout.toString() + proc.stderr.toString();
      throw new Error(`MBT simulation failed for '${mod.name}' (exit ${proc.exitCode}):\n${output}`);
    }

    const itfFiles = readdirSync(traceDir)
      .filter(f => f.endsWith('.itf.json'))
      .sort()
      .map(f => join(traceDir, f));
    if (itfFiles.length === 0) {
      throw new Error(`MBT simulation for '${mod.name}' produced zero ITF traces`);
    }

    const declaredSet = new Set(declaredStepActions);
    const actionCounts: Record<string, number> = {};
    const stateDigests = new Set<string>();
    let totalTransitions = 0;

    for (const file of itfFiles) {
      const trace = JSON.parse(readFileSync(file, 'utf8')) as {
        states?: Array<Record<string, unknown>>;
      };
      const states = trace.states ?? [];
      for (let i = 0; i < states.length; i++) {
        const st = states[i]!;
        const domainState: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(st)) {
          if (!k.startsWith('mbt::') && k !== '#meta') {
            domainState[k] = v;
          }
        }
        stateDigests.add(JSON.stringify(domainState));
        if (i === 0) continue;
        totalTransitions++;
        const actionTaken = st['mbt::actionTaken'];
        if (typeof actionTaken === 'string' && actionTaken.length > 0) {
          const normalized =
            declaredSet.has(actionTaken)
              ? actionTaken
              : actionTaken.includes('::')
                ? actionTaken.split('::').pop()!
                : actionTaken;
          actionCounts[normalized] = (actionCounts[normalized] ?? 0) + 1;
        }
      }
    }

    const coveredActions = declaredStepActions.filter(a => (actionCounts[a] ?? 0) > 0);
    const uncoveredActions = declaredStepActions.filter(a => (actionCounts[a] ?? 0) === 0);
    const actionCoverage = declaredStepActions.length === 0
      ? 1
      : coveredActions.length / declaredStepActions.length;
    const passed = actionCoverage + 1e-9 >= minCoverage;

    const report: MbtAuditReport = {
      file: fullPath,
      module: mod.name,
      modelIdentity: directives.modelIdentity,
      tracesGenerated: itfFiles.length,
      totalTransitions,
      uniqueStates: stateDigests.size,
      declaredStepActions,
      coveredActions,
      uncoveredActions,
      actionCounts,
      actionCoverage,
      minCoverage,
      passed,
    };
    if (absOutDir) {
      const manifestPath = join(absOutDir, 'mbt-manifest.json');
      report.outDir = absOutDir;
      report.traceFiles = itfFiles;
      report.manifestPath = manifestPath;
      writeFileSync(manifestPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    }
    return report;
  } finally {
    rmSync(tempDir, {recursive: true, force: true});
  }
}

function walkQntUnder(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, {withFileTypes: true})) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...walkQntUnder(full));
    } else if (entry.name.endsWith('.qnt')) {
      found.push(full);
    }
  }
  return found.sort();
}

const FLEET_CAS_SCHEMA = 'qmr.fleet-cas.v1';
const MAX_FLEET_CAS_ENTRIES = 2048;

interface FleetCasEntry {
  actionKey: string;
  scopeKey: string;
  modeKey: string;
  cachedAt: string;
  modelIdentity?: string;
  skipped?: boolean;
  skippedReason?: string;
  actionCoverage?: number;
  coveredActions?: number;
  declaredStepActions?: number;
}

interface FleetCasStore {
  schema: string;
  entries: Record<string, FleetCasEntry>;
}

let cachedResolverEngineDigest: string | null = null;

function computeResolverEngineDigest(): string {
  if (cachedResolverEngineDigest !== null) return cachedResolverEngineDigest;
  const h = createHash('sha256');
  const srcDir = dirname(new URL(import.meta.url).pathname);
  const pkgRoot = resolve(srcDir, '..');
  let quintVersion = 'unknown';
  try {
    const req = createRequire(import.meta.url);
    const qPkg = JSON.parse(readFileSync(req.resolve('@informalsystems/quint/package.json'), 'utf8')) as {
      version?: string;
    };
    quintVersion = qPkg.version ?? 'unknown';
  } catch {
    quintVersion = 'unknown';
  }
  h.update(`schema:${FLEET_CAS_SCHEMA}\nquint:${quintVersion}\nbun:${Bun.version}\nplatform:${process.platform}:${process.arch}\n`);
  const pkgJsonPath = join(pkgRoot, 'package.json');
  if (existsSync(pkgJsonPath)) {
    h.update(`pkg:package.json\n`);
    h.update(readFileSync(pkgJsonPath));
    h.update('\n');
  }
  for (const name of readdirSync(srcDir).sort()) {
    if (!name.endsWith('.ts')) continue;
    const full = join(srcDir, name);
    if (statSync(full).isFile()) {
      h.update(`src:${name}\n`);
      h.update(readFileSync(full));
      h.update('\n');
    }
  }
  cachedResolverEngineDigest = h.digest('hex');
  return cachedResolverEngineDigest;
}

function collectTransitiveQntFiles(entryFile: string): {expandedText: string; files: string[]} {
  const visited = new Set<string>();
  const collected: string[] = [];
  let rootExpandedText = '';

  const walk = (filePath: string, isRoot: boolean) => {
    const abs = resolve(filePath);
    if (visited.has(abs)) return;
    visited.add(abs);
    collected.push(abs);
    const expanded = expandExtendedQntFile(abs);
    if (isRoot) rootExpandedText = expanded.expandedText;
    for (const parent of expanded.chain) {
      if (existsSync(parent)) walk(parent, false);
    }
    for (const m of expanded.expandedText.matchAll(/\bfrom\s+"([^"]+)"/g)) {
      const spec = m[1]!;
      try {
        const resolved = resolveQuintSpec(spec, dirname(abs));
        if (existsSync(resolved.fullPath)) walk(resolved.fullPath, false);
      } catch {
        // Built-in / virtual Quint modules (e.g. basicSpells) have no local source file.
      }
    }
  };

  walk(entryFile, true);
  collected.sort();
  return {expandedText: rootExpandedText, files: collected};
}

function computeFleetActionKey(
  file: string,
  relFile: string,
  engineDigest: string,
  flagsKey: string,
): string {
  const h = createHash('sha256');
  const {expandedText, files} = collectTransitiveQntFiles(file);
  h.update(`schema:${FLEET_CAS_SCHEMA}\nengine:${engineDigest}\nflags:${flagsKey}\nrel:${relFile}\n`);
  h.update(`expanded:\n${expandedText}\n`);
  for (const f of files) {
    h.update(`dep:${f}\n`);
    h.update(readFileSync(f));
    h.update('\n');
  }
  return h.digest('hex');
}

function loadFleetCasStore(cacheDir: string | undefined): FleetCasStore {
  if (!cacheDir) return {schema: FLEET_CAS_SCHEMA, entries: {}};
  const cachePath = resolve(process.cwd(), cacheDir, 'qmr-fleet-cas.v1.json');
  if (!existsSync(cachePath)) return {schema: FLEET_CAS_SCHEMA, entries: {}};
  try {
    const parsed = JSON.parse(readFileSync(cachePath, 'utf8')) as FleetCasStore;
    if (parsed.schema !== FLEET_CAS_SCHEMA || !parsed.entries) {
      return {schema: FLEET_CAS_SCHEMA, entries: {}};
    }
    return parsed;
  } catch {
    return {schema: FLEET_CAS_SCHEMA, entries: {}};
  }
}

function saveFleetCasStore(
  cacheDir: string | undefined,
  store: FleetCasStore,
  scopeKey: string,
  modeKey: string,
  activeKeys: Set<string>,
): void {
  if (!cacheDir) return;
  const absDir = resolve(process.cwd(), cacheDir);
  mkdirSync(absDir, {recursive: true});

  // Active-set GC (SM18): prune stale models removed from this (scopeKey, modeKey)
  // while preserving other modes in the same shard cache directory, capped at MAX_FLEET_CAS_ENTRIES.
  const kept = Object.entries(store.entries).filter(([k, v]) => {
    if (v.scopeKey === scopeKey && v.modeKey === modeKey) {
      return activeKeys.has(k);
    }
    return true;
  });
  kept.sort((a, b) => (b[1].cachedAt ?? '').localeCompare(a[1].cachedAt ?? ''));
  const bounded: Record<string, FleetCasEntry> = {};
  for (const [k, v] of kept.slice(0, MAX_FLEET_CAS_ENTRIES)) {
    bounded[k] = v;
  }

  const targetPath = join(absDir, 'qmr-fleet-cas.v1.json');
  const tmpPath = `${targetPath}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify({schema: FLEET_CAS_SCHEMA, entries: bounded}, null, 2)}\n`, 'utf8');
  renameSync(tmpPath, targetPath);
}

export async function runFleetPlans(rootDir: string, options: FleetOptions = {}): Promise<FleetReport> {
  const absRoot = resolve(process.cwd(), rootDir);
  const verify = options.verify ?? false;
  const mbtAudit = options.mbtAudit ?? false;
  // Apalache server binds localhost:8822 exclusively; serialize --verify to prevent port collisions.
  const concurrency = verify ? 1 : Math.max(1, options.concurrency ?? 4);
  const cliPath = options.cliPath ?? resolve(dirname(new URL(import.meta.url).pathname), 'cli.ts');
  const allowedSubdomains = options.subdomain
    ? new Set(options.subdomain.split(',').map(s => s.trim()).filter(Boolean))
    : null;

  const allFiles = walkQntUnder(absRoot).filter(file => {
    const rel = relative(absRoot, file).replaceAll('\\', '/');
    const parts = rel.split('/');
    if (options.domain && parts[0] !== options.domain && !parts.includes(options.domain)) return false;
    if (allowedSubdomains && !parts.some(p => allowedSubdomains.has(p))) return false;
    return true;
  });

  const modeKey = mbtAudit ? 'mbt-audit' : verify ? 'run-plan-verify' : 'run-plan';
  const scopeKey = `${options.domain ?? '*'}::${options.subdomain ?? '*'}`;
  const flagsKey = JSON.stringify({
    modeKey,
    verify,
    mbtAudit,
    minCoverage: mbtAudit ? (options.minCoverage ?? 0.75) : null,
    nTraces: mbtAudit ? (options.nTraces ?? 12) : null,
    seed: mbtAudit ? (options.seed ?? '7') : null,
  });
  const engineDigest = options.cacheDir ? computeResolverEngineDigest() : '';
  const casStore = loadFleetCasStore(options.cacheDir);
  const activeEntryKeys = new Set<string>();

  const startedAt = Date.now();
  const results: FleetModelResult[] = new Array(allFiles.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < allFiles.length) {
      const idx = cursor++;
      const file = allFiles[idx]!;
      const relFile = relative(absRoot, file).replaceAll('\\', '/');
      const directives = parseQntHeaderDirectives(readFileSync(file, 'utf8'));
      const t0 = Date.now();

      const entryKey = `${modeKey}:${relFile}`;
      activeEntryKeys.add(entryKey);
      const actionKey = options.cacheDir
        ? computeFleetActionKey(file, relFile, engineDigest, flagsKey)
        : '';

      if (options.cacheDir) {
        const hit = casStore.entries[entryKey];
        if (hit && hit.actionKey === actionKey) {
          results[idx] = {
            file: relFile,
            modelIdentity: hit.modelIdentity ?? directives.modelIdentity,
            passed: true,
            cached: true,
            skipped: hit.skipped,
            skippedReason: hit.skippedReason,
            actionCoverage: hit.actionCoverage,
            coveredActions: hit.coveredActions,
            declaredStepActions: hit.declaredStepActions,
            durationMs: 0,
            output: `CACHE-HIT (${actionKey.slice(0, 12)})`,
          };
          continue;
        }
      }

      if (mbtAudit) {
        const elig = inspectModuleMbtEligibility(file);
        if (!elig.eligible) {
          results[idx] = {
            file: relFile,
            modelIdentity: directives.modelIdentity,
            passed: true,
            skipped: true,
            skippedReason: elig.reason,
            durationMs: Date.now() - t0,
            output: `SKIPPED (${elig.reason})`,
          };
          if (options.cacheDir) {
            casStore.entries[entryKey] = {
              actionKey,
              scopeKey,
              modeKey,
              cachedAt: new Date().toISOString(),
              modelIdentity: directives.modelIdentity,
              skipped: true,
              skippedReason: elig.reason,
            };
          }
          continue;
        }
        const args = [
          'bun',
          cliPath,
          'mbt-audit',
          file,
          `--n-traces=${options.nTraces ?? 12}`,
          `--seed=${options.seed ?? '7'}`,
          `--min-coverage=${options.minCoverage ?? 0.75}`,
          '--json',
        ];
        const proc = Bun.spawn(args, {
          cwd: process.cwd(),
          stdout: 'pipe',
          stderr: 'pipe',
        });
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(proc.stdout).text(),
          new Response(proc.stderr).text(),
          proc.exited,
        ]);
        let parsedReport: MbtAuditReport | undefined;
        try {
          parsedReport = JSON.parse(stdout) as MbtAuditReport;
        } catch {
          parsedReport = undefined;
        }
        results[idx] = {
          file: relFile,
          modelIdentity: directives.modelIdentity,
          passed: exitCode === 0,
          actionCoverage: parsedReport?.actionCoverage,
          coveredActions: parsedReport?.coveredActions.length,
          declaredStepActions: parsedReport?.declaredStepActions.length,
          durationMs: Date.now() - t0,
          output: (stdout + stderr).trim(),
        };
        if (options.cacheDir && exitCode === 0) {
          casStore.entries[entryKey] = {
            actionKey,
            scopeKey,
            modeKey,
            cachedAt: new Date().toISOString(),
            modelIdentity: directives.modelIdentity,
            actionCoverage: parsedReport?.actionCoverage,
            coveredActions: parsedReport?.coveredActions.length,
            declaredStepActions: parsedReport?.declaredStepActions.length,
          };
        }
        continue;
      }

      const args = ['bun', cliPath, 'run-plan', file];
      if (verify) args.push('--verify');
      const proc = Bun.spawn(args, {
        cwd: process.cwd(),
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);
      results[idx] = {
        file: relFile,
        modelIdentity: directives.modelIdentity,
        passed: exitCode === 0,
        durationMs: Date.now() - t0,
        output: (stdout + stderr).trim(),
      };
      if (options.cacheDir && exitCode === 0) {
        casStore.entries[entryKey] = {
          actionKey,
          scopeKey,
          modeKey,
          cachedAt: new Date().toISOString(),
          modelIdentity: directives.modelIdentity,
        };
      }
    }
  }

  await Promise.all(
    Array.from({length: Math.min(concurrency, Math.max(1, allFiles.length))}, () => worker()),
  );

  if (options.cacheDir) {
    saveFleetCasStore(options.cacheDir, casStore, scopeKey, modeKey, activeEntryKeys);
  }

  const skipped = results.filter(r => r.skipped).length;
  const cached = results.filter(r => r.cached).length;
  const passed = results.filter(r => r.passed && !r.skipped).length;
  const failed = results.filter(r => !r.passed).length;
  const coverages = results
    .filter(r => typeof r.actionCoverage === 'number')
    .map(r => r.actionCoverage as number);
  const minActionCoverage = coverages.length > 0 ? Math.min(...coverages) : undefined;
  const avgActionCoverage =
    coverages.length > 0 ? coverages.reduce((a, b) => a + b, 0) / coverages.length : undefined;

  return {
    root: absRoot,
    verify,
    mbtAudit,
    concurrency,
    total: results.length,
    passed,
    cached,
    skipped,
    failed,
    minActionCoverage,
    avgActionCoverage,
    durationMs: Date.now() - startedAt,
    results,
  };
}
