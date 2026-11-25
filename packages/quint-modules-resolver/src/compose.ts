// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname, isAbsolute, relative, resolve} from 'node:path';
import {
  moduleToString,
  newIdGenerator,
  parsePhase1fromText,
  typeToString,
  type QuintApp,
  type QuintDeclaration,
  type QuintDef,
  type QuintEx,
  type QuintImport,
  type QuintModule,
  type QuintOpDef,
  type QuintTypeDef,
} from '@informalsystems/quint';
import {isBareSpecifier} from './resolver.ts';
import {type QuintPlan, verifyPlanReceipt} from './plan.ts';

export interface ResolvedBaseQnt {
  fullPath: string;
  packageName?: string;
  packageRoot?: string;
}

function findEnclosingPackage(filePath: string): {name: string; root: string} | undefined {
  let cur = dirname(filePath);
  while (true) {
    const pkgPath = resolve(cur, 'package.json');
    if (existsSync(pkgPath)) {
      try {
        const parsed = JSON.parse(readFileSync(pkgPath, 'utf8')) as {name?: string};
        if (parsed.name) {
          return {name: parsed.name, root: cur};
        }
      } catch {
        // Ignore malformed package.json while walking upward.
      }
    }
    const parent = dirname(cur);
    if (parent === cur) return undefined;
    cur = parent;
  }
}

export function resolveQuintSpec(spec: string, fromDir: string = process.cwd()): ResolvedBaseQnt {
  const candidates = spec.endsWith('.qnt') ? [spec] : [spec, `${spec}.qnt`];
  if (!isBareSpecifier(spec)) {
    for (const c of candidates) {
      const full = isAbsolute(c) ? c : resolve(fromDir, c);
      if (existsSync(full)) {
        const pkg = findEnclosingPackage(full);
        return {fullPath: full, packageName: pkg?.name, packageRoot: pkg?.root};
      }
    }
    throw new Error(`Could not resolve Quint module '${spec}' from '${fromDir}'`);
  }

  const anchors = [
    resolve(fromDir, '_quint_compose_.qnt'),
    resolve(process.cwd(), '_quint_compose_.qnt'),
  ];
  if (process.env.QUINT_RESOLVE_ROOT) {
    anchors.push(resolve(process.env.QUINT_RESOLVE_ROOT, '_quint_compose_.qnt'));
  }
  if (process.argv[1]) {
    anchors.push(resolve(process.argv[1]));
  }
  anchors.push(import.meta.url);

  let lastErr: unknown;
  for (const anchor of anchors) {
    const req = createRequire(anchor);
    for (const c of candidates) {
      try {
        const full = req.resolve(c);
        const pkg = findEnclosingPackage(full);
        return {fullPath: full, packageName: pkg?.name, packageRoot: pkg?.root};
      } catch (err) {
        lastErr = err;
      }
    }
  }
  throw lastErr ?? new Error(`Could not resolve bare Quint specifier '${spec}'`);
}

function parseSingleModule(filePath: string): QuintModule {
  const text = readFileSync(filePath, 'utf8');
  const idGen = newIdGenerator();
  const res = parsePhase1fromText(idGen, text, filePath);
  if (res.errors.length > 0) {
    const detail = res.errors.map(e => `${e.code}: ${e.message}`).join('; ');
    throw new Error(`Failed to parse Quint module '${filePath}': ${detail}`);
  }
  if (res.modules.length !== 1) {
    throw new Error(`Expected exactly 1 module in '${filePath}', found ${res.modules.length}`);
  }
  return res.modules[0]!;
}

function rewriteImportSource(imp: QuintImport, baseInfo: ResolvedBaseQnt): QuintImport {
  if (!imp.fromSource || isBareSpecifier(imp.fromSource)) {
    return imp;
  }
  const baseDir = dirname(baseInfo.fullPath);
  const targetNoExt = resolve(baseDir, imp.fromSource);
  if (baseInfo.packageName && baseInfo.packageRoot) {
    const rel = relative(baseInfo.packageRoot, targetNoExt).replaceAll('\\', '/');
    if (!rel.startsWith('..')) {
      return {...imp, fromSource: `${baseInfo.packageName}/${rel.replace(/\.qnt$/, '')}`};
    }
  }
  return {...imp, fromSource: targetNoExt.replace(/\.qnt$/, '')};
}

function mergeStateTypedef(baseTd: QuintTypeDef, overlayTd: QuintTypeDef): {merged: QuintTypeDef; addedFields: string[]} {
  if (!baseTd.type || baseTd.type.kind !== 'rec' || baseTd.type.fields.kind !== 'row') {
    throw new Error(`Base type 'State' must be a closed record type`);
  }
  if (!overlayTd.type || overlayTd.type.kind !== 'rec' || overlayTd.type.fields.kind !== 'row') {
    throw new Error(`Overlay type 'State' must be a closed record type`);
  }
  const fields = [...baseTd.type.fields.fields];
  const byName = new Map(fields.map(f => [f.fieldName, f]));
  const addedFields: string[] = [];

  for (const f of overlayTd.type.fields.fields) {
    const existing = byName.get(f.fieldName);
    if (existing) {
      const baseT = typeToString(existing.fieldType);
      const overT = typeToString(f.fieldType);
      if (baseT !== overT) {
        throw new Error(`State field '${f.fieldName}' type conflict: base has '${baseT}', overlay has '${overT}'`);
      }
    } else {
      fields.push(f);
      byName.set(f.fieldName, f);
      addedFields.push(f.fieldName);
    }
  }

  return {
    merged: {
      ...baseTd,
      type: {
        ...baseTd.type,
        fields: {...baseTd.type.fields, fields},
      },
    },
    addedFields,
  };
}

function extractInitRecordArgs(initDef: QuintOpDef, label: string): {target: QuintEx; recApp: QuintApp} {
  const expr = initDef.expr;
  if (expr.kind !== 'app' || expr.opcode !== 'assign' || expr.args.length !== 2) {
    throw new Error(`${label} 'init' must have the form "h' = { ... }"`);
  }
  const [target, rhs] = expr.args as [QuintEx, QuintEx];
  if (rhs.kind !== 'app' || rhs.opcode !== 'Rec' || rhs.args.length % 2 !== 0) {
    throw new Error(`${label} 'init' right-hand side must be a record literal`);
  }
  return {target, recApp: rhs};
}

function mergeInitDef(baseInit: QuintOpDef, overlayInit: QuintOpDef | undefined, addedFields: string[]): QuintOpDef {
  if (!overlayInit) {
    if (addedFields.length > 0) {
      throw new Error(`Overlay adds State field(s) [${addedFields.join(', ')}] but defines no 'action init'`);
    }
    return baseInit;
  }
  const baseRec = extractInitRecordArgs(baseInit, 'Base');
  const overRec = extractInitRecordArgs(overlayInit, 'Overlay');

  const pairs = new Map<string, [QuintEx, QuintEx]>();
  for (let i = 0; i < baseRec.recApp.args.length; i += 2) {
    const k = baseRec.recApp.args[i]!;
    const v = baseRec.recApp.args[i + 1]!;
    if (k.kind === 'str') pairs.set(k.value, [k, v]);
  }
  const overKeys = new Set<string>();
  for (let i = 0; i < overRec.recApp.args.length; i += 2) {
    const k = overRec.recApp.args[i]!;
    const v = overRec.recApp.args[i + 1]!;
    if (k.kind !== 'str') throw new Error(`Overlay 'init' record key must be a string literal`);
    overKeys.add(k.value);
    pairs.set(k.value, [k, v]);
  }
  for (const field of addedFields) {
    if (!overKeys.has(field)) {
      throw new Error(`Overlay adds State field '${field}' without initializing it in 'action init'`);
    }
  }

  const mergedArgs: QuintEx[] = [];
  for (const [k, v] of pairs.values()) {
    mergedArgs.push(k, v);
  }
  return {
    ...baseInit,
    expr: {
      id: baseInit.expr.id,
      kind: 'app',
      opcode: 'assign',
      args: [
        baseRec.target,
        {...baseRec.recApp, args: mergedArgs},
      ],
    },
  };
}

function mergeStepDef(baseStep: QuintOpDef, overlayStep: QuintOpDef): QuintOpDef {
  const baseBranches: QuintEx[] =
    baseStep.expr.kind === 'app' && baseStep.expr.opcode === 'actionAny'
      ? [...baseStep.expr.args]
      : [baseStep.expr];
  const overlayBranches: QuintEx[] =
    overlayStep.expr.kind === 'app' && overlayStep.expr.opcode === 'actionAny'
      ? [...overlayStep.expr.args]
      : [overlayStep.expr];
  return {
    ...baseStep,
    expr: {
      id: baseStep.expr.id,
      kind: 'app',
      opcode: 'actionAny',
      args: [...baseBranches, ...overlayBranches],
    },
  };
}

function mergeSafetyDef(baseSafety: QuintOpDef, overlaySafety: QuintOpDef): QuintOpDef {
  // Safety monotonicity: child may ONLY strengthen inherited safety via conjunction.
  return {
    ...baseSafety,
    expr: {
      id: baseSafety.expr.id,
      kind: 'app',
      opcode: 'and',
      args: [baseSafety.expr, overlaySafety.expr],
    },
  };
}

function declKey(d: QuintDeclaration): string | undefined {
  if (d.kind === 'def' || d.kind === 'typedef' || d.kind === 'var' || d.kind === 'const' || d.kind === 'assume') {
    return `${d.kind}:${d.name}`;
  }
  return undefined;
}

export function composeQuintAst(
  baseMod: QuintModule,
  overlayMod: QuintModule,
  baseInfo: ResolvedBaseQnt,
): QuintModule {
  const overImports: QuintImport[] = [];
  let overState: QuintTypeDef | undefined;
  let overInit: QuintOpDef | undefined;
  let overStep: QuintOpDef | undefined;
  let overSafety: QuintOpDef | undefined;
  const overMidDecls: QuintDeclaration[] = [];
  const overRunDecls: QuintDeclaration[] = [];

  for (const d of overlayMod.declarations) {
    if (d.kind === 'import') {
      overImports.push(d);
    } else if (d.kind === 'typedef' && d.name === 'State') {
      overState = d;
    } else if (d.kind === 'def' && d.name === 'init') {
      overInit = d;
    } else if (d.kind === 'def' && d.name === 'step') {
      overStep = d;
    } else if (d.kind === 'def' && d.name === 'safety') {
      overSafety = d;
    } else if (d.kind === 'def' && d.qualifier === 'run') {
      overRunDecls.push(d);
    } else {
      overMidDecls.push(d);
    }
  }

  // Check for accidental symbol collisions on non-mergeable declarations.
  const baseKeys = new Set<string>();
  for (const d of baseMod.declarations) {
    const k = declKey(d);
    if (k) baseKeys.add(k);
  }
  for (const d of [...overMidDecls, ...overRunDecls]) {
    const k = declKey(d);
    if (k && baseKeys.has(k)) {
      throw new Error(`Overlay redeclares non-mergeable symbol '${(d as QuintDef).name}' from base module '${baseMod.name}'`);
    }
  }

  const seenImports = new Set<string>();
  const finalImports: QuintImport[] = [];
  for (const d of baseMod.declarations) {
    if (d.kind === 'import') {
      const rw = rewriteImportSource(d, baseInfo);
      const sig = `${rw.protoName}:${rw.defName ?? '*'}:${rw.fromSource ?? ''}`;
      if (!seenImports.has(sig)) {
        seenImports.add(sig);
        finalImports.push(rw);
      }
    }
  }
  for (const imp of overImports) {
    const sig = `${imp.protoName}:${imp.defName ?? '*'}:${imp.fromSource ?? ''}`;
    if (!seenImports.has(sig)) {
      seenImports.add(sig);
      finalImports.push(imp);
    }
  }

  let addedFields: string[] = [];
  const mergedBody: QuintDeclaration[] = [];
  let insertedMid = false;

  for (const d of baseMod.declarations) {
    if (d.kind === 'import') continue;
    if (d.kind === 'typedef' && d.name === 'State' && overState) {
      const res = mergeStateTypedef(d, overState);
      addedFields = res.addedFields;
      mergedBody.push(res.merged);
      continue;
    }
    if (d.kind === 'def' && d.name === 'init') {
      mergedBody.push(mergeInitDef(d, overInit, addedFields));
      continue;
    }
    if (d.kind === 'def' && d.name === 'step') {
      mergedBody.push(...overMidDecls);
      insertedMid = true;
      mergedBody.push(overStep ? mergeStepDef(d, overStep) : d);
      continue;
    }
    if (d.kind === 'def' && d.name === 'safety' && overSafety) {
      mergedBody.push(mergeSafetyDef(d, overSafety));
      continue;
    }
    mergedBody.push(d);
  }

  if (!insertedMid) {
    mergedBody.push(...overMidDecls);
    if (overStep) mergedBody.push(overStep);
  }
  mergedBody.push(...overRunDecls);

  return {
    id: overlayMod.id,
    name: overlayMod.name,
    declarations: [...finalImports, ...mergedBody],
  };
}

export function emitPlanFromComposedAst(mod: QuintModule, fileName: string): QuintPlan {
  const hasRuns = mod.declarations.some(d => d.kind === 'def' && d.qualifier === 'run');
  const hasSafety = mod.declarations.some(d => d.kind === 'def' && d.name === 'safety');
  const hasStep = mod.declarations.some(d => d.kind === 'def' && d.name === 'step');

  const steps: QuintPlan['steps'] = [
    {label: 'typecheck', command: ['typecheck', fileName], expectedExit: 0, kind: 'typecheck'},
  ];
  if (hasRuns) {
    steps.push({
      label: 'traces',
      command: ['test', fileName, `--main=${mod.name}`, '--max-samples=1', '--seed=7', '--backend=typescript'],
      expectedExit: 0,
      kind: 'deterministic-traces',
    });
  }
  if (hasSafety && hasStep) {
    steps.push({
      label: 'safety',
      command: ['verify', fileName, `--main=${mod.name}`, '--invariant=safety', '--max-steps=12'],
      expectedExit: 0,
      kind: 'bounded-safety',
    });
  }
  return {
    module: mod.name,
    file: fileName,
    quintVersion: '0.33.0',
    apalacheVersion: '0.62.1',
    seed: 7,
    positiveDepth: 12,
    negativeDepth: 6,
    timeout: 120,
    steps,
  };
}

export function composeQuintFiles(
  baseSpecOrPath: string,
  overlayQntPath: string,
  outQntPath: string,
  outPlanPath?: string,
): QuintModule {
  const baseInfo = resolveQuintSpec(baseSpecOrPath, process.cwd());
  const baseDir = dirname(baseInfo.fullPath);
  if (existsSync(resolve(baseDir, 'receipt.json'))) {
    verifyPlanReceipt(baseDir);
  }

  const baseMod = parseSingleModule(baseInfo.fullPath);
  const overlayMod = parseSingleModule(resolve(process.cwd(), overlayQntPath));
  const composed = composeQuintAst(baseMod, overlayMod, baseInfo);

  // REUSE-IgnoreStart
  const header = [
    '// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors',
    '// SPDX-License-Identifier: LGPL-2.1-or-later',
    `// Structurally composed via quint-modules-resolver AST from '${baseMod.name}' + '${overlayMod.name}'. Do not edit by hand.`,
  ].join('\n');
  // REUSE-IgnoreEnd

  const emitted = `${header}\n${moduleToString(composed)}\n`;

  // Verify the structurally emitted Quint parses cleanly with zero errors before writing.
  const verifyParse = parsePhase1fromText(newIdGenerator(), emitted, outQntPath);
  if (verifyParse.errors.length > 0) {
    const detail = verifyParse.errors.map(e => `${e.code}: ${e.message}`).join('; ');
    throw new Error(`Internal compose error: emitted Quint failed phase-1 parse: ${detail}`);
  }

  mkdirSync(dirname(resolve(outQntPath)), {recursive: true});
  writeFileSync(outQntPath, emitted, 'utf8');

  if (outPlanPath) {
    const fileName = resolve(outQntPath).split('/').pop()!;
    const plan = emitPlanFromComposedAst(composed, fileName);
    mkdirSync(dirname(resolve(outPlanPath)), {recursive: true});
    writeFileSync(outPlanPath, JSON.stringify(plan, null, 2) + '\n', 'utf8');
  }
  return composed;
}
