// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {mkdirSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, relative, resolve} from 'node:path';
import {
  moduleToString,
  newIdGenerator,
  parsePhase1fromText,
  typeToString,
  type QuintApp,
  type QuintConst,
  type QuintDeclaration,
  type QuintDef,
  type QuintEx,
  type QuintImport,
  type QuintModule,
  type QuintOpDef,
  type QuintTypeDef,
} from '@informalsystems/quint';
import {isBareSpecifier, resolveQuintSpec, type ResolvedQuintFile} from './spec.ts';
import {type QuintPlan} from './plan.ts';

export type ResolvedBaseQnt = ResolvedQuintFile;
export {resolveQuintSpec} from './spec.ts';

export interface ExtendDirectives {
  modelIdentity?: string;
  quintVersion?: string;
  apalacheVersion?: string;
  extendsSpecs: string[];
  constBindings: Array<{name: string; exprText: string}>;
  verify?: {invariant: string; maxSteps: number; constBindings?: string};
  countermodels: Array<{
    droppedGuard: string;
    stepAction: string;
    maxSteps: number;
    expectedItfPredicate: string;
  }>;
  limits?: string;
}

export interface ExpandedQntResult {
  isExtended: boolean;
  expandedText: string;
  module: QuintModule;
  chain: string[];
}

export function parseExtendDirectives(source: string): ExtendDirectives {
  const result: ExtendDirectives = {
    extendsSpecs: [],
    constBindings: [],
    countermodels: [],
  };
  for (const rawLine of source.split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('//')) {
      if (line.startsWith('module ')) break;
      continue;
    }
    const modelMatch = line.match(/^\/\/\s*@quint-model\s+(\S+)/);
    if (modelMatch) {
      result.modelIdentity = modelMatch[1];
      continue;
    }
    const verMatch = line.match(/^\/\/\s*@quint-version\s+(\S+)/);
    if (verMatch) {
      result.quintVersion = verMatch[1];
      continue;
    }
    const apaMatch = line.match(/^\/\/\s*@apalache-version\s+(\S+)/);
    if (apaMatch) {
      result.apalacheVersion = apaMatch[1];
      continue;
    }
    const limitsMatch = line.match(/^\/\/\s*Limits:\s*(.+)$/);
    if (limitsMatch) {
      result.limits = limitsMatch[1]!.trim();
      continue;
    }
    const verifyMatch = line.match(
      /^\/\/\s*@verify\s+(\S+)(?:\s+max-steps=(\d+))?(?:\s+const="([^"]+)")?/,
    );
    if (verifyMatch) {
      result.verify = {
        invariant: verifyMatch[1]!,
        maxSteps: verifyMatch[2] ? Number(verifyMatch[2]) : 12,
        constBindings: verifyMatch[3],
      };
      continue;
    }
    const cmMatch = line.match(
      /^\/\/\s*@countermodel\s+(\S+)\s+step=(\S+)(?:\s+max-steps=(\d+))?(?:\s+itf="([^"]*)")?/,
    );
    if (cmMatch) {
      result.countermodels.push({
        droppedGuard: cmMatch[1]!,
        stepAction: cmMatch[2]!,
        maxSteps: cmMatch[3] ? Number(cmMatch[3]) : 6,
        expectedItfPredicate: cmMatch[4] ?? '',
      });
      continue;
    }
    const extMatch =
      line.match(/^\/\/\s*@quint-extends\s+"([^"]+)"/) ??
      line.match(/^\/\/\s*@quint-extends\s+(\S+)/);
    if (extMatch) {
      result.extendsSpecs.push(extMatch[1]!);
      continue;
    }
    const constMatch = line.match(/^\/\/\s*@quint-const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
    if (constMatch) {
      result.constBindings.push({name: constMatch[1]!, exprText: constMatch[2]!.trim()});
    }
  }
  return result;
}

export function hasExtendDirectives(source: string): boolean {
  const d = parseExtendDirectives(source);
  return d.extendsSpecs.length > 0 || d.constBindings.length > 0;
}

function parseSingleModuleText(text: string, filePath: string): QuintModule {
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

function parseSingleModule(filePath: string): QuintModule {
  return parseSingleModuleText(readFileSync(filePath, 'utf8'), filePath);
}

function parseQuintExpr(exprText: string, label: string): QuintEx {
  const mod = parseSingleModuleText(`module __const_expr__ {\n  val __v__ = ${exprText}\n}\n`, `<${label}>`);
  const decl = mod.declarations[0];
  if (!decl || decl.kind !== 'def') {
    throw new Error(`Failed to parse Quint expression for ${label}: ${exprText}`);
  }
  return decl.expr;
}

function bindConstsInModule(
  mod: QuintModule,
  bindings: Array<{name: string; exprText: string}>,
): QuintModule {
  if (bindings.length === 0) return mod;
  const decls = [...mod.declarations];
  for (const b of bindings) {
    const idx = decls.findIndex(d => d.kind === 'const' && d.name === b.name);
    if (idx < 0) {
      throw new Error(
        `Module '${mod.name}' binds @quint-const '${b.name}', which is not a declared const`,
      );
    }
    const constDecl = decls[idx] as QuintConst;
    const pureValDecl: QuintOpDef = {
      id: constDecl.id,
      kind: 'def',
      qualifier: 'pureval',
      name: constDecl.name,
      typeAnnotation: constDecl.typeAnnotation,
      expr: parseQuintExpr(b.exprText, `@quint-const ${b.name}`),
    };
    decls[idx] = pureValDecl;
  }
  return {...mod, declarations: decls};
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

/**
 * Transparently expands single-parent `// @quint-extends` chains and `// @quint-const`
 * bindings by reusing `composeQuintAst`. Ordinary `.qnt` files pass through unchanged.
 */
export function expandExtendedQntFile(qntPath: string): ExpandedQntResult {
  const absPath = resolve(process.cwd(), qntPath);
  const rawRoot = readFileSync(absPath, 'utf8');
  if (!hasExtendDirectives(rawRoot)) {
    const mod = parseSingleModuleText(rawRoot, absPath);
    return {isExtended: false, expandedText: rawRoot, module: mod, chain: [mod.name]};
  }

  interface ChainNode {
    fileInfo: ResolvedBaseQnt;
    directives: ExtendDirectives;
    module: QuintModule;
  }

  const visited = new Set<string>();
  const chainNodes: ChainNode[] = [];
  let curInfo = resolveQuintSpec(absPath, process.cwd());

  while (true) {
    const canonical = realpathSync(curInfo.fullPath);
    if (visited.has(canonical)) {
      const names = [...chainNodes.map(n => n.module.name), canonical];
      throw new Error(`Cycle detected in @quint-extends chain: ${names.join(' -> ')}`);
    }
    visited.add(canonical);
    const text = readFileSync(canonical, 'utf8');
    const directives = parseExtendDirectives(text);
    if (directives.extendsSpecs.length > 1) {
      throw new Error(
        `Module '${canonical}' declares ${directives.extendsSpecs.length} @quint-extends parents; only single-parent extension is supported (use Scheme POO for multi-prototype composition)`,
      );
    }
    const mod = parseSingleModuleText(text, canonical);
    chainNodes.push({fileInfo: {...curInfo, fullPath: canonical}, directives, module: mod});
    if (directives.extendsSpecs.length === 0) break;
    curInfo = resolveQuintSpec(directives.extendsSpecs[0]!, dirname(canonical));
  }

  // Apply from base -> derived using composeQuintAst.
  const ordered = [...chainNodes].reverse();
  let composed = bindConstsInModule(ordered[0]!.module, ordered[0]!.directives.constBindings);
  let quintVersion = ordered[0]!.directives.quintVersion ?? '0.33.0';
  let apalacheVersion = ordered[0]!.directives.apalacheVersion ?? '0.62.1';
  let verifyHeader = ordered[0]!.directives.verify;
  const countermodels = [...ordered[0]!.directives.countermodels];
  const limitsParts: string[] = [];
  if (ordered[0]!.directives.limits) {
    limitsParts.push(`${ordered[0]!.module.name}: ${ordered[0]!.directives.limits}`);
  }

  for (let i = 1; i < ordered.length; i++) {
    const parentNode = ordered[i - 1]!;
    const childNode = ordered[i]!;
    composed = composeQuintAst(composed, childNode.module, parentNode.fileInfo);
    composed = bindConstsInModule(composed, childNode.directives.constBindings);
    if (childNode.directives.quintVersion) quintVersion = childNode.directives.quintVersion;
    if (childNode.directives.apalacheVersion) apalacheVersion = childNode.directives.apalacheVersion;
    if (childNode.directives.verify) verifyHeader = childNode.directives.verify;
    if (childNode.directives.limits) {
      limitsParts.push(`${childNode.module.name}: ${childNode.directives.limits}`);
    }
    for (const cm of childNode.directives.countermodels) {
      const dup = countermodels.some(
        existing => existing.droppedGuard === cm.droppedGuard && existing.stepAction === cm.stepAction,
      );
      if (!dup) countermodels.push(cm);
    }
  }

  const rootNode = chainNodes[0]!;
  const chainNames = chainNodes.map(n => n.module.name);
  // REUSE-IgnoreStart
  const headerLines: string[] = [
    '// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors',
    '// SPDX-License-Identifier: LGPL-2.1-or-later',
  ];
  // REUSE-IgnoreEnd
  if (rootNode.directives.modelIdentity) {
    headerLines.push(`// @quint-model ${rootNode.directives.modelIdentity}`);
  }
  headerLines.push(`// @quint-version ${quintVersion}`);
  headerLines.push(`// @apalache-version ${apalacheVersion}`);
  headerLines.push(`// Extended from: ${chainNames.join(' -> ')}`);

  const hasRemainingConst = composed.declarations.some(d => d.kind === 'const');
  if (verifyHeader) {
    const constSuffix =
      hasRemainingConst && verifyHeader.constBindings ? ` const="${verifyHeader.constBindings}"` : '';
    headerLines.push(`// @verify ${verifyHeader.invariant} max-steps=${verifyHeader.maxSteps}${constSuffix}`);
  } else if (
    composed.declarations.some(d => d.kind === 'def' && d.name === 'safety') &&
    composed.declarations.some(d => d.kind === 'def' && d.name === 'step')
  ) {
    headerLines.push('// @verify safety max-steps=12');
  }
  for (const cm of countermodels) {
    headerLines.push(
      `// @countermodel ${cm.droppedGuard} step=${cm.stepAction} max-steps=${cm.maxSteps} itf="${cm.expectedItfPredicate}"`,
    );
  }
  if (limitsParts.length > 0) {
    headerLines.push(`// Limits: ${limitsParts.join(' | ')}`);
  }

  const expandedText = `${headerLines.join('\n')}\n${moduleToString(composed)}\n`;
  const verifyParse = parsePhase1fromText(newIdGenerator(), expandedText, absPath);
  if (verifyParse.errors.length > 0) {
    const detail = verifyParse.errors.map(e => `${e.code}: ${e.message}`).join('; ');
    throw new Error(`Internal extend expansion error for '${absPath}': ${detail}`);
  }
  return {isExtended: true, expandedText, module: composed, chain: chainNames};
}

export function writeExpandedQntFile(inputQntPath: string, outQntPath: string): ExpandedQntResult {
  const expanded = expandExtendedQntFile(inputQntPath);
  const absOut = resolve(process.cwd(), outQntPath);
  mkdirSync(dirname(absOut), {recursive: true});
  writeFileSync(absOut, expanded.expandedText, 'utf8');
  return expanded;
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
