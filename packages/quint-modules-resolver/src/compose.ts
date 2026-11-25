// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname, isAbsolute, resolve} from 'node:path';
import {isBareSpecifier} from './resolver.ts';
import {type QuintPlan, verifyPlanReceipt} from './plan.ts';

export interface CountermodelIR {
  identity: string;
  droppedGuard: string;
  stepAction: string;
  counterAction: string;
  expectedItfPredicate: string;
}

export interface PrototypeIR {
  schemaVersion: number;
  identity: string;
  module: string;
  file: string;
  domainDir: string;
  imports: [string, string][];
  parameters: [string, string][];
  state: [string, string, string?][];
  guards: [string, string][];
  transitions: [string, string][];
  safety: string;
  traces: [string, string][];
  countermodels: CountermodelIR[];
  limits: string;
}

export interface PrototypeOverlay {
  extends: string;
  identity?: string;
  module: string;
  file?: string;
  addImports?: [string, string][];
  addParameters?: [string, string][];
  addState?: [string, string, string][];
  addGuards?: [string, string][];
  addTransitions?: [string, string][];
  addStepActions?: string[];
  strengthenSafety?: string;
  addTraces?: [string, string][];
  addCountermodels?: CountermodelIR[];
  limits?: string;
}

function resolvePrototypeSpec(spec: string, fromDir: string): string {
  if (!isBareSpecifier(spec)) {
    return isAbsolute(spec) ? spec : resolve(fromDir, spec);
  }
  const anchors = [
    resolve(fromDir, '_quint_proto_.json'),
    resolve(process.cwd(), '_quint_proto_.json'),
  ];
  if (process.env.QUINT_RESOLVE_ROOT) {
    anchors.push(resolve(process.env.QUINT_RESOLVE_ROOT, '_quint_proto_.json'));
  }
  if (process.argv[1]) {
    anchors.push(resolve(process.argv[1]));
  }
  anchors.push(import.meta.url);
  let lastErr: unknown;
  for (const anchor of anchors) {
    try {
      return createRequire(anchor).resolve(spec);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

export function loadPrototype(specOrPath: string, fromDir: string = process.cwd()): PrototypeIR {
  const fullPath = resolvePrototypeSpec(specOrPath, fromDir);
  const dir = dirname(fullPath);
  if (existsSync(resolve(dir, 'receipt.json'))) {
    verifyPlanReceipt(dir);
  }
  const raw = JSON.parse(readFileSync(fullPath, 'utf8')) as PrototypeIR | PrototypeOverlay;
  if ('extends' in raw && typeof raw.extends === 'string') {
    const base = loadPrototype(raw.extends, dir);
    return composePrototype(base, raw);
  }
  validatePrototype(raw as PrototypeIR);
  return raw as PrototypeIR;
}

export function validatePrototype(proto: PrototypeIR): void {
  if (!proto.module || !proto.identity) {
    throw new Error('Prototype IR requires non-empty identity and module');
  }
  const guardIds = new Set(proto.guards.map(([id]) => id));
  for (const cm of proto.countermodels) {
    if (!guardIds.has(cm.droppedGuard)) {
      throw new Error(
        `Prototype '${proto.identity}' countermodel '${cm.identity}' references undeclared droppedGuard '${cm.droppedGuard}'`,
      );
    }
  }
}

export function composePrototype(base: PrototypeIR, overlay: PrototypeOverlay): PrototypeIR {
  const stateMap = new Map<string, [string, string, string?]>();
  for (const row of base.state) stateMap.set(row[0], row);
  for (const row of overlay.addState ?? []) {
    const existing = stateMap.get(row[0]);
    if (existing && existing[1] !== row[1]) {
      throw new Error(`State field '${row[0]}' type conflict: ${existing[1]} vs ${row[1]}`);
    }
    stateMap.set(row[0], row);
  }

  const guards = [...base.guards, ...(overlay.addGuards ?? [])];
  const imports = [...base.imports, ...(overlay.addImports ?? [])];
  const parameters = [...base.parameters, ...(overlay.addParameters ?? [])];
  const traces = [...base.traces, ...(overlay.addTraces ?? [])];
  const countermodels = [...base.countermodels, ...(overlay.addCountermodels ?? [])];

  // Insert new transitions before 'step' and optionally extend 'step = any { ... }'.
  const transitions: [string, string][] = [];
  let stepRow: [string, string] | undefined;
  for (const tr of base.transitions) {
    if (tr[0] === 'step') {
      stepRow = tr;
    } else {
      transitions.push(tr);
    }
  }
  for (const tr of overlay.addTransitions ?? []) {
    if (tr[0] === 'step') {
      stepRow = tr;
    } else {
      transitions.push(tr);
    }
  }
  if (stepRow) {
    let stepCode = stepRow[1];
    if (overlay.addStepActions && overlay.addStepActions.length > 0) {
      const idx = stepCode.lastIndexOf('}');
      if (idx < 0) throw new Error(`Cannot extend step action: ${stepCode}`);
      stepCode = `${stepCode.slice(0, idx).trimEnd()}, ${overlay.addStepActions.join(', ')} }`;
    }
    transitions.push(['step', stepCode]);
  }

  // Safety monotonicity: child may ONLY strengthen inherited safety via conjunction.
  const safety = overlay.strengthenSafety
    ? `(${base.safety}) and (${overlay.strengthenSafety})`
    : base.safety;

  const composed: PrototypeIR = {
    schemaVersion: 1,
    identity: overlay.identity ?? `${base.identity}.${overlay.module}`,
    module: overlay.module,
    file: overlay.file ?? `${overlay.module}.qnt`,
    domainDir: base.domainDir,
    imports,
    parameters,
    state: [...stateMap.values()],
    guards,
    transitions,
    safety,
    traces,
    countermodels,
    limits: overlay.limits ?? base.limits,
  };
  validatePrototype(composed);
  return composed;
}

export function emitQuintFromPrototype(proto: PrototypeIR): string {
  // REUSE-IgnoreStart
  const lines: string[] = [
    '// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors',
    '// SPDX-License-Identifier: LGPL-2.1-or-later',
    `// Composed via quint-modules-resolver POO prototype '${proto.identity}'. Do not edit by hand.`,
    `// Limits: ${proto.limits}`,
    `module ${proto.module} {`,
  ];
  // REUSE-IgnoreEnd
  for (const [mod, spec] of proto.imports) {
    lines.push(`  import ${mod}.* from "${spec}"`);
  }
  for (const [name, typ] of proto.parameters) {
    lines.push(`  const ${name}: ${typ}`);
  }
  const hasStateRecord = proto.state.length > 0 && proto.state[0]!.length === 3;
  if (hasStateRecord) {
    const typeFields = proto.state.map(([k, t]) => `${k}: ${t}`).join(', ');
    const initFields = proto.state.map(([k, , init]) => `${k}: ${init}`).join(', ');
    lines.push(`  type State = { ${typeFields} }`);
    lines.push('  var h: State');
    lines.push(`  action init = h' = { ${initFields} }`);
  }
  for (const [, code] of proto.transitions) {
    lines.push(`  ${code}`);
  }
  if (hasStateRecord) {
    lines.push(`  val safety = ${proto.safety}`);
  }
  for (const cm of proto.countermodels) {
    lines.push(`  // Countermodel ${cm.identity} (dropped guard: ${cm.droppedGuard})`);
    lines.push(`  ${cm.counterAction}`);
  }
  for (const [, code] of proto.traces) {
    lines.push(`  ${code}`);
  }
  lines.push('}', '');
  return lines.join('\n');
}

export function emitPlanFromPrototype(proto: PrototypeIR, fileName: string): QuintPlan {
  const steps: QuintPlan['steps'] = [
    {label: 'typecheck', command: ['typecheck', fileName], expectedExit: 0, kind: 'typecheck'},
  ];
  if (proto.traces.length > 0) {
    steps.push({
      label: 'traces',
      command: ['test', fileName, `--main=${proto.module}`, '--max-samples=1', '--seed=7', '--backend=typescript'],
      expectedExit: 0,
      kind: 'deterministic-traces',
    });
  }
  if (proto.state.length > 0 && proto.state[0]!.length === 3) {
    steps.push({
      label: 'safety',
      command: ['verify', fileName, `--main=${proto.module}`, '--invariant=safety', '--max-steps=12'],
      expectedExit: 0,
      kind: 'bounded-safety',
    });
  }
  for (const cm of proto.countermodels) {
    steps.push({
      label: `countermodel-${cm.droppedGuard}`,
      command: [
        'verify',
        fileName,
        `--main=${proto.module}`,
        `--step=${cm.stepAction}`,
        '--invariant=safety',
        '--max-steps=6',
      ],
      expectedExit: 1,
      kind: 'required-countermodel',
      droppedGuard: cm.droppedGuard,
      expectedItfPredicate: cm.expectedItfPredicate,
    });
  }
  return {
    module: proto.module,
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

export function composeToFiles(overlayPath: string, outQntPath: string, outPlanPath?: string): PrototypeIR {
  const proto = loadPrototype(overlayPath, process.cwd());
  const qntText = emitQuintFromPrototype(proto);
  mkdirSync(dirname(resolve(outQntPath)), {recursive: true});
  writeFileSync(outQntPath, qntText, 'utf8');
  if (outPlanPath) {
    const fileName = resolve(outQntPath).split('/').pop()!;
    const plan = emitPlanFromPrototype(proto, fileName);
    mkdirSync(dirname(resolve(outPlanPath)), {recursive: true});
    writeFileSync(outPlanPath, JSON.stringify(plan, null, 2) + '\n', 'utf8');
  }
  return proto;
}
