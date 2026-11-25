#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {basename, dirname, resolve} from 'node:path';
import {
  fileSourceResolver,
  newIdGenerator,
  parsePhase1fromText,
  parsePhase2sourceResolution,
  parsePhase3importAndNameResolution,
  parsePhase4toposort,
} from '@informalsystems/quint';
import {packageSourceResolver} from './resolver.ts';
import {executePlan} from './plan.ts';
import {composeQuintFiles} from './compose.ts';
import {discoverInstalledQuintModels, verifyInstalledQuintPackages} from './pkg.ts';

const req = createRequire(import.meta.url);
const quintPkg = req.resolve('@informalsystems/quint/package.json');
const quintReq = createRequire(quintPkg);
const cliCommands = quintReq('./dist/src/cliCommands.js');
const cliHelpers = quintReq('./dist/src/cliHelpers.js');
const apalache = quintReq('./dist/src/apalache.js');
const {version: quintVersion} = quintReq('./dist/src/version.js');
const {left, right} = quintReq('@sweet-monads/either');
const {just, none} = quintReq('@sweet-monads/maybe');

interface ParsedArgs {
  command: string;
  input: string;
  main?: string;
  seed?: string;
  maxSamples?: number;
  maxSteps?: number;
  invariant?: string;
  invariants?: string[];
  inductiveInvariant?: string;
  step?: string;
  init?: string;
  backend?: string;
  verbosity: number;
  out?: string;
  outItf?: string;
  match?: string;
  apalacheVersion?: string;
  apalacheConfig?: string;
  tlcConfig?: string;
  randomTransitions?: boolean;
  serverEndpoint?: {hostname: string; port: number};
}

function parseCliArgs(argv: string[]): ParsedArgs {
  if (argv[0] === '--version' || argv[0] === '-v') {
    console.log(quintVersion);
    process.exit(0);
  }
  const [command, input, ...rest] = argv;
  if (!command || !input) {
    console.error('Usage: quint-modules-resolver <parse|typecheck|test|verify> <input.qnt> [options]');
    process.exit(2);
  }
  const args: ParsedArgs = {command, input, verbosity: 2};
  let rawServerEndpoint = 'localhost:8822';
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!;
    const eq = token.indexOf('=');
    const key = eq >= 0 ? token.slice(0, eq) : token;
    const val = eq >= 0 ? token.slice(eq + 1) : rest[++i];
    switch (key) {
      case '--main': args.main = val; break;
      case '--seed': args.seed = val; break;
      case '--max-samples': args.maxSamples = Number(val); break;
      case '--max-steps': args.maxSteps = Number(val); break;
      case '--invariant': args.invariant = val; break;
      case '--invariants':
        args.invariants = [...(args.invariants ?? []), ...(val ? val.split(',').filter(Boolean) : [])];
        break;
      case '--inductive-invariant': args.inductiveInvariant = val; break;
      case '--step': args.step = val; break;
      case '--init': args.init = val; break;
      case '--backend': args.backend = val; break;
      case '--verbosity': args.verbosity = Number(val); break;
      case '--out': args.out = val; break;
      case '--out-itf': args.outItf = val; break;
      case '--match': args.match = val; break;
      case '--apalache-version': args.apalacheVersion = val; break;
      case '--apalache-config': args.apalacheConfig = val; break;
      case '--tlc-config': args.tlcConfig = val; break;
      case '--random-transitions': args.randomTransitions = val !== 'false'; break;
      case '--server-endpoint': rawServerEndpoint = val ?? rawServerEndpoint; break;
      default:
        console.error(`Unknown option: ${token}`);
        process.exit(2);
    }
  }
  if (command === 'test' && args.maxSamples === undefined) {
    args.maxSamples = args.seed !== undefined ? 1 : 10000;
  }
  if (command === 'verify') {
    args.init ??= 'init';
    args.step ??= 'step';
    args.invariants ??= [];
    args.maxSteps ??= 10;
    args.randomTransitions ??= false;
    args.backend ??= 'apalache';
    args.apalacheVersion ??= apalache.DEFAULT_APALACHE_VERSION_TAG;
    const parsedEndpoint = apalache.parseServerEndpoint(rawServerEndpoint);
    if (parsedEndpoint.isLeft()) {
      console.error(parsedEndpoint.value);
      process.exit(2);
    }
    args.serverEndpoint = parsedEndpoint.value;
  }
  return args;
}

async function parseWithPackages(args: ParsedArgs) {
  const fullPath = resolve(process.cwd(), args.input);
  let text: string;
  try {
    text = readFileSync(fullPath, 'utf8');
  } catch (err) {
    return left({
      msg: `file ${args.input} could not be opened due to ${String(err)}`,
      stage: {stage: 'loading', args, errors: [], sourceCode: new Map()},
    });
  }
  const sourceCode = new Map([[fullPath, text]]);
  const idGen = newIdGenerator();
  const phase1 = parsePhase1fromText(idGen, text, fullPath);
  const defaultModuleName = phase1.modules.length === 1 ? just(phase1.modules[0]!.name) : none();
  const resolver = packageSourceResolver(sourceCode);
  const mainLookup = fileSourceResolver(sourceCode).lookupPath(dirname(fullPath), basename(fullPath));
  const phase2 = parsePhase2sourceResolution(idGen, resolver, mainLookup, phase1);
  const phase3 = parsePhase3importAndNameResolution(phase2);
  const phase4 = parsePhase4toposort(phase3);
  const stage = {stage: 'parsing', args, path: fullPath, sourceCode, warnings: [], ...phase4, defaultModuleName, idGen};
  if (phase4.errors.length > 0) {
    const errors = phase4.errors.map(cliHelpers.mkErrorMessage(phase4.sourceMap));
    return left({msg: 'parsing failed', stage: {...stage, errors}});
  }
  return right(stage);
}

export async function runCli(argv: string[]) {
  if (argv[0] === 'list') {
    const models = discoverInstalledQuintModels(process.cwd());
    if (argv.includes('--json')) {
      console.log(JSON.stringify(models, null, 2));
    } else {
      for (const m of models) {
        console.log(`${m.bareSpecifier} (${m.modelIdentity}, quint@${m.quintVersion})`);
      }
      console.log(`Total: ${models.length} installed Quint model(s)`);
    }
    return;
  }
  if (argv[0] === 'verify-deps') {
    const res = verifyInstalledQuintPackages(process.cwd(), quintVersion);
    console.log(`DEPS-OK verified ${res.verified} installed Quint model(s) (quint@${quintVersion})`);
    return;
  }
  if (argv[0] === 'compose') {
    const baseSpec = argv[1];
    const overlayPath = argv[2];
    let outQnt: string | undefined;
    let outPlan: string | undefined;
    for (let i = 3; i < argv.length; i++) {
      const tok = argv[i]!;
      const eq = tok.indexOf('=');
      const key = eq >= 0 ? tok.slice(0, eq) : tok;
      const val = eq >= 0 ? tok.slice(eq + 1) : argv[++i];
      if (key === '--out') outQnt = val;
      else if (key === '--plan') outPlan = val;
    }
    if (!baseSpec || !overlayPath || !outQnt) {
      console.error('Usage: quint-modules-resolver compose <base.qnt|bare-spec> <overlay.qnt> --out <Derived.qnt> [--plan <plan.json>]');
      process.exit(2);
    }
    const mod = composeQuintFiles(baseSpec, overlayPath, outQnt, outPlan);
    console.log(`COMPOSE-OK ${mod.name} -> ${outQnt}${outPlan ? ` (+ ${outPlan})` : ''}`);
    return;
  }
  if (argv[0] === 'run-plan') {
    const planPath = argv[1];
    if (!planPath) {
      console.error('Usage: quint-modules-resolver run-plan <plan.json> [--verify]');
      process.exit(2);
    }
    const verify = argv.includes('--verify');
    const summary = executePlan(planPath, {verify});
    console.log(`PLAN-OK ${planPath} (passed=${summary.passed}, skipped=${summary.skipped}, verify=${verify})`);
    return;
  }
  const args = parseCliArgs(argv);
  let result = await parseWithPackages(args);
  if (args.command === 'typecheck' || args.command === 'test' || args.command === 'verify') {
    result = await result.asyncChain(cliCommands.typecheck);
  }
  if (args.command === 'test') {
    result = await result.asyncChain(cliCommands.runTests);
  } else if (args.command === 'verify') {
    result = await result.asyncChain(cliCommands.compile);
    result = await result.asyncChain(cliCommands.verifySpec);
  } else if (args.command !== 'parse' && args.command !== 'typecheck') {
    console.error(`Unsupported command: ${args.command}`);
    process.exit(2);
  }
  cliCommands.outputResult(result);
}

if (import.meta.main) {
  await runCli(process.argv.slice(2));
}
