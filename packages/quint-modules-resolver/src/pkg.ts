// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {existsSync, readdirSync, readFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {verifyPlanReceipt} from './plan.ts';

export interface InstalledQuintModel {
  packageName: string;
  packageVersion: string;
  modelIdentity: string;
  bareSpecifier: string;
  modelDir: string;
  quintVersion: string;
}

function walkReceipts(dir: string): string[] {
  const found: string[] = [];
  if (!existsSync(dir)) return found;
  for (const entry of readdirSync(dir, {withFileTypes: true})) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...walkReceipts(full));
    } else if (entry.name === 'receipt.json') {
      found.push(full);
    }
  }
  return found.sort();
}

function collectPackageDirs(nodeModulesDir: string): string[] {
  const pkgs: string[] = [];
  if (!existsSync(nodeModulesDir)) return pkgs;
  for (const entry of readdirSync(nodeModulesDir, {withFileTypes: true})) {
    if (entry.name.startsWith('.')) continue;
    const full = join(nodeModulesDir, entry.name);
    if (entry.name.startsWith('@') && (entry.isDirectory() || entry.isSymbolicLink())) {
      for (const sub of readdirSync(full, {withFileTypes: true})) {
        pkgs.push(join(full, sub.name));
      }
    } else if (entry.isDirectory() || entry.isSymbolicLink()) {
      pkgs.push(full);
    }
  }
  return pkgs.sort();
}

export function discoverInstalledQuintModels(projectRoot: string = process.cwd()): InstalledQuintModel[] {
  const nm = resolve(projectRoot, 'node_modules');
  const results: InstalledQuintModel[] = [];
  for (const pkgDir of collectPackageDirs(nm)) {
    const pkgJsonPath = join(pkgDir, 'package.json');
    if (!existsSync(pkgJsonPath)) continue;
    const pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf8')) as {name?: string; version?: string};
    if (!pkgJson.name) continue;
    for (const receiptPath of walkReceipts(pkgDir)) {
      const modelDir = dirname(receiptPath);
      const receipt = JSON.parse(readFileSync(receiptPath, 'utf8')) as {
        modelIdentity?: string;
        quintVersion?: string;
        artifacts?: Record<string, string>;
      };
      if (!receipt.modelIdentity || !receipt.artifacts) continue;
      const qntFile = Object.keys(receipt.artifacts).find(k => k.endsWith('.qnt'));
      if (!qntFile) continue;
      const relDir = relative(pkgDir, modelDir).replaceAll('\\', '/');
      const bareBase = `${pkgJson.name}/${relDir}`;
      results.push({
        packageName: pkgJson.name,
        packageVersion: pkgJson.version ?? '0.0.0',
        modelIdentity: receipt.modelIdentity,
        bareSpecifier: `${bareBase}/${qntFile.replace(/\.qnt$/, '')}`,
        modelDir,
        quintVersion: receipt.quintVersion ?? 'unknown',
      });
    }
  }
  return results;
}

export function verifyInstalledQuintPackages(
  projectRoot: string = process.cwd(),
  expectedQuintVersion?: string,
): {verified: number; models: InstalledQuintModel[]} {
  const models = discoverInstalledQuintModels(projectRoot);
  for (const m of models) {
    verifyPlanReceipt(m.modelDir);
    if (expectedQuintVersion && m.quintVersion !== expectedQuintVersion) {
      throw new Error(
        `Quint version mismatch in ${m.bareSpecifier}: package expects ${m.quintVersion}, installed ${expectedQuintVersion}`,
      );
    }
  }
  return {verified: models.length, models};
}
