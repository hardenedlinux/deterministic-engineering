// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {existsSync, readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname, isAbsolute, resolve} from 'node:path';

export interface ResolvedQuintFile {
  fullPath: string;
  packageName?: string;
  packageRoot?: string;
}

export function isBareSpecifier(specifier: string): boolean {
  return specifier.length > 0 && !specifier.startsWith('.') && !isAbsolute(specifier);
}

export function findEnclosingPackage(filePath: string): {name: string; root: string} | undefined {
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

export function hasNodeModulesInAncestors(startDir: string): boolean {
  let cur = startDir;
  while (true) {
    if (existsSync(resolve(cur, 'node_modules'))) return true;
    const parent = dirname(cur);
    if (parent === cur) return false;
    cur = parent;
  }
}

export function resolveQuintSpec(spec: string, fromDir: string = process.cwd()): ResolvedQuintFile {
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

  const anchors: string[] = [];
  if (process.env.QUINT_RESOLVE_ROOT) {
    anchors.push(resolve(process.env.QUINT_RESOLVE_ROOT, '_quint_resolver_.qnt'));
  }
  if (hasNodeModulesInAncestors(fromDir)) {
    anchors.push(resolve(fromDir, '_quint_resolver_.qnt'));
  }
  if (hasNodeModulesInAncestors(process.cwd())) {
    anchors.push(resolve(process.cwd(), '_quint_resolver_.qnt'));
  }
  if (process.argv[1] && hasNodeModulesInAncestors(dirname(resolve(process.argv[1])))) {
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
