// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileSourceResolver} from '@informalsystems/quint';
import {hasNodeModulesInAncestors, isBareSpecifier} from './spec.ts';
import {expandExtendedQntFile, hasExtendDirectives} from './compose.ts';

export {isBareSpecifier} from './spec.ts';

export type SourceResolver = ReturnType<typeof fileSourceResolver>;
export type SourceLookupPath = ReturnType<SourceResolver['lookupPath']>;

/**
 * Package-aware Quint SourceResolver with transparent single-parent `@quint-extends`
 * and `@quint-const` expansion:
 * - Relative and absolute imports delegate path lookup to Quint's native fileSourceResolver.
 * - Bare package specifiers resolve via Node's module resolution (node_modules + package exports).
 * - Loaded `.qnt` files declaring `@quint-extends` / `@quint-const` expand in memory via `composeQuintAst`.
 */
export function packageSourceResolver(
  sourceCode: Map<string, string> = new Map(),
  replacer: (path: string) => string = path => path,
): SourceResolver {
  const nativeResolver = fileSourceResolver(sourceCode, replacer);
  return {
    lookupPath(basepath: string, importPath: string): SourceLookupPath {
      if (!isBareSpecifier(importPath)) {
        return nativeResolver.lookupPath(basepath, importPath);
      }
      const candidates: string[] = [];
      if (process.env.QUINT_RESOLVE_ROOT) {
        candidates.push(resolve(process.env.QUINT_RESOLVE_ROOT, '_quint_importer_.qnt'));
      }
      if (hasNodeModulesInAncestors(basepath)) {
        candidates.push(resolve(basepath, '_quint_importer_.qnt'));
      }
      if (hasNodeModulesInAncestors(process.cwd())) {
        candidates.push(resolve(process.cwd(), '_quint_importer_.qnt'));
      }
      if (process.argv[1] && hasNodeModulesInAncestors(dirname(resolve(process.argv[1])))) {
        candidates.push(resolve(process.argv[1]));
      }
      candidates.push(import.meta.url);

      let target: string | undefined;
      let lastError: unknown;
      for (const anchor of candidates) {
        try {
          target = createRequire(anchor).resolve(importPath);
          break;
        } catch (err) {
          lastError = err;
        }
      }
      if (!target) {
        throw lastError;
      }
      return {
        normalizedPath: target,
        toSourceName: () => replacer(importPath),
      };
    },
    load(lookupPath: SourceLookupPath) {
      let raw: string | undefined;
      try {
        raw = readFileSync(lookupPath.normalizedPath, 'utf8');
      } catch {
        return nativeResolver.load(lookupPath);
      }
      if (hasExtendDirectives(raw)) {
        const expanded = expandExtendedQntFile(lookupPath.normalizedPath).expandedText;
        const loaded = nativeResolver.load(lookupPath);
        if (loaded.isRight()) {
          sourceCode.set(lookupPath.normalizedPath, expanded);
          return loaded.map(() => expanded);
        }
        return loaded;
      }
      return nativeResolver.load(lookupPath);
    },
    stempath(lookupPath: SourceLookupPath): string {
      return nativeResolver.stempath(lookupPath);
    },
  };
}
