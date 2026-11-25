// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {createRequire} from 'node:module';
import {isAbsolute, resolve} from 'node:path';
import {fileSourceResolver} from '@informalsystems/quint';

export type SourceResolver = ReturnType<typeof fileSourceResolver>;
export type SourceLookupPath = ReturnType<SourceResolver['lookupPath']>;

export function isBareSpecifier(specifier: string): boolean {
  return specifier.length > 0 && !specifier.startsWith('.') && !isAbsolute(specifier);
}

/**
 * Package-aware Quint SourceResolver.
 * Relative and absolute imports delegate directly to Quint's native fileSourceResolver.
 * Bare package specifiers resolve via Node's module resolution (node_modules + package exports).
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
      const importer = resolve(basepath, '_quint_importer_.qnt');
      let target: string;
      try {
        target = createRequire(importer).resolve(importPath);
      } catch {
        target = createRequire(resolve(process.cwd(), '_quint_importer_.qnt')).resolve(importPath);
      }
      return {
        normalizedPath: target,
        toSourceName: () => replacer(importPath),
      };
    },
    load(lookupPath: SourceLookupPath) {
      return nativeResolver.load(lookupPath);
    },
    stempath(lookupPath: SourceLookupPath): string {
      return nativeResolver.stempath(lookupPath);
    },
  };
}
