import { readFileSync } from 'node:fs';
import { viewKinds } from './source/types';
/** Packaged presentation sources, mounted at a stable virtual D2 path. */
export function standardThemes(): Record<string, string> {
  return Object.fromEntries(['base', ...viewKinds].map(name => [
    `architecture/themes/${name}.d2`,
    readFileSync(new URL(`../themes/${name}.d2`, import.meta.url), 'utf8'),
  ]));
}
