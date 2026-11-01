import { createHash } from 'node:crypto';
import path from 'node:path';
import { defaultTheme, extendTheme, type RenderTheme } from '../theme';
import { validatePurposeKind, type Presentation, type SourceCatalog, type ViewSelection } from './types';

export type { ViewSelection } from './types';
export interface CatalogInput {
  readonly sources: Readonly<Record<string, string>>;
  readonly views: readonly ViewSelection[];
  readonly presentation: Presentation;
  readonly theme?: RenderTheme;
}
export const digest = (bytes: string | Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
export function relativeSource(source: string): void {
  if (!source || source.split('/').some(part => !part || part === '.' || part === '..') || source.includes('\\') || source.startsWith('/') || source.startsWith('../') || path.posix.normalize(source) !== source)
    throw new Error(`Expected a normalized repository-relative source: ${source}`);
}
/** Capture text supplied by the repository owner; no directory discovery or writes. */
export function createCatalog(input: CatalogInput): SourceCatalog {
  if (input.theme?.render.ascii) throw new Error('Image rendering requires native SVG output');
  if (!input.presentation.project.trim()) throw new Error('Project label is required');
  const fs: Record<string, string> = {};
  for (const source of Object.keys(input.sources).sort()) {
    relativeSource(source);
    if (!source.endsWith('.d2')) throw new Error(`Expected a D2 source: ${source}`);
    const text = input.sources[source];
    if (typeof text !== 'string') throw new Error(`Expected source text: ${source}`);
    fs[source] = text;
  }
  const seen = new Set<string>();
  const views = input.views.map(view => {
    relativeSource(view.source);
    if (seen.has(view.source)) throw new Error(`Duplicate view: ${view.source}`);
    seen.add(view.source);
    validatePurposeKind(view.purpose, view.kind);
    if (!view.question?.ref.trim() || !view.question.text.trim() || !view.basis?.captureRef.trim())
      throw new Error('A question and existing project capture reference are required');
    for (const references of [view.basis.modelRefs, view.basis.obligationRefs, view.basis.evidenceRefs]) {
      if (!Array.isArray(references) || references.some(reference => !reference.trim())) throw new Error('Invalid basis references');
    }
    if (!view.title.trim()) throw new Error(`View title is required: ${view.source}`);
    const text = fs[view.source];
    if (text === undefined) throw new Error(`Missing view source: ${view.source}`);
    return { ...view, question: Object.freeze({ ...view.question }), basis: Object.freeze({
      ...view.basis, modelRefs: Object.freeze([...view.basis.modelRefs]),
      obligationRefs: Object.freeze([...view.basis.obligationRefs]), evidenceRefs: Object.freeze([...view.basis.evidenceRefs]),
    }), id: view.source, sha256: digest(text) };
  }).sort((a, b) => a.source.localeCompare(b.source));
  if (!views.length) throw new Error('At least one view is required');
  return Object.freeze({
    views: Object.freeze(views.map(view => Object.freeze(view))), fs: Object.freeze(fs),
    theme: extendTheme(input.theme ?? defaultTheme),
    presentation: Object.freeze({ ...input.presentation }),
  });
}
export function catalogDigest(catalog: SourceCatalog): string { return digest(JSON.stringify(catalog)); }
