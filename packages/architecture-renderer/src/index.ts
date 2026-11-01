import { Worker } from 'node:worker_threads';
import { createCatalog, catalogDigest, type CatalogInput } from './source/catalog';
import type { RenderResponse } from './worker';
import type { RenderedView } from './pipeline';
export { createCatalog, catalogDigest } from './source/catalog';
export type { CatalogInput, ViewSelection } from './source/catalog';
export type { ViewKind, Presentation, QuestionRef, ViewBasis } from './source/types';
export { renderView } from './pipeline';
export type { RenderedView, RenderEffects } from './pipeline';
export type { SourceCatalog, ViewEntry } from './source/types';
export interface RenderOptions { readonly workers?: 1 | 2; }
export interface RenderResult { readonly inputSHA256: string; readonly workers: number; readonly images: readonly RenderedView[]; }

/** Render a captured input. Publication and source revalidation belong to the caller. */
export async function renderCatalog(input: CatalogInput, options: RenderOptions = {}): Promise<RenderResult> {
  const configured = options.workers ?? 2;
  if (configured !== 1 && configured !== 2) throw new Error('Renderer supports one or two workers');
  const catalog = createCatalog(input);
  const count = Math.min(configured, catalog.views.length);
  const workers: Worker[] = [];
  const images: RenderedView[] = [];
  const errors: Error[] = [];
  let cursor = 0;
  try {
    await Promise.all(Array.from({ length: count }, () => new Promise<void>((resolve, reject) => {
      const worker = new Worker(new URL('./worker.ts', import.meta.url), { workerData: catalog });
      workers.push(worker);
      let finished = false;
      const next = () => {
        const index = cursor++;
        if (index >= catalog.views.length) { finished = true; resolve(); }
        else worker.postMessage({ index });
      };
      worker.on('error', reject);
      worker.on('exit', code => { if (!finished) reject(new Error(`Renderer worker exited before completion: ${code}`)); });
      worker.on('message', (message: RenderResponse) => {
        if ('error' in message) errors.push(new Error(`${catalog.views[message.index]?.source}: ${message.error}`));
        else images.push(message.image);
        next();
      });
      next();
    })));
  } finally {
    await Promise.all(workers.map(worker => worker.terminate()));
  }
  if (errors.length) throw new AggregateError(errors, 'D2 rendering failed; no result was published');
  if (images.length !== catalog.views.length) throw new Error('Incomplete renderer result');
  return { inputSHA256: catalogDigest(catalog), workers: count, images: images.sort((a, b) => a.source.localeCompare(b.source)) };
}
export { standardThemes } from './themes';

export { defaultTheme, extendTheme } from './theme';
export type { RenderTheme, ThemeOverrides } from './theme';

export { composePresentation } from './presentation';
export type { PresentationInput, PresentedView, Explanation, StatementStatus } from './presentation';
