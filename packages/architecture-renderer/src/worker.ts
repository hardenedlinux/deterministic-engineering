import { parentPort, workerData } from 'node:worker_threads';
import { D2 } from '@terrastruct/d2';
import { renderView, type RenderedView, type RenderEffects } from './pipeline';
import type { SourceCatalog } from './source/types';

export type RenderResponse = { index: number; image: RenderedView } | { index: number; error: string };
const catalog = workerData as SourceCatalog;
const engine = new D2();
const effects: RenderEffects = {
  compile: (input, view) => engine.compile({ fs: { ...input.fs }, inputPath: view.source,
    options: { ...input.theme.compile, ...input.theme.render },
  }),
  svg: compiled => engine.render(compiled.diagram, compiled.renderOptions),

};
if (!parentPort) throw new Error('Renderer requires an owned worker port');
parentPort.on('message', async ({ index }: { index: number }) => {
  try {
    const view = catalog.views[index];
    if (!view) throw new Error(`Unknown view index: ${index}`);
    parentPort?.postMessage({ index, image: await renderView(catalog, view, effects) } satisfies RenderResponse);
  } catch (error: unknown) {
    parentPort?.postMessage({ index, error: error instanceof Error ? error.message : String(error) } satisfies RenderResponse);
  }
});
