import { parentPort, workerData } from 'node:worker_threads';
import { D2 } from '@terrastruct/d2';
import { readD2Figure } from './d2-figure';
import type { FigureInput } from './figure';
import { renderView, type RenderedView, type RenderEffects } from './pipeline';
import type { SourceCatalog } from './source/types';

export type RenderResponse = { index: number; image: RenderedView } | { index: number; error: string };
export interface FigureRequest { readonly resources?: import('./d2-figure').FigureResources; readonly kind: 'figure'; readonly fs: Readonly<Record<string, string>>; readonly inputPath: string; }
export type FigureResponse = { readonly figure: FigureInput } | { readonly error: string };
const input = workerData as SourceCatalog | FigureRequest;
const engine = new D2();
if ('kind' in input) {
  try {
    const compiled = await engine.compile({fs: {...input.fs}, inputPath: input.inputPath, options: {}});
    parentPort?.postMessage({figure: readD2Figure({data: compiled.graph.data as unknown, diagram: compiled.diagram, inputPath: compiled.inputPath, fs: compiled.fs}, input.fs, input.resources)} satisfies FigureResponse);
  } catch (error: unknown) { parentPort?.postMessage({error: error instanceof Error ? error.message : String(error)} satisfies FigureResponse); }
} else {
const catalog = input;
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

}
