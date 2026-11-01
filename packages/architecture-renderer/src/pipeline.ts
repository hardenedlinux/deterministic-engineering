import type { CompileResponse } from '@terrastruct/d2';
import { digest } from './source/catalog';
import type { SourceCatalog, ViewEntry } from './source/types';

export interface RenderedView {
  readonly source: string; readonly purpose: ViewEntry['purpose']; readonly kind: ViewEntry['kind'];
  readonly question: ViewEntry['question']; readonly basis: ViewEntry['basis'];
  readonly nodeIds: readonly string[]; readonly edgeIds: readonly string[];
  readonly sourceSHA256: string; readonly svg: string;
  readonly svgSHA256: string;
  readonly nodes: number; readonly edges: number;
}
/** Official D2 owns its complete diagram; TS composes effects without redrawing it. */
export interface RenderEffects {
  readonly compile: (catalog: SourceCatalog, view: ViewEntry) => Promise<CompileResponse>;
  readonly svg: (compiled: CompileResponse) => Promise<string>;
}
export async function renderView(catalog: SourceCatalog, view: ViewEntry, effects: RenderEffects): Promise<RenderedView> {
  const selected = catalog.views.find(candidate => candidate.source === view.source);
  if (!selected || JSON.stringify(selected) !== JSON.stringify(view))
    throw new Error('View is not part of the captured catalog');
  const compiled = await effects.compile(catalog, selected);
  if (compiled.inputPath !== selected.source) throw new Error('Compile effect replaced the captured source');
  const svg = await effects.svg(compiled);
  return {
    question: selected.question, basis: selected.basis,
    nodeIds: compiled.diagram.shapes.map(node => node.id), edgeIds: compiled.diagram.connections.map(edge => edge.id),
    source: view.source, purpose: view.purpose, kind: view.kind, sourceSHA256: view.sha256, svg,
    svgSHA256: digest(svg),
    nodes: compiled.diagram.shapes.length, edges: compiled.diagram.connections.length,
  };
}
