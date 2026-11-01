import type { Connection, RenderedView, RenderSpan } from '@openmbee/opensysml';
import { digest } from './source/catalog';
import type { ViewSelection } from './source/catalog';

export type OpenSysMLRenderOptions = Parameters<Connection['renderView']>[2];
export interface OpenSysMLCapture {
  readonly modelHash: string;
  readonly requestedView: string;
  readonly rendering: RenderedView;
}
export interface SysMLProjection {
  readonly selection: ViewSelection;
  readonly layout: 'reflow';
  readonly roles?: Readonly<Record<string, string>>;
}
export interface ModelNodeTrace { readonly id: string; readonly d2Id: string; readonly parent: string; readonly origin?: RenderSpan; }
export interface ModelEdgeTrace { readonly index: number; readonly from: string; readonly to: string; readonly kind: string; readonly origin?: RenderSpan; }
export interface SysMLProjectionResult {
  readonly source: string;
  readonly text: string;
  readonly view: ViewSelection;
  readonly trace: {
    readonly modelHash: string; readonly requestedView: string; readonly resolvedView: string;
    readonly renderingSHA256: string; readonly capturedRenderingJSON: string;
    readonly nodes: readonly ModelNodeTrace[]; readonly edges: readonly ModelEdgeTrace[];
  };
}
/** Effect adapter: use the SDK's capability/error/lifecycle implementation unchanged. */
export async function captureOpenSysMLView(
  connection: Pick<Connection, 'renderView'>, modelHash: string, viewName: string, options?: OpenSysMLRenderOptions,
): Promise<OpenSysMLCapture> {
  if (!modelHash.trim() || !viewName.trim()) throw new Error('Model hash and view name are required');
  const rendering = await connection.renderView(modelHash, viewName, options);
  // Decouple the selected SDK result from subsequent mutation by the caller.
  return Object.freeze({ modelHash, requestedView: viewName, rendering: structuredClone(rendering) });
}
/** Pure projection of the SDK's rendering, not a SysML parser or validator. */
export function projectOpenSysMLView(capture: OpenSysMLCapture, profile: SysMLProjection): SysMLProjectionResult {
  if (!capture.modelHash.trim() || !capture.requestedView.trim()) throw new Error('Model/view binding is required');
  if (profile.layout !== 'reflow') throw new Error('D2 projection requires explicit reflow');
  const rendering = capture.rendering;
  if (!rendering.view) throw new Error('SDK rendering has no resolved view');
  if (rendering.columns.length || rendering.rows.length || rendering.notes.length)
    throw new Error('Table/notes notation is not supported by this D2 projection');
  const nodes = [...rendering.nodes].sort((a, b) => a.id.localeCompare(b.id));
  const byId = new Map(nodes.map(node => [node.id, node]));
  if (!nodes.length || byId.size !== nodes.length || nodes.some(node => !node.id)) throw new Error('Empty or duplicate SDK node identity');
  if (nodes.some(node => node.ports.length || node.compartment || node.standIn || node.geometry?.collapsed))
    throw new Error('Ports, compartment rows, stand-ins and collapsed nodes need a supported notation adapter');
  for (const id of Object.keys(profile.roles ?? {})) {
    if (!byId.has(id)) throw new Error(`Role selection references a missing SDK node: ${id}`);
  }
  for (const node of nodes) {
    const seen = new Set<string>([node.id]);
    let owner = node.parent;
    while (owner) {
      if (!byId.has(owner)) throw new Error(`Missing SDK owner: ${owner}`);
      if (seen.has(owner)) throw new Error(`Cyclic SDK ownership: ${node.id}`);
      seen.add(owner);
      owner = byId.get(owner)!.parent;
    }
  }
  for (const edge of rendering.edges) {
    if (!byId.has(edge.from) || !byId.has(edge.to)) throw new Error('Missing SDK edge endpoint');
    if (edge.fromPort || edge.toPort) throw new Error('Port edges need a supported notation adapter');
  }
  const aliases = new Map(nodes.map((node, index) => [node.id, `n${index}`]));
  const fullId = (id: string): string => {
    const node = byId.get(id)!;
    return node.parent ? `${fullId(node.parent)}.${aliases.get(id)!}` : aliases.get(id)!;
  };
  const capturedRenderingJSON = JSON.stringify({ modelHash: capture.modelHash, requestedView: capture.requestedView, rendering });
  const renderingSHA256 = digest(capturedRenderingJSON);
  const lines = [`# OpenSysML rendering SHA256: ${renderingSHA256}`, '# Explicit D2 reflow; source model semantics remain with OpenSysML.'];
  const emit = (parent: string, depth: number) => {
    for (const node of nodes.filter(node => node.parent === parent)) {
      const pad = '  '.repeat(depth);
      const label = [node.name, node.type, node.detail, node.text].filter(Boolean).join('\n');
      lines.push(`${pad}${aliases.get(node.id)!}: {`, `${pad}  label: ${JSON.stringify(label || node.id)}`);
      const role = profile.roles?.[node.id];
      if (role && !/^[A-Za-z_][A-Za-z0-9_-]*$/.test(role)) throw new Error('Expected a D2 class identifier');
      if (role) lines.push(`${pad}  class: ${role}`);
      emit(node.id, depth + 1);
      lines.push(`${pad}}`);
    }
  };
  emit('', 0);
  for (const edge of rendering.edges) {
    lines.push(`${fullId(edge.from)} -> ${fullId(edge.to)}: ${JSON.stringify(edge.label || edge.name || edge.kind)}`);
  }
  return {
    source: profile.selection.source, text: lines.join('\n') + '\n', view: { ...profile.selection },
    trace: {
      modelHash: capture.modelHash, requestedView: capture.requestedView, resolvedView: rendering.view,
      renderingSHA256, capturedRenderingJSON,
      nodes: nodes.map(node => ({ id: node.id, d2Id: fullId(node.id), parent: node.parent, ...(node.origin ? { origin: { ...node.origin } } : {}) })),
      edges: rendering.edges.map((edge, index) => ({ index, from: edge.from, to: edge.to, kind: edge.kind, ...(edge.origin ? { origin: { ...edge.origin } } : {}) })),
    },
  };
}
