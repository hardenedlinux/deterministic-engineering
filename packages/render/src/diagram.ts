import type {ElkNode} from 'elkjs/lib/elk-api';
import type {FigureContext, FigureComposition, FigureModel} from './figure';
import {digest} from './source/catalog';
export interface DiagramSpec {
  readonly graph: ElkNode;
  readonly icons?: Readonly<Record<string,string>>;
  readonly edgeLabels?: boolean;
  readonly roles?: Readonly<Record<string,string>>;
}
export type DiagramNodeComposer = (node: FigureModel['subjects'][number], context: FigureContext) => string;
const defaultNode: DiagramNodeComposer = (node, {text}) => `<text class="scene-node-text">${(node.label ?? node.id).split('\n').map((line,index) => `<tspan class="${index ? 'scene-detail' : 'scene-title'}" x="0" dy="${index ? '1.45em' : '0'}">${text(line)}</tspan>`).join('')}</text>`;
/** Project declares the native ELK graph projection; labels/relations stay in the captured model. */
export function composeDiagram(context: FigureContext, specification: DiagramSpec, nodeComposer: DiagramNodeComposer = defaultNode): FigureComposition {
  const graph = structuredClone(specification.graph), model = context.model;
  graph.layoutOptions = {...context.theme.layoutOptions, ...graph.layoutOptions};
  if (!model || !graph || typeof graph.id !== 'string' || !Array.isArray(graph.children)) throw new Error('Diagram needs a captured model and declared graph');
  const seen = new Set<string>([graph.id]), leaves = new Set<string>();
  const routing = graph.layoutOptions?.['elk.edgeRouting'];
  if (routing && !['ORTHOGONAL', 'POLYLINE'].includes(routing)) throw new Error('Unsupported SVG edge routing: ' + routing);
  const bodies: string[] = [];
  const walk = (node: ElkNode) => {
    if (node.ports?.length || node.edges?.length) throw new Error('Ports and nested edge containers need a dedicated SVG compositor');
    if (typeof node.id !== 'string' || seen.has(node.id)) throw new Error('Duplicate or missing diagram node'); seen.add(node.id);
    const subject = model.subjects.find(subject => subject.id === node.id);
    if (!subject) throw new Error(`Undeclared diagram node: ${node.id}`);
    const group = node.children !== undefined;
    if (group && !Array.isArray(node.children)) throw new Error('Invalid diagram children');
    const icon = specification.icons?.[node.id];
    const role = specification.roles?.[node.id] ?? 'default';
    const surface = context.theme.surfaces?.[role] ?? context.theme.surfaces?.['default'];
    if (surface && (!surface.svg.trim().startsWith('<svg') || !surface.label.trim())) throw new Error('Invalid declared scene surface');
    const content = group ? `<text class="scene-group-title">${context.text(subject.label ?? subject.id)}</text>` : nodeComposer(subject, context);
    bodies.push(`<g data-scene-node="${context.text(node.id)}" data-scene-group="${group}" data-role="${context.text(role)}"><rect class="scene-frame"${surface ? ' opacity="0" data-custom-surface' : ''}/>${surface ? `<g class="scene-surface">${surface.svg}</g>` : ''}<g class="scene-content">${icon ? `<g class="scene-glyph">${context.glyph(icon)}</g>` : ''}<g class="scene-copy" transform="translate(${icon ? 44 : 0} 18)">${content}</g></g></g>`);
    if (group) node.children!.forEach(walk); else leaves.add(node.id);
  };
  graph.children.forEach(walk);
  const relations = model.relations.filter(edge => leaves.has(edge.src) && leaves.has(edge.dst));
  const edgeIDs = new Set<string>();
  if (graph.edges) for (const edge of graph.edges) {
    if (edgeIDs.has(edge.id)) throw new Error('Duplicate diagram relation');
    edgeIDs.add(edge.id);
    if (edge.sources.length !== 1 || edge.targets.length !== 1 || !relations.some(relation => relation.id === edge.id && relation.src === edge.sources[0] && relation.dst === edge.targets[0])) throw new Error('Undeclared diagram relation');
  }
  else graph.edges = relations.map(edge => ({id:edge.id,sources:[edge.src],targets:[edge.dst]}));
  const edges = graph.edges.map(edge => {
    const relation = relations.find(relation => relation.id === edge.id)!;
    return `<g data-scene-edge="${context.text(edge.id)}"><path class="scene-edge"/><g class="scene-label"><rect/>${specification.edgeLabels === false ? '' : `<text>${context.text(relation.label)}</text>`}</g></g>`;
  }).join('');
  const id = 'arrow-'+digest(context.view.source+graph.id).slice(0,12);
  const encoded = context.text(JSON.stringify({graph,marker:id}));
  return {markup:`<svg xmlns="http://www.w3.org/2000/svg" class="scene-svg" data-scene style="--scene-port:url(#port-${id})" role="img" aria-label="${context.text(context.view.question.text)}"><metadata data-scene-input>${encoded}</metadata><defs><marker id="port-${id}" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto"><circle cx="5" cy="5" r="3" fill="var(--surface)" stroke="var(--accent)" stroke-width="1.5"/></marker><marker id="${id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M1 1L9 5L1 9" class="scene-arrow"/></marker></defs><g class="scene-groups"></g><g class="scene-edges">${edges}</g><g class="scene-nodes">${bodies.join('')}</g></svg>`,css:diagramStyle};
}
export const diagramStyle = `
.scene-surface>svg{overflow:visible}.scene-svg{display:block;max-width:100%;overflow:visible;font-family:inherit;color:var(--ink);--scene-padding:18;--scene-label-padding:7}
[data-role="pending"]>.scene-frame{fill:var(--secondaryTint);stroke:var(--pending);stroke-dasharray:5 4}.scene-frame{fill:var(--surface);stroke:var(--border);stroke-width:1.4;rx:8}.scene-title{font-size:18px;font-weight:700;fill:var(--ink)}.scene-detail{font-size:14px;font-weight:400;fill:var(--muted)}.scene-glyph{color:var(--accent)}.scene-glyph>svg{width:32px;height:32px}.scene-group-title{font-size:16px;fill:var(--muted);font-weight:600}[data-scene-group="true"]>.scene-frame{fill:var(--tint);stroke:var(--border);rx:10}.scene-edge,.scene-arrow{fill:none;stroke:var(--accent);stroke-width:1.5;stroke-linejoin:round}.scene-label text{fill:var(--muted);font-size:12px}.scene-label rect{fill:var(--surface);stroke:none;rx:4}
`;
