import type {Connection, RenderedView, RenderSpan} from '@openmbee/opensysml';
import type {FigureModel} from './figure';
import {digest} from './source/catalog';
import type {ViewSelection} from './source/types';

export type OpenSysMLRenderOptions = Parameters<Connection['renderView']>[2];
export interface OpenSysMLCapture {
  readonly modelHash: string;
  readonly requestedView: string;
  readonly rendering: RenderedView;
}
export interface SysMLProjection {
  readonly selection: ViewSelection;
  readonly layout: 'reflow';
  readonly portProjection?: 'owner';
  readonly labels?: Readonly<Record<string,string>>;
}
export interface ModelNodeTrace {readonly id:string; readonly parent:string; readonly origin?:RenderSpan;}
export interface ModelEdgeTrace {
  readonly id:string; readonly index:number; readonly from:string; readonly to:string;
  readonly fromPort:string; readonly toPort:string; readonly kind:string; readonly origin?:RenderSpan;
}
export interface SysMLProjectionResult {
  readonly model: FigureModel;
  readonly view: ViewSelection;
  readonly trace: {
    readonly modelHash:string; readonly requestedView:string; readonly resolvedView:string;
    readonly renderingSHA256:string; readonly capturedRenderingJSON:string;
    readonly portProjection?:'owner';
    readonly nodes:readonly ModelNodeTrace[]; readonly edges:readonly ModelEdgeTrace[];
  };
}
/** The host owns SDK transport and capability admission. No replacement JSON decoder. */
export async function captureOpenSysMLView(connection:Pick<Connection,'renderView'>,modelHash:string,viewName:string,options?:OpenSysMLRenderOptions):Promise<OpenSysMLCapture> {
  if(!modelHash.trim()||!viewName.trim())throw new Error('Model hash and view name are required');
  const rendering=await connection.renderView(modelHash,viewName,options);
  return Object.freeze({modelHash,requestedView:viewName,rendering:structuredClone(rendering)});
}
/** Pure display projection of SDK results. SysML parsing/validation stays with the SDK. */
export function projectOpenSysMLView(capture:OpenSysMLCapture,profile:SysMLProjection):SysMLProjectionResult {
  if(!capture.modelHash.trim()||!capture.requestedView.trim())throw new Error('Model/view binding is required');
  if(profile.portProjection!==undefined&&profile.portProjection!=='owner')throw new Error('Unsupported port projection');
  if(profile.layout!=='reflow')throw new Error('Projection requires explicit reflow');
  const rendering=capture.rendering;
  if(!rendering.view)throw new Error('SDK rendering has no resolved view');
  if(rendering.columns.length||rendering.rows.length||rendering.notes.length)throw new Error('Table/notes notation needs a supported notation adapter');
  const nodes=[...rendering.nodes],byId=new Map(nodes.map(node=>[node.id,node]));
  if(!nodes.length||byId.size!==nodes.length||nodes.some(node=>!node.id))throw new Error('Empty or duplicate SDK node identity');
  if(nodes.some(node=>node.compartment||node.standIn||node.geometry?.collapsed||node.ports.length&&profile.portProjection!=='owner'))
    throw new Error('Ports, compartment rows, stand-ins and collapsed nodes need a supported notation adapter');
  for(const id of Object.keys(profile.labels??{}))
    if(!byId.has(id))throw new Error('Presentation references a missing SDK node ID: '+id);
  if(Object.values(profile.labels??{}).some(label=>typeof label!=='string'||!label.trim()))throw new Error('Invalid display caption');
  for(const node of nodes){
    const seen=new Set([node.id]);let parent=node.parent;
    while(parent){const owner=byId.get(parent);if(!owner)throw new Error('Missing SDK owner');if(seen.has(parent))throw new Error('Cyclic SDK ownership');seen.add(parent);parent=owner.parent;}
    if(node.ports.some(port=>!port.id)||new Set(node.ports.map(port=>port.id)).size!==node.ports.length)throw new Error('Invalid or duplicate SDK port identity');
  }
  for(const edge of rendering.edges){
    const from=byId.get(edge.from),to=byId.get(edge.to);
    if(!from||!to)throw new Error('Missing SDK edge endpoint');
    if((edge.fromPort||edge.toPort)&&profile.portProjection!=='owner')throw new Error('Port edges need a supported notation adapter');
    if(edge.fromPort&&!from.ports.some(port=>port.id===edge.fromPort)||edge.toPort&&!to.ports.some(port=>port.id===edge.toPort))
      throw new Error('SDK port does not belong to the declared endpoint');
  }
  const capturedRenderingJSON=JSON.stringify(capture),renderingSHA256=digest(capturedRenderingJSON);
  const ids=new Set(byId.keys());
  const edges=rendering.edges.map((edge,index)=>{
    let id=`edge:${index}`;while(ids.has(id))id='edge:'+id;ids.add(id);
    return {id,index,from:edge.from,to:edge.to,fromPort:edge.fromPort,toPort:edge.toPort,kind:edge.kind,...(edge.origin?{origin:{...edge.origin}}:{})};
  });
  return {
    view:structuredClone(profile.selection),
    model:{subjects:nodes.map(node=>({id:node.id,type:node.kind||'rectangle',parent:node.parent||undefined,sourceName:node.name,label:profile.labels&&Object.hasOwn(profile.labels,node.id)?profile.labels[node.id]:[node.name,node.type,node.detail,node.text].filter(Boolean).join('\n')})),
      // The SDK does not expose arrowhead notation; retain ordered endpoints and kind without inventing arrows.
      relations:rendering.edges.map((edge,index)=>({id:edges[index]!.id,src:edge.from,dst:edge.to,label:edge.label||edge.name||edge.kind,kind:edge.kind,fromPort:edge.fromPort,toPort:edge.toPort,srcArrow:'none',dstArrow:'none'}))},
    trace:{modelHash:capture.modelHash,requestedView:capture.requestedView,resolvedView:rendering.view,renderingSHA256,capturedRenderingJSON,
      ...(profile.portProjection?{portProjection:profile.portProjection}:{}),
      nodes:nodes.map(node=>({id:node.id,parent:node.parent,...(node.origin?{origin:{...node.origin}}:{})})),edges},
  };
}
