import type {ElkNode} from 'elkjs/lib/elk-api';
import {composeDiagram} from './diagram';
import type {FigureComposer,FigureModel} from './figure';

/** Pure hierarchy projection. Model ownership stays with D2/OpenSysML. */
export function graphFromModel(model:FigureModel,options:ElkNode['layoutOptions']={}):ElkNode {
 const ids=new Set(model.subjects.map(node=>node.id));
 if(model.subjects.some(node=>!node.id))throw new Error('Empty model subject');
 if(model.subjects.some(node=>(node.level??1)>1&&!node.parent))throw new Error('D2 hierarchy requires an explicit graph projection');
 if(model.relations.some(edge=>!ids.has(edge.src)||!ids.has(edge.dst)))throw new Error('Unsupported model endpoint: select a dedicated notation adapter');
 if(ids.size!==model.subjects.length)throw new Error('Duplicate model subject');
 const branch=(id:string,ancestors:Set<string>):ElkNode=>{
  if(ancestors.has(id))throw new Error('Cyclic model ownership');
  const children=model.subjects.filter(node=>node.parent===id);
  return {id,...(children.length?{children:children.map(node=>branch(node.id,new Set([...ancestors,id])))}:{})};
 };
 for(const node of model.subjects)if(node.parent&&!ids.has(node.parent))throw new Error('Missing model owner');
 const children=model.subjects.filter(node=>!node.parent).map(node=>branch(node.id,new Set()));
 const visited=(nodes:ElkNode[]):number=>nodes.reduce((n,node)=>n+1+visited(node.children??[]),0);
 if(visited(children)!==ids.size)throw new Error('Unreachable model ownership');
 let id='model-root';while(ids.has(id))id+='-root';
 return {id,children,layoutOptions:{'elk.direction':'DOWN','elk.hierarchyHandling':'INCLUDE_CHILDREN',...options}};
}

/** Optional reusable functional compositor; projects supply data and resources,
 * or replace this function. It has no README/page identity or kind registry. */
export const composeModelView:FigureComposer=context=>{
 if(!context.model)throw new Error('Model view requires captured model semantics');
 const value=context.presentation;
 if(value!==undefined&&(!value||typeof value!=='object'||Array.isArray(value)))throw new Error('Invalid model presentation');
 const data=(value??{})as Record<string,unknown>;
 const options:Record<string,string>={};
 if(data.options!==undefined){if(!data.options||typeof data.options!=='object'||Array.isArray(data.options))throw new Error('Invalid ELK options');for(const[key,value]of Object.entries(data.options)){if(typeof value!=='string')throw new Error('ELK option must be text');options[key]=value;}}
 const select=(value:unknown):Record<string,string>=>{
  if(value===undefined)return {};
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Invalid presentation mapping');
  return Object.fromEntries(Object.entries(value).map(([name,item])=>{
   const selected=context.model!.subjects.filter(node=>node.id===name);
   if(selected.length!==1||typeof item!=='string')throw new Error('Unresolved presentation subject: '+name);
   return [selected[0]!.id,item];
  }));
 };
 const roles=select(data.roles);
 const graph=data.graph===undefined?graphFromModel(context.model,options):structuredClone(data.graph) as ElkNode;
 if(!graph||typeof graph!=='object'||Array.isArray(graph))throw new Error('Invalid declared ELK graph');
 graph.layoutOptions={...options,...graph.layoutOptions};
 const scene=composeDiagram(context,{graph,roles,icons:select(data.icons),edgeLabels:data.edgeLabels!==false});
 const heading=(text:string,kind:string,height:number)=>`<svg data-vector-annotation class="model-${kind}" width="100%" height="${height}"><text x="0" y="${height-10}">${context.text(text)}</text></svg>`;
 return {markup:`<main data-question="${context.text(context.view.question.ref)}"><header>${heading(context.view.title,'title',48)}${heading(context.view.question.text,'question',36)}</header><section data-region="model">${scene.markup}</section></main>`,css:scene.css+`[data-figure]{padding:24px;background:var(--background)}header{margin-bottom:20px}.model-title text{font-size:30px;font-weight:700;fill:var(--ink)}.model-question text{font-size:20px;fill:var(--muted)}`};
};
