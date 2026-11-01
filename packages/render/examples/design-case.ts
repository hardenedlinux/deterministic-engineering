import * as v from 'valibot';
import {composeDiagram,composeHeading,type DiagramSpec,type FigureComposer,type FigureContext,type TasteRule} from '@deterministic-engineering/render';
import {presentationThemeLayers} from '@deterministic-engineering/render/presentation-theme';
const text=v.pipe(v.string(),v.minLength(1));
const Choice=v.object({title:text,ordinal:v.number(),format:v.picklist(['graph','matrix']),reason:text,tradeoff:text,diagram:v.optional(v.custom<DiagramSpec>(value=>!!value&&typeof value==='object'&&'graph'in value)),axes:v.optional(v.array(text)),icons:v.optional(v.record(v.string(),text))});
export const Presentation=v.object({preferences:v.object({minimumTextSize:v.pipe(v.number(),v.minValue(1)),maximumFocals:v.pipe(v.number(),v.integer(),v.minValue(1)),maximumAnswerShare:v.pipe(v.number(),v.minValue(0),v.maxValue(1))}),choices:v.record(v.string(),Choice)});
export const resources={themeLayers:{...presentationThemeLayers,'case-emphasis':{stylesheet:'[data-role="focal"]>.scene-frame{stroke:var(--secondary);stroke-width:2.4;fill:var(--secondaryTint)}[data-role="focal"] .scene-title{fill:var(--ink)}[data-role="project-boundary"]>.scene-frame{fill:none;stroke:var(--muted);stroke-width:1.5}.scene-groups [data-role="project-boundary"]>.sketch-surface path:not([stroke="none"]){stroke:var(--muted);stroke-width:1.5}[data-crosses-boundary="true"]>.scene-edge{stroke-dasharray:6 5}'}}};
export function choiceFor(context:Pick<FigureContext,'presentation'|'layout'>){const data=v.parse(Presentation,context.presentation);if(!Object.hasOwn(data.choices,context.layout))throw new Error('Undeclared Case design choice');return{...data,choice:data.choices[context.layout]!};}
/** Project-specific composition over the current source model; the Library has no Case registry. */
export const designCase:FigureComposer=context=>{
 if(!context.design||!context.model)throw new Error('The Case requires a captured Design and model');
 const {choice}=choiceFor(context),parts:ReturnType<typeof composeHeading>[]=[];
 const heading=(text:string,role:string,questionRef?:string,ordinal?:number,glyph?:string)=>{const part=composeHeading(context,{text,role,questionRef,ordinal,glyph});parts.push(part);return part.markup;};
 const header=heading(context.view.title,'title')+heading(context.question('ownership').text,'question','ownership')+heading(choice.title,'heading',undefined,choice.ordinal)+heading(context.design.message,'answer');
 let answer:string,sceneCSS='';
 if(choice.format==='graph'){
  if(!choice.diagram)throw new Error('Declared Case graph is missing');
  const roles={...choice.diagram.roles,...Object.fromEntries(context.design.focalSubjects.map(id=>[id,'focal']))};
  const scene=composeDiagram(context,{...choice.diagram,roles});answer=scene.markup;sceneCSS=scene.css;
 }else{
  const axes=choice.axes;if(!axes?.length||new Set(axes).size!==axes.length)throw new Error('Declared Case matrix axes are missing or duplicated');
  const label=(id:string)=>{const node=context.model!.subjects.find(node=>node.id===id);if(!node)throw new Error('Unknown Case matrix subject: '+id);return(node.label??id).split('\n')[0]!;};
  const title=(id:string)=>heading(label(id),'answer',undefined,undefined,choice.icons?.[id]);
  const cells=axes.map(from=>`<div class="row-name">${heading(label(from),'answer')}</div>`+axes.map(to=>{
   const edge=context.model!.relations.find(edge=>edge.src===from&&edge.dst===to);
   return edge?`<div data-surface data-relation="${context.text(edge.id)}" class="relation-cell">${heading(context.relation(from,to).label,'answer')}</div>`:`<div class="empty">${heading('—','note')}</div>`;
  }).join('')).join('');
  answer=`<aside data-node="project">${heading(context.copy('project-note'),'note')}</aside><section class="relation-matrix" style="grid-template-columns:180px repeat(${axes.length},minmax(0,1fr))"><div>${heading('Row → column','note')}</div>${axes.map(id=>`<div class="column-name" data-node="${context.text(id)}">${title(id)}</div>`).join('')}${cells}</section>`;
 }
 return{markup:`<main><header>${header}</header><section data-region="answer">${answer}</section><footer>${choice.format==='graph'?heading(context.copy('scope-legend'),'note'):''}${heading(choice.reason,'note')}${heading(choice.tradeoff,'note')}${heading(context.copy('status'),'note')}</footer></main>`,css:sceneCSS+parts.map(part=>part.css).join('\n')+`[data-figure]{padding:var(--gutter)}header{margin-bottom:16px}header>svg{margin-bottom:7px}footer{margin-top:16px}footer>svg{margin-top:5px}.relation-matrix{display:grid;gap:8px;align-items:center;margin-top:14px}.relation-matrix>div{padding:8px 6px;min-height:52px;display:flex;align-items:center}.relation-matrix [data-heading-role=answer] text{font-size:14px}.relation-matrix [data-annotation-part=glyph]>svg{width:24px;height:24px}.column-name{border-bottom:2px solid var(--accent)}.relation-cell{background:var(--tint);border:1px solid var(--border)}.row-name text{fill:var(--secondary)}.empty{opacity:.65}`};
};
export const answerSpace=(maximum:number,rationale:string):TasteRule=>({id:'answer-space',parameters:{maximum},rationale,inspect:context=>{
 const box=context.bounds.answer;if(!box)return[{kind:'unobserved',message:'Answer region was not observed.',questionRefs:[...context.design.questionRefs],subjectRefs:[]}];
 const share=box.height/context.height;return[{kind:share>maximum?'advice':'observation',message:`Answer occupies ${(share*100).toFixed(1)}% of figure height; selected upper preference ${(maximum*100).toFixed(0)}%.`,questionRefs:[...context.design.questionRefs],subjectRefs:[...context.design.focalSubjects]}];
}});
