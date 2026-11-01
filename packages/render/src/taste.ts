import * as v from 'valibot';
import {isDeepStrictEqual} from 'node:util';
import {parseFragment,type DefaultTreeAdapterTypes} from 'parse5';
import {deepFreeze} from './immutable';
import {DesignSchema,type Design} from './design';
import {digest} from './source/catalog';
import type {ComposedFigure,FigureModel,FigureQuestion} from './figure';
import type {ViewSelection} from './source/types';
import type {FigureImage} from './export';
export interface MeasuredBox {readonly x:number;readonly y:number;readonly width:number;readonly height:number;}
/** Browser observations use existing model IDs. They do not replace the model. */
export interface RenderObservation {
 readonly canvas:MeasuredBox;
 readonly subjects:readonly (MeasuredBox & {readonly id:string;readonly role:string;readonly owner?:string})[];
 readonly relations:readonly string[];
 readonly headings:readonly (MeasuredBox & {readonly role:string})[];
}
const text=v.pipe(v.string(),v.check(value=>!!value.trim(),'Expected nonempty taste text'));
const NoteSchema=v.pipe(v.strictObject({kind:v.picklist(['observation','advice','unobserved']),message:text,questionRefs:v.pipe(v.array(text),v.readonly()),subjectRefs:v.pipe(v.array(text),v.readonly())}),v.readonly());
export type TasteNote=v.InferOutput<typeof NoteSchema>;
export interface TasteContext {
 readonly design:Design;
 readonly model?:FigureModel;
 readonly questions:readonly FigureQuestion[];
 readonly view:ViewSelection;
 readonly observation:RenderObservation;
 readonly readability:FigureImage['receipt']['readability'];
 readonly bounds:FigureImage['receipt']['bounds'];
 readonly width:number;readonly height:number;
}
export interface TasteRule {
 readonly id:string;
 readonly rationale:string;
 readonly parameters?:Readonly<Record<string,string|number|boolean>>;
 /** Pure inspection. Acquisition, rendering and model edits belong to their current owners. */
 readonly inspect:(context:TasteContext)=>readonly TasteNote[];
}
export type Taste=readonly TasteRule[];
export interface TasteReport {
 readonly inputSHA256:string;readonly htmlSHA256:string;readonly pngSHA256:string;
 readonly design:Design;
 readonly sourceSHA256:Readonly<Record<string,string>>;
 readonly judgments:readonly {readonly rule:string;readonly rationale:string;readonly parameters?:Readonly<Record<string,string|number|boolean>>;readonly notes:readonly TasteNote[]}[];
}
/** Ordinary function/data composition, with no process, global registry or scoring runtime. */
export function composeTaste(...rules:readonly TasteRule[]):Taste {
 const ids=new Set<string>();
 return Object.freeze(rules.map(rule=>{
  v.parse(text,rule.id);v.parse(text,rule.rationale);
  if(ids.has(rule.id))throw new Error('Duplicate taste rule: '+rule.id);ids.add(rule.id);
  if(typeof rule.inspect!=='function')throw new Error('Taste rule needs a pure inspector');
  const parameters=rule.parameters===undefined?undefined:v.parse(v.record(v.string(),v.union([v.string(),v.pipe(v.number(),v.finite()),v.boolean()])),rule.parameters);
  return Object.freeze({...rule,parameters:parameters===undefined?undefined:deepFreeze(structuredClone(parameters))});
 }));
}
/** Review an actual bound output; advice never becomes a beauty/pass score or execution evidence. */
export function reviewTaste(figure:ComposedFigure,image:FigureImage,taste:Taste):TasteReport {
 const receipt=image.receipt;
 if(digest(figure.html)!==figure.htmlSHA256||receipt.inputSHA256!==figure.inputSHA256||receipt.composedHTMLSHA256!==figure.htmlSHA256||digest(image.html)!==receipt.htmlSHA256||digest(image.png)!==receipt.pngSHA256||image.svg.length!==receipt.svgSHA256.length||image.svg.some((svg,index)=>digest(svg)!==receipt.svgSHA256[index]))throw new Error('Taste output binding mismatch');
 const read=(html:string)=>{
  const nodes:DefaultTreeAdapterTypes.Node[]=[...parseFragment(html).childNodes],metadata:string[]=[];
  while(nodes.length){const node=nodes.pop()!;if('tagName'in node&&node.tagName==='script'&&node.attrs.some(attr=>attr.name==='id'&&attr.value==='figure-provenance'))metadata.push(node.childNodes.filter((child):child is DefaultTreeAdapterTypes.TextNode=>child.nodeName==='#text').map(child=>child.value).join(''));if('childNodes'in node)nodes.push(...node.childNodes);}
  if(metadata.length!==1)throw new Error('Taste needs one captured figure provenance');
  return v.parse(v.record(v.string(),v.unknown()),JSON.parse(metadata[0]!));
 };
 const original=read(figure.html),baked=read(image.html),{rendered,...source}=baked;
 const actual={observation:receipt.observation,readability:receipt.readability,bounds:receipt.bounds};
 if(!isDeepStrictEqual(source,original)||!isDeepStrictEqual(rendered,JSON.parse(JSON.stringify(actual))))throw new Error('Taste observation binding mismatch');
 const capture=v.parse(v.object({design:DesignSchema,questions:v.array(v.object({ref:text,text,focusRefs:v.array(text)})),model:v.optional(v.object({subjects:v.array(v.object({id:text}))})),sourceSHA256:v.record(text,text)}),original);
 const context:TasteContext=deepFreeze(structuredClone({design:capture.design,model:original.model as FigureModel|undefined,questions:capture.questions,view:original.view as ViewSelection,observation:receipt.observation,readability:receipt.readability,bounds:receipt.bounds,width:receipt.observation.canvas.width,height:receipt.observation.canvas.height}));
 const subjects=new Set(capture.model?.subjects.map(subject=>subject.id)),questions=new Set(capture.questions.map(question=>question.ref));
 const judgments=composeTaste(...taste).map(rule=>({rule:rule.id,rationale:rule.rationale,parameters:rule.parameters,notes:rule.inspect(context).map(note=>{
  const result=v.parse(NoteSchema,note);
  for(const id of result.questionRefs)if(!questions.has(id))throw new Error('Unknown taste Question: '+id);
  for(const id of result.subjectRefs)if(!subjects.has(id))throw new Error('Unknown taste subject: '+id);
  return result;
 })}));
 return deepFreeze(structuredClone({inputSHA256:figure.inputSHA256,htmlSHA256:receipt.htmlSHA256,pngSHA256:receipt.pngSHA256,design:capture.design,sourceSHA256:capture.sourceSHA256,judgments}));
}
/** A selected numeric preference, evaluated against existing measured text-size observations. */
export function minimumTextSize(minimum:number):TasteRule {
 v.parse(v.pipe(v.number(),v.finite(),v.minValue(Number.MIN_VALUE)),minimum);
 return deepFreeze({id:'minimum-text-size',parameters:{minimum},rationale:'Read SVG text at the selected logical display size.',inspect:context=>{
  const size=context.readability.minimumTextSize;
  return [{kind:size===null?'unobserved':size<minimum?'advice':'observation',message:size===null?'No visible SVG text samples were measured.':`Observed minimum ${size.toFixed(2)} CSS px; selected preference ${minimum} CSS px.`,questionRefs:[...context.design.questionRefs],subjectRefs:[]}];
 }});
}
/** Counts declared focal subjects; this does not claim to measure perceived salience. */
export function focalBudget(maximum:number):TasteRule {
 v.parse(v.pipe(v.number(),v.integer(),v.minValue(1)),maximum);
 return deepFreeze({id:'focal-budget',parameters:{maximum},rationale:'Reserve emphasis for the selected reader question.',inspect:context=>[{kind:context.design.focalSubjects.length>maximum?'advice':'observation',message:`${context.design.focalSubjects.length} declared focal subjects; selected preference at most ${maximum}.`,questionRefs:[...context.design.questionRefs],subjectRefs:[...context.design.focalSubjects]}]});
}
