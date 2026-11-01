// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import * as v from 'valibot';
import {deepFreeze} from './immutable';
import {bindDesign,DesignSchema} from './design';
import {digest} from './source/catalog';
import type {FigureInput,FigureModel,FigureQuestion} from './figure';
import {composeTaste,type Taste} from './taste';
const text=v.pipe(v.string(),v.check(value=>!!value.trim(),'Expected nonempty projection text'));
const refs=v.pipe(v.array(text),v.check(items=>new Set(items).size===items.length,'Duplicate projection reference'),v.readonly());
/** Read-only display projection of existing source material, never evidence issuance. */
export const EvidenceProjectionSchema=v.pipe(v.strictObject({sourceRef:text,excerpt:text,state:v.picklist(['supported','counter','conflict','missing','stale','unknown']),subjectRefs:refs,relationRefs:refs}),v.readonly());
export type EvidenceProjection=v.InferOutput<typeof EvidenceProjectionSchema>;
export function readEvidenceProjections(value:unknown):readonly EvidenceProjection[]{return deepFreeze(structuredClone(v.parse(v.array(EvidenceProjectionSchema),value)));}
export function bindQuestionTargets(questions:readonly FigureQuestion[],model?:FigureModel):void {
 for(const question of questions){
  if(question.subjectRefs!==undefined)v.parse(refs,question.subjectRefs);if(question.relationRefs!==undefined)v.parse(refs,question.relationRefs);
  for(const id of question.subjectRefs??[])if(!model?.subjects.some(subject=>subject.id===id))throw new Error('Unknown Question subject: '+id);
  for(const id of question.relationRefs??[])if(!model?.relations.some(relation=>relation.id===id))throw new Error('Unknown Question relation: '+id);
 }
}
export function bindEvidence(input:FigureInput):readonly EvidenceProjection[]{
 if(input.evidence===undefined)return [];
 const projections=readEvidenceProjections(input.evidence),selected=new Set(input.view.basis.evidenceRefs);
 const result=projections.filter(item=>selected.has(item.sourceRef));
 for(const ref of selected)if(!result.some(item=>item.sourceRef===ref))throw new Error('Unprojected selected evidence: '+ref);
 for(const item of result){
  const file=Object.hasOwn(input.references,item.sourceRef)?input.references[item.sourceRef]:undefined;
  if(!file||!Object.hasOwn(input.sources,file)||!input.sources[file]!.includes(item.excerpt))throw new Error('Unbound evidence source/excerpt: '+item.sourceRef);
  for(const id of item.subjectRefs)if(!input.model?.subjects.some(subject=>subject.id===id))throw new Error('Unknown evidence subject: '+id);
  for(const id of item.relationRefs)if(!input.model?.relations.some(relation=>relation.id===id))throw new Error('Unknown evidence relation: '+id);
 }
 return deepFreeze(structuredClone(result));
}
export interface TasteSelectionContext {
 readonly input:FigureInput;
 readonly evidence:readonly EvidenceProjection[];
}
export interface TasteProposal {
 readonly rationale:string;
 readonly questionRefs:readonly string[];readonly subjectRefs:readonly string[];readonly evidenceRefs:readonly string[];
 /** Existing render inputs only. Model, sources and fidelity requirements cannot be rewritten. */
 readonly changes:Partial<Pick<FigureInput,'design'|'presentation'|'layout'|'theme'>>;
}
export interface TasteSelection {
 readonly bindingSHA256:string;
 readonly decisions:readonly (TasteProposal & {readonly rule:string;readonly parameters?:Readonly<Record<string,string|number|boolean>>})[];
}
const ProposalSchema=v.strictObject({rationale:text,questionRefs:refs,subjectRefs:refs,evidenceRefs:refs,changes:v.strictObject({design:v.optional(DesignSchema),presentation:v.optional(v.unknown()),layout:v.optional(text),theme:v.optional(v.unknown())})});
function binding(input:FigureInput):string{const{taste:_,...state}=input;return digest(JSON.stringify(state));}
export function assertTasteSelection(input:FigureInput):void {if(input.taste&&input.taste.bindingSHA256!==binding(input))throw new Error('Stale Taste selection: reselect against the current input');}
/** Ordered pure transformations over the current capture, not a catalog of fixed layouts. */
export function selectTaste(input:FigureInput,taste:Taste):FigureInput {
 const{taste:_,...base}=structuredClone(input);let current:FigureInput=base;
 if(!current.design)throw new Error('Taste selection requires Design');
 bindDesign(current.design,current.questions,current.model);bindQuestionTargets(current.questions,current.model);
 const decisions:TasteSelection['decisions'][number][]=[];
 for(const rule of composeTaste(...taste)){
  if(!rule.select)continue;
  const context=deepFreeze(structuredClone({input:current,evidence:bindEvidence(current)}));
  const proposal=rule.select(context);if(proposal===undefined)continue;
  const parsed=v.parse(ProposalSchema,proposal),changes=parsed.changes as TasteProposal['changes'];
  for(const ref of parsed.questionRefs)if(!current.questions.some(question=>question.ref===ref))throw new Error('Unknown selection Question: '+ref);
  for(const id of parsed.subjectRefs)if(!current.model?.subjects.some(subject=>subject.id===id))throw new Error('Unknown selection subject: '+id);
  for(const ref of parsed.evidenceRefs)if(!context.evidence.some(item=>item.sourceRef===ref))throw new Error('Unselected selection evidence: '+ref);
  if(changes.design){
   const before={...current.design,focalSubjects:[]},after={...changes.design,focalSubjects:[]};
   if(JSON.stringify(before)!==JSON.stringify(after))throw new Error('Taste cannot rewrite Design intent or fidelity requirements');
   bindDesign(changes.design,current.questions,current.model);
  }
  current=deepFreeze(structuredClone({...current,...changes}));
  decisions.push({...parsed,changes,rule:rule.id,parameters:rule.parameters});
 }
 bindEvidence(current);
 return deepFreeze(structuredClone({...current,taste:{bindingSHA256:binding(current),decisions}}));
}
