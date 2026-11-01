// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import type {ElkNode} from 'elkjs';
import type {TasteRule} from './taste';
import type {TasteSelectionContext,TasteProposal} from './taste-selection';
import {modelDiagram} from './model-view';
const selectedQuestions=(context:TasteSelectionContext)=>context.input.questions.filter(question=>context.input.design!.questionRefs.includes(question.ref));
const evidenceSubjects=(context:TasteSelectionContext,item:TasteSelectionContext['evidence'][number])=>[...item.subjectRefs,...item.relationRefs.flatMap(id=>{const edge=context.input.model?.relations.find(edge=>edge.id===id);return edge?[edge.src,edge.dst]:[];})];
const base=(context:TasteSelectionContext,rationale:string,subjectRefs:readonly string[],changes:TasteProposal['changes'],evidenceRefs:readonly string[]=[]):TasteProposal=>({rationale,subjectRefs:[...new Set(subjectRefs)],questionRefs:context.input.design!.questionRefs,evidenceRefs:[...new Set(evidenceRefs)],changes});
/** Explicit Question bindings supply intent; English keywords and project names are never parsed. */
export function questionFocus():TasteRule{return{id:'question-focus',rationale:'Choose emphasis from selected Question/model bindings.',select:context=>{
 const ids=[...new Set(selectedQuestions(context).flatMap(question=>[...(question.subjectRefs??[]),...(question.relationRefs??[]).flatMap(id=>{const relation=context.input.model?.relations.find(edge=>edge.id===id);return relation?[relation.src,relation.dst]:[];})]))];
 if(!ids.length)return undefined;
 return base(context,`${ids.length} subjects are explicitly linked to the selected Questions.`,ids,{design:{...context.input.design!,focalSubjects:ids}});
}};}
/** Attention is a visual choice. A supported projection never confers admission or approval. */
export function evidenceFocus():TasteRule{return{id:'evidence-focus',rationale:'Expose selected counterevidence, conflict, stale or missing source observations.',select:context=>{
 const rank={conflict:0,counter:1,stale:2,missing:3,unknown:4,supported:5}as const;
 const adverse=context.evidence.filter(item=>item.state!=='supported').sort((a,b)=>rank[a.state]-rank[b.state]);
 if(!adverse.length)return undefined;
 const chosen=adverse.filter(item=>item.state===adverse[0]!.state),ids=[...new Set(chosen.flatMap(item=>evidenceSubjects(context,item)))];
 if(!ids.length)return undefined;
 return base(context,`Selected source projections contain ${chosen[0]!.state}; their subjects take visual priority without changing model facts.`,ids,{design:{...context.input.design!,focalSubjects:ids}},chosen.map(item=>item.sourceRef));
}};}
/** Required references plus Question neighbourhood, retaining explicit graph ancestors. */
export function questionScope():TasteRule{return{id:'question-scope',rationale:'Choose the view scope from Questions while preserving all required references.',select:context=>{
 const input=context.input;if(!input.model)return undefined;
 const spec=modelDiagram(input.model,input.presentation),kept=new Set([...input.design!.requiredSubjects,...input.design!.focalSubjects,...selectedQuestions(context).flatMap(question=>question.subjectRefs??[])]);
 const questionEdges=new Set(selectedQuestions(context).flatMap(question=>question.relationRefs??[]));
 for(const edge of input.model.relations)if(input.design!.requiredRelations.includes(edge.id)||questionEdges.has(edge.id)||input.design!.focalSubjects.includes(edge.src)||input.design!.focalSubjects.includes(edge.dst)){kept.add(edge.src);kept.add(edge.dst);}
 const prune=(node:ElkNode):ElkNode|undefined=>{const children=node.children?.map(prune).filter((node):node is ElkNode=>!!node),{children:_,...plain}=node;return kept.has(node.id)||children?.length?{...plain,...(children?.length?{children}: {})}:undefined;};
 const graph={...spec.graph,children:spec.graph.children!.map(prune).filter((node):node is ElkNode=>!!node)};
 const ids=new Set<string>();const collect=(node:ElkNode)=>{ids.add(node.id);node.children?.forEach(collect);};graph.children.forEach(collect);
 if(graph.edges)graph.edges=graph.edges.filter(edge=>edge.sources.every(id=>ids.has(id))&&edge.targets.every(id=>ids.has(id)));
 return base(context,`Retain ${ids.size} displayed subjects, including required references and their declared containers.`,[...ids],{presentation:{...spec,graph}});
}};}
/** Choose an ELK preference from actual relation direction, leaving routing to ELK. */
export function dependencyLayout():TasteRule{return{id:'dependency-layout',rationale:'Orient the selected relationship view around its focal dependency position.',select:context=>{
 const input=context.input;if(!input.model||!input.design!.focalSubjects.length)return undefined;
 const spec=modelDiagram(input.model,input.presentation),focus=new Set(input.design!.focalSubjects);
 const expand=(node:ElkNode,inFocus=false)=>{const included=inFocus||focus.has(node.id);if(included)focus.add(node.id);node.children?.forEach(child=>expand(child,included));};spec.graph.children!.forEach(node=>expand(node));
 const incoming=input.model.relations.filter(edge=>focus.has(edge.dst)&&!focus.has(edge.src)).length,outgoing=input.model.relations.filter(edge=>focus.has(edge.src)&&!focus.has(edge.dst)).length;
 const direction=incoming>outgoing?'UP':outgoing>incoming?'DOWN':'RIGHT';
 return base(context,`Focal subjects have ${incoming} incoming and ${outgoing} outgoing relationships; select ELK ${direction}.`,[...focus],{presentation:{...spec,graph:{...spec.graph,layoutOptions:{...spec.graph.layoutOptions,'elk.direction':direction}}}});
}};}
/** Roles are open theme hooks; source state is retained instead of becoming a success badge. */
export function visualHierarchy():TasteRule{return{id:'visual-hierarchy',rationale:'Give focal subjects and selected source gaps distinct visual roles.',select:context=>{
 const input=context.input;if(!input.model)return undefined;
 const spec=modelDiagram(input.model,input.presentation),roles={...spec.roles};
 for(const id of input.design!.focalSubjects)roles[id]='focal';
 for(const item of context.evidence)if(item.state!=='supported')for(const id of evidenceSubjects(context,item))roles[id]=item.state==='counter'||item.state==='conflict'?'counter':'pending';
 return base(context,'Selected focal and source-gap roles use the chosen theme; no evidence state is promoted to approval.',[...new Set([...input.design!.focalSubjects,...context.evidence.flatMap(item=>evidenceSubjects(context,item))])],{presentation:{...spec,roles}},context.evidence.map(item=>item.sourceRef));
}};}
