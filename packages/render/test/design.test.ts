// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {test,expect} from 'bun:test';
import fc from 'fast-check';
import {defineDesign,DesignSchema,composeFigure,readD2Figure,composeModelView,composeTaste,focalBudget,minimumTextSize,type FigureInput} from '../src';
import * as v from 'valibot';
const brief={audience:'Library adopter',medium:'README',message:'Definitions and project choices have distinct owners.',questionRefs:['q'],requiredSubjects:['a','b'],requiredRelations:['ab'],focalSubjects:['a']};
const input:FigureInput={view:{source:'view.d2',title:'Ownership',purpose:'architecture',kind:'dependency-map',question:{ref:'q',text:'Who owns the definitions?'},basis:{captureRef:'candidate',modelRefs:[],obligationRefs:[],evidenceRefs:[]}},width:1100,language:'en',sources:{'view.d2':'captured'},references:{source:'view.d2'},questions:[{ref:'q',text:'Who owns the definitions?',focusRefs:['source']}],model:{subjects:[{id:'a',type:'rectangle',label:'Library'},{id:'b',type:'rectangle',label:'Profile'}],relations:[{id:'ab',src:'b',dst:'a',label:'selects'}]}};
export {brief,input};
test('Design derives its types from the schema and owns immutable declaration data',()=>{
 const original=structuredClone(brief),design=defineDesign(original);original.focalSubjects[0]='changed';
 expect(design.focalSubjects).toEqual(['a']);expect(Reflect.set(design,'audience','changed')).toBe(false);expect(Object.isFrozen(design.requiredRelations)).toBe(true);
 for(const value of [{...brief,typo:true},{...brief,audience:' '},{...brief,focalSubjects:['a','a']},{...brief,questionRefs:[]},{...brief,requiredSubjects:[4]}])expect(v.safeParse(DesignSchema,value).success).toBe(false);
});
test('Design binds to current selected model identities and Questions before composition',()=>{
 for(const changed of [{questionRefs:['missing']},{requiredSubjects:['missing']},{focalSubjects:['missing']},{requiredRelations:['missing']}])expect(()=>composeFigure({...input,design:defineDesign({...brief,...changed})},composeModelView)).toThrow();
 const a=composeFigure({...input,design:defineDesign(brief)},composeModelView);
 const b=composeFigure({...input,design:defineDesign({...brief,audience:'Project maintainer'})},composeModelView);
 expect(a.inputSHA256).not.toBe(b.inputSHA256);expect(a.html).toContain('"audience":"Library adopter"');
 expect(()=>composeFigure({...input,design:defineDesign(brief)},()=>({markup:'<div data-question="q">Only a headline</div>',css:''}))).toThrow('not rendered');
 expect(()=>composeFigure({...input,design:defineDesign(brief)},()=>({markup:'<div data-question="q" data-node="unknown">Invented</div>',css:''}))).toThrow('Unknown rendered');
});
test('D2 design and source-declared candidate composition override use existing variant selection',async()=>{
 const {selectFigureVariant}=await import('../src');
 const declaration={title:input.view.title,purpose:'architecture',kind:'dependency-map',language:'en',width:1100,primary:'q',questions:input.questions,references:input.references,basis:input.view.basis,copy:{},design:brief,presentation:{options:{'elk.direction':'RIGHT'}},variants:[{name:'boundary',design:{...brief,focalSubjects:['b']},presentation:{options:{'elk.direction':'DOWN'}}}]};
 const selected=readD2Figure({inputPath:'view.d2',fs:input.sources,data:{figure:JSON.stringify(declaration)},model:input.model},input.sources);
 const variant=selectFigureVariant(selected,'boundary');expect(variant.design!.focalSubjects).toEqual(['b']);expect(variant.presentation).toEqual({options:{'elk.direction':'DOWN'}});expect(variant.model).toBe(selected.model);expect(variant.questions).toBe(selected.questions);
 expect(()=>readD2Figure({inputPath:'view.d2',fs:input.sources,data:{figure:JSON.stringify({...declaration,design:{...brief,typo:true}})}},input.sources)).toThrow();
});
test('all required subjects survive ELK graph choices without mutating the input (PBT)',()=>{
 fc.assert(fc.property(fc.array(fc.stringMatching(/^[a-z][a-z0-9]{0,5}$/),{minLength:2,maxLength:6}).filter(ids=>new Set(ids).size===ids.length),ids=>{
  const model={subjects:ids.map(id=>({id,type:'rectangle',label:id})),relations:[]};
  const design=defineDesign({...brief,requiredSubjects:ids,requiredRelations:[],focalSubjects:[ids[0]!]});
  const candidate={...input,model,design};const before=JSON.stringify(candidate);
  composeFigure(candidate,composeModelView);expect(JSON.stringify(candidate)).toBe(before);
  expect(()=>composeFigure(candidate,context=>({markup:`<section data-question="q">${ids.slice(1).map(id=>`<div data-node="${context.text(id)}">${context.text(id)}</div>`).join('')}</section>`,css:''}))).toThrow('not rendered');
 }),{seed:145,numRuns:30});
});
test('Taste composes immutable pure rules and rejects ambiguous or invalid declarations',()=>{
 const rule={...focalBudget(1)},taste=composeTaste(rule,minimumTextSize(12));rule.id='changed';expect(taste[0]!.id).toBe('focal-budget');expect(Object.isFrozen(taste[0])).toBe(true);
 expect(()=>composeTaste(focalBudget(1),focalBudget(2))).toThrow('Duplicate taste');expect(()=>minimumTextSize(NaN)).toThrow();expect(()=>minimumTextSize(0)).toThrow();expect(()=>focalBudget(0.5)).toThrow();
});

test('Design binds after the selected OpenSysML projection, preserving SDK subject identities',async()=>{
 const {captureFixture,declarationFixture}=await import('./fixtures/model-view');
 const {projectOpenSysMLView}=await import('../src/opensysml');
 const {compileFigureSource}=await import('../src');
 const capture=captureFixture(),fixture=declarationFixture(capture);
 const projected=projectOpenSysMLView(capture,{selection:input.view,layout:'reflow'});
 const design=defineDesign({...brief,requiredSubjects:projected.model.subjects.map(subject=>subject.id),requiredRelations:projected.model.relations.map(edge=>edge.id),focalSubjects:['n1']});
 fixture.sources['view.d2']=fixture.sources['view.d2'].replace('"modelSource":','"design":'+JSON.stringify(design)+',"modelSource":');
 const bound=await compileFigureSource(fixture.sources,'view.d2',fixture.resources);
 const sources={...bound.sources,...fixture.sources};expect(composeFigure({...bound,sources},composeModelView).html).toContain('data-scene-node="n1"');
},30000);
