// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {test,expect} from 'bun:test';
import fc from 'fast-check';
import {composeFigure,composeModelView,composeTaste,defineDesign,selectTaste,questionFocus,evidenceFocus,questionScope,dependencyLayout,visualHierarchy,modelDiagram,type FigureInput,type TasteProposal} from '../src';
const program=()=>composeTaste(questionFocus(),evidenceFocus(),questionScope(),dependencyLayout(),visualHierarchy());
function fixture(prefix=''):FigureInput {
 const id=(name:string)=>prefix+name;
 return {view:{source:'view.d2',title:'Selection test',purpose:'architecture',kind:'dependency-map',question:{ref:'definition',text:'Which definitions?'},basis:{captureRef:'test-fixture',modelRefs:[],obligationRefs:[],evidenceRefs:[]}},width:1100,language:'en',sources:{'view.d2':'model fixture','observation.txt':'test-fixture: capture blocked'},references:{source:'view.d2',observation:'observation.txt'},questions:[{ref:'definition',text:'Which definitions?',focusRefs:['source'],subjectRefs:[id('defs')]},{ref:'binding',text:'Which binder?',focusRefs:['source'],subjectRefs:[id('binder')]}],design:defineDesign({audience:'Reader',medium:'README',message:'Stable facts.',questionRefs:['definition'],requiredSubjects:[id('defs'),id('binder'),id('selector'),id('inputs')],requiredRelations:['selects','binds','input'],focalSubjects:[]}),evidence:[{sourceRef:'observation',excerpt:'capture blocked',state:'missing',subjectRefs:[id('binder')],relationRefs:[]}],model:{subjects:['defs','binder','selector','inputs','optional'].map(name=>({id:id(name),type:'rectangle',label:name})),relations:[{id:'selects',src:id('selector'),dst:id('defs'),label:'selects'},{id:'binds',src:id('binder'),dst:id('selector'),label:'binds'},{id:'input',src:id('binder'),dst:id('inputs'),label:'input'}]}};
}
const graph=(input:FigureInput)=>modelDiagram(input.model!,input.presentation).graph;
test('Questions drive focal subjects, scope and ELK direction before composition',()=>{
 const input=fixture(),before=JSON.stringify(input),a=selectTaste(input,program());
 expect(a.design!.focalSubjects).toEqual(['defs']);expect(graph(a).layoutOptions!['elk.direction']).toBe('UP');expect(graph(a).children!.some(node=>node.id==='optional')).toBe(false);
 const b=selectTaste({...input,design:defineDesign({...input.design!,questionRefs:['binding']})},program());
 expect(b.design!.focalSubjects).toEqual(['binder']);expect(graph(b).layoutOptions!['elk.direction']).toBe('DOWN');
 const extra={ref:'another',text:'A new question never seen by the Case',focusRefs:['source'],subjectRefs:['optional']};
 const c=selectTaste({...input,questions:[...input.questions,extra],design:defineDesign({...input.design!,questionRefs:['another']})},program());
 expect(c.design!.focalSubjects).toEqual(['optional']);expect(graph(c).children).toHaveLength(5);expect(graph(c).layoutOptions!['elk.direction']).toBe('RIGHT');
 expect(a.model).toEqual(input.model);expect(a.design!.requiredRelations).toEqual(input.design!.requiredRelations);expect(JSON.stringify(input)).toBe(before);expect(Object.isFrozen(a.presentation)).toBe(true);
 expect(composeFigure(a,composeModelView).html).toContain('question-focus');
});
test('selected source observations change hierarchy without becoming evidence approval',()=>{
 const input=fixture(),selected={...input,view:{...input.view,basis:{...input.view.basis,evidenceRefs:['observation']}}};
 const missing=selectTaste(selected,program());expect(missing.design!.focalSubjects).toEqual(['binder']);expect(modelDiagram(missing.model!,missing.presentation).roles!.binder).toBe('pending');
 const counter=selectTaste({...selected,evidence:[{...input.evidence![0]!,state:'counter',subjectRefs:[],relationRefs:['input']}]},program());
 expect(counter.design!.focalSubjects).toContain('inputs');expect(modelDiagram(counter.model!,counter.presentation).roles!.inputs).toBe('counter');
 const supported=selectTaste({...selected,evidence:[{...input.evidence![0]!,state:'supported'}]},program());expect(supported.design!.focalSubjects).toEqual(['defs']);expect(JSON.stringify(supported.presentation)).not.toContain('approved');
 expect(()=>selectTaste({...selected,sources:{...input.sources,'observation.txt':'changed source'}},program())).toThrow('source/excerpt');
 expect(()=>selectTaste({...selected,evidence:[{...input.evidence![0]!,subjectRefs:['unknown']}]},program())).toThrow('Unknown evidence subject');
});
test('selection cannot remove fidelity requirements or silently replay across input changes',()=>{
 const input=fixture(),selected=selectTaste(input,program());
 expect(()=>composeFigure({...selected,sources:{...selected.sources,'extra.txt':'changed'}},composeModelView)).toThrow('Stale Taste');
 const next=selectTaste({...selected,sources:{...selected.sources,'extra.txt':'changed'}},program());expect(next.taste!.bindingSHA256).not.toBe(selected.taste!.bindingSHA256);
 expect(()=>selectTaste(input,composeTaste({id:'drop',rationale:'Negative control',select:context=>({rationale:'Drop',questionRefs:[],subjectRefs:[],evidenceRefs:[],changes:{design:{...context.input.design!,requiredSubjects:[]}}})}))).toThrow('fidelity');
 expect(()=>selectTaste(input,composeTaste({id:'rewrite',rationale:'Negative control',select:()=>({rationale:'Rewrite',questionRefs:[],subjectRefs:[],evidenceRefs:[],changes:{model:{}}}as unknown as TasteProposal)}))).toThrow();
 expect(()=>selectTaste(input,composeTaste({id:'unknown',rationale:'Negative control',select:()=>({rationale:'Unknown',questionRefs:[],subjectRefs:['unknown'],evidenceRefs:[],changes:{}})}))).toThrow('Unknown selection subject');
});
test('policies do not depend on Case names or identifiers (seeded PBT)',()=>{
 fc.assert(fc.property(fc.stringMatching(/^[a-z]{1,8}$/),prefix=>{const input=fixture(prefix);const selected=selectTaste(input,program());expect(selected.design!.focalSubjects).toEqual([prefix+'defs']);expect(graph(selected).layoutOptions!['elk.direction']).toBe('UP');}),{seed:146,numRuns:25});
});
