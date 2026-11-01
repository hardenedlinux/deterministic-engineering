import {test,expect} from 'playwright/test';
import {composeFigure,composeModelView,defineDesign,composeTaste,reviewTaste,focalBudget,minimumTextSize,type FigureInput} from '../src';
import {exportFigure} from '../src/export';
const input:FigureInput={view:{source:'case.d2',title:'Library ownership',purpose:'architecture',kind:'dependency-map',question:{ref:'q',text:'Who publishes and selects?'},basis:{captureRef:'candidate',modelRefs:[],obligationRefs:[],evidenceRefs:[]}},width:1100,language:'en',sources:{'case.d2':'source'},references:{source:'case.d2'},questions:[{ref:'q',text:'Who publishes and selects?',focusRefs:['source']}],model:{subjects:[{id:'library',type:'rectangle',label:'Library'},{id:'profile',type:'rectangle',label:'Profile'}],relations:[{id:'selects',src:'profile',dst:'library',label:'selects'}]},design:defineDesign({audience:'Library adopter',medium:'README',message:'Publication and selection: a < b & "</script>".',questionRefs:['q'],requiredSubjects:['library','profile'],requiredRelations:['selects'],focalSubjects:['library']})};
test('Design fidelity and pure Taste review share actual bound export observations',async({browser})=>{
 const figure=composeFigure(input,composeModelView),image=await exportFigure(figure,browser);
 const before=JSON.stringify(image.receipt),report=reviewTaste(figure,image,composeTaste(minimumTextSize(12),focalBudget(1)));
 expect(report.judgments[0]!.parameters).toEqual({minimum:12});expect(report.sourceSHA256['case.d2']).toHaveLength(64);
 expect(report.judgments).toHaveLength(2);expect(report.judgments[0]!.notes[0]!.kind).toBe('observation');expect(report.design).toEqual(input.design);
 expect(image.receipt.observation.subjects.map(node=>node.id).sort()).toEqual(['library','profile']);expect(image.receipt.observation.relations).toEqual(['selects']);expect(JSON.stringify(image.receipt)).toBe(before);expect(Object.isFrozen(report.design.focalSubjects)).toBe(true);
 const advice=reviewTaste(figure,image,composeTaste(minimumTextSize(40)));expect(advice.judgments[0]!.notes[0]!.kind).toBe('advice');
 expect(()=>reviewTaste({...figure,inputSHA256:'stale'},image,[])).toThrow('binding');
 expect(()=>reviewTaste(figure,{...image,png:new Uint8Array([1])},[])).toThrow('binding');
 expect(()=>reviewTaste(figure,{...image,receipt:{...image.receipt,observation:{...image.receipt.observation,subjects:[]}}},[])).toThrow('observation binding');
 const custom=reviewTaste(figure,image,composeTaste({id:'reader',rationale:'Inspect the same captured model and wording.',inspect:context=>[{kind:'observation',message:context.view.purpose+': '+context.questions[0]!.text+' / '+context.model!.subjects[0]!.label,questionRefs:['q'],subjectRefs:['library']}]}));
 expect(custom.judgments[0]!.notes[0]!.message).toContain('Library');
 expect(()=>reviewTaste(figure,image,composeTaste({id:'bad-question',rationale:'Negative control.',inspect:()=>[{kind:'advice',message:'Unknown question.',questionRefs:['invented'],subjectRefs:[]}]}))).toThrow('Unknown taste Question');
 expect(()=>reviewTaste(figure,image,composeTaste({id:'bad',rationale:'Unknown model reference.',inspect:()=>[{kind:'advice',message:'Invented subject.',questionRefs:['q'],subjectRefs:['invented']}]}))).toThrow('Unknown taste subject');
 expect(()=>reviewTaste(figure,image,composeTaste({id:'mutation',rationale:'Negative control.',inspect:context=>{(context.design as {audience:string}).audience='changed';return[];}}))).toThrow();
});
test('hidden required subjects and relations refuse; a separate valid export recovers',async({browser})=>{
 for(const css of ['[data-scene-node="profile"]{display:none}','[data-scene-edge]{display:none}','[data-scene-edge]{opacity:0}']){
  const figure=composeFigure(input,context=>{const result=composeModelView(context);return{...result,css:result.css+css};});
  await expect(exportFigure(figure,browser)).rejects.toThrow('Design');
 }
 const figure=composeFigure({...input,presentation:{options:{'elk.direction':'RIGHT'},edgeLabels:false}},composeModelView);
 expect((await exportFigure(figure,browser)).receipt.observation.relations).toEqual(['selects']);
});
test('HTML-only text reports unobserved SVG readability without granting aesthetic acceptance',async({browser})=>{
 const figure=composeFigure({...input,model:undefined,design:defineDesign({...input.design!,requiredSubjects:[],requiredRelations:[],focalSubjects:[]})},context=>({markup:`<section data-question="q">${context.text(context.question('q').text)}</section>`,css:''}));
 const image=await exportFigure(figure,browser);const report=reviewTaste(figure,image,composeTaste(minimumTextSize(12)));
 expect(report.judgments[0]!.notes[0]!.kind).toBe('unobserved');
});
