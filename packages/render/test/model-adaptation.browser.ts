import {test,expect} from 'playwright/test';
import {composeFigure,type FigureInput,type FigureModel,composeModelView,composeDiagram} from '../src';
import {exportFigure} from '../src/export';
import {projectOpenSysMLView} from '../src/opensysml';
import {captureFixture,selection} from './fixtures/model-view';
const base:FigureInput={view:selection,width:1000,language:'en',questions:[{ref:'q',text:selection.question.text,focusRefs:['sdk']}],references:{sdk:'model.json'},sources:{'view.d2':'test declaration','model.json':'native fixture'}};
test('direct SDK parents and owner-projected ports reach a vector model view',async({browser})=>{
 const capture=captureFixture(true),projection=projectOpenSysMLView(capture,{selection,layout:'reflow',portProjection:'owner'});
 const figure=composeFigure({...base,model:projection.model,modelTrace:projection.trace,sources:{...base.sources,'model.json':JSON.stringify(capture)},presentation:{icons:{root:'model',n1:'capture',n2:'selection'}}},composeModelView);
 const output=await exportFigure(figure,browser);
 expect(output.receipt.scenes[0]!.nodes).toBe(3);expect(output.html).toContain('"fromPort":"p1"');
 expect(output.svg[0]).toContain('data-source-arrow="none"');expect(output.svg[0]).not.toContain('data-d2-version');
});
test('SVG arrows retain none/triangle and both endpoints rather than boolean coercion',async({browser})=>{
 const model:FigureModel={subjects:[{id:'a',type:'rectangle',label:'Library'},{id:'b',type:'rectangle',label:'Profile'},{id:'c',type:'rectangle',label:'Scenario'}],relations:[{id:'ab',src:'a',dst:'b',label:'unoriented',srcArrow:'none',dstArrow:'none'},{id:'bc',src:'b',dst:'c',label:'directed',srcArrow:'none',dstArrow:'triangle'},{id:'ca',src:'c',dst:'a',label:'bidirectional',srcArrow:'triangle',dstArrow:'triangle'}]};
 const output=await exportFigure(composeFigure({...base,model},composeModelView),browser);
 const context=await browser.newContext();try{const page=await context.newPage();await page.setContent(output.svg[0]!);
 const markers=await page.locator('[data-scene-edge]>.scene-edge').evaluateAll(edges=>edges.map(edge=>({id:edge.parentElement!.getAttribute('data-scene-edge'),start:(edge as SVGElement).style.markerStart,end:(edge as SVGElement).style.markerEnd})));
 expect(markers.find(e=>e.id==='ab')).toMatchObject({start:'',end:''});expect(markers.find(e=>e.id==='bc')!.end).toContain('-triangle');expect(markers.find(e=>e.id==='ca')!.start).toContain('-triangle');expect(markers.find(e=>e.id==='ca')!.end).toContain('-triangle');
 }finally{await context.close();}
 const bad={...model,relations:[{id:'ab',src:'a',dst:'b',label:'',dstArrow:'diamond' as const}]};
 expect(()=>composeFigure({...base,model:bad},composeModelView)).toThrow('Unsupported SVG arrowhead');
});
test('native class method names and nullable SQL constraints render without a second member parser',async({browser})=>{
 const model:FigureModel={subjects:[{id:'Class',type:'class',label:'Worker',fields:[{name:'id',type:'int',visibility:'public'}],methods:[{name:'run()',return:'bool',visibility:'public'}]},{id:'Table',type:'sql_table',label:'Events',columns:[{name:{label:'id'},type:{label:'int'},constraint:[],reference:''}]}],relations:[]};
 const result=await exportFigure(composeFigure({...base,model},composeModelView),browser);
 expect(result.html).toContain('public run(): bool');expect(result.html).not.toContain('run()()');expect(result.html).toContain('id · int');
});
test('compound subjects can be real relation endpoints; virtual roots and invalid declarations refuse',async({browser})=>{
 const model:FigureModel={subjects:[{id:'owner',type:'part',label:'Project'},{id:'child',type:'part',parent:'owner',label:'Profile'},{id:'external',type:'part',label:'Library'}],relations:[{id:'oe',src:'owner',dst:'external',label:'selects',srcArrow:'none',dstArrow:'triangle'}]};
 const output=await exportFigure(composeFigure({...base,model},composeModelView),browser);expect(output.receipt.scenes[0]!.edges).toBe(1);
 expect(()=>composeFigure({...base,model},context=>composeDiagram(context,{graph:{id:'owner',children:[{id:'external'}]}}))).toThrow('root collides');
 expect(()=>composeFigure({...base,model,presentation:{icons:{Project:'model'}}},composeModelView)).toThrow('Unresolved presentation subject');
 expect(()=>composeFigure({...base,model,presentation:{options:{'elk.direction':123}}},composeModelView)).toThrow('ELK option must be text');
});
