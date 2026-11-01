// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {test,expect} from 'playwright/test';
import {composeFigure,type FigureInput} from '../src/figure';
import {composeDiagram} from '../src/diagram';
import {exportFigure} from '../src/export';

// A nested responsibility lane gives edge coordinates a non-root origin.
const input:FigureInput={view:{source:'compound.d2',title:'Compound edge origin',purpose:'workflow',kind:'flow',question:{ref:'q',text:'Do lane-local edges reach their actual nodes?'},basis:{captureRef:'candidate',modelRefs:[],obligationRefs:[],evidenceRefs:[]}},width:900,language:'en',sources:{'compound.d2':'outer.inner.a -> outer.inner.b'},references:{source:'compound.d2'},questions:[{ref:'q',text:'Do lane-local edges reach their actual nodes?',focusRefs:['source']}],model:{subjects:[{id:'outer',type:'rectangle',label:'Rust owner'},{id:'inner',type:'rectangle',label:'Execution lane'},{id:'a',type:'rectangle',label:'Consume'},{id:'b',type:'rectangle',label:'Final send'}],relations:[{id:'ab',src:'a',dst:'b',label:''}]}};
test('compound lane edges use the actual ELK container origin',async({browser})=>{
 const figure=composeFigure(input,context=>{const scene=composeDiagram(context,{graph:{id:'root',children:[{id:'outer',children:[{id:'inner',children:[{id:'a'},{id:'b'}]}]}],layoutOptions:{'elk.direction':'DOWN','elk.hierarchyHandling':'INCLUDE_CHILDREN'}},edgeLabels:false});return {markup:`<section data-question="q">${scene.markup}</section>`,css:scene.css};});
 const exported=await exportFigure(figure,browser);
 const context=await browser.newContext();try{
  const page=await context.newPage();await page.setContent(exported.svg[0]!);
  const endpoints=await page.evaluate(()=>{
   const path=document.querySelector<SVGPathElement>('[data-scene-edge="ab"] path')!;
   const ctm=path.getScreenCTM()!;
   const point=(length:number)=>{const p=path.getPointAtLength(length);return new DOMPoint(p.x,p.y).matrixTransform(ctm);};
   const check=(id:string,p:DOMPoint)=>{
    const rect=document.querySelector(`[data-scene-node="${id}"]>rect`)!.getBoundingClientRect();
    const outside=Math.max(rect.left-p.x,p.x-rect.right,rect.top-p.y,p.y-rect.bottom,0);
    const boundary=Math.min(Math.abs(p.x-rect.left),Math.abs(p.x-rect.right),Math.abs(p.y-rect.top),Math.abs(p.y-rect.bottom));
    return {outside,boundary};
   };
   return [check('a',point(0)),check('b',point(path.getTotalLength()))];
  });
  for(const endpoint of endpoints){expect(endpoint.outside).toBeLessThan(2);expect(endpoint.boundary).toBeLessThan(2);}
 }finally{await context.close();}
});

test('scope containment refuses moved descendants and internally routed relations',async({browser})=>{
 const make=(css:string)=>composeFigure(input,context=>{const scene=composeDiagram(context,{graph:{id:'root',children:[{id:'outer',children:[{id:'inner',children:[{id:'a'},{id:'b'}]}]}]},edgeLabels:false});return{markup:`<section data-question="q">${scene.markup}</section>`,css:scene.css+css};});
 await expect(exportFigure(make('[data-scene-node="a"]{transform:translateX(1200px)!important}'),browser)).rejects.toThrow('outside owner scope');
 await expect(exportFigure(make('[data-scene-edge]{transform:translateX(1200px)!important}'),browser)).rejects.toThrow('internal relation outside owner scope');
 const output=await exportFigure(make(''),browser);
 expect(output.receipt.observation.subjects.find(subject=>subject.id==='a')!.owner).toBe('inner');
});

test('cross-boundary relationships may leave a scope and remain explicitly distinguished',async({browser})=>{
 const candidate={...input,model:{subjects:[{id:'scope',type:'rectangle',label:'Project'},{id:'inside',type:'rectangle',label:'Profile'},{id:'outside',type:'rectangle',label:'Library'}],relations:[{id:'selected',src:'inside',dst:'outside',label:'selects'}]}};
 const figure=composeFigure(candidate,context=>{const scene=composeDiagram(context,{graph:{id:'root',children:[{id:'scope',children:[{id:'inside'}]},{id:'outside'}]}});return{markup:`<section data-question="q">${scene.markup}</section>`,css:scene.css};});
 const image=await exportFigure(figure,browser);expect(image.html).toContain('data-crosses-boundary="true"');
 expect(image.receipt.observation.subjects.find(subject=>subject.id==='inside')!.owner).toBe('scope');
 expect(image.receipt.observation.relations).toContain('selected');
});
