// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {test,expect} from 'playwright/test';
import {composeFigure,type FigureInput,type FigureComposer} from '../src/figure';
import {composeDiagram,type DiagramSpec} from '../src/diagram';
import {composePresentationTheme} from '../src/presentation-theme';
import {exportFigure} from '../src/export';
const input:FigureInput={view:{source:'model.d2',title:'Measured architecture',purpose:'architecture',kind:'dependency-map',question:{ref:'q',text:'Who owns the declarations?'},basis:{captureRef:'candidate',modelRefs:[],obligationRefs:[],evidenceRefs:[]}},width:1000,language:'en',sources:{'model.d2':'captured model'},references:{source:'model.d2'},questions:[{ref:'q',text:'Who owns the declarations?',focusRefs:['source']}],model:{subjects:[{id:'a',type:'rectangle',label:'Library publisher\nModels, methods and obligations'},{id:'b',type:'rectangle',label:'Project selection\nProfile and Scenario'}],relations:[{id:'ab',src:'a',dst:'b',label:'publishes definitions'}]}};
const spec:DiagramSpec={graph:{id:'scene',children:[{id:'a'},{id:'b'}],layoutOptions:{'elk.direction':'RIGHT'}},icons:{a:'library',b:'capture'}};
const composer=(specification=spec,css=''):FigureComposer=>context=>{const scene=composeDiagram(context,specification);return{markup:`<section data-question="q">${scene.markup}</section>`,css:scene.css+css};};
test('measured ELK scene exports offline vector SVG and PNG with bounded glyphs',async({browser})=>{
 const before=browser.contexts().length;
 const figure=composeFigure(input,composer());
 const a=await exportFigure(figure,browser),b=await exportFigure(figure,browser);
 expect(a.receipt.scenes[0]!.nodes).toBe(2);expect(a.receipt.scenes[0]!.edges).toBe(1);
 expect(a.receipt.routing).toBe('elkjs@0.12.1');expect(a.receipt.scenes[0]!.layoutSHA256).toBe(b.receipt.scenes[0]!.layoutSHA256);
 expect(a.receipt.pngSHA256).toBe(b.receipt.pngSHA256);const difference=a.svg.map((svg,index)=>{const other=b.svg[index]!;let offset=0;while(offset<svg.length&&svg[offset]===other[offset])offset++;return offset<svg.length?{index,offset,a:svg.slice(Math.max(0,offset-50),offset+180),b:other.slice(Math.max(0,offset-50),offset+180)}:null;}).filter(Boolean);
 expect(a.receipt.svgSHA256,JSON.stringify(difference)).toEqual(b.receipt.svgSHA256);
 expect(a.svg).toHaveLength(2);expect(a.svg[0]).toContain('data:font/woff2;base64,');
 expect(a.svg[0]).not.toMatch(/foreignObject|data:image\/png|data-d2-version/);
 expect(a.html).toContain('width="32" height="32"');
 const context=await browser.newContext();try{const page=await context.newPage();await page.setContent(`<img src="data:image/svg+xml;base64,${Buffer.from(a.svg[0]!).toString('base64')}">`);expect(await page.locator('img').evaluate(async(image:HTMLImageElement)=>{await image.decode();return image.naturalWidth;})).toBe(input.width);}finally{await context.close();}
 expect(browser.contexts()).toHaveLength(before);
});
test('declarations cannot invent nodes, edges or unsupported SVG capabilities',()=>{
 expect(()=>composeFigure(input,composer({...spec,graph:{id:'scene',children:[{id:'unknown'}]}}))).toThrow('Undeclared diagram node');
 expect(()=>composeFigure(input,composer({...spec,graph:{id:'scene',children:[{id:'a'},{id:'a'}]}}))).toThrow('Duplicate');
 expect(()=>composeFigure(input,composer({...spec,graph:{...spec.graph,edges:[{id:'ab',sources:['b'],targets:['a']}]}}))).toThrow('Undeclared diagram relation');
 expect(()=>composeFigure(input,composer({...spec,graph:{...spec.graph,layoutOptions:{'elk.edgeRouting':'SPLINES'}}}))).toThrow('Unsupported SVG edge routing');
});
test('layout failure cleans worker/context; a separate valid export recovers',async({browser})=>{
 const before=browser.contexts().length;
 await expect(exportFigure(composeFigure(input,composer({...spec,graph:{...spec.graph,layoutOptions:{'elk.algorithm':'does-not-exist'}}})),browser)).rejects.toThrow();
 expect(browser.contexts()).toHaveLength(before);
 expect((await exportFigure(composeFigure(input,composer()),browser)).receipt.scenes).toHaveLength(1);
});
test('post-layout CSS cannot move text outside its measured node or overlap nodes',async({browser})=>{
 await expect(exportFigure(composeFigure(input,composer(spec,'.scene-content{transform:translateX(1000px)}')),browser)).rejects.toThrow('scene content outside node');
 await expect(exportFigure(composeFigure(input,composer(spec,'[data-scene-node]{transform:none!important}')),browser)).rejects.toThrow('overlapping scene nodes');
});

test('scene hand drawing delegates actual measured frames to Rough.js',async({browser})=>{
 const precise=await exportFigure(composeFigure(input,composer()),browser);
 const sketch=await exportFigure(composeFigure({...input,theme:composePresentationTheme(['sketchbook'])},composer()),browser);
 expect(sketch.receipt.drawing).toBe('roughjs@4.6.6');
 expect(sketch.svg[0]).toContain('sketch-surface');expect(sketch.svg[0]).toContain('opacity="0"');
 expect(sketch.receipt.scenes[0]!.inputSHA256).not.toBe(precise.receipt.scenes[0]!.inputSHA256);
 expect(sketch.receipt.pngSHA256).not.toBe(precise.receipt.pngSHA256);
});

test('theme surfaces compose as SVG assets and cannot mutate captured theme',async({browser})=>{
 const theme=composePresentationTheme(['editorial']);const graph={...spec,roles:{a:'publication'}};
 const output=await exportFigure(composeFigure({...input,theme},composer(graph)),browser);
 expect(output.svg[0]).toContain('preserveAspectRatio="none"');expect(output.svg[0]).toContain('class="scene-surface"');
 expect(output.receipt.pngSHA256).not.toBe((await exportFigure(composeFigure(input,composer()),browser)).receipt.pngSHA256);
 expect(()=>composeFigure({...input,theme},context=>{(context.theme.surfaces!.publication as {svg:string}).svg='changed';return composer(graph)(context);})).toThrow();
 const invalid={...theme,surfaces:{publication:{label:'bad',svg:'<div>wrong surface</div>'}}};
 expect(()=>composeFigure({...input,theme:invalid},composer(graph))).toThrow('Invalid declared scene surface');
});

test('theme layout preferences reach ELK and explicit view options take precedence',async({browser})=>{
 const theme={...composePresentationTheme(['editorial']),layoutOptions:{'elk.algorithm':'does-not-exist'}};
 await expect(exportFigure(composeFigure({...input,theme},composer()),browser)).rejects.toThrow();
 const selected={...spec,graph:{...spec.graph,layoutOptions:{...spec.graph.layoutOptions,'elk.algorithm':'layered'}}};
 expect((await exportFigure(composeFigure({...input,theme},composer(selected)),browser)).receipt.scenes).toHaveLength(1);
});

test('computed CSS property enumeration order does not change vector bytes',async({browser})=>{
 // Negative environment control: CSSOM enumeration is not a serialization order.
 const reversed=new Proxy(browser,{get(target,key){
  if(key==='newContext')return async(...args:Parameters<typeof browser.newContext>)=>{
   const context=await target.newContext(...args);
   await context.addInitScript(()=>{
    const original=CSSStyleDeclaration.prototype[Symbol.iterator];
    CSSStyleDeclaration.prototype[Symbol.iterator]=function(){return Array.from(original.call(this)).reverse()[Symbol.iterator]();};
   });return context;
  };
  const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value;
 }});
 const figure=composeFigure(input,composer());
 const a=await exportFigure(figure,browser),b=await exportFigure(figure,reversed);
 expect(a.receipt.pngSHA256).toBe(b.receipt.pngSHA256);
 expect(a.receipt.scenes[0]!.layoutSHA256).toBe(b.receipt.scenes[0]!.layoutSHA256);
 expect(a.receipt.svgSHA256).toEqual(b.receipt.svgSHA256);
});
