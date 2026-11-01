// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {test,expect} from 'playwright/test';
import type {Browser} from 'playwright';
import {composeFigure,type FigureInput} from '../src/figure';
import {composeModelView} from '../src/model-view';
import {composeHeading} from '../src/heading';
import {composePresentationTheme,extendPresentationTheme} from '../src/presentation-theme';
import {exportFigure,type FigureImage} from '../src/export';
const input:FigureInput={view:{source:'case.d2',title:'Library ownership',purpose:'architecture',kind:'dependency-map',question:{ref:'q',text:'Who publishes and selects?'},basis:{captureRef:'candidate',modelRefs:[],obligationRefs:[],evidenceRefs:[]}},width:1100,language:'en',sources:{'case.d2':'source'},references:{source:'case.d2'},questions:[{ref:'q',text:'Who publishes and selects?',focusRefs:['source']},{ref:'scope',text:'Which inputs remain project-owned?',focusRefs:['source']}],model:{subjects:[{id:'library',type:'rectangle',label:'Library\nModels and methods'},{id:'profile',type:'rectangle',label:'Profile\nSelect published declarations'},{id:'scenario',type:'rectangle',label:'Scenario\nBind actual project inputs'}],relations:[{id:'selects',src:'profile',dst:'library',label:'selects'},{id:'binds',src:'scenario',dst:'profile',label:'binds'}]}};
async function boxes(image:FigureImage,browser:Browser){const context=await browser.newContext();try{const page=await context.newPage();await page.setContent(image.html);await page.evaluate(()=>document.fonts.ready);return await page.locator('[data-scene-node]').evaluateAll(nodes=>nodes.map(node=>{const box=node.querySelector('.scene-frame')!.getBoundingClientRect();return{id:node.getAttribute('data-scene-node'),x:box.x,y:box.y,w:box.width,h:box.height};}));}finally{await context.close();}}
test('automatic model layout honors theme direction and explicit source options win',async({browser})=>{
 const make=(layers:string[],presentation?:unknown)=>exportFigure(composeFigure({...input,presentation,theme:composePresentationTheme(layers)},composeModelView),browser);
 const down=await make(['layered-down']),right=await make(['layered-right']),explicit=await make(['layered-down'],{options:{'elk.direction':'RIGHT'}});
 const d=await boxes(down,browser),r=await boxes(right,browser);
 expect(Math.abs(d[0]!.x+d[0]!.w/2-d[2]!.x-d[2]!.w/2)).toBeLessThan(2);expect(Math.abs(d[0]!.y-d[2]!.y)).toBeGreaterThan(100);
 expect(Math.abs(r[0]!.y+r[0]!.h/2-r[2]!.y-r[2]!.h/2)).toBeLessThan(2);expect(Math.abs(r[0]!.x-r[2]!.x)).toBeGreaterThan(100);
 expect(explicit.receipt.scenes[0]!.layoutSHA256).toBe(right.receipt.scenes[0]!.layoutSHA256);
 expect(down.html.indexOf('Who publishes')).toBeLessThan(down.html.indexOf('Which inputs'));
 expect(down.receipt.readability.samples).toBeGreaterThan(6);
});
test('typography, icon and spacing tokens change real measurements without density font shrinking',async({browser})=>{
 const base=composePresentationTheme(['compact','layered-down']);
 const large=extendPresentationTheme(base,{typography:{titleSize:'26px',detailSize:'20px',lineHeight:'2em'},spacing:{scenePadding:30,iconSize:50,iconGap:20}});
 const make=(theme:typeof base)=>exportFigure(composeFigure({...input,theme,presentation:{icons:{library:'library'}}},composeModelView),browser);
 const a=await make(base),b=await make(large),ab=await boxes(a,browser),bb=await boxes(b,browser);
 expect(bb[0]!.w).toBeGreaterThan(ab[0]!.w);expect(bb[0]!.h).toBeGreaterThan(ab[0]!.h);
 expect(b.html).toContain('width="50" height="50"');
 await expect(exportFigure(composeFigure({...input,theme:large},composeModelView),browser,{minimumTextSize:40})).rejects.toThrow('declared minimum');
 await expect(exportFigure(composeFigure(input,composeModelView),browser,{minimumTextSize:NaN})).rejects.toThrow('Invalid minimum');
 const compressed=extendPresentationTheme(base,{typography:{lineHeight:'0em'}});
 await expect(exportFigure(composeFigure({...input,theme:compressed},composeModelView),browser)).rejects.toThrow('overlapping scene text lines');
});
test('browser validates open downstream palette values',async({browser})=>{
 const base=composePresentationTheme(['ocean']);
 const custom=extendPresentationTheme(base,{colors:{domainAccent:'oklch(60% 0.15 240)'}});
 expect((await exportFigure(composeFigure({...input,theme:custom},composeModelView),browser)).html).toContain('--domainAccent:oklch');
 await expect(exportFigure(composeFigure({...input,theme:extendPresentationTheme(base,{colors:{domainAccent:'invalid-color'}})},composeModelView),browser)).rejects.toThrow('Invalid CSS palette color');
});
test('semantic heading aligns the whole ordinal/glyph/text group; roles and icons stay distinct',async({browser})=>{
 const single={...input,questions:[input.questions[0]!]};
 for(const layers of [['editorial'],['sketchbook','ocean'],['node-editor','ember']]){
  const figure=composeFigure({...single,theme:composePresentationTheme(layers)},context=>{
   const parts=[composeHeading(context,{role:'question',questionRef:'q',text:context.question('q').text}),composeHeading(context,{role:'answer',text:'Library publishes reusable definitions',glyph:'library'}),composeHeading(context,{role:'domain-heading',text:'A project-owned role',ordinal:'A.1',glyph:'model'})];
   return{markup:parts.map(p=>p.markup).join(''),css:parts.map(p=>p.css).join('')};
  });
  const output=await exportFigure(figure,browser);const context=await browser.newContext();
  try{const page=await context.newPage();await page.setContent(output.html);await page.evaluate(()=>document.fonts.ready);
   const observations=await page.locator('[data-heading-role]').evaluateAll(headings=>headings.map(heading=>{const parts=Array.from(heading.querySelectorAll('[data-annotation-part]')).map(part=>part.getBoundingClientRect());return{role:heading.getAttribute('data-heading-role'),parts:parts.map(box=>({left:box.left,right:box.right,cy:box.y+box.height/2})),glyphs:heading.querySelectorAll('[data-annotation-part="glyph"]').length};}));
   expect(observations[0]!.glyphs).toBe(0);expect(await page.locator('[data-heading-role=question] [data-annotation-part=ordinal] text').textContent()).toBe('?');expect(observations[1]!.glyphs).toBe(1);
   for(const row of observations)for(let i=1;i<row.parts.length;i++){expect(Math.abs(row.parts[i]!.cy-row.parts[0]!.cy)).toBeLessThan(1);expect(row.parts[i]!.left).toBeGreaterThan(row.parts[i-1]!.right);}
  }finally{await context.close();}
 }
 expect(()=>composeFigure(single,context=>composeHeading(context,{role:'question',questionRef:'q',text:'Invented question'}))).toThrow('differs from selected');
 const bad=composeFigure(single,context=>{const part=composeHeading(context,{role:'question',questionRef:'q',text:context.question('q').text,ordinal:2,glyph:'library'});return{...part,css:part.css+'[data-annotation-content]{transform:translateX(2000px)!important}'};});
 await expect(exportFigure(bad,browser)).rejects.toThrow('clipped vector annotation');
 const overlap=composeFigure(single,context=>{const part=composeHeading(context,{role:'question',questionRef:'q',text:context.question('q').text,glyph:'library'});return{...part,css:part.css+'[data-annotation-part]{transform:none!important}'};});
 await expect(exportFigure(overlap,browser)).rejects.toThrow('overlapping heading parts');
});
test('independent SVG images decode with a default canvas and explicit transparent opt-in',async({browser})=>{
 const figure=composeFigure({...input,theme:composePresentationTheme(['ocean','layered-down'])},composeModelView);
 const opaque=await exportFigure(figure,browser),transparent=await exportFigure(figure,browser,{transparent:true});
 const context=await browser.newContext();try{const page=await context.newPage();
  for(const[output,alpha]of [[opaque,255],[transparent,0]]as const)for(const data of [...[output.svg[0]!,output.svg[1]!].map(svg=>'data:image/svg+xml;base64,'+Buffer.from(svg).toString('base64')),'data:image/png;base64,'+Buffer.from(output.png).toString('base64')]){
   const actual=await page.evaluate(async(source)=>{const image=new Image();image.src=source;await image.decode();const canvas=document.createElement('canvas');canvas.width=image.naturalWidth;canvas.height=image.naturalHeight;const ctx=canvas.getContext('2d')!;ctx.drawImage(image,0,0);return ctx.getImageData(0,0,1,1).data[3];},data);
   expect(actual).toBe(alpha);
  }
 }finally{await context.close();}
});

test('declared HTML surfaces survive PNG and vector export with nested paint order',async({browser})=>{
 const single={...input,questions:[input.questions[0]!]};
 for(const layer of ['ocean','sketchbook']){
  const figure=composeFigure({...single,theme:composePresentationTheme([layer])},context=>{
   const q=composeHeading(context,{role:'question',questionRef:'q',text:context.question('q').text});
   const a=composeHeading(context,{role:'answer',text:'Library',glyph:'library'});
   return{markup:`<section data-surface data-region="outer">${q.markup}<article data-surface>${a.markup}</article></section>`,css:q.css+a.css+'[data-figure]{padding:20px}[data-region=outer]{padding:20px;background:var(--tint);border:1px solid var(--border);border-radius:12px}article{margin-top:20px;padding:20px;background:var(--secondaryTint);border:1px solid var(--border);border-radius:8px}'};
  });
  const output=await exportFigure(figure,browser),context=await browser.newContext();
  try{const page=await context.newPage();await page.setContent(output.html);
   expect(await page.locator('svg[data-vector-surface]').count()).toBe(2);
   const samples=await page.locator('[data-surface]').evaluateAll(elements=>elements.map(element=>{const box=element.getBoundingClientRect();return {x:Math.ceil(box.x+15),y:Math.ceil(box.y+15)};}));
   const pixels=[];
   for(const data of ['data:image/png;base64,'+Buffer.from(output.png).toString('base64'),'data:image/svg+xml;base64,'+Buffer.from(output.svg[0]!).toString('base64')])pixels.push(await page.evaluate(async({data,samples})=>{const image=new Image();image.src=data;await image.decode();const canvas=document.createElement('canvas');canvas.width=image.naturalWidth;canvas.height=image.naturalHeight;const ctx=canvas.getContext('2d')!;ctx.drawImage(image,0,0);return samples.map(({x,y})=>Array.from(ctx.getImageData(x,y,1,1).data));},{data,samples}));
   expect(pixels[1]).toEqual(pixels[0]);
   const order=await page.locator('svg[data-vector-surface],svg[data-vector-annotation]').evaluateAll(elements=>elements.map(element=>element.hasAttribute('data-vector-surface')?'surface':element.getAttribute('data-heading-role')));
   expect(order).toEqual(['surface','question','surface','answer']);
  }finally{await context.close();}
 }
 const gradient=composeFigure(single,context=>{const q=composeHeading(context,{role:'question',questionRef:'q',text:context.question('q').text});return{markup:`<div data-surface>${q.markup}</div>`,css:q.css+'[data-surface]{background-image:linear-gradient(red,blue)}'};});
 await expect(exportFigure(gradient,browser)).rejects.toThrow('explicit SVG');
});
