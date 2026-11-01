// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {chromium} from 'playwright';
import {compileFigureSource,composeFigure,composeHeading,selectFigureVariant,selectTaste,reviewTaste,type FigureComposer} from '@deterministic-engineering/render';
import {exportFigure} from '@deterministic-engineering/render/export';
import {designCase,designTaste} from './design-case';
import {attributionFor} from './attribution';
const root=fileURLToPath(new URL('../../../',import.meta.url)),file='docs/90-99-views/90-architecture-views/90.138-library-design-taste-choices.d2';
const input=await compileFigureSource({[file]:await readFile(path.join(root,file),'utf8')},file);
const files=[...new Set([...Object.values(input.references),'packages/render/examples/design-choices.ts','packages/render/examples/design-case.ts','packages/render/examples/attribution.ts',...['design','taste','taste-selection','taste-policies','model-view','figure','diagram','export','scene-export'].map(name=>'packages/render/src/'+name+'.ts'),'packages/render/package.json'])];
const sources=Object.fromEntries(await Promise.all(files.map(async file=>[file,await readFile(path.join(root,file),'utf8')])));
const directory=path.join(root,'.cache/render/design-choices');await mkdir(directory,{recursive:true});
const candidates=input.variants?.length?input.variants.map(variant=>({name:variant.name,input:selectFigureVariant(input,variant.name)})):[{name:'selected',input}];
const browser=await chromium.launch(),previews:{name:string;image:string;hash:string;drawing:string}[]=[];
try{for(const candidate of candidates){
 if(!/^[a-z0-9-]+$/.test(candidate.name))throw new Error('Invalid publication filename');
 const selected=selectTaste({...candidate.input,sources},designTaste);
 const figure=composeFigure(selected,designCase),image=await exportFigure(figure,browser,{scale:1.5,attribution:attributionFor(figure)}),report=reviewTaste(figure,image,designTaste);
 for(const[file,hash]of Object.entries(figure.sourceSHA256))if(createHash('sha256').update(await readFile(path.join(root,file))).digest('hex')!==hash)throw new Error('Stale design source: '+file);
 for(const[ext,value]of [['html',image.html],['png',image.png],['svg',image.svg[0]!],['json',JSON.stringify({sources:figure.sourceSHA256,receipt:image.receipt,taste:report},null,2)]]as const)await writeFile(path.join(directory,candidate.name+'.'+ext),value);
 previews.push({name:candidate.name,image:Buffer.from(image.png).toString('base64'),hash:image.receipt.pngSHA256,drawing:image.receipt.drawing});
 console.log(candidate.name,selected.design!.focalSubjects,JSON.stringify(image.receipt.scenes.map(scene=>scene.layoutSHA256)),image.receipt.drawing);
 }
 const question=input.questions.find(question=>question.ref===input.view.question.ref)!;
 const comparison:FigureComposer=context=>{
  const title=composeHeading(context,{role:'title',text:context.copy('comparison-title')}),note=composeHeading(context,{role:'note',text:context.copy('comparison-note')});
  return{markup:`<main data-question="${context.text(question.ref)}">${title.markup}${note.markup}${previews.map(preview=>`<section><img src="data:image/png;base64,${preview.image}" alt="${context.text(preview.name)}"></section>`).join('')}</main>`,css:title.css+note.css+'[data-figure]{padding:20px}main>svg{margin-bottom:10px}section{margin-top:18px;border-top:1px dashed var(--border)}img{display:block;width:100%;height:auto}'};
 };
 const figure=composeFigure({...input,questions:[question],view:{...input.view,question},design:undefined,evidence:undefined,sources},comparison);
 const image=await exportFigure(figure,browser,{attribution:attributionFor(figure)});
 await writeFile(path.join(directory,'comparison.html'),image.html);await writeFile(path.join(directory,'comparison.png'),image.png);await writeFile(path.join(directory,'comparison.json'),JSON.stringify({sources:figure.sourceSHA256,receipt:image.receipt,candidates:previews.map(({image:_,...value})=>value)},null,2));
}finally{await browser.close();}
