// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {attributionFor} from './attribution';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {chromium} from 'playwright';
import {compileFigureSource,composeFigure,selectFigureVariant} from '@deterministic-engineering/render';
import {exportFigure} from '@deterministic-engineering/render/export';
import {overview} from './overview-composition';
const root=fileURLToPath(new URL('../../../',import.meta.url));
const names=['90.02-agent-evidence-loop','90.129-functional-architecture-rendering','90.130-llm-assisted-model-view-workflow','90.134-render-responsibility-boundaries','90.135-library-project-architecture','90.136-model-adaptation-boundaries','90.137-functional-render-composition'];
const directory='docs/90-99-views/90-architecture-views/';
const output=path.join(root,'.cache/render/overviews');await mkdir(output,{recursive:true});
const browser=await chromium.launch();
try{for(const name of names){
 const file=directory+name+'.d2',source=await readFile(path.join(root,file),'utf8');
 const input=await compileFigureSource({[file]:source},file);
 const extra=Object.fromEntries(await Promise.all([...new Set(['packages/render/examples/attribution.ts','packages/render/examples/overviews.ts','packages/render/examples/overview-composition.ts',...Object.values(input.references)])].map(async file=>[file,await readFile(path.join(root,file),'utf8')])));
 const candidates=[{name,input},...(input.variants??[]).map(variant=>({name:name+'-'+variant.name,input:selectFigureVariant(input,variant.name)}))];
 for(const candidate of candidates){
 const figure=composeFigure({...candidate.input,sources:{...candidate.input.sources,...extra}},overview);
 const outputName=candidate.name;
 const result=await exportFigure(figure,browser,{scale:1.5,attribution:attributionFor(figure)});
 for(const[file,source]of Object.entries(figure.sourceSHA256)) { const {createHash}=await import('node:crypto');if(createHash('sha256').update(await readFile(path.join(root,file))).digest('hex')!==source)throw new Error('Stale overview source: '+file); }
 await writeFile(path.join(output,outputName+'.html'),result.html);await writeFile(path.join(output,outputName+'.png'),result.png);
 for(const[index,svg]of result.svg.entries())await writeFile(path.join(output,outputName+(index===0?'':`-scene-${index}`)+'.svg'),svg);
 await writeFile(path.join(output,outputName+'.json'),JSON.stringify({...result.receipt,sources:figure.sourceSHA256},null,2));
 console.log(outputName,result.receipt.width,result.receipt.height,'TS measured scenes',result.receipt.scenes.length);
}}}finally{await browser.close();}
