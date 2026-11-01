import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {chromium} from 'playwright';
import {compileFigureSource,composeFigure,selectFigureVariant,composeTaste,reviewTaste,minimumTextSize,focalBudget} from '@deterministic-engineering/render';
import {exportFigure} from '@deterministic-engineering/render/export';
import {designCase,resources,choiceFor,answerSpace} from './design-case';
const root=fileURLToPath(new URL('../../../',import.meta.url)),file='docs/90-99-views/90-architecture-views/90.138-library-design-taste-choices.d2';
const input=await compileFigureSource({[file]:await readFile(path.join(root,file),'utf8')},file,resources);
const files=[...new Set([...Object.values(input.references),'packages/render/examples/design-choices.ts','packages/render/examples/design-case.ts','packages/render/src/design.ts','packages/render/src/taste.ts','packages/render/src/figure.ts','packages/render/src/diagram.ts','packages/render/src/export.ts','packages/render/src/scene-export.ts','packages/render/package.json'])];
const sources=Object.fromEntries(await Promise.all(files.map(async file=>[file,await readFile(path.join(root,file),'utf8')])));
const directory=path.join(root,'.cache/render/design-choices');await mkdir(directory,{recursive:true});
const candidates=[{name:'publication',input},...(input.variants??[]).map(variant=>({name:variant.name,input:selectFigureVariant(input,variant.name)}))];
const browser=await chromium.launch(),previews:string[]=[];
const esc=(text:string)=>text.replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]!));
try{for(const candidate of candidates){
 const figure=composeFigure({...candidate.input,sources},designCase),image=await exportFigure(figure,browser,{scale:1.5});
 const {choice,preferences}=choiceFor({presentation:candidate.input.presentation,layout:candidate.input.layout!});
 const taste=composeTaste(minimumTextSize(preferences.minimumTextSize),focalBudget(preferences.maximumFocals),answerSpace(preferences.maximumAnswerShare,candidate.input.copy!.preferences!));
 const report=reviewTaste(figure,image,taste);
 for(const[file,hash]of Object.entries(figure.sourceSHA256))if(createHash('sha256').update(await readFile(path.join(root,file))).digest('hex')!==hash)throw new Error('Stale design source: '+file);
 for(const[ext,value]of [['html',image.html],['png',image.png],['svg',image.svg[0]!],['json',JSON.stringify({sources:figure.sourceSHA256,receipt:image.receipt,taste:report},null,2)]]as const)await writeFile(path.join(directory,candidate.name+'.'+ext),value);
 previews.push(`<section><h2>${esc(choice.title)} · ${esc(candidate.input.design!.audience)}</h2><p>${esc(choice.reason)}</p><img src="data:image/png;base64,${Buffer.from(image.png).toString('base64')}" alt="${esc(choice.title)}"><p class="tradeoff">${esc(choice.tradeoff)}</p><ul>${report.judgments.flatMap(judgment=>judgment.notes.map(note=>`<li><b>${esc(note.kind)}</b> ${esc(note.message)}</li>`)).join('')}</ul></section>`);
 console.log(candidate.name,image.receipt.width,image.receipt.height,JSON.stringify(report.judgments.map(j=>[j.rule,j.notes.map(n=>n.kind)])));
 }
 const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><style>body{margin:0;background:#f2f4f3;color:#203d42;font:17px/1.5 Arial,sans-serif}main{width:1240px;margin:0;padding:24px}h1{font-size:28px;margin:0 0 8px}h2{font-size:22px;margin:0 0 8px}p{margin:0 0 14px}section{margin:20px 0 0;padding:18px;background:white;border-left:4px solid #087e82}img{width:100%;height:auto;display:block}.tradeoff{margin-top:10px;color:#66523e}ul{padding-left:22px;font-size:14px;margin-bottom:0}</style></head><body><main><h1>Same Library model. Three design choices.</h1><p>All five subjects and four relationships remain visible. Taste produces observations and advice, without choosing an automatic winner.</p>${previews.join('')}</main></body></html>`;
 const page=await browser.newPage({viewport:{width:1240,height:1000}});try{await page.setContent(html);await page.evaluate(()=>Promise.all(Array.from(document.images,image=>image.decode())));await writeFile(path.join(directory,'comparison.html'),html);await writeFile(path.join(directory,'comparison.png'),await page.locator('main').screenshot({type:'png'}));}finally{await page.close();}
}finally{await browser.close();}
