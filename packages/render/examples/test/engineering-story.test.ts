// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect} from 'bun:test';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {compileFigureSource,composeFigure} from '@deterministic-engineering/render';
import {overview} from '../overview-composition';
const root=new URL('../../../../',import.meta.url),file='docs/90-99-views/90-architecture-views/90.02-agent-evidence-loop.d2';
async function capture(){const input=await compileFigureSource({[file]:await readFile(new URL(file,root),'utf8')},file);return{...input,sources:{...input.sources,...Object.fromEntries(await Promise.all(Object.values(input.references).map(async path=>[path,await readFile(new URL(path,root),'utf8')])))} };}
test('engineering overview preserves the original seven subjects and ten feedback associations',async()=>{
 const input=await capture();expect(input.model!.subjects.map(node=>node.id).sort()).toEqual(['agent','aitia','ascent','experiments','library','observations','view']);
 expect(input.model!.relations.map(edge=>[edge.src,edge.dst,edge.label])).toEqual(expect.arrayContaining([
 ['library','ascent','domain facts and associations'],['agent','ascent','caller-selected questions and scope'],['ascent','view','current truthful evidence'],['view','agent','inform; do not rank or choose'],['agent','experiments','choose, revise, or invent'],['experiments','observations','record results and failures'],['observations','ascent','checked support and changed premises'],['ascent','aitia','references with explicit scope'],['aitia','observations','actual execution / operational feedback'],['agent','library','propose reviewed extensions']]));
 expect(Object.fromEntries(input.model!.subjects.map(subject=>[subject.id,subject.label?.replace(/\s+/g,' ')]))).toEqual({
  agent:'LLM-based AI agent Engineering reasoning Questions, alternatives, new hypotheses',library:'POO design Library Domains, contracts, extensible knowledge',ascent:'ASCENT Evidence Chain + DAG + Trajectory',view:'Progressive evidence view Support, counterevidence, unknowns Current references and deeper reads',experiments:'LLM-based AI agent investigation Source inspection, QNT, Lean, experiments',observations:'Bound observations Premises, source, result, scope',aitia:'Aitia / Host boundary Scoped admission, authorization, effects'
 });
 expect(input.model!.relations).toHaveLength(10);expect(input.design!.requiredRelations).toHaveLength(10);
 const figure=composeFigure(input,overview);expect(figure.drawing.mode).toBe('sketch');expect(figure.fonts.some(font=>font.family==='Kalam')).toBe(true);expect(figure.html).toContain('story-takeaway');
 expect(()=>composeFigure({...input,presentation:{sections:[{questionRef:'invented',ordinal:'1'}]}},overview)).toThrow();
 expect(()=>composeFigure({...input,presentation:{sections:[],shortLabels:{invented:'Wrong subject'}}},overview)).toThrow('Unknown story caption');
 expect(()=>composeFigure({...input,presentation:{sections:[{questionRef:'purpose',ordinal:'1',relationRefs:['invented']}]}},overview)).toThrow('Unknown story relation');
},30000);
test('README workflow displays the actual sketch PNG and keeps its current source/output binding',async()=>{
 const readme=await readFile(new URL('README.org',root),'utf8');const section=readme.split('* Engineering workflow')[1]!.split('\n* ')[0]!;
 expect(section).toContain('[[file:'+file.replace('.d2','.png')+']]');expect(section).not.toContain('[[file:'+file.replace('.d2','.svg')+']]');
 const receipt:{drawing:string;pngSHA256:string;sources:Record<string,string>;width:number;height:number;readability:{minimumTextSize:number};observation:{subjects:{id:string}[];relations:string[];headings:{role:string}[]}}=JSON.parse(await readFile(new URL(file.replace('.d2','.json'),root),'utf8'));
 expect(receipt.drawing).toBe('roughjs@4.6.6');expect(receipt.readability.minimumTextSize).toBeGreaterThanOrEqual(12);expect(receipt.height/receipt.width).toBeLessThan(1.6);expect(new Set(receipt.observation.subjects.map(subject=>subject.id)).size).toBe(7);expect(receipt.observation.relations).toHaveLength(10);expect(receipt.observation.headings.filter(heading=>heading.role==='question')).toHaveLength(6);const sha=(data:Uint8Array|string)=>createHash('sha256').update(data).digest('hex');
 expect(sha(await readFile(new URL(file.replace('.d2','.png'),root)))).toBe(receipt.pngSHA256);
 const svg=await readFile(new URL(file.replace('.d2','.svg'),root),'utf8');expect(svg).toContain('data-vector-surface');expect(svg).not.toContain('foreignObject');
 for(const[path,fingerprint]of Object.entries(receipt.sources))expect(sha(await readFile(new URL(path,root)))).toBe(fingerprint);
});
