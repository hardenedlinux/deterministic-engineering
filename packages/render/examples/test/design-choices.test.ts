// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect} from 'bun:test';
import {readFile} from 'node:fs/promises';
import {compileFigureSource,composeFigure,selectFigureVariant,selectTaste,modelDiagram} from '@deterministic-engineering/render';
import {resources} from '../library-case/resources';
import {designCase,designTaste} from '../design-case';
const root=new URL('../../../../',import.meta.url),file='docs/90-99-views/90-architecture-views/90.138-library-design-taste-choices.d2';
test('one model and one Taste program respond to source-selected Questions/evidence',async()=>{
 const input=await compileFigureSource({[file]:await readFile(new URL(file,root),'utf8')},file);
 const sources={...input.sources,...Object.fromEntries(await Promise.all(Object.values(input.references).map(async file=>[file,await readFile(new URL(file,root),'utf8')])))};
 const focal:string[][]=[],directions:string[]=[];
 for(const variant of input.variants!){
  const candidate=selectFigureVariant({...input,sources},variant.name);expect(candidate.design!.focalSubjects).toEqual([]);expect(candidate.presentation).toBe(input.presentation);
  const selected=selectTaste(candidate,designTaste);expect(selected.model).toEqual(input.model);expect(selected.design!.requiredRelations).toEqual(input.design!.requiredRelations);
  expect(selected.design!.requiredSubjects).toHaveLength(5);expect(selected.design!.requiredRelations).toHaveLength(4);
  focal.push([...selected.design!.focalSubjects]);directions.push(modelDiagram(selected.model!,selected.presentation).graph.layoutOptions!['elk.direction']!);
  expect(composeFigure(selected,designCase).html).toContain('dependency-layout');
 }
 expect(focal).toEqual([['library'],['project.scenario'],['project.scenario']]);expect(directions).toEqual(['UP','DOWN','DOWN']);
},30000);

test('README images use one sketchbook language while alternate styles stay in package declarations',async()=>{
 const readme=await readFile(new URL('README.org',root),'utf8');
 const paths=[...readme.matchAll(/\[\[file:([^\]]+\.(?:png|svg))\]/g)].map(match=>match[1]!);
 expect(paths.length).toBeGreaterThan(5);
 for(const path of paths){
  if(path.includes('90.138-')){expect(path).not.toMatch(/publication|project\.png|matrix/);continue;}
  const file=path.replace(/(?:-sketchbook)?(?:-detail)?\.(?:png|svg)$/,'.d2');
  const source=await readFile(new URL(file,root),'utf8');const declaration=await compileFigureSource({[file]:source},file,resources);
  const selected=path.includes('-sketchbook')?selectFigureVariant(declaration,'sketchbook'):declaration;
  expect(selected.theme!.drawing.mode).toBe('sketch');expect(selected.theme!.fonts.some(font=>font.family==='Kalam')).toBe(true);
 }
},30000);
