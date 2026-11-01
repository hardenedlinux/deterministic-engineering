import {test,expect} from 'bun:test';
import {readFile} from 'node:fs/promises';
import {compileFigureSource,composeFigure,selectFigureVariant} from '@deterministic-engineering/render';
import {designCase,resources,choiceFor} from '../design-case';
const root=new URL('../../../../',import.meta.url),file='docs/90-99-views/90-architecture-views/90.138-library-design-taste-choices.d2';
test('real source-declared Design choices preserve five subjects and all four relationships',async()=>{
 const input=await compileFigureSource({[file]:await readFile(new URL(file,root),'utf8')},file,resources);
 const sources={...input.sources,...Object.fromEntries(await Promise.all(Object.values(input.references).map(async file=>[file,await readFile(new URL(file,root),'utf8')])))};
 const all=[input,...input.variants!.map(variant=>selectFigureVariant(input,variant.name))];
 const hashes=[];
 for(const candidate of all){
  expect(candidate.model).toBe(input.model);expect(candidate.design!.requiredSubjects).toEqual(input.design!.requiredSubjects);expect(candidate.design!.requiredRelations).toEqual(input.design!.requiredRelations);
  expect(candidate.design!.requiredSubjects).toHaveLength(5);expect(candidate.design!.requiredRelations).toHaveLength(4);
  const {choice}=choiceFor({presentation:candidate.presentation,layout:candidate.layout!});expect(choice.reason.length).toBeGreaterThan(20);expect(choice.tradeoff.length).toBeGreaterThan(20);
  hashes.push(composeFigure({...candidate,sources},designCase).inputSHA256);
 }
 expect(new Set(hashes).size).toBe(3);
 expect(()=>composeFigure({...input,sources,layout:'undeclared'},designCase)).toThrow('Undeclared Case');
},30000);
