// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect} from 'bun:test';
import {compileModel,graphFromModel} from '../src';
import {captureFixture,selection} from './fixtures/model-view';
import {projectOpenSysMLView} from '../src/opensysml';

test('D2 identities, arrowheads and nullable table/class members come from the actual SDK',async()=>{
 const source='outer: {inner: A}\n"outer.fake": B\nouter.inner -- "outer.fake"\nC: {shape: class; +run(): bool}\nT: {shape: sql_table; id: int}';
 const {model}=await compileModel({'model.d2':source},'model.d2');
 expect(model.subjects.map(n=>n.id)).toContain('"outer.fake"');expect(model.subjects.find(n=>n.id==='outer.inner')).not.toHaveProperty('parent');
 expect(model.relations[0]).toMatchObject({src:'outer.inner',dst:'"outer.fake"',srcArrow:'none',dstArrow:'none'});
 expect(model.subjects.find(n=>n.id==='C')!.methods![0]!.name).toBe('run()');
 expect(model.subjects.find(n=>n.id==='T')!.columns![0]!.name).toEqual({label:'id'});
 expect(model.subjects.find(n=>n.id==='T')!.columns![0]!.name).not.toHaveProperty('labelWidth');
 expect(()=>graphFromModel(model)).toThrow('explicit graph projection');
},30000);
test('sequence drawing artifacts remain exact SDK observations, not filtered by generated-name heuristics',async()=>{
 const {model}=await compileModel({'sequence.d2':'shape: sequence_diagram\na -> b: message'},'sequence.d2');
 expect(model.relations).toHaveLength(3);expect(model.relations.filter(e=>!model.subjects.some(n=>n.id===e.dst))).toHaveLength(2);
 expect(()=>graphFromModel(model)).toThrow('dedicated notation adapter');
},30000);
test('generic hierarchy follows explicit SDK parents and rejects broken ownership/endpoint closure',()=>{
 const model=projectOpenSysMLView(captureFixture(),{selection,layout:'reflow'}).model;
 const graph=graphFromModel(model);expect(graph.children![0]!.children!.map(n=>n.id)).toEqual(['n1','n2']);
 expect(()=>graphFromModel({...model,subjects:[...model.subjects,model.subjects[0]!]})).toThrow('Duplicate');
 expect(()=>graphFromModel({...model,subjects:[{id:'a',type:'part',parent:'missing'}],relations:[]})).toThrow('Missing model owner');
 expect(()=>graphFromModel({subjects:[{id:'a',type:'part',parent:'b'},{id:'b',type:'part',parent:'a'}],relations:[]})).toThrow('Unreachable');
 expect(()=>graphFromModel({...model,relations:[{id:'bad',src:'root',dst:'missing',label:''}]})).toThrow('endpoint');
});
