import {test,expect} from 'bun:test';
import {compileModel} from '../src';
test('D2 contributes labels and relationships without legacy geometry or SVG',async()=>{
 const capture=await compileModel({'model.d2':'a: Publisher\nb: Consumer\na -> b: selects'},'model.d2',{layout:'dagre'});
 expect(capture.fs['model.d2']).toBe('a: Publisher\nb: Consumer\na -> b: selects');
 expect(capture.model.subjects[0]!.label).toBe('Publisher');expect(capture.model.relations[0]!.label).toBe('selects');
 expect(capture.model.subjects[0]).not.toHaveProperty('pos');expect(capture).not.toHaveProperty('svg');expect(capture.options.layout).toBe('dagre');
},30000);
test('failed syntax/import and absent/outside source refuse; independent compilation recovers',async()=>{
 await expect(compileModel({'model.d2':'node: {'},'model.d2')).rejects.toThrow();
 await expect(compileModel({'model.d2':'...@missing'},'model.d2')).rejects.toThrow();
 await expect(compileModel({'model.d2':'a'},'missing.d2')).rejects.toThrow('Missing model');
 await expect(compileModel({'../outside.d2':'a'},'../outside.d2')).rejects.toThrow('repository-relative');
 expect((await compileModel({'model.d2':'a -> b'},'model.d2')).model.relations).toHaveLength(1);
},30000);
