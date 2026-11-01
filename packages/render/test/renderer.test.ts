// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

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

// Each call resolves only after its isolated allocation domain exits naturally.
// Keeping each call a separate case preserves the existing test watchdog.
const compilerParentRSS=process.memoryUsage().rss;
test.each(Array.from({length:24},(_,index)=>index))('compiler allocation ownership is reclaimed after call %i',async()=>{
 const capture=await compileModel({'repeat.d2':'a: Producer\nb: Consumer\na -> b: binds'},'repeat.d2',{layout:'elk'});
 expect(capture.model.subjects).toHaveLength(2);
 expect(capture.model.relations).toHaveLength(1);
 expect(process.memoryUsage().rss-compilerParentRSS).toBeLessThan(256*1024*1024);
});
