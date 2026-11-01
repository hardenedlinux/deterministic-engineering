// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect} from 'bun:test';
import {renderedViewFromJson} from '@openmbee/opensysml';
import {captureOpenSysMLView,projectOpenSysMLView} from '../src/opensysml';
import {compileFigureSource,composeFigure,composeModelView} from '../src';
import {captureFixture,declarationFixture,selection} from './fixtures/model-view';

test('official decoded SDK result projects directly with identities, parents and origins',()=>{
 const capture=captureFixture(),before=JSON.stringify(capture);
 const projected=projectOpenSysMLView(capture,{selection,layout:'reflow',labels:{n1:'Selected worker'}});
 expect(JSON.stringify(capture)).toBe(before);expect(projected.model.subjects.map(n=>n.id)).toEqual(['root','n1','n2']);
 expect(projected.model.subjects[1]).toMatchObject({parent:'root',sourceName:'Worker',label:'Selected worker'});
 expect(projected.trace.nodes[0]!.origin?.file).toBe('model.sysml');
 expect(projected.model.relations[0]).toMatchObject({src:'n1',dst:'n2',kind:'connection',srcArrow:'none',dstArrow:'none'});
 expect(projected).not.toHaveProperty('text');expect(projected).not.toHaveProperty('source');
 expect(projectOpenSysMLView({...capture,modelHash:'changed'},{selection,layout:'reflow'}).trace.renderingSHA256).not.toBe(projected.trace.renderingSHA256);
});
test('port owner projection is explicit, preserves endpoints and checks real port ownership',()=>{
 const capture=captureFixture(true);
 expect(()=>projectOpenSysMLView(capture,{selection,layout:'reflow'})).toThrow('notation adapter');
 const projected=projectOpenSysMLView(capture,{selection,layout:'reflow',portProjection:'owner'});
 expect(projected.model.relations[0]).toMatchObject({src:'n1',dst:'n2',fromPort:'p1',toPort:'p2'});
 expect(projected.trace.portProjection).toBe('owner');expect(projected.trace.edges[0]!.fromPort).toBe('p1');
 capture.rendering.edges[0]!.fromPort='p2';
 expect(()=>projectOpenSysMLView(capture,{selection,layout:'reflow',portProjection:'owner'})).toThrow('declared endpoint');
 capture.rendering.edges[0]!.fromPort='p1';capture.rendering.nodes[1]!.ports=[...capture.rendering.nodes[1]!.ports,...capture.rendering.nodes[1]!.ports];
 expect(()=>projectOpenSysMLView(capture,{selection,layout:'reflow',portProjection:'owner'})).toThrow('duplicate SDK port');
});
test('dangling endpoints, duplicate nodes, cycles, unsupported notation and name-based caption guesses refuse',()=>{
 const bad=captureFixture();bad.rendering.edges[0]!.to='missing';expect(()=>projectOpenSysMLView(bad,{selection,layout:'reflow'})).toThrow('endpoint');
 const cyclic=captureFixture();cyclic.rendering.nodes[0]!.parent='n1';expect(()=>projectOpenSysMLView(cyclic,{selection,layout:'reflow'})).toThrow('Cyclic');
 const missing=captureFixture();missing.rendering.nodes[1]!.parent='absent';expect(()=>projectOpenSysMLView(missing,{selection,layout:'reflow'})).toThrow('Missing SDK owner');
 const duplicate=captureFixture();duplicate.rendering.nodes[1]!.id='root';expect(()=>projectOpenSysMLView(duplicate,{selection,layout:'reflow'})).toThrow('duplicate');
 const notes=captureFixture();notes.rendering.nodes[1]!.compartment='parts';expect(()=>projectOpenSysMLView(notes,{selection,layout:'reflow'})).toThrow('notation adapter');
 const prototype=captureFixture();prototype.rendering.nodes[0]!.id='toString';prototype.rendering.nodes[1]!.parent='toString';prototype.rendering.nodes[2]!.parent='toString';expect(projectOpenSysMLView(prototype,{selection,layout:'reflow',labels:{}}).model.subjects[0]!.label).toBe('Demo::System');
 expect(()=>projectOpenSysMLView(captureFixture(),{selection,layout:'reflow',labels:{Worker:'Ambiguous name'}})).toThrow('missing SDK node ID');
});
test('transport decoding belongs to the SDK and effect failures propagate',async()=>{
 expect(()=>renderedViewFromJson({View:'Demo::Context',Nodes:[]})).toThrow();
 const refusal=new Error('render_view capability missing');await expect(captureOpenSysMLView({renderView:async()=>{throw refusal;}},'m','v')).rejects.toBe(refusal);
 const fixture=captureFixture();let calls=0;
 const captured=await captureOpenSysMLView({renderView:async(hash,view)=>{calls++;expect(hash).toBe('model-hash');expect(view).toBe('Demo::Context');return fixture.rendering;}},fixture.modelHash,fixture.requestedView);
 fixture.rendering.nodes[0]!.name='mutated';expect(captured.rendering.nodes[0]!.name).toBe('Demo::System');expect(calls).toBe(1);
});
test('declared model hash/view/source bind one direct SDK projection and rendering footprint',async()=>{
 const capture=captureFixture(true),fixture=declarationFixture(capture,{portProjection:'owner'});
 const input=await compileFigureSource(fixture.sources,'view.d2',fixture.resources);
 expect(input.model!.subjects.map(n=>n.id)).toEqual(['root','n1','n2']);expect(input.modelTrace!.modelHash).toBe(capture.modelHash);
 expect(Object.keys(input.sources).sort()).toEqual(['models/view.json','view.d2']);
 const figure=composeFigure(input,composeModelView);expect(figure.html).toContain('"portProjection":"owner"');expect(figure.html).toContain('"fromPort":"p1"');
 expect(()=>composeFigure({...input,modelSource:{...input.modelSource!,modelHash:'different declaration'}},composeModelView)).toThrow('captured SDK trace');
 expect(()=>composeFigure({...input,modelSource:{...input.modelSource!,portProjection:undefined}},composeModelView)).toThrow('captured SDK trace');
 const changed=declarationFixture({...capture,modelHash:'new hash'},{portProjection:'owner'});const fresh=await compileFigureSource(changed.sources,'view.d2',changed.resources);expect(composeFigure(fresh,composeModelView).inputSHA256).not.toBe(figure.inputSHA256);
},30000);
test('wrong revisions, source bytes and uncaptured references cannot select a SDK view',async()=>{
 const fixture=declarationFixture();
 const wrong=structuredClone(fixture.resources);wrong.sysmlViews['Demo::Context']={...wrong.sysmlViews['Demo::Context']!,modelHash:'old'};await expect(compileFigureSource(fixture.sources,'view.d2',wrong)).rejects.toThrow('binding mismatch');
 const different=structuredClone(fixture.resources);different.sysmlViews['Demo::Context']!.rendering.nodes[1]!.name='changed';await expect(compileFigureSource(fixture.sources,'view.d2',different)).rejects.toThrow('source bytes');
 const missing=declarationFixture(captureFixture(),{ref:'missing'});await expect(compileFigureSource(missing.sources,'view.d2',missing.resources)).rejects.toThrow('Uncaptured');
 await expect(compileFigureSource(fixture.sources,'view.d2',{})).rejects.toThrow('binding mismatch');
 const escape={...fixture.sources,'view.d2':fixture.sources['view.d2'].replace('models/view.json','../escape.json')};await expect(compileFigureSource(escape,'view.d2',fixture.resources)).rejects.toThrow('repository-relative');
},30000);
