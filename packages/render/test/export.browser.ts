// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {composePresentationTheme} from '../src/presentation-theme';
import { test, expect } from 'playwright/test';
import { composeFigure, type FigureInput, type FigureComposer } from '../src/figure';
import { exportFigure } from '../src/export';
const input: FigureInput = {
  view: {source: 'case.ts', title: 'Browser export', purpose: 'architecture', kind: 'system', question: {ref: 'q', text: 'Which source?'}, basis: {captureRef: 'candidate', modelRefs: [], obligationRefs: [], evidenceRefs: []}},
  width: 720, language: 'en', questions: [{ref: 'q', text: 'Which source?', focusRefs: ['source']}], sources: {'case.ts': 'case'}, references: {source: 'case.ts'},
};
const normal: FigureComposer = ({icon}) => ({markup: `<section data-question="q" data-region="diagram"><h1>Source &amp; model</h1>${icon('model')}<p>Actual browser fonts.</p></section>`, css: '[data-figure]{padding:20px}'});
test('exports just the figure with real fonts/icons and records actual browser and dimensions', async ({browser}) => {
  const figure = composeFigure(input, normal), count = browser.contexts().length;
  const result = await exportFigure(figure, browser, {scale: 1.5, regions: ['diagram']});
  expect([...result.png.slice(0, 8)]).toEqual([137,80,78,71,13,10,26,10]);
  expect(result.receipt.width).toBe(1080);
  expect(result.receipt.height).toBeGreaterThan(50);
  expect(result.receipt.bounds.diagram!.width).toBeGreaterThan(0);
  expect(result.receipt.browser).toBe(browser.version());
  expect(result.regionImages.diagram!.length).toBeGreaterThan(100);
  expect(result.receipt.regionSHA256.diagram).toHaveLength(64);
  await expect(exportFigure(figure, browser, {regions: ['missing']})).rejects.toThrow('Unknown requested figure region');
  expect(browser.contexts()).toHaveLength(count);
});
test('modified HTML is rejected before browser rendering', async ({browser}) => {
  const figure = composeFigure(input, normal);
  await expect(exportFigure({...figure, html: figure.html + 'changed'}, browser)).rejects.toThrow('fingerprint');
});
test('text clipping refuses and cleans its own browser context', async ({browser}) => {
  const figure = composeFigure(input, () => ({markup: '<section data-question="q"><div data-fit style="width:20px;white-space:nowrap;overflow:hidden">Unacceptably clipped text</div></section>', css: ''}));
  const count = browser.contexts().length;
  await expect(exportFigure(figure, browser)).rejects.toThrow('clipped text');
  expect(browser.contexts()).toHaveLength(count);
});
test('missing image fails rather than exporting a misleading completed figure', async ({browser}) => {
  const figure = composeFigure(input, () => ({markup: '<section data-question="q"><img src="data:image/png;base64,broken"></section>', css: ''}));
  await expect(exportFigure(figure, browser)).rejects.toThrow();
});

test('sketch materialization embeds real font and repeatable Rough.js SVG rather than a color swap', async ({browser}) => {
  const figure = composeFigure({...input, theme: composePresentationTheme(['sketchbook'])}, () => ({markup: '<div data-question="q" data-surface style="padding:20px">Handwritten model</div>', css: '[data-surface]{position:relative}.sketch-surface{position:absolute;inset:0;pointer-events:none}'}));
  const a = await exportFigure(figure, browser), b = await exportFigure(figure, browser);
  expect(a.html).toContain('class="sketch-surface"');
  expect(a.html).toContain('data:font/woff2;base64,');
  expect(a.receipt.drawing).toContain('roughjs@');
  expect(Object.keys(a.receipt.assetSHA256)).toHaveLength(2);
  expect(a.receipt.htmlSHA256).toBe(b.receipt.htmlSHA256);
  expect(a.receipt.pngSHA256).toBe(b.receipt.pngSHA256);
  await expect(exportFigure({...figure, drawing: {...figure.drawing, options: {...figure.drawing.options, seed: 1}}}, browser)).rejects.toThrow('Drawing differs');
});
test('measured connectors refuse missing rendered endpoints', async ({browser}) => {
  const figure = composeFigure(input, () => ({markup: '<div data-question="q"><svg data-connections><path data-from="missing" data-to="other"/></svg></div>', css: ''}));
  await expect(exportFigure(figure, browser)).rejects.toThrow('unique rendered endpoints');
});

test('rendered edges must exist in the captured model, including their direction', async ({browser}) => {
  const withModel = {...input, model: {subjects: [{id: 'a', type: 'rectangle'}, {id: 'b', type: 'rectangle'}], relations: [{id: 'ab', src: 'a', dst: 'b', label: 'selects'}]}};
  const diagram = (from: string, to: string): FigureComposer => () => ({markup: `<div data-question="q" style="position:relative;padding:20px;display:flex;gap:80px"><div data-node="a">A</div><div data-node="b">B</div><svg data-connections style="position:absolute;inset:0"><path data-from="${from}" data-to="${to}"/></svg></div>`, css: ''});
  const good = await exportFigure(composeFigure(withModel, diagram('a', 'b')), browser);
  expect(good.receipt.routing).toContain('xyflow@');
  expect(good.html).toContain('data-connection-index="0"');
  await expect(exportFigure(composeFigure(withModel, diagram('b', 'a')), browser)).rejects.toThrow('Undeclared rendered model relation');
});

test('declared Rough.js options and surfaces replace fixed rectangle/fill defaults', async ({browser}) => {
  const theme = composePresentationTheme(['sketchbook']);
  const make = (shape: string) => composeFigure({...input, theme: {...theme, drawing: {...theme.drawing, options: {...theme.drawing.options, fillStyle: 'solid', roughness: .5}}}}, () => ({markup: `<section data-question="q"><div data-surface="${shape}" style="position:relative;width:220px;height:120px">Declared primitive</div></section>`, css: '.sketch-surface{position:absolute;inset:0}'}));
  const ellipse = await exportFigure(make('ellipse'), browser), diamond = await exportFigure(make('diamond'), browser);
  expect(ellipse.receipt.pngSHA256).not.toBe(diamond.receipt.pngSHA256);
  expect(ellipse.html).toContain('sketch-surface');
  await expect(exportFigure(make('unknown'), browser)).rejects.toThrow('Unsupported declared sketch surface');
});

test('theme CSS cannot hide a selected Question and still qualify the export', async ({browser}) => {
  const figure = composeFigure(input, () => ({markup:'<section data-question="q">Required question</section>',css:'[data-question]{visibility:hidden}'}));
  await expect(exportFigure(figure, browser)).rejects.toThrow('Question has no visible region');
});

test('vertical connector sides are declared rather than forced into a horizontal workflow', async ({browser}) => {
  const model = {subjects:[{id:'a',type:'rectangle'},{id:'b',type:'rectangle'}],relations:[{id:'ab',src:'a',dst:'b',label:'binds'}]};
  const figure = (side: string) => composeFigure({...input,model}, () => ({markup:`<section data-question="q" style="position:relative;display:flex;flex-direction:column;gap:50px;padding:20px"><div data-node="a">Publisher</div><div data-node="b">Consumer</div><svg data-connections style="position:absolute;inset:0"><path data-from="a" data-to="b" data-source-position="${side}" data-target-position="top"/></svg></section>`,css:''}));
  const output = await exportFigure(figure('bottom'), browser);
  expect(output.receipt.routing).toContain('xyflow@'); expect(output.html).toContain('data-source-position="bottom"');
  await expect(exportFigure(figure('unknown'), browser)).rejects.toThrow('Invalid declared connector position');
});

test('PNG compression preserves real browser pixels and region hashes',async({browser})=>{
 const {default:sharp}=await import('sharp');
 const {digest}=await import('../src/source/catalog');
 const figure=composeFigure(input,normal),baseline=await exportFigure(figure,browser,{regions:['diagram'],transparent:true,pngCompression:false});
 const optimized=await exportFigure(figure,browser,{regions:['diagram'],transparent:true});
 for(const [before,after] of [[baseline.png,optimized.png],[baseline.regionImages.diagram!,optimized.regionImages.diagram!]] as const){
  const original=await sharp(before).ensureAlpha().raw().toBuffer({resolveWithObject:true});
  const compressed=await sharp(after).ensureAlpha().raw().toBuffer({resolveWithObject:true});
  expect(compressed).toEqual(original);expect(after.byteLength).toBeLessThanOrEqual(before.byteLength);
 }
 expect(optimized.receipt.pngSHA256).toBe(digest(optimized.png));
 expect(optimized.receipt.regionSHA256.diagram).toBe(digest(optimized.regionImages.diagram!));
 expect(optimized.receipt.pngCompression.figure.outputBytes).toBe(optimized.png.byteLength);
 expect(optimized.receipt.pngCompression.regions.diagram!.outputBytes).toBe(optimized.regionImages.diagram!.byteLength);
 const contexts=browser.contexts().length;
 await expect(exportFigure(figure,browser,{pngCompression:{compressionLevel:10}})).rejects.toThrow();
 expect(browser.contexts().length).toBe(contexts);
});

test('preferred raster chooses actual smaller PNG/WebP with matching hashes and MIME',async({browser})=>{
 const {default:sharp}=await import('sharp'),{digest}=await import('../src/source/catalog');
 const figure=composeFigure(input,normal),image=await exportFigure(figure,browser);
 expect(image.webp).toBeDefined();
 expect((await sharp(image.webp!).metadata()).format).toBe('webp');
 expect(await sharp(image.webp!).raw().toBuffer()).toEqual(await sharp(image.png).raw().toBuffer());
 expect(image.receipt.webp!.sha256).toBe(digest(image.webp!));
 const selected=image.webp!.byteLength<image.png.byteLength?'webp':'png';
 expect(image.preferredRaster.format).toBe(selected);expect(image.receipt.preferredRaster).toBe(selected);
 expect(image.preferredRaster.mimeType).toBe('image/'+selected);
 expect(image.preferredRaster.bytes).toBe(selected==='webp'?image.webp!:image.png);
 const pngOnly=await exportFigure(figure,browser,{webp:false});
 expect(pngOnly.webp).toBeUndefined();expect(pngOnly.receipt.webp).toBeUndefined();expect(pngOnly.preferredRaster.format).toBe('png');
});
