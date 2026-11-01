// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import { test, expect } from 'bun:test';
import { composePresentationTheme, defaultPresentationTheme, presentationThemeLayers } from '../src/presentation-theme';
import {palettes} from '../src/palettes';
import { engineeringIcons } from '../src/icons';
test('declarative upstream themes compose without mutating their source', () => {
  const before = JSON.stringify(presentationThemeLayers);
  const blueprint = composePresentationTheme(['blueprint', 'compact']);
  const paper = composePresentationTheme(['field-notes', 'compact']);
  const dark = composePresentationTheme(['graphite', 'compact']);
  expect(blueprint.colors.accent).not.toBe(paper.colors.accent);
  expect(dark.colors.onAccent).not.toBe(blueprint.colors.onAccent);
  expect(paper.fontFamily).toBe(blueprint.fontFamily);
  expect(JSON.stringify(presentationThemeLayers)).toBe(before);
});
test('downstream layers override selected properties and unknown declarations refuse', () => {
  const custom = composePresentationTheme(['blueprint', 'downstream'], {...presentationThemeLayers, downstream: {colors: {accent: '#13579B'}, spacing: {gap: 18}}});
  expect(custom.colors.accent).toBe('#13579B');
  expect(custom.colors.ink).toBe(defaultPresentationTheme.colors.ink);
  expect(custom.spacing.gap).toBe(18);
  expect(() => composePresentationTheme(['missing'])).toThrow('Unknown declared');
});
test('project glyph assets are distinct semantic shapes with shared dimensions', () => {
  expect(new Set(Object.values(engineeringIcons).map(icon => icon.svg)).size).toBe(Object.keys(engineeringIcons).length);
  expect(Object.values(engineeringIcons).every(icon => icon.svg.includes('viewBox="0 0 32 32"'))).toBe(true);
});

test('visual languages change drawing and node grammar, independently of palette', () => {
  const sketch = composePresentationTheme(['sketchbook', 'compact']);
  const editor = composePresentationTheme(['blueprint', 'node-editor']);
  expect(sketch.drawing.mode).toBe('sketch');
  expect(sketch.fontFamily).toContain('Kalam');
  expect(editor.drawing.mode).toBe('precise');
  expect(editor.stylesheet).toContain('[data-node]:before');
  expect(editor.colors).toEqual(defaultPresentationTheme.colors);
  const combined = composePresentationTheme(['graphite', 'node-editor']);
  expect(combined.colors.background).toBe(presentationThemeLayers.graphite!.colors!.background!);
  expect(combined.stylesheet).toBe(editor.stylesheet);
});

test('downstream icon packs compose immutably and unknown/invalid assets refuse', async () => {
  const {composeIconPacks, iconPacks} = await import('../src/icons');
  const custom = {label:'Domain asset',svg:'<svg viewBox="0 0 32 32"><circle cx="16" cy="16" r="12"/></svg>'};
  const before = JSON.stringify(iconPacks);
  const result = composeIconPacks(['engineering','domain'], {...iconPacks, domain:{library:custom}});
  expect(result.library).toEqual(custom); expect(result.capture).toEqual(iconPacks.engineering!.capture!);
  expect(JSON.stringify(iconPacks)).toBe(before);
  expect(() => composeIconPacks(['toString'])).toThrow('Unknown declared');
  expect(() => composeIconPacks(['bad'], {bad:{asset:{label:'',svg:''}}})).toThrow('Invalid icon');
});


test('visual layers inherit and override SVG surfaces independently of palette',()=>{
 const asset={label:'Domain boundary',svg:'<svg viewBox="0 0 100 100"><ellipse cx="50" cy="50" rx="48" ry="48"/></svg>'};
 const theme=composePresentationTheme(['editorial','brand'],{...presentationThemeLayers,brand:{surfaces:{domain:asset},colors:{accent:'#123456'}}});
 expect(theme.surfaces!.domain).toEqual(asset);expect(theme.surfaces!.publication).toEqual(presentationThemeLayers.editorial!.surfaces!.publication);
 expect(theme.colors.accent).toBe('#123456');
 expect(presentationThemeLayers.editorial!.colors!.accent).toBe('#117A72');
});

test('theme layout preferences compose ELK options without a second constraint schema',()=>{
 const theme=composePresentationTheme(['dense','project'],{dense:{layoutOptions:{'elk.spacing.nodeNode':'20','elk.direction':'DOWN'}},project:{layoutOptions:{'elk.spacing.nodeNode':'50'}}});
 expect(theme.layoutOptions).toEqual({'elk.spacing.nodeNode':'50','elk.direction':'DOWN'});
});

test('palette, visual language, density and layout compose independently',()=>{
 const theme=composePresentationTheme(['sketchbook','compact','ocean','layered-right']);
 expect(theme.drawing.mode).toBe('sketch');expect(theme.fontFamily).toContain('Kalam');
 expect(theme.colors).toEqual(presentationThemeLayers.ocean!.colors as typeof theme.colors);
 expect(theme.typography.lineHeight).toBe('2.3em');expect(theme.spacing.scenePadding).toBe(12);
 expect(theme.layoutOptions!['elk.direction']).toBe('RIGHT');
 for(const palette of Object.keys(palettes)){const reset=composePresentationTheme(['sketchbook',palette]);
 expect(reset.drawing.mode).toBe('sketch');expect(reset.fontFamily).toContain('Kalam');expect(reset.typography.lineHeight).toBe('2.3em');}
 expect(composePresentationTheme(['compact']).typography).toEqual(defaultPresentationTheme.typography);
});
test('downstream tokens and external nested assets are copied and deeply frozen',()=>{
 const surface={label:'Domain',svg:'<svg viewBox="0 0 32 32"><circle r="10"/></svg>'};
 const dash=[2,4];
 const theme=composePresentationTheme(['domain'],{domain:{colors:{domainWarning:'oklch(60% 0.2 25)'},spacing:{domainInset:23},typography:{domainCaption:'19px'},surfaces:{domain:surface},drawing:{options:{strokeLineDash:dash}}}});
 surface.svg='changed';dash[0]=99;
 expect(theme.surfaces!.domain!.svg).not.toBe('changed');expect(theme.drawing.options.strokeLineDash).toEqual([2,4]);
 expect(Object.isFrozen(surface)).toBe(false);expect(Object.isFrozen(theme.drawing.options.strokeLineDash)).toBe(true);
 expect(theme.colors.domainWarning).toBe('oklch(60% 0.2 25)');
 expect(Reflect.set(theme.spacing,'domainInset',1)).toBe(false);
 for(const layer of [{spacing:{gap:-1}},{spacing:{gap:NaN}},{colors:{'bad;token':'red'}},{colors:{gap:'red'}},{typography:{labelSize:''}}])expect(()=>composePresentationTheme(['invalid'],{invalid:layer})).toThrow();
});
