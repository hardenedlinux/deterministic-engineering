import { test, expect } from 'bun:test';
import { composePresentationTheme, defaultPresentationTheme, presentationThemeLayers } from '../src/presentation-theme';
import { engineeringIcons } from '../src/icons';
test('declarative upstream themes compose without mutating their source', () => {
  const before = JSON.stringify(presentationThemeLayers);
  const blueprint = composePresentationTheme(['blueprint', 'compact']);
  const paper = composePresentationTheme(['field-notes', 'compact']);
  const dark = composePresentationTheme(['graphite', 'compact']);
  expect(blueprint.colors.accent).not.toBe(paper.colors.accent);
  expect(dark.colors.onAccent).not.toBe(blueprint.colors.onAccent);
  expect(paper.fontFamily).not.toBe(blueprint.fontFamily);
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

test('native D2 options are not limited to layout or replaced by forced defaults', async () => {
  const {defaultTheme, extendTheme} = await import('../src/theme');
  expect(defaultTheme.compile.layout).toBeUndefined();
  const theme = extendTheme(defaultTheme, {compile:{layout:'dagre',fontRegular:new Uint8Array([1,2,3])}});
  expect(theme.compile.fontRegular).toEqual(new Uint8Array([1,2,3]));
});
