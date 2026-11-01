import { test, expect } from 'bun:test';
import { composePresentation, type PresentationInput } from '../src/presentation';
import { defaultPresentationTheme, extendPresentationTheme } from '../src/presentation-theme';
const input = (): PresentationInput => ({
  title: 'Actual <architecture>', subtitle: 'Case & context', scope: 'design', answer: 'One owner per capability.',
  view: {source: 'model.d2', purpose: 'architecture', kind: 'system', sourceSHA256: 'source', svgSHA256: 'svg',
    svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 300"><style>.native{fill:red}</style><text class="native">untouched model</text></svg>',
    nodeIds: ['a'], edgeIds: [], nodes: 1, edges: 0, question: {ref: 'Q1', text: 'Who owns execution?'},
    basis: {captureRef: 'candidate', modelRefs: ['M1'], obligationRefs: ['O1'], evidenceRefs: []}},
  findings: [{title: 'Pending execution', text: 'No method evidence.', status: 'pending', refs: []}], limits: ['Live model validation remains open.'],
});
test('TS composition preserves native diagram and makes question and missing evidence visible', () => {
  const original = input(), before = JSON.stringify(original);
  const page = composePresentation(original);
  expect(page.svg).toContain(original.view.svg);
  expect(page.svg).toContain('Who owns execution?');
  expect(page.svg).toContain('none linked');
  expect(page.svg).toContain('Actual &lt;architecture&gt;');
  expect(page.svg).toContain('PENDING');
  expect(page.svg).toContain('data:image/svg+xml;base64,');
  expect(page.svg).toContain('<metadata>');
  expect(page.svg).toContain('Architecture / boundaries');
  expect(JSON.stringify(original)).toBe(before);
});
test('downstream theme changes page, not model identity or native D2 bytes', () => {
  const original = input(), before = JSON.stringify(defaultPresentationTheme);
  const a = composePresentation(original), b = composePresentation({...original, theme: extendPresentationTheme(defaultPresentationTheme, {colors: {accent: '#006655'}})});
  expect(a.inputSHA256).not.toBe(b.inputSHA256);
  expect(b.svg).toContain('#006655');
  expect(b.svg).toContain(original.view.svg);
  expect(b.basis).toEqual(a.basis);
  expect(JSON.stringify(defaultPresentationTheme)).toBe(before);
});
test('unsupported approval claim, malformed diagram and invalid theme refuse', () => {
  const original = input();
  expect(() => composePresentation({...original, findings: [{title: 'Pass', text: 'claim', status: 'supported', refs: []}]})).toThrow('evidence reference');
  expect(() => composePresentation({...original, view: {...original.view, svg: '<svg/>'}})).toThrow('viewBox');
  expect(() => composePresentation({...original, theme: extendPresentationTheme(defaultPresentationTheme, {spacing: {gutter: -1}})})).toThrow('spacing');
});

test('custom icons are explicit inputs and change the presentation footprint', () => {
  const original = input();
  const custom = {svg: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/></svg>', label: 'Downstream question'};
  const a = composePresentation(original), b = composePresentation({...original, icons: {question: custom}});
  expect(a.inputSHA256).not.toBe(b.inputSHA256);
  expect(b.svg).toContain('Downstream question');
  expect(b.svg).toContain(original.view.svg);
});
