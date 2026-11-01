import { test, expect } from 'bun:test';
import { composeFigure, type FigureInput, type FigureComposer } from '../src/figure';
import { defaultPresentationTheme, extendPresentationTheme } from '../src/presentation-theme';
const input = (): FigureInput => ({
  view: {source: 'case/view.ts', title: 'Case', purpose: 'architecture', kind: 'system', question: {ref: 'ownership', text: 'Who owns this?'}, basis: {captureRef: 'design-candidate:case', modelRefs: ['project.sysml'], obligationRefs: [], evidenceRefs: []}},
  language: 'en', width: 800, questions: [{ref: 'ownership', text: 'Who owns this?', focusRefs: ['model']}],
  sources: {'case/view.ts': 'composition', 'project.sysml': 'model source'}, references: {model: 'project.sysml'},
});
export const minimal: FigureComposer = ({question, icon, text}) => ({markup: `<section data-question="ownership" data-region="model"><h1>${text(question('ownership').text)}</h1>${icon('library')}</section>`, css: '[data-figure]{padding:24px}h1{font-size:32px}'});
export { input as fixture };
test('HTML composition retains questions, captured sources and empty evidence without a fixed template', () => {
  const original = input(), before = JSON.stringify(original), figure = composeFigure(original, minimal);
  expect(figure.html).toContain('Who owns this?');
  expect(figure.html).toContain('figure-provenance');
  expect(figure.html).toContain('"evidenceRefs":[]');
  expect(figure.html).not.toContain('Design at a glance');
  expect(JSON.stringify(original)).toBe(before);
});
test('a question selects its composition and must have a visible region', () => {
  expect(() => composeFigure(input(), () => ({markup: '<div>hidden questions</div>', css: ''}))).toThrow('no visible region');
  expect(() => composeFigure(input(), () => ({markup: '<div data-question="invented"></div>', css: ''}))).toThrow('Unselected rendered question');
  expect(() => composeFigure(input(), context => { context.question('invented'); return {markup: '', css: ''}; })).toThrow('Unselected question');
});
test('unknown or stale source associations refuse before composition', () => {
  const original = input();
  expect(() => composeFigure({...original, references: {model: 'missing.sysml'}}, minimal)).toThrow('Uncaptured');
  expect(() => composeFigure({...original, sources: {'../outside': 'source'}}, minimal)).toThrow('Composition source');
  expect(() => composeFigure({...original, questions: [{...original.questions[0]!, focusRefs: ['missing']}]}, minimal)).toThrow('Unknown question focus');
});
test('architecture and workflow are independent purposes', () => {
  const original = input();
  expect(() => composeFigure({...original, view: {...original.view, purpose: 'workflow'} as FigureInput['view']}, minimal)).toThrow('separate');
  expect(composeFigure({...original, view: {...original.view, purpose: 'workflow', kind: 'flow'}}, minimal).purpose).toBe('workflow');
});
test('source/theme/icon changes invalidate rendering footprint without rewriting the model', () => {
  const original = input(), a = composeFigure(original, minimal);
  const changedSource = composeFigure({...original, sources: {...original.sources, 'project.sysml': 'new source'}}, minimal);
  const custom = {label: 'Custom icon', svg: '<svg viewBox="0 0 24 24"><circle r="3"/></svg>'};
  const themed = composeFigure({...original, theme: extendPresentationTheme(defaultPresentationTheme, {colors: {accent: '#006655'}}), icons: {library: custom}}, minimal);
  expect(changedSource.inputSHA256).not.toBe(a.inputSHA256);
  expect(themed.inputSHA256).not.toBe(a.inputSHA256);
  expect(themed.html).toContain('#006655');
  expect(themed.html).toContain(custom.svg);
  expect(themed.sourceSHA256).toEqual(a.sourceSHA256);
});

test('project-owned view organizations stay open beyond node and lane examples', () => {
  const original = {...input(), layout: 'domain-owned-view', presentation: {axis: 'responsibility'}};
  const figure = composeFigure(original, ({layout, presentation, question, text}) => ({
    markup: `<article data-question="ownership"><h1>${text(question('ownership').text)}</h1><pre>${text(JSON.stringify({layout, presentation}))}</pre></article>`, css: 'article{padding:20px}',
  }));
  expect(figure.html).toContain('domain-owned-view');
  expect(figure.html).toContain('responsibility');
  expect(figure.html).not.toContain('class="step"');
  const changed = composeFigure({...original, presentation: {axis: 'dependency'}}, minimal);
  expect(changed.inputSHA256).not.toBe(figure.inputSHA256);
});

test('custom diagrams cannot mutate captured model or project presentation', () => {
  const original = {...input(), view: {...input().view, kind:'domain-custom'}, model:{subjects:[{id:'a',type:'rectangle'}],relations:[]}, presentation:{role:'owner'}};
  expect(() => composeFigure(original, context => { Object.assign(context.model!.subjects[0]!, {id:'forged'}); return {markup:'<section data-question="ownership"/>',css:''}; })).toThrow();
  expect(() => composeFigure(original, context => { Object.assign(context.presentation!, {role:'forged'}); return {markup:'<section data-question="ownership"/>',css:''}; })).toThrow();
  expect(original.model.subjects[0]!.id).toBe('a');
});

test('standard HTML parsing accepts native quoting and rejects inert question lookalikes', () => {
  const original = input();
  expect(composeFigure(original, () => ({markup:"<section data-question='ownership'>Answer</section>",css:''})).html).toContain("data-question='ownership'");
  expect(composeFigure(original, () => ({markup:'<section data-question=ownership>Answer</section>',css:''})).html).toContain('data-question=ownership');
  for (const markup of ['<!-- <section data-question="ownership">fake</section> -->', '<template><section data-question="ownership">inert</section></template>', '<section hidden data-question="ownership">hidden</section>']) expect(() => composeFigure(original, () => ({markup,css:''}))).toThrow('no visible region');
});
