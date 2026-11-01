// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import { test, expect } from 'bun:test';
import { compileFigureSource, composeFigure, selectFigureVariant, type FigureContext } from '../src';
import { readD2Figure } from '../src/d2-figure';
const declaration = (wording: string) => ({title: 'Declared view', purpose: 'architecture', kind: 'system', language: 'en', width: 800, primary: 'ownership',
  questions: [{ref: 'ownership', text: wording, focusRefs: ['model']}], references: {model: 'project.sysml'},
  basis: {captureRef: 'design-candidate:test', modelRefs: ['project.sysml'], obligationRefs: [], evidenceRefs: []}, copy: {answer: 'Declared answer'}});
const source = (wording: string): string => `vars: {d2-config: {data: {figure: |json\n${JSON.stringify(declaration(wording))}\n|\n}}}\nlibrary -> project: publishes`;
test('official D2 data owns Questions; changing D2 changes HTML without editing TS', async () => {
  const compose = ({question, copy, text}: FigureContext) => ({markup: `<section data-question="ownership">${text(question('ownership').text)} / ${text(copy('answer'))}</section>`, css: ''});
  const a = await compileFigureSource({'view.d2': source('Who owns this?'), 'project.sysml': 'model'}, 'view.d2');
  const b = await compileFigureSource({'view.d2': source('Who publishes this?'), 'project.sysml': 'model'}, 'view.d2');
  expect(a.model?.relations[0]?.label).toBe('publishes');
  expect(() => composeFigure(a, context => { context.relation('project', 'library'); return {markup: '', css: ''}; })).toThrow('Undeclared model relation');
  expect(composeFigure(a, compose).html).toContain('Who owns this?');
  expect(composeFigure(b, compose).html).toContain('Who publishes this?');
  expect(composeFigure(a, compose).inputSHA256).not.toBe(composeFigure(b, compose).inputSHA256);
}, 30000);
test('syntax errors refuse through the owned worker', async () => {
  await expect(compileFigureSource({'view.d2': 'node: {'}, 'view.d2')).rejects.toThrow();
}, 30000);
test('missing metadata, malformed JSON and purpose mismatch are refused', () => {
  const fs = {'view.d2': 'source'};
  expect(() => readD2Figure({inputPath: 'view.d2', fs, data: {figure: null}}, fs)).toThrow('JSON block');
  expect(() => readD2Figure({inputPath: 'view.d2', fs, data: {figure: '{bad'}}, fs)).toThrow();
  expect(() => readD2Figure({inputPath: 'view.d2', fs, data: {figure: JSON.stringify({...declaration('Who?'), purpose: 'workflow'})}}, fs)).toThrow('purpose');
});


test('D2 selects downstream kinds, composed themes and icon packs through the actual worker', async () => {
  const {presentationThemeLayers} = await import('../src/presentation-theme');
  const {iconPacks} = await import('../src/icons');
  const svg = '<svg viewBox="0 0 32 32"><path d="M4 4L28 28"/></svg>';
  const metadata = {...declaration('Who owns this?'), kind: 'domain-responsibility', themes: ['blueprint', 'brand'], icons: ['engineering'],
    variants: [{name: 'domain', kind: 'dependency-table', themes: ['field-notes', 'brand'], icons: ['engineering', 'brand'], layout: 'domain-matrix'}]};
  const fs = {'view.d2': `vars: {d2-config: {layout-engine: dagre; data: {figure: |json\n${JSON.stringify(metadata)}\n|\n}}}\na -> b`, 'project.sysml': 'captured model'};
  const resources = {themeLayers: {...presentationThemeLayers, brand: {colors: {accent: '#123456'}}}, iconPacks: {...iconPacks, brand: {library: {svg, label: 'Domain publication'}}}};
  const input = await compileFigureSource(fs, 'view.d2', resources);
  const variant = selectFigureVariant(input, 'domain');
  expect(input.view.kind).toBe('domain-responsibility');
  expect(variant.view.kind).toBe('dependency-table');
  expect(variant.theme!.colors.accent).toBe('#123456');
  expect(variant.icons!.library!.svg).toBe(svg);
  expect(variant.model).toEqual(input.model);
  expect(variant.questions).toEqual(input.questions);
  expect(() => selectFigureVariant(input, 'missing')).toThrow('Undeclared figure variant');
  const compose = ({icon}: FigureContext) => ({markup: `<section data-question="ownership">${icon('library')}</section>`, css: ''});
  const html = composeFigure(variant, compose).html;
  expect(html).toContain(svg); expect(html).toContain('#123456');
  expect(html).not.toContain('"icons":"engineering"');
}, 30000);
test('declaration rejects unknown resources, duplicate variants and reserved-purpose mismatch', () => {
  const read = (extra: Record<string, unknown>) => readD2Figure({inputPath:'view.d2', fs:{'view.d2':'source'}, data:{figure:JSON.stringify({...declaration('Who?'), ...extra})}}, {'view.d2':'source','project.sysml':'model'});
  expect(() => read({icons: ['missing']})).toThrow('Unknown declared icon pack');
  expect(() => read({icons: ['constructor']})).toThrow('Unknown declared icon pack');
  expect(() => read({themes: ['toString']})).toThrow('Unknown declared theme');
  expect(() => read({variants:[{name:'same'}, {name:'same'}]})).toThrow('Duplicate declared');
  expect(() => read({variants:[{name:'bad', kind:'flow'}]})).toThrow('purpose');
  expect(() => read({kind:''})).toThrow();
});
