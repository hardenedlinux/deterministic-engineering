// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {test, expect} from 'bun:test';
import {readFile} from 'node:fs/promises';
import {compileFigureSource, selectFigureVariant, composeFigure} from '@deterministic-engineering/render';
import {resources} from '../library-case/resources';
import {architecture} from '../library-case/architecture';
import {workflow} from '../library-case/workflow';
const root = new URL('../../../../', import.meta.url);
const declarations = ['docs/90-99-views/90-architecture-views/90.132-library-profile-scenario-architecture.d2','docs/90-99-views/90-architecture-views/90.133-capture-preparation-workflow.d2'];
test('real Library/Profile/Scenario D2 selects downstream kinds, themes and icons without framework edits', async () => {
  for (const file of declarations) {
    const bytes = await readFile(new URL(file, root), 'utf8');
    const input = await compileFigureSource({[file]:bytes},file,resources);
    const sources = {...input.sources, ...Object.fromEntries(await Promise.all(Object.values(input.references).map(async source => [source, await readFile(new URL(source,root),'utf8')])))};
    const variant = selectFigureVariant({...input,sources},'project-owned');
    expect(variant.view.kind).toBe(input.view.purpose === 'architecture' ? 'responsibility-map' : 'capture-handoff');
    expect(variant.questions).toEqual(input.questions); expect(variant.model).toEqual(input.model);
    expect(variant.theme!.colors.accent).toBe('#246B59');
    expect(variant.icons!.library!.label).toBe('Repository publication');
    const figure = composeFigure(variant, input.view.purpose === 'architecture' ? architecture : workflow);
    expect(figure.html).toContain('capture-blocked'); expect(figure.html).toContain('"evidenceRefs":[]');
    expect(() => composeFigure({...variant, layout:'not-declared'}, input.view.purpose === 'architecture' ? architecture : workflow)).toThrow('Unsupported case');
  }
},30000);
