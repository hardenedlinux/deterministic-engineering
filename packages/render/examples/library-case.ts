// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {attributionFor} from './attribution';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { chromium } from 'playwright';
import { composeFigure, compileFigureSource, selectFigureVariant, type FigureInput } from '@deterministic-engineering/render';
import { exportFigure } from '@deterministic-engineering/render/export';
import {resources} from './library-case/resources';
import { architecture } from './library-case/architecture';
import { workflow } from './library-case/workflow';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const declarationFiles = ['docs/90-99-views/90-architecture-views/90.132-library-profile-scenario-architecture.d2', 'docs/90-99-views/90-architecture-views/90.133-capture-preparation-workflow.d2'];
const d2Sources = Object.fromEntries(await Promise.all(declarationFiles.map(async file => [file, await readFile(path.join(root, file), 'utf8')])));
const [architectureDeclaration, workflowDeclaration] = await Promise.all(declarationFiles.map(file => compileFigureSource(d2Sources, file, resources)));
if (!architectureDeclaration || !workflowDeclaration) throw new Error('Missing D2 declarations');
const references = architectureDeclaration.references;
const sourceFor = (ref: string): string => { const value = references[ref]; if (!value) throw new Error(`Undeclared source: ${ref}`); return value; };
const compositionFiles = ['packages/render/examples/attribution.ts','packages/render/examples/library-case.ts', 'packages/render/examples/library-case/architecture.ts', 'packages/render/examples/library-case/architecture-diagram.ts', 'packages/render/examples/library-case/dependency-matrix.ts', 'packages/render/examples/library-case/workflow.ts', 'packages/render/examples/library-case/workflow-diagram.ts', 'packages/render/examples/library-case/workflow-declaration.ts', 'packages/render/examples/library-case/resources.ts', 'packages/render/examples/library-case/style.ts', 'packages/render/examples/comparison.ts'];
const sourcePaths = [...new Set([...Object.values(references), ...Object.values(workflowDeclaration.references), ...compositionFiles, ...declarationFiles])];
const sources = Object.fromEntries(await Promise.all(sourcePaths.map(async file => [file, await readFile(path.join(root, file), 'utf8')])));
// Explicit source-excerpt observations, not a Scheme/SysML parser, execution or C issuance.
const presentation = architectureDeclaration.presentation;
if (!presentation || typeof presentation !== 'object' || !('observations' in presentation) || !Array.isArray(presentation.observations) || !presentation.observations.length) throw new Error('Case source observations must be declared');
const anchors = presentation.observations.map((value: unknown) => {
  if (!value || typeof value !== 'object' || !('ref' in value) || !('excerpt' in value) || typeof value.ref !== 'string' || typeof value.excerpt !== 'string' || !value.excerpt.trim()) throw new Error('Invalid declared source observation');
  return [value.ref, value.excerpt] as const;
});
const observations = anchors.map(([ref, excerpt]) => {
  const file = sourceFor(ref), source = sources[file]!;
  const index = source.indexOf(excerpt);
  if (index < 0) throw new Error(`Case source changed; update its explanation: ${file} / ${excerpt}`);
  return {kind: 'source-excerpt-observation', source: file, line: source.slice(0, index).split('\n').length, excerpt};
});
const architectureInput: FigureInput = {...architectureDeclaration, sources};
const workflowInput: FigureInput = {...workflowDeclaration, sources};
const candidates = [
  {name: 'architecture', figure: composeFigure(architectureInput, architecture)},
  {name: 'workflow', figure: composeFigure(workflowInput, workflow)},
  ...[{input: architectureInput, composer: architecture, prefix: 'architecture'}, {input: workflowInput, composer: workflow, prefix: 'workflow'}].flatMap(({input, composer, prefix}) => (input.variants ?? []).map(variant => {
    if (!/^[a-z0-9-]+$/.test(variant.name)) throw new Error('Invalid variant file name');
    return {name: `${prefix}-${variant.name}`, figure: composeFigure(selectFigureVariant(input, variant.name), composer)};
  })),
];
const output = path.join(root, '.cache/render/library-case');
await mkdir(output, {recursive: true});
const browser = await chromium.launch();
try {
  for (const {name, figure} of candidates) {
    const region = figure.purpose === 'architecture' ? 'architecture' : 'workflow';
    const image = await exportFigure(figure, browser, {scale: 2, regions: [region],attribution:attributionFor(figure)});
    for (const file of sourcePaths) if (await readFile(path.join(root, file), 'utf8') !== sources[file]) throw new Error(`Source changed during export: ${file}`);
    await writeFile(path.join(output, `${name}.html`), image.html);
    await writeFile(path.join(output, `${name}.png`), image.png);
    await writeFile(path.join(output, `${name}-detail.png`), image.regionImages[region]!);
    await writeFile(path.join(output, `${name}.json`), JSON.stringify({status: 'design explanation / source observations only', ...image.receipt, sources: figure.sourceSHA256, observations}, null, 2));
    console.log(`${name}: ${image.receipt.width}x${image.receipt.height}; browser ${image.receipt.browser}`);
  }
} finally { await browser.close(); }
console.log(`Editable HTML and browser-exported PNG: ${output}`);
