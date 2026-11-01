import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { renderCatalog, createCatalog, catalogDigest, standardThemes, defaultTheme, extendTheme, type CatalogInput } from '@deterministic-engineering/architecture-renderer';

const root = fileURLToPath(new URL('../../', import.meta.url));
const architecture = 'docs/90-99-views/90-architecture-views/90.129-functional-architecture-rendering.d2';
const workflow = 'docs/90-99-views/90-architecture-views/90.130-llm-assisted-model-view-workflow.d2';
async function capture(): Promise<CatalogInput> {
  return {
    sources: { ...Object.fromEntries(Object.entries(standardThemes()).map(([source, text]) => [source.replace('architecture/themes/', 'packages/architecture-renderer/themes/'), text])),
      [architecture]: await readFile(path.join(root, architecture), 'utf8'),
      [workflow]: await readFile(path.join(root, workflow), 'utf8'),
    },
    views: [
      { source: architecture, title: 'Rendering framework / component architecture', purpose: 'architecture', kind: 'system',
        question: { ref: '10.140/ownership', text: 'Which repository owns each component and dependency?' },
        basis: { captureRef: '10.140/current-source-candidate', modelRefs: ['project.sysml', 'packages/architecture-renderer/src/index.ts'], obligationRefs: ['10.140/architecture-rendering-contracts'], evidenceRefs: [] } },
      { source: workflow, title: 'Model-to-view authoring / workflow', purpose: 'workflow', kind: 'flow',
        question: { ref: '10.140/authoring', text: 'How does confirmed intent become a reviewed view candidate?' },
        basis: { captureRef: '10.140/target-design-candidate', modelRefs: ['project.sysml'], obligationRefs: ['10.140/architecture-rendering-migration'], evidenceRefs: [] } },
    ],
    theme: extendTheme(defaultTheme, { render: { pad: 40 } }),
    presentation: { project: 'Deterministic Engineering', footer: 'Architecture candidate / explicit publication' },
  };
}
const input = await capture();
const result = await renderCatalog(input, { workers: 2 });
// This is a stale-input check, not an authorization or atomic publication claim.
if (catalogDigest(createCatalog(await capture())) !== result.inputSHA256) throw new Error('Render input changed');
const output = path.join(root, '.cache/architecture-rendering');
await mkdir(output, { recursive: true });
for (const image of result.images) {
  const family = input.views.find(view => view.source === image.source)!.purpose;
  const destination = path.join(output, family);
  await mkdir(destination, { recursive: true });
  const stem = path.basename(image.source, '.d2');
  await writeFile(path.join(destination, `${stem}.svg`), image.svg);
}
await writeFile(path.join(output, 'receipt.json'), JSON.stringify({
  inputSHA256: result.inputSHA256, workers: result.workers,
  images: result.images.map(({ svg, ...receipt }) => receipt),
}, null, 2));
console.log(`Rendered ${result.images.length} candidate into ${output}`);
