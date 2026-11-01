import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { renderCatalog, defaultTheme, extendTheme, type ViewSelection } from '@deterministic-engineering/architecture-renderer';

// Explicit review cases, not another repository discovery or evidence framework.
const root = fileURLToPath(new URL('../../', import.meta.url));
const directory = 'docs/90-99-views/90-architecture-views';
const cases = [
  { name: '90.91-engineering-content-contracts', question: 'Who publishes, selects and captures architecture, documents and decisions?', document: '10.31-architecture-document-and-decision-contracts.org', kind: 'assurance' },
  { name: '90.120-ascent-domain-owned-module-topology', question: 'Which ASCENT domain owns each module and which boundaries remain transitional?', document: '10.131-ascent-domain-owned-module-topology.org', kind: 'system' },
  { name: '90.84-sysml-interoperability', question: 'How do optional SysML observations reach reasoning and review without granting approval?', document: '10.24-sysml-interoperability-and-authority-boundaries.org', kind: 'assurance' },
] as const;
const sources = Object.fromEntries(await Promise.all(cases.map(async item => [`${directory}/${item.name}.d2`, await readFile(path.join(root, directory, `${item.name}.d2`), 'utf8')])));
const views: ViewSelection[] = cases.map(item => ({
  source: `${directory}/${item.name}.d2`, title: item.name, purpose: 'architecture', kind: item.kind,
  question: { ref: `10.140/cases/${item.name}`, text: item.question },
  basis: { captureRef: '10.140/repository-source-rendering-candidate',
    modelRefs: [`${directory}/${item.name}.d2`],
    obligationRefs: [`docs/10-19-design/10-architecture/${item.document}`], evidenceRefs: [] },
}));
const result = await renderCatalog({ sources, views, presentation: { project: 'Deterministic Engineering / existing design sources' },
  theme: extendTheme(defaultTheme, { render: { themeID: 0, pad: 24 } }) }, { workers: 2 });
const output = path.join(root, '.cache/architecture-rendering/repository-cases');
await mkdir(output, { recursive: true });
for (const image of result.images) {
  // Current rendering of historical design content is not current architecture admission.
  if ((await readFile(path.join(root, image.source), 'utf8')) !== sources[image.source]) throw new Error('Case source changed');
  const stem = path.basename(image.source, '.d2');
  await writeFile(path.join(output, `${stem}.svg`), image.svg);
}
await writeFile(path.join(output, 'receipt.json'), JSON.stringify({ status: 'rendering-only; historical design claims not revalidated', ...result,
  images: result.images.map(({svg, ...receipt}) => receipt),
}, null, 2));
console.log(`Rendered ${result.images.length} unchanged repository D2 cases into ${output}`);

// TS presentation adds a question, explanatory hierarchy and evidence context.
// It does not redraw the native D2 graph or relabel historical claims as passes.
const { composePresentation } = await import('@deterministic-engineering/architecture-renderer');
const { defaultPresentationTheme, extendPresentationTheme } = await import('@deterministic-engineering/architecture-renderer/presentation-theme');
const notes = {
  '90.91-engineering-content-contracts': [
    { title: 'Library publishes meaning', text: 'Models, obligations and content duties are published once. Project document bodies remain project-owned.', status: 'design', refs: ['10.31 / Library contract'] },
    { title: 'Profile selects; Scenario binds', text: 'Selection does not copy model bodies. Scenario associates actual content with one captured use.', status: 'design', refs: ['10.31 / Profile and Scenario'] },
    { title: 'A drawing is not assurance', text: 'Observers, admitted evidence and fresh review are still required. Dashed links describe proposed integration.', status: 'pending', refs: [] },
  ],
  '90.120-ascent-domain-owned-module-topology': [
    { title: 'Domains own their modules', text: 'Core, table, program, candidate, rules and temporal have distinct responsibilities; the engine owns transport effects.', status: 'design', refs: ['10.131 / domain topology'] },
    { title: 'Reuse source admission', text: 'Selection and transitive source closure belong to existing Core capabilities rather than a parallel module loader.', status: 'design', refs: ['10.131 / Core boundary'] },
    { title: 'Migration remains a claim', text: 'The source explicitly marks transitional forwarders. Rendering it does not prove removal or fresh-consumer acceptance.', status: 'pending', refs: [] },
  ],
  '90.84-sysml-interoperability': [
    { title: 'A model method has a scope', text: 'The mapping, imported model bytes and declared omissions must accompany a SysML observation.', status: 'design', refs: ['10.24 / method scope'] },
    { title: 'Keep the independent oracle', text: 'Rust and QNT correspondence controls remain distinct from the model tool and its rendering.', status: 'design', refs: ['10.24 / independent controls'] },
    { title: 'Satisfaction is not approval', text: 'Review freshness and recipient authorization are separate obligations. This page supplies no live model evidence.', status: 'pending', refs: [] },
  ],
} as const;
for (const image of result.images) {
  const stem = path.basename(image.source, '.d2') as keyof typeof notes;
  const item = cases.find(item => item.name === stem)!;
  for (const [name, theme] of Object.entries({
    default: defaultPresentationTheme,
    downstream: extendPresentationTheme(defaultPresentationTheme, { colors: {
      background: '#F6F3EE', ink: '#253932', accent: '#157465', secondary: '#B35B35', tint: '#E6F1EB', secondaryTint: '#F5EDE4',
    } }),
  })) {
    const page = composePresentation({
      title: stem === '90.91-engineering-content-contracts' ? 'One Library. Three clear responsibilities.' : stem === '90.120-ascent-domain-owned-module-topology' ? 'ASCENT / domains, ownership and boundaries' : 'SysML observations / scoped assurance',
      subtitle: 'Deterministic Engineering · real repository case · original D2 source preserved',
      scope: 'Architecture explanation / design candidate',
      answer: item.question === image.question.text ? 'Read the original architecture below alongside its responsibilities and open evidence obligations.' : 'Question association requires review.',
      view: image, findings: notes[stem],
      limits: ['Historical design content; current implementation has not been re-audited.', 'TS presentation status is project-authored. No accepted Q, review R or publication authority is issued here.'],
      theme,
    });
    await writeFile(path.join(output, `${stem}.${name}.svg`), page.svg);
    await writeFile(path.join(output, `${stem}.${name}.json`), JSON.stringify({ ...page, svg: undefined }, null, 2));
  }
}
console.log('Composed three question-led TS presentation pages in independent default and downstream themes');
