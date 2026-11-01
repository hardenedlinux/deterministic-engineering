import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { renderCatalog, composePresentation } from '@deterministic-engineering/architecture-renderer';
import { defaultPresentationTheme, extendPresentationTheme } from '@deterministic-engineering/architecture-renderer/presentation-theme';
const root = fileURLToPath(new URL('../../', import.meta.url));
const source = 'docs/90-99-views/90-architecture-views/90.131-library-responsibility-explanation.d2';
const { defaultIcons, iconDataURI } = await import('@deterministic-engineering/architecture-renderer/icons');
const sourceText = await readFile(path.join(root, source), 'utf8');
const iconBindings = {library: defaultIcons.library, profile: defaultIcons.selection, scenario: defaultIcons.capture, 'content.model': defaultIcons.model, 'content.docs': defaultIcons.document, 'content.decisions': defaultIcons.decision};
const withIcons = sourceText + '\n' + Object.entries(iconBindings).map(([id, icon]) => `${id}.icon: ${JSON.stringify(iconDataURI(icon, '#245FE5'))}`).join('\n');
const result = await renderCatalog({sources: {[source]: withIcons}, presentation: {project: 'Deterministic Engineering'}, views: [{
  source, title: 'Library / Profile / Scenario responsibilities', purpose: 'architecture', kind: 'system',
  question: {ref: '10.140/questions/three-responsibilities', text: 'Who publishes, who selects, and who captures?'},
  basis: {captureRef: '10.140/question-led-design-candidate', modelRefs: ['90.91 / original content-contract view'], obligationRefs: ['10.31 / public contracts'], evidenceRefs: []},
}]});
const output = path.join(root, '.cache/architecture-rendering/focused'); await mkdir(output, {recursive: true});
for (const [name, theme] of Object.entries({default: defaultPresentationTheme, downstream: extendPresentationTheme(defaultPresentationTheme, {colors: {accent: '#157465', secondary: '#B35B35', background: '#F6F3EE', tint: '#E6F1EB', secondaryTint: '#F5EDE4'}})})) {
  const page = composePresentation({ title: 'One Library. Three clear responsibilities.',
    subtitle: 'Deterministic Engineering / DE-CASE-01 · question-led architecture explanation', scope: 'Architecture / ownership',
    answer: 'Publish reusable contracts. Select the right configuration. Bind real project content.',
    view: result.images[0]!, theme, findingsTitle: 'Three responsibilities / no duplicated ownership',
    findings: [
      {icon: defaultIcons.library, title: 'Publish once', text: 'Models · methods · policies · obligations', status: 'design', refs: ['10.31 / Library']},
      {icon: defaultIcons.selection, title: 'Select explicitly', text: 'Stage · viewpoints · required contracts', status: 'design', refs: ['10.31 / Profile']},
      {icon: defaultIcons.capture, title: 'Capture one use', text: 'Architecture · Org · decisions · sources', status: 'design', refs: ['10.31 / Scenario']},
    ], limits: ['Design candidate derived from 90.91 / 10.31. Evidence and independent review remain open.'],
  });
  await writeFile(path.join(output, `library-responsibilities.${name}.svg`), page.svg);
  await writeFile(path.join(output, `library-responsibilities.${name}.json`), JSON.stringify({...page, svg: undefined}, null, 2));
}
console.log(`Composed focused question-led architecture explanation into ${output}`);
