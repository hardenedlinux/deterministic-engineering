import { describe, test, expect } from 'bun:test';
import fc from 'fast-check';
import { createCatalog, catalogDigest, renderCatalog, standardThemes, defaultTheme, extendTheme, renderView, type RenderEffects, type ViewSelection, type ViewKind } from '../src';

const question = { ref: 'questions/component-ownership', text: 'Which component owns execution?' };
const basis = { captureRef: 'capture/example', modelRefs: ['model/components'], obligationRefs: ['obligations/owner'], evidenceRefs: [] as string[] };
function selection(kind: ViewKind, source: string): ViewSelection {
  const base = { source, title: `${kind} view`, question, basis };
  return kind === 'system' || kind === 'data' || kind === 'assurance'
    ? { ...base, purpose: 'architecture', kind }
    : { ...base, purpose: 'workflow', kind };
}
function fixture(): { sources: Record<string, string>; views: ViewSelection[]; presentation: { project: string } } {
  return {
    sources: { ...standardThemes(), 'docs/ownership.d2': '...@../architecture/themes/system\ncontrol: "Project control"\nrunner: "Method executor"\ncontrol -> runner: selected input\n' },
    views: [selection('system', 'docs/ownership.d2')], presentation: { project: 'Example repository' },
  };
}
describe('question-driven captured inputs', () => {
  test('canonical source order and theme/import footprint', () => {
    const a = fixture(), b = fixture();
    b.sources = Object.fromEntries(Object.entries(b.sources).reverse());
    expect(catalogDigest(createCatalog(a))).toBe(catalogDigest(createCatalog(b)));
    b.sources['architecture/themes/base.d2'] += '\n# changed\n';
    expect(catalogDigest(createCatalog(a))).not.toBe(catalogDigest(createCatalog(b)));
  });
  test('snapshot and existing evidence references are copied; evidence changes invalidate reuse', () => {
    const input = fixture(), captured = createCatalog(input);
    input.sources['docs/ownership.d2'] = 'changed';
    expect(captured.fs['docs/ownership.d2']).toContain('control');
    const changed = fixture();
    changed.views = [{ ...changed.views[0]!, basis: { ...basis, evidenceRefs: ['evidence/new-observation'] } }];
    expect(catalogDigest(createCatalog(changed))).not.toBe(catalogDigest(captured));
    expect(Object.isFrozen(captured.views[0]!.basis.evidenceRefs)).toBe(true);
  });
  test('functional entry refuses a different question/capture before running an effect', async () => {
    const catalog = createCatalog(fixture());
    let invoked = false;
    const effects: RenderEffects = {
      compile: async () => { invoked = true; throw new Error('must not execute'); },
      svg: async () => '',
    };
    await expect(renderView(catalog, { ...catalog.views[0]!, question: { ...question, ref: 'other' } }, effects)).rejects.toThrow('captured catalog');
    expect(invoked).toBe(false);
  });
  test('architecture and workflow remain distinct contracts', () => {
    const input = fixture();
    expect(() => createCatalog({ ...input, views: [{ ...input.views[0]!, purpose: 'workflow' } as ViewSelection] })).toThrow('separate');
  });
  test('a missing question/capture, duplicate or missing source refuses', () => {
    const input = fixture();
    expect(() => createCatalog({ ...input, views: [{ ...input.views[0]!, question: { ref: '', text: '' } }] })).toThrow('question');
    delete input.sources['docs/ownership.d2'];
    expect(() => createCatalog(input)).toThrow('Missing view source');
    const duplicate = fixture();
    duplicate.views.push({ ...duplicate.views[0]! });
    expect(() => createCatalog(duplicate)).toThrow('Duplicate view');
  });
  test('repository-relative source law', () => {
    fc.assert(fc.property(fc.stringMatching(/^[a-z]{1,16}$/), name => {
      const input = fixture(); input.sources[`../${name}.d2`] = 'a -> b';
      expect(() => createCatalog(input)).toThrow('repository-relative');
    }), { numRuns: 64 });
  });
});
describe('official D2 compile/render, without TS redrawing', () => {
  test('preserves source IDs, question links and produces native SVG', async () => {
    const image = (await renderCatalog(fixture())).images[0]!;
    expect(image.nodeIds).toEqual(['control', 'runner']);
    expect(image.edges).toBe(1);
    expect(image.svg).toContain('Project control');
    expect(image.question.ref).toBe(question.ref);
    expect(image.basis.captureRef).toBe(basis.captureRef);
    expect(image.svg).toContain('<svg');

  }, 30000);
  test('seven classifications consume native D2; classifications do not replace its language', async () => {
    const input = fixture();
    const kinds: ViewKind[] = ['system', 'routing', 'flow', 'sequence', 'state', 'data', 'assurance'];
    input.views = kinds.map(kind => selection(kind, `docs/${kind}.d2`));
    for (const kind of kinds) input.sources[`docs/${kind}.d2`] = `...@../architecture/themes/${kind}\na -> b: relation`;
    const before = JSON.stringify(input);
    const result = await renderCatalog(input, { workers: 2 });
    expect(result.images).toHaveLength(7);
    expect(result.images.every(image => image.nodes === 2 && image.edges === 1)).toBe(true);
    expect(JSON.stringify(input)).toBe(before);
  }, 30000);
  test('native nested component ownership and endpoint selection survive', async () => {
    const input = fixture();
    input.sources['docs/ownership.d2'] = 'project: {caller: Gateway}\nlibrary: {api: API; core: Core}\nproject.caller -> library.api: dependency\nlibrary.api -> library.core: composition';
    const image = (await renderCatalog(input)).images[0]!;
    expect(image.nodes).toBe(5);
    expect(image.nodeIds).toContain('library.api');
    expect(image.edges).toBe(2);
  }, 30000);
  test('D2 sequence notation stays native rather than becoming TS cards', async () => {
    const input = fixture();
    input.views = [selection('sequence', 'docs/ownership.d2')];
    input.sources['docs/ownership.d2'] = 'shape: sequence_diagram\nclient -> server: request\nserver -> client: response';
    const image = (await renderCatalog(input)).images[0]!;
    // Native D2 adds two actor lifelines to the two messages.
    expect(image.edgeIds).toEqual(['(client -> server)[0]', '(server -> client)[0]', '(client -- )[0]', '(server -- )[0]']);
    expect(image.svg).toContain('request');
    expect(image.svg).toContain('response');
  }, 30000);
  test('downstream D2 profiles and official theme options replace defaults without changing the model', async () => {
    const input = fixture();
    input.sources['docs/ownership.d2'] += '\ncontrol.style.fill: "#123456"';
    const theme = extendTheme(defaultTheme, { render: { pad: 48, themeID: 200 } });
    const before = JSON.stringify(defaultTheme);
    const result = await renderCatalog({ ...input, theme });
    expect(result.images[0]!.svg.toLowerCase()).toContain('#123456');
    expect(result.images[0]!.nodeIds).toEqual(['control', 'runner']);
    expect(JSON.stringify(defaultTheme)).toBe(before);
    expect(catalogDigest(createCatalog({ ...input, theme }))).not.toBe(catalogDigest(createCatalog(input)));
  }, 30000);
  test('syntax and import failures return no partial result; next independent scope still works', async () => {
    const input = fixture(); input.sources['docs/ownership.d2'] = 'node: {';
    await expect(renderCatalog(input)).rejects.toThrow('D2 rendering failed');
    input.sources['docs/ownership.d2'] = '...@missing';
    await expect(renderCatalog(input)).rejects.toThrow('D2 rendering failed');
    expect((await renderCatalog(fixture())).images).toHaveLength(1);
  }, 30000);
});

test('native D2 rendering accepts a downstream architecture classification without a new framework profile', async () => {
  const input = fixture(); input.views = [{...input.views[0]!,kind:'domain-ownership-map'}];
  const image = (await renderCatalog(input)).images[0]!;
  expect(image.kind).toBe('domain-ownership-map'); expect(image.svg).toContain('Project control');
});
