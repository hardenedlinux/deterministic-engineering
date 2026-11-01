import { test, expect } from 'bun:test';
import { renderedViewFromJson } from '@openmbee/opensysml';
import { captureOpenSysMLView, projectOpenSysMLView } from '../src/opensysml';
import { renderCatalog } from '../src';

const selection = { source: 'models/context.d2', title: 'SDK model projection', purpose: 'architecture' as const, kind: 'system' as const, question: { ref: 'questions/model-ownership', text: 'Which model elements are related?' }, basis: { captureRef: 'capture/model', modelRefs: ['model-capture-1'], obligationRefs: [], evidenceRefs: [] } };
function model() {
  // Decode a protojson response through the actual SDK, not a local model parser.
  return renderedViewFromJson({ view: 'Demo::Context', kind: 'interconnection', stated: 'candidate', nodes: [
    { id: 'Demo::Control', name: 'Control', kind: 'part', origin: { file: 'demo.sysml', startLine: 2 } },
    { id: 'Demo::Worker', name: 'Worker', kind: 'part' },
  ], edges: [{ from: 'Demo::Control', to: 'Demo::Worker', kind: 'connection', label: 'dispatch' }] });
}
test('SDK decoded view -> pure D2 projection -> actual image, with model identity', async () => {
  const rendering = model();
  const capture = { modelHash: 'model-capture-1', requestedView: 'Demo::Context', rendering };
  const prior = JSON.stringify(capture);
  const projection = projectOpenSysMLView(capture, { selection, layout: 'reflow', roles: { 'Demo::Control': 'semantic' } });
  expect(JSON.stringify(capture)).toBe(prior);
  expect(projection.trace.nodes[0]!.origin?.file).toBe('demo.sysml');
  expect(projection.trace.edges[0]!.from).toBe('Demo::Control');
  const image = await renderCatalog({ sources: { [projection.source]: projection.text }, views: [projection.view], presentation: { project: 'SDK consumer' } });
  expect(image.images[0]!.nodes).toBe(2);
  expect(image.images[0]!.edges).toBe(1);
  const changed = projectOpenSysMLView({ ...capture, modelHash: 'model-capture-2' }, { selection, layout: 'reflow' });
  expect(changed.trace.renderingSHA256).not.toBe(projection.trace.renderingSHA256);
}, 30000);
test('unsupported SDK notation, dangling endpoints and cyclic ownership refuse', () => {
  const input = { modelHash: 'm', requestedView: 'v', rendering: model() };
  input.rendering.nodes[0]!.ports = [{ id: 'p', name: 'p', type: '', direction: '' }];
  expect(() => projectOpenSysMLView(input, { selection, layout: 'reflow' })).toThrow('notation adapter');
  input.rendering = model();
  input.rendering.edges[0]!.to = 'missing';
  expect(() => projectOpenSysMLView(input, { selection, layout: 'reflow' })).toThrow('endpoint');
  input.rendering = model();
  input.rendering.nodes[0]!.parent = input.rendering.nodes[0]!.id;
  expect(() => projectOpenSysMLView(input, { selection, layout: 'reflow' })).toThrow('Cyclic');
});
test('SDK effect failures propagate; the adapter does not fake capability or service acceptance', async () => {
  const refusal = new Error('render_view capability missing');
  await expect(captureOpenSysMLView({ renderView: async () => { throw refusal; } }, 'm', 'v')).rejects.toBe(refusal);
});
