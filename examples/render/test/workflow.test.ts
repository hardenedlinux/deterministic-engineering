import {test, expect} from 'bun:test';
import {composeFigure, type FigureComposer} from '@deterministic-engineering/render';
import {readWorkflow} from '../library-case/workflow-declaration';
test('flow layout validates responsibility membership and the native model path', async () => {

  const input = {
    view: {source: 'flow.d2', title: 'Flow', purpose: 'workflow' as const, kind: 'flow' as const, question: {ref: 'q', text: 'Who?'}, basis: {captureRef: 'candidate', modelRefs: [], obligationRefs: [], evidenceRefs: []}},
    language: 'en', width: 720, sources: {'flow.d2': 'a -> b'}, references: {source: 'flow.d2'}, questions: [{ref: 'q', text: 'Who?', focusRefs: ['source']}],
    copy: {a: 'Acquire', b: 'Bind', detail: 'Observed source'}, layout: 'swimlane',
    presentation: {flow: {lanes: [{id: 'scenario', label: 'Scenario'}], steps: [{node: 'a', lane: 'scenario', title: 'a', detail: 'detail', icon: 'model'}, {node: 'b', lane: 'scenario', title: 'b', detail: 'detail', icon: 'model'}]}},
    model: {subjects: [{id: 'a', type: 'rectangle'}, {id: 'b', type: 'rectangle'}], relations: [{id: 'edge', src: 'a', dst: 'b', label: 'binds'}]},
  };
  const composer: FigureComposer = context => {readWorkflow(context); return {markup: '<section data-question="q">Who?</section>', css: ''};};
  expect(composeFigure(input, composer).purpose).toBe('workflow');
  expect(() => composeFigure({...input, presentation: {flow: {...input.presentation.flow, lanes: [{id: 'other', label: 'Invented'}]}}}, composer)).toThrow('Undeclared flow lane');
  expect(() => composeFigure({...input, model: {...input.model, relations: []}}, composer)).toThrow('Undeclared model relation');
});
