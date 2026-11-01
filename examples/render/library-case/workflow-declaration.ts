import type {FigureContext} from '@deterministic-engineering/render';
interface Workflow {
  readonly lanes: readonly {id: string; label: string}[];
  readonly steps: readonly {node: string; lane: string; title: string; detail: string; icon: string}[];
}
const record = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid case workflow declaration');
  return value as Record<string, unknown>;
};
const text = (value: unknown): string => {if (typeof value !== 'string' || !value.trim()) throw new Error('Invalid workflow text'); return value;};
/** The linear preparation path is this Case's contract, not a framework-wide rule. */
export function readWorkflow(context: FigureContext): Workflow {
  if (context.view.purpose !== 'workflow') throw new Error('Case preparation needs a workflow view');
  const value = record(record(context.presentation).flow);
  if (!Array.isArray(value.lanes) || !Array.isArray(value.steps)) throw new Error('Expected case lanes and steps');
  const lanes = value.lanes.map(item => {const lane = record(item); return {id: text(lane.id), label: text(lane.label)};});
  const steps = value.steps.map(item => {const step = record(item); return {node: text(step.node), lane: text(step.lane), title: text(step.title), detail: text(step.detail), icon: text(step.icon)};});
  if (!lanes.length || new Set(lanes.map(lane => lane.id)).size !== lanes.length) throw new Error('Invalid workflow lanes');
  if (!steps.length || new Set(steps.map(step => step.node)).size !== steps.length) throw new Error('Invalid workflow steps');
  steps.forEach((step, index) => {
    if (!lanes.some(lane => lane.id === step.lane)) throw new Error('Undeclared flow lane');
    if (!context.model?.subjects.some(subject => subject.id === step.node)) throw new Error('Undeclared flow node');
    context.copy(step.title); context.copy(step.detail); context.icon(step.icon);
    if (index) context.relation(steps[index - 1]!.node, step.node);
  });
  return {lanes, steps};
}
