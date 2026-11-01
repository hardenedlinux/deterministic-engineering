// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {readWorkflow} from './workflow-declaration';
import type { FigureContext } from '@deterministic-engineering/render';
/** Layouts consume the same declared steps and model edges. No invented owners. */
export function workflowDiagram(context: FigureContext): string {
  const {layout, text, copy, icon} = context;
  const flow = readWorkflow(context);
  if (!flow) throw new Error('Workflow needs declared steps and responsibility lanes');
  if (!['default', 'swimlane'].includes(layout)) throw new Error(`Unsupported case layout: ${layout}`);
  const node = (step: typeof flow.steps[number], index: number) => `<div data-node="${text(step.node)}" data-surface class="step"><span class="step-index">${index + 1}</span>${icon(step.icon)}<div><b>${text(copy(step.title))}</b><small>${text(copy(step.detail))}</small></div></div>`;
  const links = `<svg class="diagram-connections" data-connections aria-hidden="true">${flow.steps.slice(1).map((step, i) => `<path data-from="${text(flow.steps[i]!.node)}" data-to="${text(step.node)}"/>`).join('')}</svg>`;
  if (layout === 'swimlane') return `<div data-canvas class="lanes" style="--step-count:${flow.steps.length}">${links}${flow.lanes.map(lane => `<div class="lane"><div class="lane-label">${text(lane.label)}</div><div class="lane-track">${flow.steps.map((step, i) => step.lane === lane.id ? `<div class="lane-slot" style="grid-column:${i + 1}">${node(step, i)}</div>` : '').join('')}</div></div>`).join('')}</div>`;
  return `<div data-canvas class="flow" style="--step-count:${flow.steps.length}">${links}${flow.steps.map((step, i) => `${i ? '<div class="forward" data-flow-gap></div>' : ''}${node(step, i)}`).join('')}</div>`;
}
