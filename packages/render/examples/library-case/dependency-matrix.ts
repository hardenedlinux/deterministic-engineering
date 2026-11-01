// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import type {FigureContext} from '@deterministic-engineering/render';
/** A second architecture organization: exact dependency directions, not workflow order. */
export function dependencyMatrix({presentation, model, relation, text}: FigureContext): string {
  if (!presentation || typeof presentation !== 'object' || !('matrix' in presentation) || !Array.isArray(presentation.matrix)) throw new Error('Declared matrix axes are missing');
  const axes = presentation.matrix.map((value: unknown) => {
    if (!value || typeof value !== 'object' || !('node' in value) || !('label' in value) || typeof value.node !== 'string' || typeof value.label !== 'string') throw new Error('Invalid matrix axis');
    if (!model?.subjects.some(subject => subject.id === value.node)) throw new Error('Undeclared matrix node');
    return {node: value.node, label: value.label};
  });
  if (!axes.length || new Set(axes.map(axis => axis.node)).size !== axes.length) throw new Error('Invalid matrix axes');
  return `<table class="dependency-matrix"><thead><tr><th></th>${axes.map(axis => `<th>${text(axis.label)}</th>`).join('')}</tr></thead><tbody>${axes.map(source => `<tr><th>${text(source.label)}</th>${axes.map(target => {
    const edge = model?.relations.find(edge => edge.src === source.node && edge.dst === target.node);
    return `<td>${edge ? text(relation(source.node, target.node).label) : '—'}</td>`;
  }).join('')}</tr>`).join('')}</tbody></table>`;
}
