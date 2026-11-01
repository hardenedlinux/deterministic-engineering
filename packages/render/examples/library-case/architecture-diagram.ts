// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import type {FigureContext} from '@deterministic-engineering/render';
import {dependencyMatrix} from './dependency-matrix';
const ownership = ({reference: ref, icon, text, copy, relation}: FigureContext) => `<div class="architecture" data-canvas>
<svg class="diagram-connections" data-connections aria-hidden="true"><path data-from="project.profile" data-to="library"/><path data-from="project.scenario" data-to="project.profile"/></svg>
<div class="domain published" data-boundary data-node="library" data-surface ${ref('library')}><div class="boundary">${icon('reference')}${text(copy("library-boundary"))}</div><div class="owner-heading">${icon('library')}<div><h3>${text(copy("library-label"))}</h3><small>${text(copy("annotation-09"))}</small></div></div><div class="asset-row">${icon('model')}${text(copy("annotation-10"))}</div><div class="asset-row">${icon('obligation')}${text(copy("annotation-11"))}</div><div class="asset-row">${icon('document')}${text(copy("annotation-12"))}</div></div>
<div class="relation outer">${text(relation('project.profile', 'library').label)}</div>
<div class="domain project" data-boundary><div class="boundary">${icon('model')}${text(copy("project-boundary"))}</div><div class="project-owners">
<div class="owner" data-node="project.profile" data-surface ${ref('profile')}><div class="owner-heading">${icon('selection')}<h3>${text(copy("profile-label"))}</h3></div><p>${text(copy("annotation-14"))}<br>${text(copy("annotation-15"))}</p></div>
<div class="relation inner">${text(relation('project.scenario', 'project.profile').label)}</div>
<div class="owner scenario" data-node="project.scenario" data-surface ${ref('scenario')}><div class="owner-heading">${icon('capture')}<h3>${text(copy("scenario-label"))}</h3></div><p>${text(copy("annotation-17"))}<br>${text(copy("annotation-18"))}</p></div></div>
<div class="inputs"><span class="input-item">${icon('model')}${text(copy("model-label"))}</span><span class="input-item">${icon('document')}${text(copy("document-label"))}</span><span class="input-item">${icon('decision')}${text(copy("decision-label"))}</span></div></div></div>
`;
/** Case-owned composition table; no global registration or HTML string surgery. */
const diagrams: Readonly<Record<string, (context: FigureContext) => string>> = {default: ownership, 'dependency-matrix': dependencyMatrix};
export function architectureDiagram(context: FigureContext): string {
  if (!Object.hasOwn(diagrams, context.layout)) throw new Error(`Unsupported case architecture layout: ${context.layout}`);
  return diagrams[context.layout]!(context);
}
