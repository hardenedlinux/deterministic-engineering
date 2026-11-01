// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {presentationThemeLayers} from '@deterministic-engineering/render/presentation-theme';
import {iconPacks} from '@deterministic-engineering/render/icons';
import type {FigureResources} from '@deterministic-engineering/render';
/** Downstream-owned visual resources. Selection and content remain in D2. */
export const resources: FigureResources = {
  themeLayers: {...presentationThemeLayers, workbench: {
    fontFamily: '"Georgia",serif', colors: {accent: '#246B59', secondary: '#8E6034'}, spacing: {radius: 2, gap: 16},
    stylesheet: '[data-heading]{font-weight:600;letter-spacing:-.6px}[data-panel]{border-radius:2px!important;border-top:3px solid var(--accent)}[data-question-marker]{border-radius:2px!important}[data-badge]{border-radius:0!important;background:transparent!important;border-bottom:2px solid var(--accent)}',
  }},
  iconPacks: {...iconPacks, repo: {
    library: {label: 'Repository publication', svg: '<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M5 6h22v20H5zM10 2v8M22 2v8M10 15h12M10 21h8"/></svg>'},
    selection: {label: 'Repository selection', svg: '<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M5 6h22v20H5zM10 16l4 4 8-9"/></svg>'},
    capture: {label: 'Repository binding', svg: '<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M5 6h22v20H5zM10 12h12v9H10zM16 2v8M16 23v7"/></svg>'},
  }},
};
