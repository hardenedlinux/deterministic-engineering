// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import type {PresentationThemeOverrides} from '../presentation-theme';
export const sketchbook: PresentationThemeOverrides = Object.freeze({fonts: Object.freeze([400, 700].map(weight => Object.freeze({family: 'Kalam', weight, source: `@fontsource/kalam/files/kalam-latin-${weight}-normal.woff2`}))), fontFamily: '"Kalam","Noto Sans",sans-serif', drawing: Object.freeze({mode: 'sketch' as const, options: Object.freeze({seed: 29, roughness: 1.3})}),
    typography:Object.freeze({lineHeight:'2.3em'}),
    colors: Object.freeze({background: '#FAF7EE', surface: '#FFFDF7', ink: '#283E43', muted: '#63716F', border: '#ADBBB5', accent: '#287F79', secondary: '#946B42', tint: '#EDF4E9', secondaryTint: '#F6EDD8'}),
    stylesheet: '.scene-groups .sketch-surface path:not([stroke="none"]){stroke:var(--muted);stroke-width:1.5}[data-figure]{background:var(--background)!important}[data-panel]{border-radius:2px!important;background:transparent!important;border:0!important;border-top:1px dashed var(--border)!important}[data-heading]{letter-spacing:0!important}[data-summary]{background:var(--tint)!important;color:var(--ink)!important;border-radius:0!important}[data-surface]{position:relative;isolation:isolate;border-color:transparent!important;border-radius:0!important;background:transparent!important}[data-surface]>*{position:relative;z-index:1}[data-surface]>.sketch-surface{position:absolute;inset:0;z-index:0;pointer-events:none;overflow:visible}[data-badge]{background:transparent!important;border-bottom:2px solid var(--secondary);border-radius:0!important}' });
