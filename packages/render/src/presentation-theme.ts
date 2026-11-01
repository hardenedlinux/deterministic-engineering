import type {Options} from 'roughjs/bin/core';
import {sketchbook} from './styles/sketchbook';
import {nodeEditor} from './styles/node-editor';
/** Declarative visual layers. No process, registry mutation or language translation. */
export interface PresentationTheme {
  readonly fontFamily: string;
  readonly stylesheet: string;
  readonly fonts: readonly Readonly<{family: string; weight: number; source: string}>[];
  readonly drawing: Readonly<{mode: "precise" | "sketch"; options: Readonly<Options & {seed: number}>}>;
  readonly colors: Readonly<{
    background: string; surface: string; ink: string; muted: string; border: string;
    accent: string; secondary: string; tint: string; secondaryTint: string; onAccent: string;
    supported: string; pending: string; conflict: string;
  }>;
  readonly spacing: Readonly<{ gutter: number; gap: number; radius: number }>;
}
export interface PresentationThemeOverrides {
  readonly fontFamily?: string;
  readonly stylesheet?: string;
  readonly fonts?: PresentationTheme["fonts"];
  readonly drawing?: {readonly mode?: PresentationTheme["drawing"]["mode"]; readonly options?: Partial<Options>};
  readonly colors?: Partial<PresentationTheme['colors']>;
  readonly spacing?: Partial<PresentationTheme['spacing']>;
}
export const defaultPresentationTheme: PresentationTheme = Object.freeze({
  stylesheet: "", fonts: Object.freeze([]), drawing: Object.freeze({mode: "precise", options: Object.freeze({seed: 17, roughness: 1, strokeWidth: 1.2, fillStyle: "hachure", hachureGap: 9, fillWeight: .6})}),
  fontFamily: '"Avenir Next","Segoe UI","Noto Sans",sans-serif',
  colors: Object.freeze({background: '#F0F5F7', surface: '#FFFFFF', ink: '#193348', muted: '#627787', border: '#D5E1E7',
    accent: '#246E86', secondary: '#686084', tint: '#E7F1F5', secondaryTint: '#F0EDF5', onAccent: '#FFFFFF',
    supported: '#237C69', pending: '#9A6C25', conflict: '#A84C60'}),
  spacing: Object.freeze({gutter: 26, gap: 12, radius: 15}),
});
export function extendPresentationTheme(base: PresentationTheme, overrides: PresentationThemeOverrides = {}): PresentationTheme {
  return Object.freeze({stylesheet: overrides.stylesheet === undefined ? base.stylesheet : [base.stylesheet, overrides.stylesheet].filter(Boolean).join("\n"),
    fonts: Object.freeze([...(overrides.fonts ?? base.fonts)].map(font => Object.freeze({...font}))),
    drawing: Object.freeze({...base.drawing, ...overrides.drawing, options: Object.freeze({...base.drawing.options, ...overrides.drawing?.options})}), fontFamily: overrides.fontFamily ?? base.fontFamily,
    colors: Object.freeze({...base.colors, ...overrides.colors}), spacing: Object.freeze({...base.spacing, ...overrides.spacing})});
}
export type ThemeLayers = Readonly<Record<string, PresentationThemeOverrides>>;
export const presentationThemeLayers: ThemeLayers = Object.freeze({
  blueprint: defaultPresentationTheme,
  'field-notes': Object.freeze({fontFamily: '"Charter","Georgia",serif', colors: Object.freeze({background: '#F4F0E7', surface: '#FFFEF9', ink: '#39382F', muted: '#797365', border: '#E0D8C5', accent: '#8D6738', secondary: '#546D5B', tint: '#F4EAD7', secondaryTint: '#EAF0E5', onAccent: '#FFFFFF', supported: '#3B785A', pending: '#A67127', conflict: '#A04F4B'})}),
  graphite: Object.freeze({colors: Object.freeze({background: '#131E28', surface: '#1C2935', ink: '#E5EEF5', muted: '#A3B6C5', border: '#354956', accent: '#8BCADD', secondary: '#BFB4DD', tint: '#263D4B', secondaryTint: '#343449', onAccent: '#16222C', supported: '#8BCEAE', pending: '#E0BE81', conflict: '#ECA3AC'})}),
  sketchbook,
  'node-editor': nodeEditor,
  compact: Object.freeze({spacing: Object.freeze({gutter: 26, gap: 12, radius: 13})}),
});
/** Ordered composition is explicit and immutable. Downstream may supply its own layers. */
export function composePresentationTheme(names: readonly string[], layers: ThemeLayers = presentationThemeLayers): PresentationTheme {
  if (!names.length) throw new Error('At least one declared theme layer is required');
  return names.reduce((theme, name) => {
    const layer = layers[name]; if (!Object.hasOwn(layers, name) || !layer) throw new Error(`Unknown declared theme layer: ${name}`);
    return extendPresentationTheme(theme, layer);
  }, defaultPresentationTheme);
}
