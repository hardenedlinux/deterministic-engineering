// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {deepFreeze} from './immutable';
import {palettes,type Palette} from './palettes';
import {layoutLayers} from './layouts';
import type {LayoutOptions} from 'elkjs';
import type {IconPack} from './icons';
import type {Options} from 'roughjs/bin/core';
import {sketchbook} from './styles/sketchbook';
import {editorial} from './styles/editorial';
import {nodeEditor} from './styles/node-editor';
/** Declarative visual layers. No process, registry mutation or language translation. */
export interface PresentationTheme {
  /** Visual role markers; never derived from a domain object icon. */
  readonly headingMarkers:Readonly<Record<string,string>>;
  readonly fontFamily: string;
  readonly stylesheet: string;
  /** SVG assets keyed by open project roles; no fixed shape taxonomy. */
  readonly surfaces?: IconPack;
  readonly layoutOptions?: Readonly<LayoutOptions>;
  readonly fonts: readonly Readonly<{family: string; weight: number; source: string}>[];
  readonly drawing: Readonly<{mode: "precise" | "sketch"; options: Readonly<Options & {seed: number}>}>;
  readonly colors: Palette;
  readonly spacing: Readonly<{gutter:number;gap:number;radius:number;scenePadding:number;labelPadding:number;iconSize:number;iconGap:number;viewportPadding:number;markerSize:number;markerPadding:number;annotationPadding:number;[name:string]:number}>;
  readonly typography: Readonly<{titleSize:string;detailSize:string;labelSize:string;headingSize:string;pageTitleSize:string;pageQuestionSize:string;noteSize:string;bodySize:string;titleWeight:string;lineHeight:string;[name:string]:string}>;
}
export interface PresentationThemeOverrides {
  readonly headingMarkers?:Readonly<Record<string,string>>;
  readonly fontFamily?: string;
  readonly stylesheet?: string;
  readonly surfaces?: IconPack;
  readonly layoutOptions?: Readonly<LayoutOptions>;
  readonly fonts?: PresentationTheme["fonts"];
  readonly drawing?: {readonly mode?: PresentationTheme["drawing"]["mode"]; readonly options?: Partial<Options>};
  readonly colors?: Partial<PresentationTheme['colors']>;
  readonly spacing?: Partial<PresentationTheme['spacing']>;
  readonly typography?: Partial<PresentationTheme['typography']>;
}
export const defaultPresentationTheme: PresentationTheme = Object.freeze({
  headingMarkers:Object.freeze({question:'?'}),
  stylesheet: "", fonts: Object.freeze([400,700].map(weight=>Object.freeze({family:'Inter',weight,source:`@fontsource/inter/files/inter-latin-${weight}-normal.woff2`}))), drawing: Object.freeze({mode: "precise", options: Object.freeze({seed: 17, roughness: 1, strokeWidth: 1.2, fillStyle: "hachure", hachureGap: 9, fillWeight: .6})}),
  fontFamily: '"Inter",sans-serif',
  colors: palettes.blueprint!,
  spacing: Object.freeze({gutter:26,gap:12,radius:15,scenePadding:18,labelPadding:7,iconSize:32,iconGap:12,viewportPadding:12,markerSize:28,markerPadding:4,annotationPadding:3}),
  typography: Object.freeze({titleSize:'18px',detailSize:'14px',labelSize:'12px',headingSize:'16px',pageTitleSize:'26px',pageQuestionSize:'17px',noteSize:'13px',bodySize:'16px',titleWeight:'700',lineHeight:'1.7em'}),
});
export function extendPresentationTheme(base:PresentationTheme,overrides:PresentationThemeOverrides={}):PresentationTheme {
  const theme:PresentationTheme={
    headingMarkers:{...base.headingMarkers,...overrides.headingMarkers},
    layoutOptions:{...base.layoutOptions,...overrides.layoutOptions},surfaces:{...base.surfaces,...overrides.surfaces},
    stylesheet:overrides.stylesheet===undefined?base.stylesheet:[base.stylesheet,overrides.stylesheet].filter(Boolean).join('\n'),
    fonts:overrides.fonts??base.fonts,fontFamily:overrides.fontFamily??base.fontFamily,
    drawing:{...base.drawing,...overrides.drawing,options:{...base.drawing.options,...overrides.drawing?.options}},
    colors:{...base.colors,...overrides.colors} as Palette,
    spacing:{...base.spacing,...overrides.spacing} as PresentationTheme['spacing'],
    typography:{...base.typography,...overrides.typography} as PresentationTheme['typography'],
  };
  const names=new Set<string>();
  for(const [group,tokens]of [['colors',theme.colors],['spacing',theme.spacing],['typography',theme.typography]]as const){
    for(const[key,value]of Object.entries(tokens)){
      if(!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(key))throw new Error('Invalid CSS token name: '+key);
      const name=group==='typography'?'type-'+key:key;if(names.has(name))throw new Error('Ambiguous CSS token: '+name);names.add(name);
      if(group==='spacing'?(typeof value!=='number'||!Number.isFinite(value)||value<0):(typeof value!=='string'||!value.trim()))throw new Error('Invalid theme token: '+key);
    }
  }
  return deepFreeze(structuredClone(theme));
}
export type ThemeLayers = Readonly<Record<string, PresentationThemeOverrides>>;
export const presentationThemeLayers: ThemeLayers = Object.freeze({
  ...Object.fromEntries(Object.entries(palettes).map(([name,colors])=>[name,Object.freeze({colors})])),
  ...layoutLayers,
  editorial,
  sketchbook,
  'node-editor': nodeEditor,
  compact: deepFreeze({spacing:{gutter:20,gap:8,radius:8,scenePadding:12,labelPadding:5,iconGap:10,viewportPadding:10},layoutOptions:{'elk.spacing.nodeNode':'24','elk.layered.spacing.nodeNodeBetweenLayers':'36'}}),
  comfortable: deepFreeze({spacing:{gutter:32,gap:18,radius:12,scenePadding:24,labelPadding:8,iconGap:14,viewportPadding:16},layoutOptions:{'elk.spacing.nodeNode':'44','elk.layered.spacing.nodeNodeBetweenLayers':'64'}}),
});
/** Ordered composition is explicit and immutable. Downstream may supply its own layers. */
export function composePresentationTheme(names: readonly string[], layers: ThemeLayers = presentationThemeLayers): PresentationTheme {
  if (!names.length) throw new Error('At least one declared theme layer is required');
  return names.reduce((theme, name) => {
    const layer = layers[name]; if (!Object.hasOwn(layers, name) || !layer) throw new Error(`Unknown declared theme layer: ${name}`);
    return extendPresentationTheme(theme, layer);
  }, defaultPresentationTheme);
}
