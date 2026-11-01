import {parseFragment, type DefaultTreeAdapterTypes} from 'parse5';
import type { Shape, Connection, SQLColumn, Text, Class } from '@terrastruct/d2';
import packageInfo from '../package.json' with {type: 'json'};
import { digest, relativeSource } from './source/catalog';
import { validatePurposeKind, type QuestionRef, type ViewSelection } from './source/types';
import { defaultIcons, type IconAsset } from './icons';
import { defaultPresentationTheme, type PresentationTheme } from './presentation-theme';

export interface FigureQuestion extends QuestionRef { readonly focusRefs: readonly string[]; }
export interface FigureModel {
  readonly subjects: readonly Readonly<Pick<Shape, 'id' | 'type'> & {
    label?: string; parent?: string; level?: Shape['level']; classes?: Shape['classes']; sourceName?: string;
    columns?: readonly Readonly<Pick<SQLColumn,'constraint'|'reference'> & {name:Pick<Text,'label'>;type:Pick<Text,'label'>}>[]; fields?: Class['fields']; methods?: Class['methods'];
  }>[];
  readonly relations: readonly Readonly<Pick<Connection, 'id' | 'src' | 'dst' | 'label'> & {
    srcArrow?: Connection['srcArrow']; dstArrow?: Connection['dstArrow'];
    fromPort?: string; toPort?: string; kind?: string;
  }>[];
}
export interface ModelSource {
  readonly ref: string;
  readonly view: string;
  readonly modelHash: string;
  readonly portProjection?: 'owner';
  /** Display captions keyed by exact SDK node ID; names never become identities. */
  readonly labels?: Readonly<Record<string,string>>;
}
export interface FigureInput {
  readonly modelSource?: ModelSource;
  readonly modelTrace?: import('./opensysml').SysMLProjectionResult['trace'];
  /** Project-owned declaration, interpreted by its functional composition. */
  readonly presentation?: unknown;
  readonly layout?: string;
  readonly view: ViewSelection;
  readonly language: string;
  readonly width: number;
  readonly questions: readonly FigureQuestion[];
  /** Captured project/model/composition sources; no new model or evidence ledger. */
  readonly sources: Readonly<Record<string, string>>;
  readonly references: Readonly<Record<string, string>>;
  readonly variants?: readonly {readonly name: string; readonly theme: PresentationTheme; readonly kind?: string; readonly layout?: string; readonly icons?: Readonly<Record<string, IconAsset>>}[];
  readonly model?: FigureModel;
  readonly copy?: Readonly<Record<string, string>>;
  readonly theme?: PresentationTheme;
  readonly icons?: Readonly<Record<string, IconAsset>>;
}
export interface FigureContext {
  readonly theme: PresentationTheme;
  readonly presentation?: unknown;
  readonly model?: FigureModel;
  readonly layout: string;
  readonly view: ViewSelection;
  readonly question: (ref: string) => FigureQuestion;
  readonly reference: (ref: string) => string;
  readonly icon: (name: string) => string;
  readonly glyph: (name: string) => string;
  readonly text: (value: string) => string;
  readonly copy: (key: string) => string;
  readonly relation: (from: string, to: string) => Readonly<Pick<Connection, 'id' | 'src' | 'dst' | 'label'>>;
}
export interface FigureComposition { readonly markup: string; readonly css: string; }
export type FigureComposer = (context: FigureContext) => FigureComposition;
export interface ComposedFigure {
  readonly html: string;
  readonly drawing: PresentationTheme["drawing"];
  readonly fonts: PresentationTheme["fonts"];
  readonly inputSHA256: string;
  readonly htmlSHA256: string;
  readonly width: number;
  readonly purpose: ViewSelection['purpose'];
  readonly sourceSHA256: Readonly<Record<string, string>>;
}
export const escapeHTML = (value: string): string => value.replace(/[&<>"']/g, character => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character]!));
/** Capture first, then compose. No fixed page structure or automatic graph enlargement. */
export function composeFigure(input: FigureInput, compose: FigureComposer): ComposedFigure {
  const snapshot = structuredClone(input);
  if(snapshot.modelSource && (!snapshot.modelTrace || snapshot.modelSource.modelHash!==snapshot.modelTrace.modelHash || snapshot.modelSource.view!==snapshot.modelTrace.requestedView || snapshot.modelSource.portProjection!==snapshot.modelTrace.portProjection))
    throw new Error('Model selection differs from captured SDK trace');
  if (!Number.isInteger(snapshot.width) || snapshot.width < 320 || snapshot.width > 4096) throw new Error('Invalid figure width');
  if (!snapshot.questions.length || !snapshot.questions.some(question => question.ref === snapshot.view.question.ref)) throw new Error('Primary question is missing');
  validatePurposeKind(snapshot.view.purpose, snapshot.view.kind);
  if (!snapshot.view.basis.captureRef.trim()) throw new Error('Existing capture or labeled candidate reference is required');
  const sources = Object.fromEntries(Object.entries(snapshot.sources).sort(([a], [b]) => a.localeCompare(b)));
  if (!Object.hasOwn(sources, snapshot.view.source)) throw new Error('Composition source must be captured');
  for (const [name, source] of Object.entries(sources)) {
    relativeSource(name);
    if (typeof source !== 'string') throw new Error('Invalid captured source');
  }
  const references = Object.fromEntries(Object.entries(snapshot.references).sort(([a], [b]) => a.localeCompare(b)));
  for (const source of Object.values(references)) if (!Object.hasOwn(sources, source)) throw new Error(`Uncaptured reference source: ${source}`);
  const questions = new Map(snapshot.questions.map(question => [question.ref, question]));
  if (questions.size !== snapshot.questions.length) throw new Error('Duplicate question');
  for (const question of questions.values()) {
    if (!question.ref.trim() || !question.text.trim() || !question.focusRefs.length) throw new Error('Question needs wording and model/source focus');
    for (const ref of question.focusRefs) if (!Object.hasOwn(references, ref)) throw new Error(`Unknown question focus: ${ref}`);
    Object.freeze(question.focusRefs); Object.freeze(question);
  }
  const theme = snapshot.theme ?? defaultPresentationTheme;
  const icons = Object.fromEntries(Object.entries(snapshot.icons ?? defaultIcons).sort(([a], [b]) => a.localeCompare(b)));
  const question = (ref: string): FigureQuestion => {
    const value = questions.get(ref); if (!value) throw new Error(`Unselected question: ${ref}`); return value;
  };
  const reference = (ref: string): string => {
    if (!Object.hasOwn(references, ref)) throw new Error(`Unselected reference: ${ref}`);
    return `data-ref="${escapeHTML(ref)}"`;
  };
  const icon = (name: string): string => {
    const value = icons[name as keyof typeof icons]; if (!Object.hasOwn(icons, name) || !value) throw new Error(`Unselected icon: ${name}`);
    return `<span class="icon" aria-hidden="true">${value.svg}</span>`;
  };
  const view = Object.freeze({...snapshot.view, question: Object.freeze({...snapshot.view.question}), basis: Object.freeze({...snapshot.view.basis,
    modelRefs: Object.freeze([...snapshot.view.basis.modelRefs]), obligationRefs: Object.freeze([...snapshot.view.basis.obligationRefs]), evidenceRefs: Object.freeze([...snapshot.view.basis.evidenceRefs])})});
  const copy = (key: string): string => {
    const value = snapshot.copy?.[key]; if (typeof value !== 'string') throw new Error(`Undeclared copy: ${key}`); return value;
  };
  const relation = (from: string, to: string) => {
    const found = snapshot.model?.relations.find(edge => edge.src === from && edge.dst === to);
    if (!found) throw new Error(`Undeclared model relation: ${from} -> ${to}`); return Object.freeze({...found});
  };
  if (!['precise', 'sketch'].includes(theme.drawing.mode)) throw new Error('Unknown drawing mode');
  const {seed, roughness} = theme.drawing.options;
  if (theme.drawing.mode === 'sketch' && (!Number.isInteger(seed) || seed <= 0 || (roughness !== undefined && (!Number.isFinite(roughness) || roughness < 0)))) throw new Error('Invalid sketch drawing parameters');
  // Freeze captured model and project declarations before calling a domain compositor.
  const freeze = (value: unknown, seen = new WeakSet<object>()): void => {
    if (!value || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value); for (const item of Object.values(value)) freeze(item, seen); Object.freeze(value);
  };
  freeze(snapshot.model); freeze(snapshot.modelSource); freeze(snapshot.modelTrace); freeze(snapshot.presentation); freeze(theme);
  const composition = compose(Object.freeze({theme, view, model: snapshot.model, presentation: snapshot.presentation, layout: snapshot.layout ?? "default", question, reference, icon, glyph: name => {icon(name); return icons[name]!.svg;}, copy, relation, text: escapeHTML}));
  const usedQuestions = new Set<string>();
  const nodes: DefaultTreeAdapterTypes.Node[] = [...parseFragment(composition.markup).childNodes];
  while (nodes.length) {
    const node = nodes.pop()!;
    if ('tagName' in node) {
      if (node.tagName === 'template' || node.attrs.some(attribute => attribute.name === 'hidden')) continue;
      const marker = node.attrs.find(attribute => attribute.name === 'data-question');
      if (marker) usedQuestions.add(marker.value);
    }
    if ('childNodes' in node) nodes.push(...node.childNodes);
  }
  for (const id of usedQuestions) if (!questions.has(id)) throw new Error(`Unselected rendered question: ${id}`);
  for (const id of questions.keys()) if (!usedQuestions.has(id)) throw new Error(`Question has no visible region: ${id}`);
  const sourceSHA256 = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, digest(source)]));
  const renderer = {package: packageInfo.name, version: packageInfo.version, icons: Object.fromEntries(Object.entries(icons).map(([name, asset]) => [name, digest(asset.svg)]))};
  const footprint = {renderer, presentation: snapshot.presentation, layout: snapshot.layout, copy: snapshot.copy, model: snapshot.model, modelSource: snapshot.modelSource, modelTrace: snapshot.modelTrace, view, questions: snapshot.questions, references, sourceSHA256, theme, icons, width: snapshot.width, language: snapshot.language, composition};
  const inputSHA256 = digest(JSON.stringify(footprint));
  const variables = Object.entries(theme.colors).map(([key, value]) => `--${key}:${value}`).join(';') + ';' + Object.entries(theme.spacing).map(([key, value]) => `--${key}:${value}px`).join(';');
  const metadata = JSON.stringify({renderer, layout: snapshot.layout, presentation: snapshot.presentation, drawing: theme.drawing, fonts: theme.fonts, inputSHA256, model: snapshot.model, modelSource: snapshot.modelSource, modelTrace: snapshot.modelTrace, view, questions: snapshot.questions, references, sourceSHA256}).replaceAll('<', '\\u003c');
  const html = `<!doctype html><html lang="${escapeHTML(snapshot.language)}"><head><meta charset="utf-8"><meta name="viewport" content="width=${snapshot.width}"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:"><title>${escapeHTML(view.title)}</title><style>
*{box-sizing:border-box}html,body{margin:0;padding:0}body{background:${theme.colors.background};font-family:${theme.fontFamily};color:${theme.colors.ink}}[data-figure]{${variables};width:${snapshot.width}px;margin:0;position:relative;overflow:hidden}.icon{display:inline-flex;flex:none;width:32px;height:32px}.icon svg{width:100%;height:100%}svg{display:block}h1,h2,h3,p{margin:0}table{border-collapse:collapse}a{color:inherit}*{animation:none!important;transition:none!important}${composition.css}\n${theme.stylesheet}
</style></head><body><figure data-figure data-purpose="${view.purpose}" aria-label="${escapeHTML(view.question.text)}">${composition.markup}</figure><script type="application/json" id="figure-provenance">${metadata}</script></body></html>`;
  return Object.freeze({html, drawing: Object.freeze({...theme.drawing}), fonts: theme.fonts, inputSHA256, htmlSHA256: digest(html), width: snapshot.width, purpose: view.purpose, sourceSHA256: Object.freeze(sourceSHA256)});
}

/** Resolve one already-declared variant without re-reading global defaults. */
export function selectFigureVariant(input: FigureInput, name: string): FigureInput {
  const variant = input.variants?.find(variant => variant.name === name);
  if (!variant) throw new Error(`Undeclared figure variant: ${name}`);
  return {...input, view: {...input.view, kind: variant.kind ?? input.view.kind}, layout: variant.layout ?? input.layout,
    theme: variant.theme, icons: variant.icons ?? input.icons};
}
