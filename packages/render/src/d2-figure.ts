// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {readEvidenceProjections} from './taste-selection';
import {defineDesign} from './design';
import {relativeSource} from './source/catalog';
import {composeIconPacks, type IconPacks} from './icons';
import { composePresentationTheme, type ThemeLayers } from './presentation-theme';
import type { Diagram } from '@terrastruct/d2';
import type { FigureInput, FigureQuestion } from './figure';
import {validatePurposeKind, type ViewSelection} from './source/types';
const object = (value: unknown, name: string): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`Expected ${name} object`);
  return value as Record<string, unknown>;
};
const text = (value: unknown, name: string): string => {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`Expected ${name} text`); return value;
};
const texts = (value: unknown, name: string): string[] => {
  if (!Array.isArray(value)) throw new Error(`Expected ${name} array`);
  return value.map(item => text(item, name));
};
/** Official D2 handles syntax/imports. Its standard plugin data owns the declaration. */
export interface D2FigureData { readonly data: unknown; readonly diagram?: Pick<Diagram, 'shapes' | 'connections'>; readonly model?: FigureInput['model']; readonly inputPath: string; readonly fs: Readonly<Record<string, string>>; }
export interface FigureResources { readonly themeLayers?: ThemeLayers; readonly iconPacks?: IconPacks;readonly sysmlViews?:Readonly<Record<string,import('./opensysml').OpenSysMLCapture>>; }
export function readD2Figure(compiled: D2FigureData, captured: Readonly<Record<string, string>>, resources: FigureResources = {}): FigureInput {
  const data = compiled.data;
  const encoded = object(data, 'D2 graph.data').figure;
  // A JSON block scalar preserves nested data in the installed D2 SDK.
  if (typeof encoded !== 'string') throw new Error('D2 vars.d2-config.data.figure must be a JSON block scalar');
  const declaration = object(JSON.parse(encoded) as unknown, 'figure declaration');
  const primary = text(declaration.primary, 'primary question');
  if (!Array.isArray(declaration.questions)) throw new Error('Expected declared questions');
  const questions: FigureQuestion[] = declaration.questions.map(value => {
    const question = object(value, 'question');
    return {subjectRefs:question.subjectRefs===undefined?undefined:texts(question.subjectRefs,'Question subjects'),relationRefs:question.relationRefs===undefined?undefined:texts(question.relationRefs,'Question relations'),ref: text(question.ref, 'question ref'), text: text(question.text, 'question'), focusRefs: texts(question.focusRefs, 'focus refs')};
  });
  const question = questions.find(item => item.ref === primary);
  if (!question) throw new Error('Declared primary question is missing');
  const purpose = text(declaration.purpose, 'purpose'), kind = text(declaration.kind, 'kind');
  validatePurposeKind(purpose, kind);
  const width = declaration.width;
  if (typeof width !== 'number') throw new Error('Expected declared width');
  const referenceData = object(declaration.references, 'references');
  const references = Object.fromEntries(Object.entries(referenceData).map(([key, value]) => [key, text(value, `reference ${key}`)]));
  for(const source of Object.values(references))relativeSource(source);
  const copyData = object(declaration.copy, 'copy');
  const copy = Object.fromEntries(Object.entries(copyData).map(([key, value]) => [key, text(value, `copy ${key}`)]));
  const basis = object(declaration.basis, 'basis');
  const view = {source: compiled.inputPath, title: text(declaration.title, 'title'), purpose, kind, question,
    basis: {captureRef: text(basis.captureRef, 'capture ref'), modelRefs: texts(basis.modelRefs, 'models'), obligationRefs: texts(basis.obligationRefs, 'obligations'), evidenceRefs: texts(basis.evidenceRefs, 'evidence')}} as ViewSelection;
  const model = compiled.model ?? (compiled.diagram ? modelFromDiagram(compiled.diagram) : undefined);
  const theme = composePresentationTheme(declaration.themes === undefined ? ['blueprint'] : texts(declaration.themes, 'theme layers'), resources.themeLayers);
  const icons = composeIconPacks(declaration.icons === undefined ? ['engineering'] : texts(declaration.icons, 'icon packs'), resources.iconPacks);
  const variants = declaration.variants === undefined ? [] : (() => {
    if (!Array.isArray(declaration.variants)) throw new Error('Expected declared variants');
    const result = declaration.variants.map(value => {
      const variant = object(value, 'variant');
      const variantKind = variant.kind === undefined ? undefined : text(variant.kind, 'variant kind');
      if (variantKind !== undefined) validatePurposeKind(purpose, variantKind);
      return {questionRefs:variant.questionRefs===undefined?undefined:texts(variant.questionRefs,'variant Questions'),evidenceRefs:variant.evidenceRefs===undefined?undefined:texts(variant.evidenceRefs,'variant evidence'),design:variant.design===undefined?undefined:defineDesign(variant.design),presentation:variant.presentation,name: text(variant.name, 'variant name'), kind: variantKind, layout: variant.layout === undefined ? undefined : text(variant.layout, 'layout'),
        theme: variant.themes === undefined ? theme : composePresentationTheme(texts(variant.themes, 'variant themes'), resources.themeLayers),
        icons: variant.icons === undefined ? icons : composeIconPacks(texts(variant.icons, 'variant icon packs'), resources.iconPacks)};
    });
    if (new Set(result.map(variant => variant.name)).size !== result.length) throw new Error('Duplicate declared figure variant');
    return result;
  })();
  const origin=declaration.modelSource===undefined?undefined:object(declaration.modelSource,'model source');
  const captions=origin?.labels===undefined?undefined:object(origin.labels,'model captions');
  const modelSource=origin?{ref:text(origin.ref,'model source reference'),modelHash:text(origin.modelHash,'model hash'),view:text(origin.view,'SysML view'),portProjection:origin.portProjection===undefined?undefined:(origin.portProjection==='owner'?'owner' as const:(()=>{throw new Error('Unsupported port projection');})()),labels:captions?Object.fromEntries(Object.entries(captions).map(([key,value])=>[key,text(value,'model caption')])):undefined}:undefined;
  return {evidence:declaration.evidence===undefined?undefined:readEvidenceProjections(declaration.evidence),design:declaration.design===undefined?undefined:defineDesign(declaration.design),modelSource,view, model, theme, variants, icons, presentation: declaration.presentation, layout: declaration.layout === undefined ? undefined : text(declaration.layout, 'layout'), language: text(declaration.language, 'language'), width, questions, references, copy,
    sources: {...compiled.fs, ...captured}};
}

/** Observe the pinned SDK output; do not parse IDs, escapes or synthetic notation. */
export function modelFromDiagram(diagram: Pick<Diagram,'shapes'|'connections'>): NonNullable<FigureInput['model']> {
  return {
    subjects: diagram.shapes.map(shape => ({
      id: shape.id, type: shape.type, level: shape.level, classes: shape.classes,
      label: 'label' in shape ? shape.label : undefined,
      ...(shape.type === 'sql_table' && 'columns' in shape && Array.isArray(shape.columns) ? {columns: shape.columns.map(column=>({name:{label:column.name.label},type:{label:column.type.label},constraint:column.constraint,reference:column.reference}))} : {}),
      ...(shape.type === 'class' && 'fields' in shape ? {fields: shape.fields??[], methods: shape.methods??[]} : {}),
    })),
    relations: diagram.connections.map(({id,src,dst,label,srcArrow,dstArrow}) => ({id,src,dst,label,srcArrow,dstArrow})),
  };
}
