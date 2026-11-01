// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import * as v from 'valibot';
import {deepFreeze} from './immutable';
import type {FigureModel,FigureQuestion} from './figure';
const text=v.pipe(v.string(),v.check(value=>!!value.trim(),'Expected nonempty design text'));
const refs=v.pipe(v.array(text),v.check(items=>new Set(items).size===items.length,'Duplicate design reference'),v.readonly());
/** Reader intent and fidelity requirements. Geometry, themes and model identity have existing owners. */
export const DesignSchema=v.pipe(v.strictObject({
 audience:text,medium:text,message:text,
 questionRefs:v.pipe(refs,v.minLength(1)),
 requiredSubjects:refs,requiredRelations:refs,focalSubjects:refs,
}),v.readonly());
export type Design=v.InferOutput<typeof DesignSchema>;
/** Decode project declarations without freezing caller-owned values. */
export function defineDesign(value:unknown):Design{return deepFreeze(structuredClone(v.parse(DesignSchema,value)));}
/** Called after the selected SDK projection, before any domain compositor. */
export function bindDesign(value:unknown,questions:readonly FigureQuestion[],model?:FigureModel):Design {
 const design=defineDesign(value),subjects=new Set(model?.subjects.map(node=>node.id)),relations=new Set(model?.relations.map(edge=>edge.id));
 for(const ref of design.questionRefs)if(!questions.some(question=>question.ref===ref))throw new Error('Unselected design Question: '+ref);
 for(const id of [...design.requiredSubjects,...design.focalSubjects])if(!subjects.has(id))throw new Error('Unknown design subject: '+id);
 for(const id of design.requiredRelations)if(!relations.has(id))throw new Error('Unknown design relation: '+id);
 return design;
}
