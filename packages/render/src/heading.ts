import type {FigureContext,FigureComposition} from './figure';
/** A semantic part, not a page template. Roles are open; a Question is explicitly source-bound. */
export interface HeadingSpec {
 readonly role:string;
 readonly text:string;
 readonly questionRef?:string;
 readonly ordinal?:string|number;
 readonly glyph?:string;
}
export function composeHeading(context:FigureContext,spec:HeadingSpec):FigureComposition {
 if(!spec.role.trim()||!spec.text.trim())throw new Error('Heading needs role and text');
 if(spec.questionRef!==undefined&&context.question(spec.questionRef).text!==spec.text)throw new Error('Heading differs from selected Question');
 if(spec.ordinal!==undefined&&(typeof spec.ordinal==='number'?!Number.isFinite(spec.ordinal):!spec.ordinal.trim()))throw new Error('Invalid heading ordinal');
 const text=context.text;
 const marker=spec.ordinal??(Object.hasOwn(context.theme.headingMarkers,spec.role)?context.theme.headingMarkers[spec.role]:undefined);
 const ordinal=marker===undefined?'':`<g data-annotation-part="ordinal"><circle class="heading-ordinal" r="14"/><text>${text(String(marker))}</text></g>`;
 const glyph=spec.glyph===undefined?'':`<g data-annotation-part="glyph">${context.glyph(spec.glyph)}</g>`;
 return {markup:`<svg data-vector-annotation data-heading-role="${text(spec.role)}"${spec.questionRef===undefined?'':` data-question="${text(spec.questionRef)}"`} width="100%" height="48"><g data-annotation-content>${ordinal}${glyph}<g data-annotation-part="label"><text>${text(spec.text)}</text></g></g></svg>`,css:`
[data-heading-role]{color:var(--ink);fill:var(--ink)}[data-heading-role] text{font-size:var(--type-headingSize);font-weight:var(--type-titleWeight)}
[data-heading-role="title"] text{font-size:var(--type-pageTitleSize)}[data-heading-role="question"] text{font-size:var(--type-pageQuestionSize);fill:var(--accent)}
[data-heading-role="answer"] text{font-size:var(--type-bodySize);font-weight:400}[data-heading-role="note"] text{font-size:var(--type-noteSize);font-weight:400;fill:var(--muted)}
[data-annotation-part="ordinal"] text{font-size:var(--type-labelSize);fill:var(--onAccent)}.heading-ordinal{fill:var(--accent)}
[data-annotation-part="glyph"]>svg{width:var(--iconSize);height:var(--iconSize)}
`};
}
