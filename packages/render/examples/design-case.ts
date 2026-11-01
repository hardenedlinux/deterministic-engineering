// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {composeModelView,composeHeading,composeTaste,questionFocus,evidenceFocus,questionScope,dependencyLayout,visualHierarchy,minimumTextSize,focalBudget,type FigureComposer} from '@deterministic-engineering/render';
/** All projects use these open pure policies. No Library IDs, named layouts or diagram presets. */
export const designTaste=composeTaste(questionFocus(),evidenceFocus(),questionScope(),dependencyLayout(),visualHierarchy(),minimumTextSize(12),focalBudget(2));
/** Compose existing parts; the actual graph, role and layout choices come from Taste. */
export const designCase:FigureComposer=context=>{
 const main=composeModelView(context),notes=[composeHeading(context,{role:'answer',text:context.design!.audience})];
 for(const decision of context.taste?.decisions??[])notes.push(composeHeading(context,{role:'note',text:decision.rationale}));
 notes.push(composeHeading(context,{role:'note',text:context.copy('sources-label')+': '+(context.evidence.map(item=>item.state).join(', ')||'unobserved')}),composeHeading(context,{role:'note',text:context.copy('status')}));
 return{markup:main.markup+`<footer>${notes.map(note=>note.markup).join('')}</footer>`,css:main.css+notes.map(note=>note.css).join('\n')+'footer{margin-top:14px}footer>svg{margin-top:4px}'};
};
