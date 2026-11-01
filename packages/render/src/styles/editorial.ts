// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import type {PresentationThemeOverrides} from '../presentation-theme';
/** Quiet supporting marks, explicit publication emphasis, no universal node card. */
export const editorial:PresentationThemeOverrides=Object.freeze({
 surfaces:Object.freeze({publication:Object.freeze({label:'Published Library sheet',svg:'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" preserveAspectRatio="none"><path d="M0 0H92L100 13V100H0Z" fill="var(--accent)"/><path d="M92 0V13H100" fill="none" stroke="var(--onAccent)" stroke-opacity=".4" stroke-width=".6"/><path d="M4 10V90" fill="none" stroke="var(--onAccent)" stroke-opacity=".3" stroke-width=".6"/></svg>'})}),
 spacing:Object.freeze({scenePadding:22,iconSize:48}),
 typography:Object.freeze({titleSize:'20px',detailSize:'14px',labelSize:'11px',headingSize:'14px'}),
 colors:Object.freeze({background:'#FAFAF7',surface:'#FFFFFF',ink:'#202E3C',muted:'#64717B',accent:'#117A72',secondary:'#C06042',border:'#DADFD9',tint:'#E9F2ED',secondaryTint:'#F9EFE1',pending:'#AC752F'}),
 stylesheet:`.scene-frame{fill:none;stroke:none;rx:2}.scene-glyph>svg{stroke-width:1.5}[data-role="project-boundary"]>.scene-frame{fill:none;stroke:var(--border);stroke-width:1;rx:8}.scene-group-title{fill:var(--secondary);letter-spacing:1px}.scene-title{font-weight:700;letter-spacing:-.35px}.scene-edge{stroke:var(--muted);stroke-width:1.25}.scene-label rect{fill:var(--background)}.scene-label text{letter-spacing:.15px}[data-role="publication"]>.scene-frame{fill:var(--accent);stroke:none;rx:12}[data-role="publication"] .scene-title,[data-role="publication"] .scene-detail{fill:var(--onAccent)}[data-role="publication"] .scene-glyph{color:var(--onAccent)}[data-role="selection"] .scene-glyph{color:var(--secondary)}[data-role="capture"] .scene-glyph{color:var(--accent)}[data-role="external"]>.scene-frame{fill:none;stroke:var(--border);stroke-dasharray:3 5;rx:0}[data-role="pending"]>.scene-frame{fill:var(--secondaryTint);stroke:none;rx:0}[data-role="pending"] .scene-glyph{color:var(--pending)}`,
});
