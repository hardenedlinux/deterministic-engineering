// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import type {ComposedFigure} from '@deterministic-engineering/render';
import type {ArtifactAttribution} from '@deterministic-engineering/render/export';
/** Actual shipped font licenses are retained alongside the repository's own license. */
export function attributionFor(figure:Pick<ComposedFigure,'fonts'>):ArtifactAttribution {
 const holders:Readonly<Record<string,string>>={Inter:'2016 The Inter Project Authors (https://github.com/rsms/inter)',Kalam:'2014 Indian Type Foundry (info@indiantypefoundry.com)'};
 const fonts=[...new Set(figure.fonts.map(font=>font.family))];
 for(const family of fonts)if(!holders[family])throw new Error('Declare the actual font rights before publishing: '+family);
 return {copyright:['2026 hardenedlinux Linux Team and Contributors',...fonts.map(family=>holders[family]!)],license:fonts.length?'LGPL-2.1-or-later AND OFL-1.1':'LGPL-2.1-or-later'};
}
