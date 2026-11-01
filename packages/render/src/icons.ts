// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

/** Project-owned engineering glyphs. Assets and rendering are independently replaceable. */
export interface IconAsset { readonly svg: string; readonly label: string; }
const glyph = (label: string, body: string): IconAsset => Object.freeze({label,
  svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`});
export const engineeringIcons = Object.freeze({
  library: glyph('Published definitions', '<path d="M5 8h20v18H5zM9 4h18v18M10 13h10M10 18h7"/><path d="M5 26h8" stroke-width="3.5"/><circle cx="24" cy="25" r="4" fill="currentColor" stroke="none"/>'),
  selection: glyph('Selected configuration', '<path d="M4 7h24M4 16h24M4 25h24" opacity=".45"/><rect x="8" y="3" width="6" height="8" rx="1.5" fill="currentColor"/><rect x="19" y="12" width="6" height="8" rx="1.5"/><rect x="10" y="21" width="6" height="8" rx="1.5"/>'),
  capture: glyph('Bound project occurrence', '<path d="M11 4H4v7M21 4h7v7M4 21v7h7M28 21v7h-7"/><rect x="11" y="11" width="10" height="10" rx="2"/><path d="M16 4v4M16 24v4M4 16h4M24 16h4" opacity=".5"/>'),
  model: glyph('Architecture model', '<rect x="11" y="3" width="10" height="7" rx="1"/><rect x="3" y="22" width="9" height="7" rx="1"/><rect x="20" y="22" width="9" height="7" rx="1"/><path d="M16 10v6M7.5 22v-6h17v6"/><circle cx="16" cy="16" r="2.5" fill="currentColor" stroke="none"/>'),
  document: glyph('Document with source anchors', '<path d="M8 3h13l5 5v21H8zM21 3v6h5M13 13h8M13 18h8M13 23h5"/><path d="M3 12h6M3 20h6" stroke-width="3"/>'),
  decision: glyph('Decision and alternatives', '<path d="M16 3l7 7-7 7-7-7zM16 17v6M16 23H6v6M16 23h10v6"/><circle cx="6" cy="29" r="2" fill="currentColor" stroke="none"/><path d="M23 28h6" opacity=".45"/>'),
  evidence: glyph('Linked evidence', '<rect x="4" y="4" width="16" height="20" rx="2"/><path d="M9 9h6M9 14h6M9 19h3M18 20l5-5 6 6-5 5z"/><path d="M22 23l-4 5" opacity=".5"/>'),
  question: glyph('Design question', '<path d="M8 5H4v22h4M24 5h4v22h-4M12 11a4 4 0 118 0c0 3-4 3-4 6"/><rect x="15" y="22" width="2" height="2" fill="currentColor" stroke="none"/>'),
  pending: glyph('Open obligation', '<path d="M6 5h16l5 5v17H6zM22 5v6h5M15 11v7"/><circle cx="15" cy="23" r="1" fill="currentColor" stroke="none"/><path d="M2 10h5M2 20h5" opacity=".5"/>'),
  reference: glyph('Source reference', '<path d="M13 7H5v19h16v-8M18 4h10v10M28 4L13 19M10 16v6h6"/><circle cx="5" cy="7" r="2" fill="currentColor" stroke="none"/>'),
  obligation: glyph('Verification obligation', '<path d="M5 5h22v22H5zM10 11h12M10 16h8M10 21h5"/><path d="M23 20v9M19 25h8" stroke-width="2.5"/>'),
});
export const defaultIcons = engineeringIcons;
export type IconPack = Readonly<Record<string, IconAsset>>;
export type IconPacks = Readonly<Record<string, IconPack>>;
export const iconPacks: IconPacks = Object.freeze({engineering: engineeringIcons});
/** Ordered, immutable pack composition; no runtime registration or editor dependency. */
export function composeIconPacks(names: readonly string[], packs: IconPacks = iconPacks): IconPack {
  const result: Record<string, IconAsset> = {};
  if (!names.length) throw new Error('At least one declared icon pack is required');
  for (const name of names) {
    if (!Object.hasOwn(packs, name)) throw new Error(`Unknown declared icon pack: ${name}`);
    for (const [key, asset] of Object.entries(packs[name]!)) {
      if (!asset || typeof asset.svg !== 'string' || !asset.svg.trim() || typeof asset.label !== 'string' || !asset.label.trim()) throw new Error(`Invalid icon asset: ${key}`);
      result[key] = Object.freeze({...asset});
    }
  }
  return Object.freeze(result);
}
