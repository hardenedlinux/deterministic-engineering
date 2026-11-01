import { defaultIcons, iconDataURI, type IconAsset } from './icons';
import { digest } from './source/catalog';
import type { RenderedView } from './pipeline';
import { defaultPresentationTheme, type PresentationTheme } from './presentation-theme';

export type StatementStatus = 'supported' | 'pending' | 'conflict' | 'design';
/** Project-authored explanation. Status is an assertion, never inferred approval. */
export interface Explanation {
  readonly title: string;
  readonly icon?: IconAsset;
  readonly text: string;
  readonly status: StatementStatus;
  readonly refs: readonly string[];
}
export interface PresentationInput {
  readonly title: string;
  readonly subtitle: string;
  readonly scope: string;
  readonly answer: string;
  readonly view: RenderedView;
  readonly findings: readonly Explanation[];
  readonly limits: readonly string[];
  readonly theme?: PresentationTheme;
  readonly icons?: Partial<Readonly<typeof defaultIcons>>;
  readonly findingsTitle?: string;
}
export interface PresentedView {
  readonly svg: string;
  readonly inputSHA256: string;
  readonly svgSHA256: string;
  readonly width: number;
  readonly height: number;
  readonly question: RenderedView['question'];
  readonly basis: RenderedView['basis'];
}
const xml = (text: string): string => text.replace(/[&<>"']/g, char => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;'}[char]!));
function lines(text: string, columns: number): string[] {
  // Conservative wrapping for explanatory prose; native diagram typography is untouched.
  const result: string[] = [];
  let line = '', length = 0;
  for (const word of text.split(/\s+/).filter(Boolean)) {
    if (length + word.length + 1 > columns && line) { result.push(line); line = ''; length = 0; }
    line += (line ? ' ' : '') + word; length = line.length;
  }
  if (line) result.push(line);
  return result;
}
/** Pure SVG page composition; the original D2 diagram is embedded without redrawing. */
export function composePresentation(input: PresentationInput): PresentedView {
  const theme = input.theme ?? defaultPresentationTheme;
  const icons = {...defaultIcons, ...input.icons};
  const c = theme.colors, {gutter: g, gap, radius} = theme.spacing;
  if (![g, gap, radius].every(value => Number.isFinite(value) && value >= 0) || g > 100 || gap > 60 || radius > 40)
    throw new Error('Presentation spacing is outside supported bounds');
  if (!input.title.trim() || !input.answer.trim() || !input.findings.length) throw new Error('Presentation needs a title, answer and findings');
  if (input.findings.some(item => item.status === 'supported' && !item.refs.length))
    throw new Error('Supported explanation requires an existing evidence reference');
  if (input.findings.some(item => !['supported', 'pending', 'conflict', 'design'].includes(item.status))) throw new Error('Unknown statement status');
  const viewBox = input.view.svg.match(/<svg\b[^>]*\bviewBox="([^"]+)"/);
  const dimensions = viewBox?.[1]?.split(/\s+/).map(Number);
  if (!dimensions || dimensions.length !== 4 || !dimensions.every(Number.isFinite) || dimensions[2]! <= 0 || dimensions[3]! <= 0)
    throw new Error('Expected native D2 SVG with a finite viewBox');
  const width = 1440, inner = width - g * 2;
  const diagramHeight = Math.max(260, inner * dimensions[3]! / dimensions[2]!);
  const parts: string[] = [];
  const text = (value: string, x: number, y: number, size = 18, fill = c.ink, weight = 400) =>
    parts.push(`<text x="${x}" y="${y}" font-size="${size}" font-weight="${weight}" fill="${xml(fill)}">${xml(value)}</text>`);
  const paragraph = (value: string, x: number, y: number, columns: number, size = 18, fill = c.muted): number => {
    for (const line of lines(value, columns)) { text(line, x, y, size, fill); y += size * 1.5; }
    return y;
  };
  const panel = (x: number, y: number, w: number, h: number, fill = c.surface) =>
    parts.push(`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${radius}" fill="${xml(fill)}" stroke="${xml(c.border)}"/>`);
  const icon = (asset: IconAsset, x: number, y: number, size: number, color: string) => {
    parts.push(`<image x="${x}" y="${y}" width="${size}" height="${size}" href="${xml(iconDataURI(asset, color))}"><title>${xml(asset.label)}</title></image>`);
  };
  const section = (number: string, title: string, y: number) => {
    parts.push(`<circle cx="${g + 18}" cy="${y - 8}" r="18" fill="${xml(c.accent)}"/>`);
    text(number, g + 12, y - 2, 16, c.surface, 700); text(title, g + 50, y, 25, c.ink, 700);
  };
  text(input.scope.toUpperCase(), g, 42, 15, c.accent, 700);
  let y = paragraph(input.title, g, 98, 49, 44, c.ink) + 1;
  y = paragraph(input.subtitle, g, y, 108, 18) + 8;
  const questionLines = lines(input.view.question.text, 91);
  const answerLines = lines(input.answer, 111);
  const introHeight = 66 + questionLines.length * 30 + answerLines.length * 24;
  panel(g, y, inner, introHeight, c.tint);
  icon(icons.question, g + 22, y + 20, 32, c.accent);
  text('THE QUESTION', g + 68, y + 37, 14, c.accent, 700);
  let qy = paragraph(input.view.question.text, g + 28, y + 74, 91, 24, c.ink) + 4;
  paragraph(input.answer, g + 28, qy, 111, 16, c.muted);
  y += introHeight + 46;
  section('1', input.view.purpose === 'architecture' ? 'Architecture / boundaries and responsibilities' : 'Workflow / order and transitions', y);
  y += 24;
  panel(g, y, inner, diagramHeight + 36);
  const native = input.view.svg.replace(/<\?xml[^>]*\?>/g, '');
  // Nested viewport keeps official D2 embedded fonts, styles, hierarchy and native geometry.
  parts.push(`<svg x="${g + 18}" y="${y + 18}" width="${inner - 36}" height="${diagramHeight}" viewBox="${xml(viewBox![1]!)}">${native}</svg>`);
  y += diagramHeight + 78;
  section('2', input.findingsTitle ?? 'Design at a glance', y); y += 28;
  const columns = 3, cardWidth = (inner - gap * (columns - 1)) / columns;
  for (let start = 0; start < input.findings.length; start += columns) {
    const row = input.findings.slice(start, start + columns);
    const cardHeight = Math.max(...row.map(item => 100 + lines(item.title, 24).length * 29 + lines(item.text, 40).length * 24));
    row.forEach((item, index) => {
      const x = g + index * (cardWidth + gap);
      const color = item.status === 'design' ? c.secondary : c[item.status];
      panel(x, y, cardWidth, cardHeight);
      parts.push(`<circle cx="${x + 46}" cy="${y + 43}" r="25" fill="${xml(c.tint)}"/>`);
      icon(item.icon ?? icons.reference, x + 30, y + 27, 32, color);
      text(item.status.toUpperCase(), x + 84, y + 48, 13, color, 700);
      let fy = paragraph(item.title, x + 24, y + 99, 24, 22, c.ink) + 5;
      paragraph(item.text, x + 24, fy, 40, 16, c.muted);
    });
    y += cardHeight + gap;
  }
  y += 12; section('3', 'Model / obligations / evidence', y); y += 26;
  const basis = input.view.basis;
  const chips = [
    {asset: icons.model, title: 'Model references', label: `${basis.modelRefs.length} linked`, color: c.accent},
    {asset: icons.obligation, title: 'Obligation references', label: `${basis.obligationRefs.length} linked`, color: c.secondary},
    {asset: basis.evidenceRefs.length ? icons.evidence : icons.pending, title: 'Evidence references', label: basis.evidenceRefs.length ? `${basis.evidenceRefs.length} linked / unverified here` : 'none linked / pending', color: basis.evidenceRefs.length ? c.muted : c.pending},
  ];
  panel(g, y, inner, 100, c.secondaryTint);
  chips.forEach((chip, index) => {
    const x = g + index * inner / 3 + 24;
    icon(chip.asset, x, y + 27, 40, chip.color);
    text(chip.title, x + 58, y + 39, 16, c.ink, 600);
    text(chip.label, x + 58, y + 67, 14, chip.color);
  });
  y += 126;
  for (const limit of input.limits) y = paragraph(limit, g, y, 143, 13, c.muted) + 5;
  y += 12;
  text(`SOURCE ${input.view.sourceSHA256.slice(0, 16)}  /  DESIGN CLAIMS / ${input.view.purpose.toUpperCase()}`, g, y, 12, c.muted);
  const height = y + 35;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${width}" height="${height}" style="max-width:100%;height:auto" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" fill="${xml(c.background)}"/><metadata>${xml(JSON.stringify({question: input.view.question, basis: input.view.basis, findings: input.findings}))}</metadata><g font-family="${xml(theme.fontFamily)}">${parts.join('')}</g></svg>`;
  return {svg, width, height, question: input.view.question, basis, inputSHA256: digest(JSON.stringify({...input, theme})), svgSHA256: digest(svg)};
}
