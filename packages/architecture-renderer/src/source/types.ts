import type { RenderTheme } from '../theme';
export const viewKinds = ['system', 'routing', 'flow', 'sequence', 'state', 'data', 'assurance'] as const;
export type ViewKind = typeof viewKinds[number];
export function isViewKind(value: string): value is ViewKind { return viewKinds.some(kind => kind === value); }
export interface QuestionRef { readonly ref: string; readonly text: string; }
/** Links into the project's existing capture/obligation/evidence system, not a second ledger. */
export interface ViewBasis {
  readonly captureRef: string;
  readonly modelRefs: readonly string[];
  readonly obligationRefs: readonly string[];
  readonly evidenceRefs: readonly string[];
}
export type ViewSelection = { readonly source: string; readonly title: string; readonly question: QuestionRef; readonly basis: ViewBasis } & (
  | { readonly purpose: 'architecture'; readonly kind: 'system' | 'data' | 'assurance' }
  | { readonly purpose: 'workflow'; readonly kind: 'routing' | 'flow' | 'sequence' | 'state' }
);
export type ViewEntry = ViewSelection & { readonly id: string; readonly sha256: string };
export interface Presentation { readonly project: string; readonly footer?: string; }
export interface SourceCatalog {
  readonly views: readonly ViewEntry[];
  readonly fs: Readonly<Record<string, string>>;
  readonly presentation: Presentation;
  readonly theme: RenderTheme;
}
