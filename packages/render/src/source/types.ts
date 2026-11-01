// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

export const viewKinds = ['system', 'routing', 'flow', 'sequence', 'state', 'data', 'assurance'] as const;
/** Standard profiles are suggestions; project diagram kinds are open identifiers. */
export type ViewKind = string;
export function validatePurposeKind(purpose: string, kind: string): void {
  if (!['architecture', 'workflow'].includes(purpose) || !kind.trim()) throw new Error('Invalid view purpose/kind');
  const standardPurpose = {system: 'architecture', data: 'architecture', assurance: 'architecture', routing: 'workflow', flow: 'workflow', sequence: 'workflow', state: 'workflow'} as const;
  if (Object.hasOwn(standardPurpose, kind) && standardPurpose[kind as keyof typeof standardPurpose] !== purpose) throw new Error('Architecture and workflow purpose/kind contracts must be separate');
}
export interface QuestionRef { readonly ref: string; readonly text: string; }
/** Links into the project's existing capture/obligation/evidence system, not a second ledger. */
export interface ViewBasis {
  readonly captureRef: string;
  readonly modelRefs: readonly string[];
  readonly obligationRefs: readonly string[];
  readonly evidenceRefs: readonly string[];
}
export interface ViewSelection {
  readonly source: string; readonly title: string; readonly question: QuestionRef; readonly basis: ViewBasis;
  readonly purpose: 'architecture' | 'workflow'; readonly kind: ViewKind;
}
