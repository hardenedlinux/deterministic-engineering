/** Page presentation is independent of D2 model notation and engine options. */
export interface PresentationTheme {
  readonly fontFamily: string;
  readonly colors: Readonly<{
    background: string; surface: string; ink: string; muted: string; border: string;
    accent: string; secondary: string; tint: string; secondaryTint: string;
    supported: string; pending: string; conflict: string;
  }>;
  readonly spacing: Readonly<{ gutter: number; gap: number; radius: number }>;
}
export const defaultPresentationTheme: PresentationTheme = Object.freeze({
  fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif',
  colors: Object.freeze({ background: '#F3F6FC', surface: '#FFFFFF', ink: '#132347', muted: '#5B6A85', border: '#DFE6F2',
    accent: '#245FE5', secondary: '#7753D9', tint: '#EAF1FF', secondaryTint: '#F0EBFC',
    supported: '#138274', pending: '#A56415', conflict: '#C14361' }),
  spacing: Object.freeze({ gutter: 56, gap: 24, radius: 20 }),
});
export interface PresentationThemeOverrides {
  readonly fontFamily?: string;
  readonly colors?: Partial<PresentationTheme['colors']>;
  readonly spacing?: Partial<PresentationTheme['spacing']>;
}
export function extendPresentationTheme(base: PresentationTheme, overrides: PresentationThemeOverrides = {}): PresentationTheme {
  return Object.freeze({ fontFamily: overrides.fontFamily ?? base.fontFamily,
    colors: Object.freeze({ ...base.colors, ...overrides.colors }),
    spacing: Object.freeze({ ...base.spacing, ...overrides.spacing }) });
}
