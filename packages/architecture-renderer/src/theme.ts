import type { CompileOptions, RenderOptions } from '@terrastruct/d2';

/** Only official D2 options; D2 source profiles own classes, shapes and style. */
export interface RenderTheme {
  readonly compile: Readonly<Pick<CompileOptions, 'layout'>>;
  readonly render: Readonly<RenderOptions>;
}
export interface ThemeOverrides {
  readonly compile?: Partial<RenderTheme['compile']>;
  readonly render?: Partial<RenderTheme['render']>;
}
export const defaultTheme: RenderTheme = Object.freeze({
  compile: Object.freeze({ layout: 'elk' }), render: Object.freeze({}),
});
/** Compose optional upstream defaults; caller may also supply a complete theme. */
export function extendTheme(base: RenderTheme, overrides: ThemeOverrides = {}): RenderTheme {
  return Object.freeze({
    compile: Object.freeze({ ...base.compile, ...overrides.compile }),
    render: Object.freeze({ ...base.render, ...overrides.render }),
  });
}
