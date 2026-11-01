import type {PresentationThemeOverrides} from './presentation-theme';
/** Optional data presets for the existing theme-layer mechanism, not diagram kinds. */
export const layoutLayers:Readonly<Record<string,PresentationThemeOverrides>>=Object.freeze({
  'layered-down':Object.freeze({layoutOptions:Object.freeze({'elk.algorithm':'layered','elk.direction':'DOWN','elk.edgeRouting':'ORTHOGONAL'})}),
  'layered-right':Object.freeze({layoutOptions:Object.freeze({'elk.algorithm':'layered','elk.direction':'RIGHT','elk.edgeRouting':'ORTHOGONAL'})}),
});
