import {getSmoothStepPath, Position} from '@xyflow/system';
import rough from 'roughjs';
import packageInfo from '../package.json' with {type: 'json'};
import { readFile } from 'node:fs/promises';
import type { Browser } from 'playwright';
import type { ComposedFigure } from './figure';
import { digest } from './source/catalog';
export interface FigureExportOptions { readonly scale?: number; readonly regions?: readonly string[]; }
export interface FigureImage {
  readonly png: Uint8Array;
  readonly regionImages: Readonly<Record<string, Uint8Array>>;
  /** Fully materialized, offline HTML, including embedded fonts and measured sketch strokes. */
  readonly html: string;
  readonly receipt: {
    readonly inputSHA256: string; readonly composedHTMLSHA256: string; readonly htmlSHA256: string; readonly pngSHA256: string;
    readonly drawing: string; readonly routing: string; readonly dependencies: Readonly<Record<string, string>>; readonly assetSHA256: Readonly<Record<string, string>>;
    readonly regionSHA256: Readonly<Record<string, string>>;
    readonly browser: string; readonly width: number; readonly height: number; readonly scale: number;
    readonly bounds: Readonly<Record<string, {x: number; y: number; width: number; height: number}>>;
  };
}
/** Host owns the official browser; this effect owns and closes just its context. */
export async function exportFigure(figure: ComposedFigure, browser: Browser, options: FigureExportOptions = {}): Promise<FigureImage> {
  if (digest(figure.html) !== figure.htmlSHA256) throw new Error('Figure HTML differs from its captured fingerprint');
  const scale = options.scale ?? 1;
  if (!Number.isFinite(scale) || scale < 0.5 || scale > 4) throw new Error('Invalid export scale');
  const context = await browser.newContext({viewport: {width: figure.width, height: 900}, deviceScaleFactor: scale, reducedMotion: 'reduce'});
  try {
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    await page.setContent(figure.html, {waitUntil: 'load', timeout: 15000});
    const provenance = await page.evaluate(() => { const value: unknown = JSON.parse(document.getElementById('figure-provenance')!.textContent!); if (!value || typeof value !== 'object' || !('drawing' in value) || !('fonts' in value)) throw new Error('Invalid rendering provenance'); return {drawing: value.drawing, fonts: value.fonts}; });
    if (JSON.stringify(provenance.drawing) !== JSON.stringify(figure.drawing)) throw new Error('Drawing differs from captured HTML');
    if (JSON.stringify(provenance.fonts) !== JSON.stringify(figure.fonts)) throw new Error('Fonts differ from captured HTML');
    const assetSHA256: Record<string, string> = {};
    const faces = await Promise.all(figure.fonts.map(async ({family, weight, source}) => {
      if (!/^[a-zA-Z0-9 -]+$/.test(family) || !Number.isInteger(weight) || weight < 100 || weight > 900) throw new Error('Invalid declared font');
      const font = await readFile(new URL(import.meta.resolve(source)));
      assetSHA256[source] = digest(font);
      return `@font-face{font-family:"${family}";font-style:normal;font-weight:${weight};src:url(data:font/woff2;base64,${font.toString('base64')}) format('woff2')}`;
    }));
    if (faces.length) await page.addStyleTag({content: faces.join('\n')});
    // Settle actual text layout before waiting on its FontFaceSet.
    await page.locator('[data-figure]').boundingBox();
    await page.evaluate(async () => {
      await document.fonts.ready;
      for (const image of document.images) {
        if (!image.complete || !image.naturalWidth) throw new Error('Figure contains an unloaded or invalid image');
        await image.decode();
      }
    });
    // Route declared connectors against actual font-settled node boxes, then bake to SVG.
    const connectors = await page.evaluate(() => {
      type Side = 'top' | 'bottom' | 'left' | 'right';
      const result: {index: number; sourceX: number; sourceY: number; targetX: number; targetY: number; sourceSide: Side; targetSide: Side}[] = [];
      const side = (value: string | undefined, fallback: Side): Side => {
        if (value === undefined) return fallback;
        if (value !== 'top' && value !== 'bottom' && value !== 'left' && value !== 'right') throw new Error('Invalid declared connector position');
        return value;
      };
      const anchor = (rect: DOMRect, position: Side, distance: number) => ({
        x: position === 'left' ? rect.left - distance : position === 'right' ? rect.right + distance : rect.left + rect.width / 2,
        y: position === 'top' ? rect.top - distance : position === 'bottom' ? rect.bottom + distance : rect.top + rect.height / 2,
      });
      for (const svg of document.querySelectorAll<SVGSVGElement>('svg[data-connections]')) {
        const captured: {model?: {relations: {src: string; dst: string}[]}} = JSON.parse(document.getElementById('figure-provenance')!.textContent!);
        const canvas = svg.parentElement!, root = canvas.getBoundingClientRect();
        const ns = 'http://www.w3.org/2000/svg', defs = document.createElementNS(ns, 'defs');
        const marker = document.createElementNS(ns, 'marker');
        const id = `arrow-${Array.from(document.querySelectorAll('svg[data-connections]')).indexOf(svg)}`;
        marker.setAttribute('id', id); marker.setAttribute('viewBox', '0 0 10 10'); marker.setAttribute('refX', '9'); marker.setAttribute('refY', '5'); marker.setAttribute('markerWidth', '5'); marker.setAttribute('markerHeight', '5'); marker.setAttribute('orient', 'auto-start-reverse');
        const arrow = document.createElementNS(ns, 'path'); arrow.setAttribute('d', 'M 1 1 L 9 5 L 1 9'); arrow.setAttribute('style', 'stroke:var(--accent);fill:none'); marker.append(arrow); defs.append(marker); svg.prepend(defs);
        for (const path of svg.querySelectorAll<SVGPathElement>('path[data-from][data-to]')) {
          const find = (id: string | undefined) => Array.from(canvas.querySelectorAll<HTMLElement>('[data-node]')).filter(node => node.dataset.node === id);
          const sources = find(path.dataset.from), targets = find(path.dataset.to);
          if (sources.length !== 1 || targets.length !== 1) throw new Error('Connector needs unique rendered endpoints');
          if (!captured.model?.relations.some(edge => edge.src === path.dataset.from && edge.dst === path.dataset.to)) throw new Error('Undeclared rendered model relation');
          const a = sources[0]!.getBoundingClientRect(), b = targets[0]!.getBoundingClientRect();
          const backwards = b.right < a.left;
          path.dataset.connectionIndex = String(result.length);
          const sourceSide = side(path.dataset.sourcePosition, backwards ? 'left' : 'right'), targetSide = side(path.dataset.targetPosition, backwards ? 'right' : 'left');
          const start = anchor(a, sourceSide, 2), end = anchor(b, targetSide, 3);
          result.push({index: result.length, sourceX: start.x - root.left, sourceY: start.y - root.top, targetX: end.x - root.left, targetY: end.y - root.top, sourceSide, targetSide});
          path.setAttribute('marker-end', `url(#${id})`);
        }
      }
      return result;
    });
    const positions = {top: Position.Top, bottom: Position.Bottom, left: Position.Left, right: Position.Right};
    const routes = connectors.map(({index, sourceSide, targetSide, ...coordinates}) => ({index, path: getSmoothStepPath({...coordinates,
      sourcePosition: positions[sourceSide], targetPosition: positions[targetSide], borderRadius: 7, offset: 8})[0]}));
    await page.evaluate(routes => { for (const route of routes) document.querySelector(`[data-connection-index="${route.index}"]`)!.setAttribute('d', route.path); }, routes);
    if (figure.drawing.mode === 'sketch') {
      const surfaces = await page.locator('[data-surface]').evaluateAll(elements => elements.map(element => {
        const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
        return {shape: element.getAttribute('data-surface') || 'rectangle', width: rect.width, height: rect.height, stroke: style.getPropertyValue('--accent').trim(), fill: style.getPropertyValue('--tint').trim()};
      }));
      const generator = rough.generator();
      const sketches = surfaces.map((surface, index) => {
        const options = {stroke: surface.stroke, fill: surface.fill, ...figure.drawing.options, seed: figure.drawing.options.seed + index};
        const width = surface.width, height = surface.height;
        const drawable = surface.shape === 'rectangle' ? generator.rectangle(2, 2, width - 4, height - 4, options)
          : surface.shape === 'ellipse' ? generator.ellipse(width / 2, height / 2, width - 4, height - 4, options)
          : surface.shape === 'diamond' ? generator.polygon([[width / 2, 2], [width - 2, height / 2], [width / 2, height - 2], [2, height / 2]], options)
          : undefined;
        if (!drawable) throw new Error(`Unsupported declared sketch surface: ${surface.shape}`);
        const paths = generator.toPaths(drawable);
        return {width: surface.width, height: surface.height, paths};
      });
      await page.locator('[data-surface]').evaluateAll((elements, sketches) => {
        const ns = 'http://www.w3.org/2000/svg';
        elements.forEach((element, index) => {
          const sketch = sketches[index]!, svg = document.createElementNS(ns, 'svg');
          svg.setAttribute('class', 'sketch-surface'); svg.setAttribute('aria-hidden', 'true');
          svg.setAttribute('width', String(sketch.width)); svg.setAttribute('height', String(sketch.height));
          svg.setAttribute('viewBox', `0 0 ${sketch.width} ${sketch.height}`);
          for (const path of sketch.paths) {
            const node = document.createElementNS(ns, 'path');
            node.setAttribute('d', path.d); node.setAttribute('stroke', path.stroke); node.setAttribute('stroke-width', String(path.strokeWidth)); node.setAttribute('fill', path.fill || 'none');
            svg.append(node);
          }
          element.prepend(svg);
        });
      }, sketches);
    }
    const report = await page.evaluate(() => {
      const figure = document.querySelector<HTMLElement>('[data-figure]')!;
      const root = figure.getBoundingClientRect();
      const bounds: Record<string, {x: number; y: number; width: number; height: number}> = {};
      const issues: string[] = [];
      const captured: {questions: {ref: string}[]} = JSON.parse(document.getElementById('figure-provenance')!.textContent!);
      for (const question of captured.questions) {
        const shown = Array.from(figure.querySelectorAll<HTMLElement>('[data-question]')).some(element => element.dataset.question === question.ref && element.checkVisibility({opacityProperty: true, visibilityProperty: true}) && element.getBoundingClientRect().width > 0 && element.getBoundingClientRect().height > 0);
        if (!shown) issues.push(`Question has no visible region: ${question.ref}`);
      }

      for (const element of figure.querySelectorAll<HTMLElement>('[data-region]')) {
        const rect = element.getBoundingClientRect();
        const name = element.dataset.region!;
        if (name in bounds) issues.push(`duplicate region: ${name}`);
        bounds[name] = {x: rect.x - root.x, y: rect.y - root.y, width: rect.width, height: rect.height};
        if (rect.left < root.left - 1 || rect.right > root.right + 1 || rect.bottom > root.bottom + 1) issues.push(`out of figure: ${name}`);
      }
      for (const element of figure.querySelectorAll<HTMLElement>('[data-fit]')) {
        if (element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1) issues.push(`clipped text: ${element.textContent?.slice(0, 60)}`);
      }
      if (figure.scrollWidth > figure.clientWidth + 1) issues.push('figure horizontal overflow');
      return {bounds, issues};
    });
    if (report.issues.length) throw new Error(report.issues.join('; '));
    const html = await page.content();
    const png = await page.locator('[data-figure]').screenshot({type: 'png', animations: 'disabled'});
    const regionImages: Record<string, Uint8Array> = {};
    for (const name of options.regions ?? []) {
      if (!/^[a-zA-Z0-9_-]+$/.test(name) || !(name in report.bounds)) throw new Error(`Unknown requested figure region: ${name}`);
      regionImages[name] = await page.locator(`[data-region="${name}"]`).screenshot({type: 'png', animations: 'disabled'});
    }
    const buffer = Buffer.from(png);
    return {png, html, regionImages, receipt: {inputSHA256: figure.inputSHA256, composedHTMLSHA256: figure.htmlSHA256, dependencies: packageInfo.dependencies, regionSHA256: Object.fromEntries(Object.entries(regionImages).map(([name, bytes]) => [name, digest(bytes)])), htmlSHA256: digest(html), drawing: figure.drawing.mode === "sketch" ? `roughjs@${packageInfo.dependencies.roughjs}` : "precise", routing: connectors.length ? `xyflow@${packageInfo.dependencies["@xyflow/system"]}` : "none", assetSHA256, pngSHA256: digest(png), browser: browser.version(),
      width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20), scale, bounds: report.bounds}};
  } finally { await context.close(); }
}
