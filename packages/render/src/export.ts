import {layoutScenes, extractSceneSVGs, type SceneLayoutReceipt} from './scene-export';
import {getSmoothStepPath, Position} from '@xyflow/system';
import rough from 'roughjs';
import packageInfo from '../package.json' with {type: 'json'};
import { readFile } from 'node:fs/promises';
import type { Browser } from 'playwright';
import type {RenderObservation} from './taste';
import type {Design} from './design';
import type { ComposedFigure } from './figure';
import { digest } from './source/catalog';
export interface FigureExportOptions { readonly scale?: number; readonly regions?: readonly string[]; readonly minimumTextSize?:number; readonly transparent?:boolean; }
export interface FigureImage {
  readonly png: Uint8Array;
  readonly svg: readonly string[];
  readonly regionImages: Readonly<Record<string, Uint8Array>>;
  /** Fully materialized, offline HTML, including embedded fonts and measured sketch strokes. */
  readonly html: string;
  readonly receipt: {
    readonly inputSHA256: string; readonly composedHTMLSHA256: string; readonly htmlSHA256: string; readonly pngSHA256: string;
    /** Effective SVG text size in logical CSS pixels, after scene scaling. */
    readonly canvas:{readonly background:string;readonly transparent:boolean};
    readonly readability: {readonly minimumTextSize:number|null;readonly samples:number;readonly requiredMinimum?:number};
    readonly observation:RenderObservation;
    readonly scenes: readonly SceneLayoutReceipt[]; readonly svgSHA256: readonly string[];
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
  if(options.minimumTextSize!==undefined&&(!Number.isFinite(options.minimumTextSize)||options.minimumTextSize<=0))throw new Error('Invalid minimum text size');
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
    await page.evaluate(()=>{
      const captured:{palette:Record<string,string>}=JSON.parse(document.getElementById('figure-provenance')!.textContent!);
      for(const[name,value]of Object.entries(captured.palette))if(!CSS.supports('color',value))throw new Error('Invalid CSS palette color: '+name);
    });
    // Settle actual text layout before waiting on its FontFaceSet.
    await page.locator('[data-figure]').boundingBox();
    await page.evaluate(async () => {
      await document.fonts.ready;
      for (const image of document.images) {
        if (!image.complete || !image.naturalWidth) throw new Error('Figure contains an unloaded or invalid image');
        await image.decode();
      }
    });
    // SVG annotation height follows the selected font's real ascent/descent.
    await page.locator('svg[data-vector-annotation]').evaluateAll(elements=>{
      for(const svg of elements){const content=svg.querySelector<SVGGElement>('[data-annotation-content]');
        if(content){
          const metric=(name:string)=>{const value=parseFloat(getComputedStyle(svg).getPropertyValue(name));if(!Number.isFinite(value)||value<0)throw new Error('Invalid heading metric: '+name);return value;};
          const gap=metric('--gap'),markerSize=metric('--markerSize'),markerPadding=metric('--markerPadding'),padding=metric('--annotationPadding');
          for(const glyph of content.querySelectorAll<SVGSVGElement>('[data-annotation-part="glyph"]>svg')){const size=parseFloat(getComputedStyle(glyph).width);glyph.setAttribute('width',String(size));glyph.setAttribute('height',String(size));}
          let cursor=0;
          for(const part of content.querySelectorAll<SVGGElement>('[data-annotation-part]')){
            if(part.dataset.annotationPart==='ordinal'){const label=part.querySelector('text')!,circle=part.querySelector('circle')!,box=label.getBBox();const radius=Math.max(markerSize/2,Math.max(box.width,box.height)/2+markerPadding);circle.setAttribute('r',String(radius));label.setAttribute('transform',`translate(${-box.x-box.width/2} ${-box.y-box.height/2})`);}
            const box=part.getBBox();part.setAttribute('transform',`translate(${cursor-box.x} ${-box.y-box.height/2})`);cursor+=box.width+gap;
          }
          const box=content.getBBox();content.setAttribute('transform',`translate(${-box.x} ${padding-box.y})`);svg.setAttribute('height',String(Math.ceil(box.height+padding*2)));
        }else{const text=svg.querySelector('text')!;const box=text.getBBox();text.setAttribute('transform',`translate(0 ${3-box.y})`);svg.setAttribute('height',String(Math.ceil(box.height+6)));}}
    });
    const scenes = await layoutScenes(page);
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
    // Existing explicit HTML surface declarations become vector primitives as well.
    // This is not arbitrary HTML/CSS-to-SVG conversion.
    await page.locator('[data-surface]').evaluateAll((elements,precise)=>{
      const ns='http://www.w3.org/2000/svg';
      for(const element of elements){
        const host=element as HTMLElement,style=getComputedStyle(host),box=host.getBoundingClientRect();
        if(style.position==='static')host.style.position='relative';host.style.isolation='isolate';
        if(!precise)continue;
        const shape=host.getAttribute('data-surface')||'rectangle';
        if(!['rectangle','ellipse','diamond'].includes(shape))throw new Error('Unsupported declared surface: '+shape);
        if(style.backgroundImage!=='none')throw new Error('Declared vector surface needs an explicit SVG for background images');
        const borders=['Top','Right','Bottom','Left'].map(side=>{const key=side.toLowerCase();return [style.getPropertyValue('border-'+key+'-width'),style.getPropertyValue('border-'+key+'-style'),style.getPropertyValue('border-'+key+'-color')];});
        if(borders.some(border=>JSON.stringify(border)!==JSON.stringify(borders[0])))throw new Error('Unsupported nonuniform declared surface border');
        if(!['none','solid','dashed','dotted'].includes(style.borderTopStyle))throw new Error('Unsupported declared surface border style');
        if(shape==='rectangle'&&[style.borderTopLeftRadius,style.borderTopRightRadius,style.borderBottomLeftRadius,style.borderBottomRightRadius].some(radius=>radius!==style.borderTopLeftRadius||!radius.endsWith('px')))throw new Error('Unsupported declared surface corner radius');
        const stroke=style.borderTopStyle==='none'?0:parseFloat(style.borderTopWidth),inset=stroke/2,w=box.width,h=box.height;
        const svg=document.createElementNS(ns,'svg');svg.setAttribute('data-vector-surface','');svg.setAttribute('width',String(w));svg.setAttribute('height',String(h));svg.setAttribute('viewBox',`0 0 ${w} ${h}`);svg.setAttribute('aria-hidden','true');svg.setAttribute('style','position:absolute;inset:0;z-index:-1;pointer-events:none');
        const primitive=document.createElementNS(ns,shape==='rectangle'?'rect':shape==='ellipse'?'ellipse':'polygon');
        const attrs=shape==='rectangle'?{x:inset,y:inset,width:w-stroke,height:h-stroke,rx:Math.max(0,parseFloat(style.borderTopLeftRadius)-inset)}:shape==='ellipse'?{cx:w/2,cy:h/2,rx:(w-stroke)/2,ry:(h-stroke)/2}:{points:`${w/2},${inset} ${w-inset},${h/2} ${w/2},${h-inset} ${inset},${h/2}`};
        for(const[key,value]of Object.entries(attrs))primitive.setAttribute(key,String(value));
        if(style.borderTopStyle==='dashed')primitive.setAttribute('stroke-dasharray',`${stroke*3} ${stroke*3}`);
        if(style.borderTopStyle==='dotted'){primitive.setAttribute('stroke-dasharray',`0 ${stroke*2}`);primitive.setAttribute('stroke-linecap','round');}
        primitive.setAttribute('fill',style.backgroundColor);primitive.setAttribute('stroke',style.borderTopColor);primitive.setAttribute('stroke-width',String(stroke));svg.append(primitive);host.prepend(svg);
      }
    },figure.drawing.mode==='precise');
    if (figure.drawing.mode === 'sketch') {
      const surfaces = await page.locator('[data-surface], rect.scene-frame:not([data-custom-surface])').evaluateAll(elements => elements.map(element => {
        const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
        const scene = element instanceof SVGRectElement;
        return {scene, shape: element.getAttribute('data-surface') || 'rectangle', width: scene ? element.width.baseVal.value : rect.width, height: scene ? element.height.baseVal.value : rect.height, stroke: scene ? style.stroke : style.getPropertyValue('--accent').trim(), fill: scene ? style.fill : style.getPropertyValue('--tint').trim()};
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
        return {scene: surface.scene, width: surface.width, height: surface.height, paths};
      });
      await page.locator('[data-surface], rect.scene-frame:not([data-custom-surface])').evaluateAll((elements, sketches) => {
        const ns = 'http://www.w3.org/2000/svg';
        elements.forEach((element, index) => {
          const sketch = sketches[index]!, svg = document.createElementNS(ns, sketch.scene ? 'g' : 'svg');
          svg.setAttribute('class', 'sketch-surface'); svg.setAttribute('aria-hidden', 'true');
          svg.setAttribute('width', String(sketch.width)); svg.setAttribute('height', String(sketch.height));
          svg.setAttribute('viewBox', `0 0 ${sketch.width} ${sketch.height}`);
          for (const path of sketch.paths) {
            const node = document.createElementNS(ns, 'path');
            node.setAttribute('d', path.d); node.setAttribute('stroke', path.stroke); node.setAttribute('stroke-width', String(path.strokeWidth)); node.setAttribute('fill', path.fill || 'none');
            svg.append(node);
          }
          if (sketch.scene) { element.after(svg); element.setAttribute('opacity','0'); } else {svg.setAttribute('data-vector-surface','');svg.setAttribute('style','position:absolute;inset:0;z-index:-1;pointer-events:none');element.prepend(svg);}
        });
      }, sketches);
    }
    const report = await page.evaluate(() => {
      const figure = document.querySelector<HTMLElement>('[data-figure]')!;
      const root = figure.getBoundingClientRect();
      const bounds: Record<string, {x: number; y: number; width: number; height: number}> = {};
      const issues: string[] = [];
      const textSizes:number[]=[];
      const captured: {design?:Design;model?:import('./figure').FigureModel;questions: {ref: string}[]} = JSON.parse(document.getElementById('figure-provenance')!.textContent!);
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
      const visible=(element:Element)=>element.checkVisibility({opacityProperty:true,visibilityProperty:true})&&element.getBoundingClientRect().width>0&&element.getBoundingClientRect().height>0;
      const rect=(element:Element)=>{const box=element.getBoundingClientRect();return{x:box.x-root.x,y:box.y-root.y,width:box.width,height:box.height};};
      const subjects=Array.from(figure.querySelectorAll<HTMLElement|SVGGElement>('[data-scene-node],[data-node]')).filter(visible).map(element=>({id:element.getAttribute('data-scene-node')??element.getAttribute('data-node')!,role:element.getAttribute('data-role')??'default',...(element.getAttribute('data-scene-owner')?{owner:element.getAttribute('data-scene-owner')!}:{}),...rect(element)}));
      const visiblePath=(path:SVGGeometryElement)=>{const box=path.getBoundingClientRect(),style=getComputedStyle(path);return path.checkVisibility({opacityProperty:true,visibilityProperty:true})&&(box.width>0||box.height>0)&&style.stroke!=='none'&&style.strokeOpacity!=='0'&&path.getTotalLength()>0;};
      const visibleRelation=(element:Element)=>visible(element)||Array.from(element.querySelectorAll<SVGGeometryElement>('path[d]')).some(visiblePath);
      const relations=new Set(Array.from(figure.querySelectorAll('[data-scene-edge],[data-relation]')).filter(visibleRelation).map(element=>element.getAttribute('data-scene-edge')??element.getAttribute('data-relation')!));
      for(const path of figure.querySelectorAll<SVGPathElement>('path[data-from][data-to]'))if(path.getAttribute('d')&&visiblePath(path))for(const edge of captured.model?.relations??[])if(edge.src===path.getAttribute('data-from')&&edge.dst===path.getAttribute('data-to'))relations.add(edge.id);
      if(captured.design){
        for(const id of [...captured.design.requiredSubjects,...captured.design.focalSubjects])if(!subjects.some(subject=>subject.id===id))issues.push('Design subject has no visible region: '+id);
        for(const id of captured.design.requiredRelations)if(!relations.has(id))issues.push('Design relation has no visible region: '+id);
      }
      const observation:RenderObservation={canvas:{x:0,y:0,width:root.width,height:root.height},subjects,relations:[...relations],headings:Array.from(figure.querySelectorAll('svg[data-heading-role]')).filter(visible).map(element=>({role:element.getAttribute('data-heading-role')!,...rect(element)}))};
      // Observe the browser's final geometry; layout/routing remains owned by ELK.
      const overlaps = (a: DOMRect, b: DOMRect) => Math.min(a.right,b.right)-Math.max(a.left,b.left)>1 && Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>1;
      const contains = (outer: DOMRect, inner: DOMRect) => inner.left>=outer.left-1 && inner.top>=outer.top-1 && inner.right<=outer.right+1 && inner.bottom<=outer.bottom+1;
      for (const scene of figure.querySelectorAll<SVGSVGElement>('svg[data-scene]')) {
        const declared=Array.from(scene.querySelectorAll<SVGGElement>('[data-scene-node]'));
        const byID=new Map(declared.map(node=>[node.dataset.sceneNode!,node]));
        const ancestors=(id:string)=>{const chain:string[]=[];let owner=byID.get(id)?.dataset.sceneOwner;while(owner){if(chain.includes(owner)||!byID.has(owner))throw new Error('Invalid displayed scope ancestry');chain.push(owner);owner=byID.get(owner)!.dataset.sceneOwner;}return chain;};
        for(const node of declared){const owner=node.dataset.sceneOwner;if(owner&&!contains(byID.get(owner)!.querySelector('.scene-frame')!.getBoundingClientRect(),node.querySelector('.scene-frame')!.getBoundingClientRect()))issues.push('scene subject outside owner scope: '+node.dataset.sceneNode);}
        for(const edge of scene.querySelectorAll<SVGGElement>('[data-scene-edge]')){
          const source=edge.dataset.sourceId!,target=edge.dataset.targetId!;
          const common=ancestors(source).filter(owner=>ancestors(target).includes(owner));
          for(const owner of common)if(!contains(byID.get(owner)!.querySelector('.scene-frame')!.getBoundingClientRect(),edge.getBoundingClientRect()))issues.push('internal relation outside owner scope: '+edge.dataset.sceneEdge);
        }
        const leaves = Array.from(scene.querySelectorAll<SVGGElement>('[data-scene-group="false"]'));
        const frames = leaves.map(node => node.querySelector('.scene-frame')!.getBoundingClientRect());
        leaves.forEach((node,index) => {
          if (!contains(frames[index]!,node.querySelector('.scene-content')!.getBoundingClientRect())) issues.push(`scene content outside node: ${node.dataset.sceneNode}`);
          for (let j=index+1;j<frames.length;j++) if(overlaps(frames[index]!,frames[j]!)) issues.push('overlapping scene nodes');
        });
        for(const node of leaves){
          const lines=Array.from(node.querySelectorAll<SVGTSpanElement>('[data-text-line]'));
          for(let index=1;index<lines.length;index++)if(overlaps(lines[index-1]!.getBoundingClientRect(),lines[index]!.getBoundingClientRect()))issues.push('overlapping scene text lines');
        }
        const labels = Array.from(scene.querySelectorAll<SVGGElement>('.scene-label')).filter(label=>label.querySelector('text'));
        labels.forEach((label,index) => {
          const box=label.getBoundingClientRect();
          if(frames.some(frame=>overlaps(frame,box))) issues.push('scene label overlaps node');
          if(labels.slice(index+1).some(other=>overlaps(box,other.getBoundingClientRect()))) issues.push('overlapping scene labels');
        });
      }
      for (const annotation of figure.querySelectorAll<SVGSVGElement>('svg[data-vector-annotation]')) {
        const parts=Array.from(annotation.querySelectorAll<SVGGElement>('[data-annotation-part]'),part=>part.getBoundingClientRect());
        for(let index=0;index<parts.length;index++){
          if(parts.slice(index+1).some(other=>overlaps(parts[index]!,other)))issues.push('overlapping heading parts');
          if(index&&Math.abs(parts[index]!.y+parts[index]!.height/2-parts[0]!.y-parts[0]!.height/2)>1)issues.push('heading parts do not share a center');
        }

        if (!contains(annotation.getBoundingClientRect(),(annotation.querySelector<SVGGraphicsElement>('[data-annotation-content]')??annotation.querySelector('text')!).getBoundingClientRect())) issues.push('clipped vector annotation: '+annotation.textContent?.slice(0,60));
      }
      if (figure.scrollWidth > figure.clientWidth + 1) issues.push('figure horizontal overflow');
      for(const text of figure.querySelectorAll<SVGTextElement|SVGTSpanElement>('svg text, svg tspan')){
        if(text.querySelector('tspan')||!text.textContent?.trim()||!text.checkVisibility({opacityProperty:true,visibilityProperty:true}))continue;
        const matrix=text.getScreenCTM(),box=text.getBoundingClientRect();
        if(matrix&&box.width>0&&box.height>0)textSizes.push(parseFloat(getComputedStyle(text).fontSize)*Math.hypot(matrix.c,matrix.d));
      }
      return {bounds,issues,observation,canvasBackground:getComputedStyle(figure).backgroundColor,readability:{minimumTextSize:textSizes.length?Math.min(...textSizes):null,samples:textSizes.length}};
    });
    if(options.minimumTextSize!==undefined&&(report.readability.minimumTextSize===null||report.readability.minimumTextSize<options.minimumTextSize))report.issues.push('Text is below the declared minimum size');
    if (report.issues.length) throw new Error(report.issues.join('; '));
    if(options.transparent)await page.locator('[data-figure]').evaluate(element=>{(element as HTMLElement).style.setProperty('background','transparent','important');document.body.style.background='transparent';});
    await page.evaluate(rendered=>{const element=document.getElementById('figure-provenance')!,capture=JSON.parse(element.textContent!);capture.rendered=rendered;element.textContent=JSON.stringify(capture).replaceAll('<','\\u003c');},{observation:report.observation,readability:{...report.readability,requiredMinimum:options.minimumTextSize},bounds:report.bounds});
    const svg = await extractSceneSVGs(page,options.transparent??false);
    const html = await page.content();
    const png = await page.locator('[data-figure]').screenshot({type: 'png', animations: 'disabled',omitBackground:options.transparent??false});
    const regionImages: Record<string, Uint8Array> = {};
    for (const name of options.regions ?? []) {
      if (!/^[a-zA-Z0-9_-]+$/.test(name) || !(name in report.bounds)) throw new Error(`Unknown requested figure region: ${name}`);
      regionImages[name] = await page.locator(`[data-region="${name}"]`).screenshot({type: 'png', animations: 'disabled',omitBackground:options.transparent??false});
    }
    const buffer = Buffer.from(png);
    return {png, html, svg, regionImages, receipt: {observation:report.observation,canvas:{background:options.transparent?'transparent':report.canvasBackground,transparent:options.transparent??false},readability:{...report.readability,requiredMinimum:options.minimumTextSize},inputSHA256: figure.inputSHA256, scenes, svgSHA256:svg.map(svg=>digest(svg)), composedHTMLSHA256: figure.htmlSHA256, dependencies: packageInfo.dependencies, regionSHA256: Object.fromEntries(Object.entries(regionImages).map(([name, bytes]) => [name, digest(bytes)])), htmlSHA256: digest(html), drawing: figure.drawing.mode === "sketch" ? `roughjs@${packageInfo.dependencies.roughjs}` : "precise", routing: scenes.length ? `elkjs@${packageInfo.dependencies.elkjs}` : connectors.length ? `xyflow@${packageInfo.dependencies["@xyflow/system"]}` : "none", assetSHA256, pngSHA256: digest(png), browser: browser.version(),
      width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20), scale, bounds: report.bounds}};
  } finally { await context.close(); }
}
