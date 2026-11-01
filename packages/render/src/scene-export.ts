import ELK, {type ElkNode} from 'elkjs';
import {fileURLToPath} from 'node:url';
import type {Page} from 'playwright';
import {digest} from './source/catalog';
export interface SceneLayoutReceipt {readonly inputSHA256:string; readonly layoutSHA256:string; readonly nodes:number; readonly edges:number; readonly milliseconds:number;}
/** Actual font boxes go to the mature layout engine. No coordinates from the old D2 SVG are reused. */
export async function layoutScenes(page: Page): Promise<readonly SceneLayoutReceipt[]> {
  const scenes = page.locator('svg[data-scene]'), count = await scenes.count();
  if (!count) return [];
  const elk = new ELK({workerUrl:fileURLToPath(import.meta.resolve('elkjs/lib/elk-worker.min.js'))});
  const receipts: SceneLayoutReceipt[] = [];
  try {
    for (let index=0;index<count;index++) {
      const scene = scenes.nth(index);
      const input = await scene.evaluate(svg => {
        const data: {graph:ElkNode;marker:string} = JSON.parse(svg.querySelector('[data-scene-input]')!.textContent!);
        for(const glyph of svg.querySelectorAll<SVGSVGElement>('.scene-glyph>svg')) { const size=parseFloat(getComputedStyle(glyph).width); if(!Number.isFinite(size)||size<=0)throw new Error('Invalid glyph viewport');glyph.setAttribute('width',String(size));glyph.setAttribute('height',String(size)); }
        const metric=(name:string)=>{const value=parseFloat(getComputedStyle(svg).getPropertyValue(name));if(!Number.isFinite(value)||value<0)throw new Error('Invalid scene metric: '+name);return value;};
        const iconGap=metric('--iconGap'),viewportPadding=metric('--viewportPadding');
        const nodes: Record<string,{width:number;height:number;padding:number;boxX:number;boxY:number;group:boolean}> = {};
        for (const node of svg.querySelectorAll<SVGGElement>('[data-scene-node]')) {
          const glyph=node.querySelector<SVGSVGElement>('.scene-glyph>svg');
          node.querySelector('.scene-copy')!.setAttribute('transform',`translate(${glyph?Number(glyph.getAttribute('width'))+iconGap:0} 18)`);
          const box = node.querySelector<SVGGElement>('.scene-content')!.getBBox();
          const padding = metric('--scene-padding');
          nodes[node.dataset.sceneNode!] = {width:Math.ceil(box.width+padding*2),height:Math.ceil(box.height+padding*2),padding,boxX:box.x,boxY:box.y,group:node.dataset.sceneGroup==='true'};
        }
        const labels: Record<string,{width:number;height:number;boxX:number;boxY:number;padding:number}> = {};
        for (const edge of svg.querySelectorAll<SVGGElement>('[data-scene-edge]')) {
          const text = edge.querySelector<SVGTextElement>('.scene-label text'), box = text?.getBBox();
          const padding = metric('--scene-label-padding');
          labels[edge.dataset.sceneEdge!] = {width:box ? Math.ceil(box.width+padding*2):0,height:box ? Math.ceil(box.height+padding*2):0,boxX:box?.x??0,boxY:box?.y??0,padding};
        }
        return {...data,nodes,labels,viewportPadding};
      });
      const graph = structuredClone(input.graph);
      graph.layoutOptions = {'elk.algorithm':'layered','elk.direction':'DOWN','elk.edgeRouting':'ORTHOGONAL','elk.hierarchyHandling':'INCLUDE_CHILDREN','elk.spacing.nodeNode':'32','elk.layered.spacing.nodeNodeBetweenLayers':'48',...graph.layoutOptions};
      const size = (node: ElkNode) => {
        const measured = input.nodes[node.id]!;
        if (!measured || !Number.isFinite(measured.width) || !Number.isFinite(measured.height)) throw new Error('Diagram node has no measurable content');
        if (node.children) {
          node.labels=[{id:node.id+'-heading',text:' ',width:measured.width-measured.padding*2,height:measured.height-measured.padding*2}];
          node.layoutOptions = {'elk.nodeLabels.placement':'INSIDE V_TOP H_LEFT','elk.padding':`[top=${measured.height},left=${measured.padding},bottom=${measured.padding},right=${measured.padding}]`,...node.layoutOptions}; node.children.forEach(size);
        } else {node.width=measured.width;node.height=measured.height;}
      };
      graph.children!.forEach(size);
      for (const edge of graph.edges ?? []) {const label=input.labels[edge.id]!; if (label.width) edge.labels=[{id:edge.id+'-label',text:' ',width:label.width,height:label.height}];}
      const start=performance.now(), result=await elk.layout(graph);
      receipts.push({inputSHA256:digest(JSON.stringify({graph,measurements:input.nodes,labels:input.labels})),layoutSHA256:digest(JSON.stringify(result)),nodes:Object.keys(input.nodes).length,edges:graph.edges?.length??0,milliseconds:performance.now()-start});
      await scene.evaluate((svg, {result,input}) => {
        const nodes=Array.from(svg.querySelectorAll<SVGGElement>('[data-scene-node]'));
        const groups=svg.querySelector('.scene-groups')!;
        const origins=new Map<string,{x:number;y:number}>([[result.id,{x:0,y:0}]]);
        const place = (node: ElkNode, offsetX=0, offsetY=0) => {
          const element=nodes.find(element=>element.dataset.sceneNode===node.id)!, measured=input.nodes[node.id]!;
          const x=offsetX+(node.x??0),y=offsetY+(node.y??0),width=node.width!,height=node.height!;
          origins.set(node.id,{x,y});
          element.setAttribute('transform',`translate(${x} ${y})`);
          const frame=element.querySelector('rect')!;frame.setAttribute('width',String(width));frame.setAttribute('height',String(height));
          const surface=element.querySelector('.scene-surface>svg');if(surface){surface.setAttribute('width',String(width));surface.setAttribute('height',String(height));}
          element.querySelector('.scene-content')!.setAttribute('transform',`translate(${measured.padding-measured.boxX} ${measured.padding-measured.boxY})`);
          if(node.children){const label=node.labels?.[0];if(label)element.querySelector('.scene-content')!.setAttribute('transform',`translate(${(label.x??measured.padding)-measured.boxX} ${(label.y??measured.padding)-measured.boxY})`);groups.append(element);node.children.forEach(child=>place(child,x,y));}
        };
        result.children!.forEach(node=>place(node));
        for(const edge of result.edges??[]) {
          const element=Array.from(svg.querySelectorAll<SVGGElement>('[data-scene-edge]')).find(element=>element.dataset.sceneEdge===edge.id)!;
          const path=element.querySelector('path')!;
          const origin=origins.get(edge.container??result.id);
          if(!origin)throw new Error('Unknown layout edge container');
          element.setAttribute('transform',`translate(${origin.x} ${origin.y})`);
          const sections=edge.sections??[];
          if(!sections.length)throw new Error('Layout did not route a declared edge');
          path.setAttribute('d',sections.map(section=>`M ${section.startPoint.x} ${section.startPoint.y} `+[...(section.bendPoints??[]),section.endPoint].map(point=>`L ${point.x} ${point.y}`).join(' ')).join(' '));
          for(const [side,kind]of [['start',path.dataset.sourceArrow],['end',path.dataset.targetArrow]] as const){
            if(kind&&kind!=='none')path.style.setProperty('marker-'+side,`url(#${input.marker}${kind==='arrow'?'':'-'+kind})`);
          }
          const label=edge.labels?.[0], measured=input.labels[edge.id]!;
          if(label&&measured.width){const group=element.querySelector('.scene-label')!;group.setAttribute('transform',`translate(${label.x??0} ${label.y??0})`);const rect=group.querySelector('rect')!;rect.setAttribute('width',String(label.width));rect.setAttribute('height',String(label.height));group.querySelector('text')!.setAttribute('transform',`translate(${measured.padding-measured.boxX} ${measured.padding-measured.boxY})`);}
        }
        const pad=input.viewportPadding,w=(result.width??0)+pad*2,h=(result.height??0)+pad*2;
        svg.setAttribute('viewBox',`${-pad} ${-pad} ${w} ${h}`);svg.setAttribute('width',String(w));svg.setAttribute('height',String(h));
        (svg as SVGSVGElement).style.width=`min(100%, ${w}px)`;(svg as SVGSVGElement).style.height='auto';(svg as SVGSVGElement).style.margin='0 auto';
      },{result,input});
    }
  } finally {elk.terminateWorker();}
  return receipts;
}
/** Serialize the explicit SVG scene and annotations; no bitmap wrapper or foreignObject. */
export async function extractSceneSVGs(page:Page,transparent=false):Promise<readonly string[]> {
  return page.evaluate(transparent=>{
    const ns='http://www.w3.org/2000/svg',figure=document.querySelector<HTMLElement>('[data-figure]')!,root=figure.getBoundingClientRect();
    const elements=Array.from(figure.querySelectorAll<SVGSVGElement>('svg[data-scene],svg[data-vector-annotation],svg[data-vector-surface]' ));
    if(!elements.length)return [];
    const sheetText=Array.from(document.querySelectorAll('style'),style=>style.textContent).join('\n');
    const serializer=new XMLSerializer();
    const prepared=(element:SVGSVGElement)=>{const svg=element.cloneNode(true)as SVGSVGElement,style=getComputedStyle(element);const variables=Array.from(style).filter(name=>name.startsWith('--')).sort().map(name=>`${name}:${style.getPropertyValue(name)}`).join(';');svg.setAttribute('style',`${variables};font-family:${style.fontFamily};color:${style.color}`);return svg;};
    const combined=document.createElementNS(ns,'svg');combined.setAttribute('viewBox',`0 0 ${root.width} ${root.height}`);combined.setAttribute('width',String(root.width));combined.setAttribute('height',String(root.height));combined.setAttribute('data-renderer','@deterministic-engineering/render');
    const sheet=document.createElementNS(ns,'style');sheet.textContent=sheetText;combined.append(sheet);
    const background=getComputedStyle(figure).backgroundColor;
    const backdrop=(svg:SVGSVGElement)=>{if(transparent)return;const bg=document.createElementNS(ns,'rect'),box=svg.viewBox.baseVal;bg.setAttribute('x',String(box.x));bg.setAttribute('y',String(box.y));bg.setAttribute('width',String(box.width));bg.setAttribute('height',String(box.height));bg.setAttribute('fill',background);svg.prepend(bg);};
    backdrop(combined);
    const meta=document.createElementNS(ns,'metadata');meta.textContent=document.getElementById('figure-provenance')!.textContent;combined.append(meta);
    for(const element of elements){const clone=prepared(element),rect=element.getBoundingClientRect();clone.setAttribute('x',String(rect.x-root.x));clone.setAttribute('y',String(rect.y-root.y));clone.setAttribute('width',String(rect.width));clone.setAttribute('height',String(rect.height));combined.append(clone);}
    return [serializer.serializeToString(combined),...Array.from(figure.querySelectorAll<SVGSVGElement>('svg[data-scene]'),element=>{const clone=prepared(element),sheet=document.createElementNS(ns,'style');sheet.textContent=sheetText;clone.prepend(sheet);backdrop(clone);return serializer.serializeToString(clone);})];
  },transparent);
}
