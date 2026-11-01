import {composeDiagram, type DiagramSpec, type FigureComposer} from '@deterministic-engineering/render';
/** This explanatory page is a project composition, not a required Library template. */
export const overview: FigureComposer = context => {
  const value=context.presentation;
  if(!value||typeof value!=='object'||!('scenes' in value)||!Array.isArray(value.scenes))throw new Error('Declared scene projections are required');
  const text=context.text;
  const panels=value.scenes.map((value:unknown)=>{
    if(!value||typeof value!=='object'||!('graph' in value))throw new Error('Invalid project scene');
    const spec=value as DiagramSpec & {heading?:string};
    const heading=spec.heading ? context.model?.subjects.find(node=>node.id===spec.heading)?.label : undefined;
    if(spec.heading&&!heading)throw new Error('Undeclared scene heading');
    return {heading,figure:composeDiagram(context,spec)};
  });
  const title=(value:string,kind:string)=>`<svg data-vector-annotation class="vector-${kind}" width="100%" height="${kind==='title'?42:kind==='note'?24:28}"><text x="0" y="${kind==='title'?31:kind==='note'?17:20}">${text(value)}</text></svg>`;
  return {markup:`<article data-question="${text(context.view.question.ref)}" data-region="${context.view.purpose}"><header>${title(context.view.title,'title')}${title(context.view.question.text,'question')}${title(context.copy('description'),'note')}</header>${panels.map(panel=>`<section>${panel.heading?title(panel.heading,'panel'):''}${panel.figure.markup}</section>`).join('')}${title(context.copy('status'),'note')}</article>`,css:panels.map(panel=>panel.figure.css).join('\n')+`[data-figure]{padding:26px;background:var(--background)}article>header{margin-bottom:18px}.vector-title text{font-size:26px;font-weight:750;fill:var(--ink)}.vector-question text{font-size:17px;fill:var(--accent)}.vector-panel text{font-size:16px;font-weight:600;fill:var(--muted)}article>section{padding:12px 0;margin:10px 0}.vector-note text{fill:var(--muted);font-size:13px}header p,footer{font-size:13px;color:var(--muted);line-height:1.6}footer{padding-top:8px}`};
};
