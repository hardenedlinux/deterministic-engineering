import {Worker} from 'node:worker_threads';
import type {CompileOptions} from '@terrastruct/d2';
import {relativeSource} from './source/catalog';
import {readD2Figure,type FigureResources} from './d2-figure';
import type {FigureInput,FigureModel} from './figure';
export {composeFigure,selectFigureVariant} from './figure';
export type {FigureInput,FigureModel,FigureQuestion,FigureContext,FigureComposer,ComposedFigure} from './figure';
export {composeDiagram} from './diagram';
export type {DiagramSpec,DiagramNodeComposer} from './diagram';
export {readD2Figure} from './d2-figure';
export type {FigureResources} from './d2-figure';
export type {ViewSelection,ViewKind,QuestionRef,ViewBasis} from './source/types';
export interface CompiledModel {
  readonly data:unknown;readonly inputPath:string;readonly fs:Readonly<Record<string,string>>;
  readonly model:FigureModel;readonly options:CompileOptions;
}
/** D2 supplies language/model observations only. Its old geometry/SVG is not a renderer path. */
export async function compileModel(sources:Readonly<Record<string,string>>,inputPath:string,options:CompileOptions={}):Promise<CompiledModel> {
  relativeSource(inputPath);
  if(!Object.hasOwn(sources,inputPath))throw new Error('Missing model source');
  for(const[file,text]of Object.entries(sources)){relativeSource(file);if(typeof text!=='string')throw new Error('Invalid model source');}
  const worker=new Worker(new URL('./worker.ts',import.meta.url),{workerData:{fs:{...sources},inputPath,options} satisfies import('./worker').ModelRequest});
  try{return await new Promise((resolve,reject)=>{
    worker.once('error',reject);worker.once('exit',code=>reject(new Error(`Model worker exited before result: ${code}`)));
    worker.once('message',(message:import('./worker').ModelResponse)=>'error'in message?reject(new Error(message.error)):resolve(message.capture));
  });}finally{await worker.terminate();}
}
export async function compileFigureSource(sources:Readonly<Record<string,string>>,inputPath:string,resources:FigureResources={},options:CompileOptions={}):Promise<FigureInput> {
  const capture=await compileModel(sources,inputPath,options);
  return readD2Figure(capture,sources,resources);
}
