// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

export {selectTaste,type TasteSelection,type TasteSelectionContext,type TasteProposal,type EvidenceProjection,EvidenceProjectionSchema} from './taste-selection';
export {questionFocus,evidenceFocus,dependencyLayout,questionScope,visualHierarchy} from './taste-policies';
export {DesignSchema,defineDesign,type Design} from './design';
export {composeTaste,reviewTaste,minimumTextSize,focalBudget,type Taste,type TasteRule,type TasteNote,type TasteContext,type TasteReport,type RenderObservation,type MeasuredBox} from './taste';
export {composeHeading,type HeadingSpec} from './heading';
export {composeModelView,graphFromModel,modelDiagram} from './model-view';
import {isDeepStrictEqual} from 'node:util';
import {fork} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import type {CompileOptions} from '@terrastruct/d2';
import {relativeSource} from './source/catalog';
import {readD2Figure,type FigureResources} from './d2-figure';
import type {FigureInput,FigureModel} from './figure';
export {composeFigure,selectFigureVariant} from './figure';
export type {FigureInput,FigureModel,FigureQuestion,FigureContext,FigureComposer,ComposedFigure,ModelSource} from './figure';
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
  const child=fork(fileURLToPath(new URL('./compiler-process.ts',import.meta.url)),[],{execPath:process.execPath,stdio:['ignore','inherit','inherit','ipc']});
  return await new Promise<CompiledModel>((resolve,reject)=>{
    let response:import('./worker').ModelResponse|undefined;
    child.once('error',reject);
    child.on('message',(value:import('./worker').ModelResponse)=>{if(response){response={error:'Duplicate compiler result'};}else response=value;});
    child.once('exit',(code,signal)=>{
      if(code!==0||signal)return reject(new Error('Compiler process exit: '+code+'/'+signal));
      if(!response)return reject(new Error('Compiler process exited without result'));
      if('error' in response)return reject(new Error(response.error));
      resolve(response.capture);
    });
    child.send({fs:{...sources},inputPath,options} satisfies import('./worker').ModelRequest,error=>{if(error)reject(error);});
  });
}
export async function compileFigureSource(sources:Readonly<Record<string,string>>,inputPath:string,resources:FigureResources={},options:CompileOptions={}):Promise<FigureInput> {
  const captured={...sources};
  const capture=await compileModel(captured,inputPath,options);
  const input=readD2Figure(capture,captured,resources);
  if(!input.modelSource)return input;
  const selected=resources.sysmlViews && Object.hasOwn(resources.sysmlViews,input.modelSource.view) ? structuredClone(resources.sysmlViews[input.modelSource.view]) : undefined;
  if(!selected || selected.requestedView!==input.modelSource.view || selected.modelHash!==input.modelSource.modelHash)
    throw new Error('OpenSysML model/view binding mismatch');
  const source=input.references[input.modelSource.ref];
  if(!Object.hasOwn(input.references,input.modelSource.ref) || !source || !Object.hasOwn(input.sources,source)) throw new Error('Uncaptured OpenSysML source reference');
  const saved:unknown=JSON.parse(input.sources[source]!);
  if(!isDeepStrictEqual(saved,selected)) throw new Error('OpenSysML source bytes do not bind the selected capture');
  const {projectOpenSysMLView}=await import('./opensysml');
  const projection=projectOpenSysMLView(selected,{selection:input.view,layout:'reflow',portProjection:input.modelSource.portProjection,labels:input.modelSource.labels});
  return {...input,model:projection.model,modelTrace:projection.trace};
}
