// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {parentPort,workerData} from 'node:worker_threads';
import {D2,type CompileOptions} from '@terrastruct/d2';
import {modelFromDiagram} from './d2-figure';
import type {CompiledModel} from './index';
export interface ModelRequest {readonly fs:Readonly<Record<string,string>>;readonly inputPaths:readonly string[];readonly options:CompileOptions;}
export type ModelResponse={readonly captures:readonly Omit<CompiledModel,'fs'>[]}|{readonly error:string};
const input=workerData as ModelRequest;
try {
  const engine=new D2(),captures:Omit<CompiledModel,'fs'>[]=[];
  for(const inputPath of input.inputPaths){
    const compiled=await engine.compile({fs:{...input.fs},inputPath,options:input.options});
    captures.push({data:compiled.graph.data as unknown,inputPath:compiled.inputPath,model:modelFromDiagram(compiled.diagram),options:input.options});
  }
  parentPort!.postMessage({captures} satisfies ModelResponse);
}catch(error:unknown){parentPort!.postMessage({error:error instanceof Error?error.message:String(error)}satisfies ModelResponse);}
