// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {parentPort,workerData} from 'node:worker_threads';
import {D2,type CompileOptions} from '@terrastruct/d2';
import {modelFromDiagram} from './d2-figure';
import type {CompiledModel} from './index';
export interface ModelRequest {readonly fs:Readonly<Record<string,string>>;readonly inputPath:string;readonly options:CompileOptions;}
export type ModelResponse={readonly capture:CompiledModel}|{readonly error:string};
const input=workerData as ModelRequest;
try {
  const engine=new D2(),compiled=await engine.compile({fs:{...input.fs},inputPath:input.inputPath,options:input.options});
  parentPort!.postMessage({capture:{data:compiled.graph.data as unknown,inputPath:compiled.inputPath,fs:input.fs,model:modelFromDiagram(compiled.diagram),options:input.options}}satisfies ModelResponse);
}catch(error:unknown){parentPort!.postMessage({error:error instanceof Error?error.message:String(error)}satisfies ModelResponse);}
