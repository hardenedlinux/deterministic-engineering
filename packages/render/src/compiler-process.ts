// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {Worker} from 'node:worker_threads';
import type {ModelRequest,ModelResponse} from './worker';
/** The process owns the compiler worker's native allocation domain. Bun may
 * retain terminated worker heaps until process exit; wait for natural exit. */
// Keep IPC referenced until the worker is joined and the send callback completes.
process.on('message',async(request:ModelRequest)=>{
 let response:ModelResponse;
 try{
  const worker=new Worker(new URL('./worker.ts',import.meta.url),{workerData:request});
  try{response=await new Promise<ModelResponse>((resolve,reject)=>{
   worker.once('message',resolve);worker.once('error',reject);
   worker.once('exit',code=>reject(new Error('Compiler worker exited before result: '+code)));
  });}finally{await worker.terminate();}
 }catch(error:unknown){response={error:error instanceof Error?error.message:String(error)};}
 if(!process.connected){process.exitCode=1;return;}
 process.send!(response,error=>{if(error)process.exitCode=1;if(process.connected)process.disconnect?.();});
});
