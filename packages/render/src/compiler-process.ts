// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {Worker} from 'node:worker_threads';
import type {ModelRequest,ModelResponse} from './worker';
/** The process owns the compiler worker's native allocation domain. Bun may
 * retain terminated worker heaps until process exit; wait for natural exit. */
process.on('message',async(request:ModelRequest)=>{
 let worker:Worker|undefined;
 let response:ModelResponse;
 try{
  worker=new Worker(new URL('./worker.ts',import.meta.url),{workerData:request});
  response=await new Promise<ModelResponse>((resolve,reject)=>{
   worker!.once('message',resolve);worker!.once('error',reject);
   worker!.once('exit',code=>reject(new Error('Compiler worker exited before result: '+code)));
  });
 }catch(error:unknown){response={error:error instanceof Error?error.message:String(error)};}
 finally{if(worker)await worker.terminate();}
 process.send!(response,error=>{if(error)process.exitCode=1;process.disconnect?.();});
});
