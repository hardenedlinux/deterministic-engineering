// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect,spyOn} from 'bun:test';
import * as processes from 'node:child_process';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {compileModel} from '../src';
const fork=processes.fork;
const compile=()=>compileModel({'case.d2':'a -> b'},'case.d2');

// Observe the existing native boundary, without a production factory or test hook.
function observe(create:(...args:Parameters<typeof fork>)=>processes.ChildProcess=(...args)=>fork(...args)){
 const children:processes.ChildProcess[]=[],closed=new Set<processes.ChildProcess>();
 const spy=spyOn(processes,'fork').mockImplementation((path:string|URL,args?:readonly string[]|processes.ForkOptions,options?:processes.ForkOptions)=>{
  const child=Array.isArray(args)||args===undefined?create(path,args,options):create(path,undefined,args as processes.ForkOptions);children.push(child);child.once('close',()=>closed.add(child));return child;
 });
 return{children,closed,restore:()=>spy.mockRestore()};
}
function reclaimed(observed:ReturnType<typeof observe>){
 expect(observed.children.length).toBe(1);expect(observed.closed.size).toBe(1);
 expect(observed.children[0]!.connected).toBe(false);
}

test('successful native D2 capture is returned only after its process closes',async()=>{
 const observed=observe();
 try{expect((await compile()).model.relations.length).toBe(1);reclaimed(observed);expect(observed.children[0]!.exitCode).toBe(0);}
 finally{observed.restore();}
},30000);

test('synchronous IPC failure disconnects and awaits the actual child before rejection',async()=>{
 const observed=observe((...args)=>{const child=fork(...args);spyOn(child,'send').mockImplementation(()=>{throw new Error('Synthetic IPC serialization failure');});return child;});
 try{await expect(compile()).rejects.toThrow('Synthetic IPC serialization failure');reclaimed(observed);}
 finally{observed.restore();}
},30000);

test('native disconnected IPC rejects only after the child closes',async()=>{
 const observed=observe((...args)=>{const child=fork(...args);child.disconnect();return child;});
 try{await expect(compile()).rejects.toThrow();reclaimed(observed);}
 finally{observed.restore();}
},30000);

test('native spawn failure is rejected without claiming compiler output',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'render-no-executable-'));
 const observed=observe((path,args,options)=>fork(path,args,{...options,execPath:join(directory,'missing-bun')}));
 try{await expect(compile()).rejects.toThrow();reclaimed(observed);}
 finally{observed.restore();await rm(directory,{recursive:true,force:true});}
},30000);

// These are IPC/exit fault fixtures, not alternate compilers or test runners.
for(const fault of [
 {name:'missing result',body:'process.disconnect();',message:'without result'},
 {name:'nonzero exit',body:'process.exitCode=7;process.disconnect();',message:'Compiler process exit: 7'},
 {name:'duplicate result',body:'process.send({error:"first"},()=>process.send({error:"second"},()=>process.disconnect()));',message:'Duplicate compiler result'},
])test('native '+fault.name+' cannot be accepted as a compiler capture',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'render-ipc-fault-')),file=join(directory,'fixture.ts');
 await writeFile(file,'process.once("message",()=>{'+fault.body+'});');
 const observed=observe((_,args,options)=>fork(file,args,options));
 try{await expect(compile()).rejects.toThrow(fault.message);reclaimed(observed);}
 finally{observed.restore();await rm(directory,{recursive:true,force:true});}
},30000);
