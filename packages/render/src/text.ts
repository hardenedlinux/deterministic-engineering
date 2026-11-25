// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

/** Lossless scalar wrapping. Breaks are presentation; captured text is unchanged. */
export function wrapDiagramText(value:string,columns?:number):readonly string[] {
 if(columns!==undefined&&(!Number.isInteger(columns)||columns<8||columns>120))throw new Error('Invalid declared text columns');
 return value.split('\n').flatMap(line=>{
  if(columns===undefined)return [line];
  const scalars=Array.from(line),lines:string[]=[];
  while(scalars.length>columns){
   let cut=columns;
   for(let i=columns;i>Math.floor(columns/2);i--)if(/\s/u.test(scalars[i-1]!)){cut=i;break;}
   lines.push(scalars.splice(0,cut).join(''));
  }
  lines.push(scalars.join(''));return lines;
 });
}
