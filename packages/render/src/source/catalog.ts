import {createHash} from 'node:crypto';
import path from 'node:path';
export type {ViewSelection} from './types';
export const digest=(bytes:string|Uint8Array):string=>createHash('sha256').update(bytes).digest('hex');
export function relativeSource(source:string):void {
  if(!source||source.split('/').some(part=>!part||part==='.'||part==='..')||source.includes('\\')||path.posix.isAbsolute(source)||path.posix.normalize(source)!==source)throw new Error(`Expected a normalized repository-relative source: ${source}`);
}
