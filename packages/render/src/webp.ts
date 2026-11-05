// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import sharp,{type WebpOptions} from 'sharp';
import * as v from 'valibot';
import packageInfo from '../../../package.json' with {type:'json'};
/** Native encoder parameters. Lossy output must be explicitly declared. */
export type WebPCompression = Pick<WebpOptions,'effort'> & (
 {readonly lossless?:true}|({readonly lossless:false}&Pick<WebpOptions,'quality'|'alphaQuality'|'smartSubsample'>));
const Options=v.strictObject({lossless:v.optional(v.boolean()),effort:v.optional(v.number()),quality:v.optional(v.number()),alphaQuality:v.optional(v.number()),smartSubsample:v.optional(v.boolean())});
export interface WebPCompressionReceipt {
 readonly encoder:string;readonly options:WebPCompression;readonly inputBytes:number;readonly outputBytes:number;
}
export async function encodeWebP(input:Uint8Array,options:WebPCompression={}):Promise<{bytes:Uint8Array;receipt:WebPCompressionReceipt}>{
 const parsed=v.parse(Options,options);
 if(parsed.lossless!==false&&[parsed.quality,parsed.alphaQuality,parsed.smartSubsample].some(value=>value!==undefined))throw new Error('Lossy controls require lossless: false');
 const settings:WebPCompression={lossless:true,effort:4,...parsed} as WebPCompression;
 const bytes=await sharp(input).webp(settings).toBuffer();
 return{bytes,receipt:{encoder:'sharp@'+packageInfo.dependencies.sharp,options:settings,inputBytes:input.byteLength,outputBytes:bytes.byteLength}};
}
