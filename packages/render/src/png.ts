// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import sharp, {type PngOptions} from 'sharp';
import * as v from 'valibot';
import packageInfo from '../../../package.json' with {type:'json'};
type LosslessPNG = Pick<PngOptions,'compressionLevel'|'adaptiveFiltering'>;
/** Quantization is explicit; defaults preserve decoded pixels. Native sharp owns encoding. */
export type PNGCompression = LosslessPNG & ({readonly palette?:false}|({readonly palette:true}&Pick<PngOptions,'quality'|'colours'|'dither'|'effort'>));
const Options=v.strictObject({compressionLevel:v.optional(v.pipe(v.number(),v.integer(),v.minValue(0),v.maxValue(9))),adaptiveFiltering:v.optional(v.boolean()),palette:v.optional(v.boolean()),quality:v.optional(v.number()),colours:v.optional(v.number()),dither:v.optional(v.number()),effort:v.optional(v.number())});
export interface PNGCompressionReceipt {
 readonly encoder:string;readonly options:PNGCompression|false;
 readonly inputBytes:number;readonly outputBytes:number;readonly selected:'original'|'compressed';
}
/** CPU-only encoding effect; no file IO, global sharp settings or format substitution. */
export async function compressPNG(input:Uint8Array,options:PNGCompression|false={}):Promise<{bytes:Uint8Array;receipt:PNGCompressionReceipt}>{
 const parsed=options===false?false:v.parse(Options,options);
 if(parsed!==false&&!parsed.palette&&[parsed.quality,parsed.colours,parsed.dither,parsed.effort].some(value=>value!==undefined))throw new Error('Palette controls require palette: true');
 const settings:PNGCompression|false=parsed===false?false:{compressionLevel:9,adaptiveFiltering:true,...parsed} as PNGCompression;
 const encoder=sharp(input);
 if((await encoder.metadata()).format!=='png')throw new Error('Expected PNG input');
 const candidate=settings===false?input:await encoder.png(settings).toBuffer();
 const smaller=candidate.byteLength<input.byteLength,bytes=smaller?candidate:input;
 return{bytes,receipt:{encoder:settings===false?'browser':'sharp@'+packageInfo.dependencies.sharp,options:settings,inputBytes:input.byteLength,outputBytes:bytes.byteLength,selected:smaller?'compressed':'original'}};
}
