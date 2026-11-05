// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect} from 'bun:test';
import sharp from 'sharp';
import {encodeWebP} from '../src/export';
test('lossless WebP preserves real decoded colour, dimensions and partial alpha',async()=>{
 const input=await sharp({create:{width:320,height:160,channels:4,background:'#24608c80'}}).png().toBuffer();
 const encoded=await encodeWebP(input),decoded=await sharp(encoded.bytes).ensureAlpha().raw().toBuffer({resolveWithObject:true});
 const original=await sharp(input).ensureAlpha().raw().toBuffer({resolveWithObject:true});
 expect(decoded).toEqual(original);expect(encoded.receipt.options).toEqual({lossless:true,effort:4});
 expect((await sharp(encoded.bytes).metadata()).format).toBe('webp');
});
test('lossy WebP is explicit and native invalid settings/input refuse',async()=>{
 const input=await sharp({create:{width:320,height:160,channels:4,background:'white'}}).png().toBuffer();
 const encoded=await encodeWebP(input,{lossless:false,quality:95,smartSubsample:true});
 expect(encoded.receipt.options).toMatchObject({lossless:false,quality:95});
 for(const options of [{quality:95},{lossless:true,smartSubsample:true},{lossless:false,quality:101},{effort:99},{unknown:true}])await expect(encodeWebP(input,options as never)).rejects.toThrow();
 await expect(encodeWebP(new Uint8Array([1,2]))).rejects.toThrow();
});
