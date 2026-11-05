// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect} from 'bun:test';
import sharp from 'sharp';
import {compressPNG} from '../src/export';
const raw=async(input:Uint8Array)=>sharp(input).ensureAlpha().raw().toBuffer({resolveWithObject:true});
test('lossless compression preserves RGBA pixels, dimensions and transparency',async()=>{
 const pixels=Buffer.alloc(512*256*4);
 for(let i=0;i<pixels.length;i+=4){pixels[i]=i%251;pixels[i+1]=72;pixels[i+2]=190;pixels[i+3]=(i/4)%256;}
 const source=await sharp(pixels,{raw:{width:512,height:256,channels:4}}).png({compressionLevel:0}).toBuffer();
 const result=await compressPNG(source),before=await raw(source),after=await raw(result.bytes);
 expect(after.data).toEqual(before.data);expect(after.info).toEqual(before.info);
 expect(result.bytes.byteLength).toBeLessThan(source.byteLength);
 expect(result.receipt).toMatchObject({inputBytes:source.byteLength,outputBytes:result.bytes.byteLength,selected:'compressed',options:{compressionLevel:9,adaptiveFiltering:true}});
});
test('original wins when encoding grows; explicit bypass returns exact browser bytes',async()=>{
 const source=await sharp({create:{width:1,height:1,channels:4,background:'#ffffff00'}}).png({compressionLevel:9}).toBuffer();
 const result=await compressPNG(source,{compressionLevel:0});
 expect(result.bytes).toEqual(source);expect(result.receipt.selected).toBe('original');
 const bypass=await compressPNG(source,false);expect(bypass.bytes).toBe(source);expect(bypass.receipt.encoder).toBe('browser');
});
test('invalid controls, implicit quantization and corrupted PNG fail without fallback',async()=>{
 const source=await sharp({create:{width:4,height:4,channels:3,background:'white'}}).png().toBuffer();
 for(const options of [{compressionLevel:-1},{compressionLevel:10},{compressionLevel:1.5},{adaptiveFiltering:'yes'},{palette:'yes'},{quality:95}]){
  // Untyped downstream callers must not enable lossy quantization through this API.
  await expect(compressPNG(source,options as never)).rejects.toThrow();
 }
 await expect(compressPNG(new Uint8Array([1,2,3]))).rejects.toThrow();
 const jpeg=await sharp(source).flatten().jpeg().toBuffer();
 await expect(compressPNG(jpeg)).rejects.toThrow('Expected PNG input');
 await expect(compressPNG(jpeg,false)).rejects.toThrow('Expected PNG input');
});

test('declared high-quality palette compression preserves canvas and alpha channel',async()=>{
 const source=await sharp({create:{width:512,height:256,channels:4,background:'#24608c80'}}).png({compressionLevel:0}).toBuffer();
 const result=await compressPNG(source,{palette:true,quality:95,effort:7});
 expect(result.bytes.byteLength).toBeLessThan(source.byteLength);
 expect(result.receipt.options).toMatchObject({palette:true,quality:95,effort:7});
 const image=await sharp(result.bytes).metadata();expect(image.width).toBe(512);expect(image.height).toBe(256);expect(image.hasAlpha).toBe(true);
});
