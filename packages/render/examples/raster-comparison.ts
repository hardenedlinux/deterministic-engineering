// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {readFile,readdir,mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import sharp from 'sharp';
import {compressPNG,encodeWebP} from '@deterministic-engineering/render/export';
const root=fileURLToPath(new URL('../../../',import.meta.url));
const directory='docs/90-99-views/90-architecture-views',output=join(root,'.cache/render/raster-comparison');
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
await mkdir(output,{recursive:true});
const rows=[];
for(const file of (await readdir(join(root,directory))).filter(file=>file.endsWith('.png')).sort()){
 const input=await readFile(join(root,directory,file));
 const pngStart=performance.now(),png=await compressPNG(input),pngMS=performance.now()-pngStart;
 const webpStart=performance.now(),webp=await encodeWebP(input),webpMS=performance.now()-webpStart;
 // Verify the actual decoded corpus rather than infer fidelity from size.
 const raw=async(bytes:Uint8Array)=>sharp(bytes).ensureAlpha().raw().toBuffer();
 const original=await raw(input);
 if(!original.equals(await raw(png.bytes))||!original.equals(await raw(webp.bytes)))throw new Error('Decoded corpus pixels differ: '+file);
 await writeFile(join(output,file),png.bytes);await writeFile(join(output,file.replace(/\.png$/,'.webp')),webp.bytes);
 const svgPath=join(root,directory,file.replace(/\.png$/,'.svg'));
 const svg=await Bun.file(svgPath).exists()?await readFile(svgPath):undefined;
 rows.push({source:directory+'/'+file,sourceSHA256:hash(input),originalBytes:input.length,png:{...png.receipt,sha256:hash(png.bytes),milliseconds:pngMS},webp:{...webp.receipt,sha256:hash(webp.bytes),milliseconds:webpMS},svg:svg?{bytes:svg.length,sha256:hash(svg)}:undefined,preferredRaster:webp.bytes.length<png.bytes.length?'webp':'png'});
}
await writeFile(join(output,'comparison.json'),JSON.stringify(rows,null,2)+'\n');
console.log(JSON.stringify({images:rows.length,originalBytes:rows.reduce((n,r)=>n+r.originalBytes,0),pngBytes:rows.reduce((n,r)=>n+r.png.outputBytes,0),webpBytes:rows.reduce((n,r)=>n+r.webp.outputBytes,0),output}));
