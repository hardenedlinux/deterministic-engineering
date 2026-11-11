// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {createHash} from 'node:crypto';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright';
import sharp from 'sharp';
import {compileFigureSource, composeFigure, composeModelView} from '@deterministic-engineering/render';
import {exportFigure} from '@deterministic-engineering/render/export';
import {attributionFor} from './attribution';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const directory = 'docs/90-99-views/90-architecture-views/';
const names = [
  '90.139-source-bound-c-and-cpp-contract-verification',
  '90.140-flat-declarative-library-boundary',
];
const output = path.join(root, '.cache/render/library-boundary');
const compositionSources = [
  'packages/render/examples/library-boundary.ts',
  'packages/render/examples/attribution.ts',
  'packages/render/src/model-view.ts',
  'packages/render/src/figure.ts',
  'packages/render/src/diagram.ts',
  'packages/render/src/scene-export.ts',
  'packages/render/src/export.ts',
  'packages/render/src/png.ts',
  'packages/render/src/webp.ts',
  'package.json',
  'bun.lock',
];
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
await mkdir(output, {recursive: true});
const browser = await chromium.launch();
try {
  for (const name of names) {
    const file = directory + name + '.d2';
    const input = await compileFigureSource({[file]: await readFile(path.join(root, file), 'utf8')}, file);
    const sources = Object.fromEntries(await Promise.all(
      [...new Set([...compositionSources, ...Object.values(input.references)])]
        .map(async source => [source, await readFile(path.join(root, source), 'utf8')]),
    ));
    const figure = composeFigure({...input, sources: {...input.sources, ...sources}}, composeModelView);
    const result = await exportFigure(figure, browser, {
      scale: 1.5,
      minimumTextSize: 12,
      attribution: attributionFor(figure),
    });
    if (result.svg.length === 0 || !result.webp) throw new Error('Expected vector scene and lossless WebP');
    const png = await sharp(result.png).ensureAlpha().raw().toBuffer({resolveWithObject: true});
    const webp = await sharp(result.webp).ensureAlpha().raw().toBuffer({resolveWithObject: true});
    if (JSON.stringify(png.info) !== JSON.stringify(webp.info) || !png.data.equals(webp.data)) {
      throw new Error('Lossless raster pixels changed');
    }
    for (const [source, hash] of Object.entries(figure.sourceSHA256)) {
      if (digest(await readFile(path.join(root, source))) !== hash) throw new Error('Stale source: ' + source);
    }
    const receipt = {
      status: 'Design projection only; no Scheme or verifier acceptance',
      sources: figure.sourceSHA256,
      receipt: result.receipt,
      rasterComparison: {
        pngBytes: result.png.byteLength,
        webpBytes: result.webp.byteLength,
        decodedPixelsEqual: true,
        decodedPixelSHA256: digest(png.data),
        preferredRaster: result.preferredRaster.format,
      },
    };
    for (const [extension, bytes] of [
      ['svg', result.svg[0]!], ['png', result.png], ['webp', result.webp],
      ['html', result.html], ['json', JSON.stringify(receipt, null, 2) + '\n'],
    ] as const) {
      await writeFile(path.join(output, `${name}.${extension}`), bytes);
    }
    console.log(name, result.receipt.width, result.receipt.height, receipt.rasterComparison);
  }
} finally {
  await browser.close();
}
