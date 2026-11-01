// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

import {readFile, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {chromium} from 'playwright';
import {attributionComment} from '@deterministic-engineering/render/export';
import {resources} from './library-case/resources';
import {compileFigureSource} from '@deterministic-engineering/render';
const root = fileURLToPath(new URL('../../../', import.meta.url));
const directory = path.join(root, '.cache/render/library-case');
const files = ['docs/90-99-views/90-architecture-views/90.132-library-profile-scenario-architecture.d2', 'docs/90-99-views/90-architecture-views/90.133-capture-preparation-workflow.d2'];
const sources = Object.fromEntries(await Promise.all(files.map(async file => [file, await readFile(path.join(root, file), 'utf8')])));
const declarations = await Promise.all(files.map(file => compileFigureSource(sources, file, resources)));
const esc = (s: string) => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const hash = (data: Uint8Array|string) => createHash('sha256').update(data).digest('hex');
const browser = await chromium.launch();
try {
  for (const declaration of declarations) {
    const purpose = declaration.view.purpose;
    const previews = await Promise.all((declaration.variants ?? []).map(async variant => {
      const name = `${purpose}-${variant.name}`, png = await readFile(path.join(directory, `${name}-detail.png`));
      const receipt: {regionSHA256: Record<string, string>; sources: Record<string, string>} = JSON.parse(await readFile(path.join(directory, `${name}.json`), 'utf8'));
      if (receipt.regionSHA256[purpose] !== hash(png)) throw new Error('Comparison region differs from rendering receipt');
      for (const [source, fingerprint] of Object.entries(receipt.sources)) if (hash(await readFile(path.join(root, source))) !== fingerprint) throw new Error(`Stale comparison source: ${source}`);
      return `<section><h2>${esc(variant.name)}</h2><img src="data:image/png;base64,${png.toString('base64')}" alt="${esc(name)}"></section>`;
    }));
    const html = `<!doctype html>\n<!--\n${attributionComment({copyright:['2026 tao3k team and Contributors'],license:'LGPL-2.1-only'})}\n-->\n<html lang="${esc(declaration.language)}"><head><meta charset="utf-8"><style>*{box-sizing:border-box}body{margin:0;background:#edf2f4;color:#193348;font-family:Arial,sans-serif}main{width:1600px;padding:28px}h1{font-size:28px;margin:0 0 20px}section{background:white;border:1px solid #d5e1e7;border-radius:8px;margin:0 0 16px;padding:16px}h2{font-size:15px;margin:0 0 12px;color:#246e86}img{display:block;width:100%;height:auto}</style></head><body><main><h1>${esc(declaration.view.title)}</h1>${previews.join('')}</main></body></html>`;
    const page = await browser.newPage({viewport:{width:1600,height:1000},deviceScaleFactor:1});
    try {
      await page.setContent(html); await page.evaluate(async () => { await document.fonts.ready; await Promise.all(Array.from(document.images, image => image.decode())); });
      const png = await page.locator('main').screenshot({type:'png'});
      await writeFile(path.join(directory, `${purpose}-comparison.html`), html);
      await writeFile(path.join(directory, `${purpose}-comparison.png`), png);
      console.log(`${purpose}-comparison: ${png.readUInt32BE(16)}x${png.readUInt32BE(20)}`);
    } finally {await page.close();}
  }
} finally {await browser.close();}
