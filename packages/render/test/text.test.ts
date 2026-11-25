// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {test,expect} from 'bun:test';
import fc from 'fast-check';
import {wrapDiagramText} from '../src/text';

test('property: declared wrapping preserves every Unicode scalar and whitespace',()=>{
 fc.assert(fc.property(fc.array(fc.constantFrom('a',' ','→','𝛼','😀','界','\n','\t'),{maxLength:400}),fc.integer({min:8,max:120}),(scalars,columns)=>{
  const source=scalars.join(''),lines=wrapDiagramText(source,columns);
  expect(lines.join('')).toBe(source.replaceAll('\n',''));
  expect(lines.every(line=>Array.from(line).length<=columns)).toBe(true);
 }),{numRuns:300,seed:293});
});

test('wrapping is explicit and rejects malformed constraints',()=>{
 expect(wrapDiagramText('keep original\nlines')).toEqual(['keep original','lines']);
 for(const columns of [0,7,121,NaN,8.5])expect(()=>wrapDiagramText('text',columns)).toThrow('text columns');
});
