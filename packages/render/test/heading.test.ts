import {test,expect} from 'bun:test';
import fc from 'fast-check';
import {composeFigure,type FigureInput} from '../src/figure';
import {composeHeading} from '../src/heading';
import {composePresentationTheme} from '../src/presentation-theme';
const input:FigureInput={view:{source:'case.d2',title:'Ownership',purpose:'architecture',kind:'dependency-map',question:{ref:'q',text:'Who publishes?'},basis:{captureRef:'candidate',modelRefs:[],obligationRefs:[],evidenceRefs:[]}},width:900,language:'en',sources:{'case.d2':'source'},references:{source:'case.d2'},questions:[{ref:'q',text:'Who publishes?',focusRefs:['source']}]};
test('heading ordinal data escapes independently of Question wording and domain glyphs',()=>{
 fc.assert(fc.property(fc.oneof(fc.integer(),fc.string({minLength:1,maxLength:24}).filter(value=>!!value.trim())),ordinal=>{
  const before=JSON.stringify(input);
  const figure=composeFigure(input,context=>composeHeading(context,{role:'question',questionRef:'q',text:context.question('q').text,ordinal}));
  expect(figure.html).toContain('Who publishes?');expect(figure.html).toContain('data-annotation-part="ordinal"');
  expect(figure.html).not.toContain('<g data-annotation-part="glyph"');expect(JSON.stringify(input)).toBe(before);
 }),{numRuns:40,seed:149});
});
test('role markers can be declared once and composed without replacing domain assets',()=>{
 const theme=composePresentationTheme(['project'],{project:{headingMarkers:{question:'Q',answer:'A',custom:'§'}}});
 const figure=composeFigure({...input,theme},context=>{
  const parts=[composeHeading(context,{role:'question',questionRef:'q',text:context.question('q').text}),composeHeading(context,{role:'answer',text:'Library',glyph:'library'})];
  return{markup:parts.map(part=>part.markup).join(''),css:parts.map(part=>part.css).join('')};
 });
 expect(figure.html).toContain('>Q</text>');expect(figure.html).toContain('>A</text>');
 expect(figure.html).toContain('data-annotation-part="glyph"');
 expect(()=>composeFigure(input,context=>composeHeading(context,{role:'question',questionRef:'q',text:'Who publishes?',ordinal:NaN}))).toThrow('Invalid heading ordinal');
});
