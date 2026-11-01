// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import {renderedViewFromJson} from '@openmbee/opensysml';
import type {OpenSysMLCapture} from '../../src/opensysml';
import type {ModelSource} from '../../src/figure';
export const selection={source:'view.d2',title:'SDK model projection',purpose:'architecture' as const,kind:'system',question:{ref:'q',text:'Which model owns these connections?'},basis:{captureRef:'design-candidate',modelRefs:['model-hash'],obligationRefs:[],evidenceRefs:[]}};
export function captureFixture(ports=false):OpenSysMLCapture {
 return {modelHash:'model-hash',requestedView:'Demo::Context',rendering:renderedViewFromJson({view:'Demo::Context',kind:'interconnection',stated:'candidate',nodes:[
  {id:'root',name:'Demo::System',kind:'part',origin:{file:'model.sysml',startLine:2}},
  {id:'n1',name:'Worker',kind:'part',parent:'root',ports:ports?[{id:'p1',name:'out',direction:'out'}]:[]},
  {id:'n2',name:'Worker',kind:'part',parent:'root',ports:ports?[{id:'p2',name:'in',direction:'in'}]:[]},
 ],edges:[{from:'n1',to:'n2',fromPort:ports?'p1':'',toPort:ports?'p2':'',kind:'connection',label:'dispatch'}]})};
}
export function declarationFixture(capture=captureFixture(),overrides:Partial<ModelSource>={}) {
 const modelSource={ref:'sdk',view:capture.requestedView,modelHash:capture.modelHash,...overrides};
 const data={title:selection.title,purpose:selection.purpose,kind:selection.kind,language:'en',width:1000,primary:'q',questions:[{ref:'q',text:selection.question.text,focusRefs:['sdk']}],references:{sdk:'models/view.json'},copy:{},basis:selection.basis,modelSource};
 const source=`vars: {d2-config: {data: {figure: |json\n${JSON.stringify(data)}\n|\n}}}\ncandidate: Source declaration only`;
 return {sources:{'view.d2':source,'models/view.json':JSON.stringify(capture)},resources:{sysmlViews:{[capture.requestedView]:capture}}};
}
