import { randomUUID } from 'node:crypto';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

export const CASE_IDS=Object.freeze([
  's06-unregistered','s07-compound','s08-unknown-route','s08-all-notes',
  's08-write-notice','s08-own-note','s09-burst-read',
]);

const changed=(base,overrides)=>({...base,requestId:randomUUID(),...overrides});
const burst=()=>Array.from({length:121},(_,index)=>({
  at:new Date(Date.UTC(2026,9,1)+index*2000).toISOString(),
  method:'GET',identity:{sub:'learner_fixture'},deviceId:'aaaaaaaaaaaaaaaa',
  decision:'allow',signals:{network:'unusual'},
}));

export async function runRuleCheck(caseId){
  if(typeof caseId!=='string'||!CASE_IDS.includes(caseId))return null;
  const {normal,suspicious}=fixtureRequests();
  if(caseId==='s09-burst-read'){
    const result=detect(burst());
    return {ready:result.action==='propose_revocation'&&result.reasonCode==='burst_read',
      action:result.action,reasonCode:result.reasonCode??null};
  }
  const cases={
    's06-unregistered':[changed(normal,{deviceRegistered:false}),'deny'],
    's07-compound':[suspicious,'step_up'],
    's08-unknown-route':[changed(normal,{path:'/api/unknown',route:'GET /api/unknown'}),'deny'],
    's08-all-notes':[changed(normal,{path:'/api/notes',route:'GET /api/notes'}),'deny'],
    's08-write-notice':[changed(normal,{service:'notices',method:'PUT',path:'/api/notices/demo',route:'PUT /api/notices/:id'}),'deny'],
    's08-own-note':[changed(normal,{path:'/api/notes/demo',route:'GET /api/notes/:id'}),'allow'],
  };
  const [request,expected]=cases[caseId];
  const result=await decide(request);
  return {ready:result.decision===expected,decision:result.decision,reasonCode:result.reasonCode};
}
