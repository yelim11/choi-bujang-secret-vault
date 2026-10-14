// 12단계: 화면·점검 API·제출 묶음이 모두 이 실제 측정 목록을 공유합니다.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

const TEST_UUID='00000000-0000-4000-8000-000000000001';
const TIMEOUT_MS=8000;
const NOTES_IN_BODY=/"(?:content|body)"\s*:/u;

function loadConfig(){
  return JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
}

function resolveBase(config){
  let base;
  try{base=new URL(config.publicAppUrl)}catch{throw new Error('aleph.config.json의 실제 배포 주소를 확인해 주세요.')}
  if(base.protocol!=='https:'||base.username||base.password||base.search||base.hash||base.pathname!=='/'||base.hostname.endsWith('.example')){
    throw new Error('aleph.config.json의 실제 배포 주소를 확인해 주세요.');
  }
  return base;
}

async function probe(target,{method='GET',headers={},caseId,now,makeId}={}){
  const requestId=makeId();
  const checkedAt=now().toISOString();
  try{
    const response=await fetch(target,{
      method,
      headers:{accept:'application/json','x-request-id':requestId,...headers},
      redirect:'manual',
      signal:AbortSignal.timeout(TIMEOUT_MS),
      alephEvidence:{caseId,requestKey:'read'},
    });
    const text=await response.text();
    let json=null;
    try{json=JSON.parse(text)}catch{}
    return {ran:true,status:response.status,json,text,hasNotes:NOTES_IN_BODY.test(text),requestId,checkedAt};
  }catch{
    return {ran:false,requestId,checkedAt};
  }
}

function attempt(attackId,stage,request,expected,r,blockedWhen){
  const head={attackId,stage,kind:'live_api',request,expected,requestId:r.requestId,checkedAt:r.checkedAt};
  if(!r.ran)return {...head,observed:'not_run',result:'not_run'};
  const ready=typeof r.json?.ready==='boolean'?'; jsonReady='+String(r.json.ready):'';
  return {...head,observed:'HTTP '+r.status+ready,result:blockedWhen(r)?'blocked':'breached'};
}

function notRun(attackId,stage,request,expected,now){
  return {attackId,stage,kind:'not_run',request,expected,observed:'not_run',
    result:'not_run',requestId:null,checkedAt:now().toISOString()};
}

const denied=r=>[401,403,404].includes(r.status)&&!r.hasNotes;
const noPublicNotes=r=>r.status===404||(r.status===200&&!r.hasNotes&&!(Array.isArray(r.json?.notes)&&r.json.notes.length>0));
const manifestOk=r=>r.status===200&&typeof r.json?.name==='string'&&r.json.name.length>0&&!r.hasNotes;
const ruleReady=r=>r.status===200&&r.json?.ready===true;

export async function collectAttackChecks(input,{now=()=>new Date(),makeId=randomUUID}={}){
  const config=typeof input==='string'?{...loadConfig(),publicAppUrl:input}:(input??loadConfig());
  const base=resolveBase(config);
  const p=(path,options={})=>probe(new URL(path,base),{...options,now,makeId});
  const external=(url,options={})=>probe(new URL(url),{...options,now,makeId});
  const rule=(id,stage,expected)=>p('/api/checks?case='+encodeURIComponent(id),{caseId:id})
    .then(r=>attempt(id,stage,'GET /api/checks?case='+id,expected,r,ruleReady));

  const restorePath=typeof config.restoreRoute==='string'&&config.restoreRoute.startsWith('POST ')
    ?config.restoreRoute.slice(5).replace(':id',TEST_UUID)
    :'/api/restore/notes/'+TEST_UUID;

  const results=await Promise.all([
    p('/data.json',{caseId:'s01-static-notes'})
      .then(r=>attempt('s01-static-notes',1,'GET /data.json','공개 정적 파일에 메모가 없음',r,noPublicNotes)),
    p('/notes.json',{caseId:'s02-static-copy'})
      .then(r=>attempt('s02-static-copy',2,'GET /notes.json','다른 정적 메모 사본 없음',r,denied)),
    p('/api/my/notes',{caseId:'s03-unauth-list'})
      .then(r=>attempt('s03-unauth-list',3,'GET /api/my/notes (로그인 없음)','로그인 없는 목록 거부',r,denied)),
    p('/api/my/notes',{caseId:'s03-fake-token',headers:{authorization:'Bearer not-a-real-token'}})
      .then(r=>attempt('s03-fake-token',3,'GET /api/my/notes (엉터리 토큰)','위조 토큰 거부',r,denied)),
    p('/api/my/notes?userId='+TEST_UUID+'&role=instructor',{caseId:'s04-query-identity'})
      .then(r=>attempt('s04-query-identity',4,'GET /api/my/notes (쿼리에 사용자·역할)','쿼리 신원 위조 거부',r,denied)),
    p('/api/my/notes',{caseId:'s04-header-identity',headers:{'x-user-id':TEST_UUID,'x-role':'instructor'}})
      .then(r=>attempt('s04-header-identity',4,'GET /api/my/notes (헤더에 사용자·역할)','헤더 신원 위조 거부',r,denied)),
    external(config.originalApiUrl,{caseId:'s05-direct-table'})
      .then(r=>attempt('s05-direct-table',5,'GET originalApiUrl','원본 자료 API 직접 읽기 거부',r,denied)),
    rule('s06-unregistered',6,'미등록 기기 거부'),
    rule('s07-compound',7,'복합 이상 접속 추가 확인'),
    rule('s08-unknown-route',8,'모르는 경로 거부'),
    rule('s08-all-notes',8,'메모 전체 목록 구역 거부'),
    rule('s08-write-notice',8,'반 공지 쓰기 거부'),
    rule('s08-own-note',8,'등록 기기의 메모 단건 정상 허용'),
    p('/api/notices',{caseId:'s08-other-zone'})
      .then(r=>attempt('s08-other-zone',8,'GET /api/notices (로그인 없음)','반 공지 무인증 조회 거부',r,denied)),
    rule('s09-burst-read',9,'조회 폭주 회수 제안'),
    p(restorePath,{caseId:'s10-restore-unauth'})
      .then(r=>attempt('s10-restore-unauth',10,'GET 복구 경로 (로그인 없음)','무인증 복구 거부',r,denied)),
    p('/api/device/status',{caseId:'s11-device'})
      .then(r=>attempt('s11-device',11,'GET /api/device/status (로그인 없음)','무인증 기기 상태 조회 거부',r,denied)),
    p('/manifest.webmanifest',{caseId:'s11-device-app'})
      .then(r=>attempt('s11-device-app',11,'GET /manifest.webmanifest','설치형 앱 manifest 정상 응답',r,manifestOk)),
  ]);

  results.push(
    notRun('s03-login-read',3,'GET /api/my/notes (A 로그인)','정상 요청 허용과 본인 목록',now),
    notRun('s04-b-reads-a',4,'GET /api/notes/:id (B 로그인, A 메모)','타인 메모 거부',now),
  );
  return results.sort((a,b)=>a.stage-b.stage);
}

export async function runAttackChecks(input){
  const items=await collectAttackChecks(input);
  return items.map(({attackId,stage,expected,observed,result})=>({attackId,stage,expected,observed,result}));
}

export function summarizeAttempts(items){
  const count=value=>items.filter(item=>item.result===value).length;
  return {total:items.length,blocked:count('blocked'),failed:count('breached'),notRun:count('not_run')};
}
