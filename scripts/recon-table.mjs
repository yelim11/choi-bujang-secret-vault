// 12단계: 1~11단계 정상·금지 요청을 실제 API와 로컬 연습으로 구분해 한 표로 남깁니다.
// 실행하지 않은 요청과 ALEPH 41종 총공세는 절대 통과로 꾸미지 않고 「미실행」으로 남깁니다.
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { detect, proposeRevocation } from '../src/detect.mjs';
import { fixtureRequests } from './fixture-7.mjs';
import { verifyNoteSnapshot } from '../src/note-backup.mjs';
import { currentPolicy, diffPolicy, verifySnapshot } from '../src/policy-diff.mjs';

const ROOT=resolve(import.meta.dirname,'..');
const CONFIG=JSON.parse(readFileSync(join(ROOT,'aleph.config.json'),'utf8'));
const POLICY=JSON.parse(readFileSync(join(ROOT,'backup/policy.v1.json'),'utf8'));
const NOTES=JSON.parse(readFileSync(join(ROOT,'backup/note.v1.json'),'utf8'));
const TOKEN=/^[A-Za-z0-9._-]{20,4096}$/u;
const currentCommit=()=>{try{return execFileSync('git',['-C',ROOT,'rev-parse','HEAD'],{encoding:'utf8',timeout:3000}).trim()}catch{return '현재 작업 트리'}};
const PROBE='11111111-1111-4111-8111-111111111111';

const clean=text=>String(text).replace(/\|/gu,'\\|').replace(/\r?\n/gu,' ');
const row=(step,kind,request,expected,observed,result,basis,requestId='없음',at='-')=>({
  step,kind,request,expected,observed,result,basis,requestId,at
});
const notRun=(step,kind,request,expected,reason)=>row(
  step,kind,request,expected,`미실행 (${reason})`,'not_run','none'
);

async function send(ctx,{method='GET',path,url,body,auth='none'}){
  const headers={Accept:'application/json'};
  if(body)headers['Content-Type']='application/json';
  if(auth==='fake')headers.Authorization='Bearer aaa.bbb.ccc';
  if(auth==='token')headers.Authorization=`Bearer ${ctx.token}`;
  try{
    const response=await ctx.fetchImpl(url??new URL(path,ctx.app),{
      method,headers,body,redirect:'error',signal:AbortSignal.timeout(10000)
    });
    const at=ctx.now().toISOString();
    let text='';try{text=await response.text()}catch{}
    const id=response.headers.get('x-vercel-id')??response.headers.get('x-request-id')??response.headers.get('sb-request-id');
    const requestId=id&&id.length<180?id:'없음';
    const resource=response.headers.get('x-resource-id');
    let errorCode='';
    try{
      const value=JSON.parse(text)?.error;
      if(typeof value==='string'&&/^[A-Z][A-Z0-9_]{2,50}$/u.test(value))errorCode=value;
    }catch{}
    return{failed:false,status:response.status,text,requestId,at,resource,errorCode,
      leaked:/"(?:title|body|content)"\s*:/u.test(text)};
  }catch{
    return{failed:true,status:null,text:'',requestId:'없음',at:ctx.now().toISOString(),resource:null,errorCode:'',leaked:false};
  }
}
const describe=res=>res.failed?'요청 실패':`HTTP ${res.status}${res.resource?` · X-Resource-Id ${res.resource}`:''}${res.errorCode?` · ${res.errorCode}`:''}${res.leaked?' · 메모 내용 노출':''}`;

async function actualRow(ctx,{step,kind,method='GET',path,url,body,auth='none',expected,ok,observe}){
  const res=await send(ctx,{method,path,url,body,auth});
  const pass=!res.failed&&ok(res);
  return row(step,kind,`${method} ${path??String(url)}${auth==='fake'?' (가짜 토큰)':auth==='token'?' (로그인)':''}`,
    expected,observe?observe(res):describe(res),pass?'match':'mismatch','actual_api',res.requestId,res.at);
}
const localRow=(step,kind,request,expected,observed,pass,requestId='local')=>
  row(step,kind,request,expected,observed,pass?'match':'mismatch','local_practice',requestId,new Date().toISOString());

const readBurst=(count,{network=null,deviceId=null}={})=>Array.from({length:count},(_,i)=>({
  at:new Date(Date.UTC(2026,9,1)+i*2000).toISOString(),method:'GET',
  identity:{sub:'learner_fixture'},decision:'allow',
  ...(network?{signals:{network}}:{}),...(deviceId?{deviceId}:{})
}));

export async function buildReconRows({
  config=CONFIG,fetchImpl=globalThis.fetch,token=process.env.ALEPH_STUDENT_TOKEN??'',
  now=()=>new Date(),
}={}){
  const app=new URL(config.publicAppUrl);
  const ctx={config,app,fetchImpl,token:TOKEN.test(token)?token:'',now};
  const rows=[];

  rows.push(await actualRow(ctx,{step:1,kind:'normal',path:'/',expected:'HTTP 200 첫 화면',
    ok:r=>r.status===200}));
  {
    const res=await send(ctx,{path:'/data.json'});
    let empty=false;try{const data=JSON.parse(res.text);empty=Array.isArray(data?.notes)&&data.notes.length===0}catch{}
    rows.push(row(2,'forbidden','GET /data.json','공개 정적 파일에 메모가 없어야 함',
      `${describe(res)} · notes ${empty?'0건':'확인 실패'}`,!res.failed&&[200,404].includes(res.status)&&(!res.leaked)&&((res.status===404)||empty)?'match':'mismatch',
      'actual_api',res.requestId,res.at));
  }
  rows.push(await actualRow(ctx,{step:3,kind:'forbidden',path:'/api/notes',expected:'로그인 없음 → 401',
    ok:r=>r.status===401&&!r.leaked}));
  rows.push(await actualRow(ctx,{step:3,kind:'forbidden',path:'/api/notes',auth:'fake',expected:'가짜 토큰 → 401',
    ok:r=>r.status===401&&!r.leaked}));
  rows.push(ctx.token
    ? await actualRow(ctx,{step:3,kind:'normal',path:'/api/my/notes',auth:'token',expected:'로그인·승인 기기 → 200',
        ok:r=>r.status===200,observe:r=>`HTTP ${r.status} · 인증된 자료 응답(본문은 표에 저장하지 않음)`})
    : notRun(3,'normal','GET /api/my/notes (로그인)','HTTP 200','ALEPH_STUDENT_TOKEN 미설정'));
  rows.push(notRun(4,'forbidden','B가 A 메모 GET·PUT·DELETE','HTTP 404, A 자료 유지','두 시험 계정의 실제 ID가 필요함'));

  rows.push(await actualRow(ctx,{step:5,kind:'forbidden',method:'GET',url:new URL(config.originalApiUrl),path:'originalApiUrl',
    expected:'직접 원본 API는 401/403',ok:r=>[401,403].includes(r.status)&&!r.leaked}));

  const {normal,suspicious}=fixtureRequests();
  const unregistered={...normal,requestId:randomUUID(),deviceRegistered:false};
  const d6=await decide(unregistered);
  rows.push(localRow(6,'forbidden','decide(미등록 기기)','deny / device_not_registered',
    `${d6.decision} / ${d6.reasonCode}`,d6.decision==='deny'&&d6.reasonCode==='device_not_registered',d6.requestId));
  const d7n=await decide(normal),d7s=await decide(suspicious);
  rows.push(localRow(7,'normal','decide(정상 등록 기기)','allow',`${d7n.decision} / ${d7n.reasonCode}`,
    d7n.decision==='allow'&&d7n.ruleIds.every(id=>RULE_IDS.includes(id)),d7n.requestId));
  rows.push(localRow(7,'forbidden','decide(복합 이상)','step_up',`${d7s.decision} / ${d7s.reasonCode}`,
    d7s.decision==='step_up'&&d7s.ruleIds.every(id=>RULE_IDS.includes(id)),d7s.requestId));

  const noteItem={...normal,requestId:randomUUID(),path:'/api/notes/demo',route:'GET /api/notes/:id'};
  const noteList={...normal,requestId:randomUUID(),path:'/api/notes',route:'GET /api/notes'};
  const noticeWrite={...normal,requestId:randomUUID(),service:'notices',method:'PUT',path:'/api/notices/demo',route:'PUT /api/notices/:id'};
  for(const [req,label,want] of [[noteItem,'메모 단건 구역','allow'],[noteList,'메모 전체 목록 구역','deny'],[noticeWrite,'공지 쓰기 구역','deny']]){
    const out=await decide(req);rows.push(localRow(8,want==='allow'?'normal':'forbidden',`decide(${label})`,want,
      `${out.decision} / ${out.reasonCode}`,out.decision===want&&out.ruleIds.every(id=>RULE_IDS.includes(id)),out.requestId));
  }

  const normalDetect=detect(readBurst(120));
  const unusual=readBurst(121,{network:'unusual',deviceId:'aaaaaaaaaaaaaaaa'});
  const suspiciousDetect=detect(unusual),proposal=proposeRevocation(unusual);
  rows.push(localRow(9,'normal','detect(정상/경계 120 GET)','observe',JSON.stringify(normalDetect),normalDetect.action==='observe'));
  rows.push(localRow(9,'forbidden','detect(낯선 네트워크 + 121 GET)','propose_revocation / burst_read',
    JSON.stringify({detect:suspiciousDetect,proposal}),suspiciousDetect.action==='propose_revocation'&&proposal?.deviceId==='aaaaaaaaaaaaaaaa'));

  const restorePath=String(config.restoreRoute??'').startsWith('POST ')?String(config.restoreRoute).slice(5).replace(':id',PROBE):null;
  rows.push(restorePath
    ? await actualRow(ctx,{step:10,kind:'forbidden',method:'POST',path:restorePath,body:'{}',
        expected:'로그인 없는 복구 → 401',ok:r=>r.status===401&&!r.leaked})
    : notRun(10,'forbidden','POST 복구 경로','401','restoreRoute 없음'));
  let policyOk=false,noteOk=false,changed=null;
  try{verifySnapshot(POLICY);const diff=diffPolicy(POLICY,currentPolicy(config));policyOk=true;changed=diff.changed}catch{}
  try{noteOk=verifyNoteSnapshot(NOTES)===null}catch{}
  rows.push(localRow(10,'normal','정책·메모 사본 재검증','두 사본 검증 통과',
    `policy=${policyOk} changed=${changed??'na'} / notes=${noteOk}`,policyOk&&noteOk));

  rows.push(await actualRow(ctx,{step:11,kind:'normal',path:'/manifest.webmanifest',expected:'설치 manifest HTTP 200',ok:r=>r.status===200}));
  rows.push(await actualRow(ctx,{step:11,kind:'forbidden',path:'/api/device/status',expected:'로그인 없는 기기 상태 → 401',
    ok:r=>r.status===401&&!r.leaked}));
  rows.push(ctx.token
    ? await actualRow(ctx,{step:11,kind:'normal',path:'/api/device/status',auth:'token',expected:'로그인 기기 상태 API 응답',
        ok:r=>[200,403].includes(r.status)})
    : notRun(11,'normal','GET /api/device/status (로그인)','실제 승인 상태 응답','ALEPH_STUDENT_TOKEN 미설정'));

  rows.push(await actualRow(ctx,{step:12,kind:'forbidden',path:'/api/war-room',expected:'무인증 작전실 → 401',
    ok:r=>r.status===401&&!r.leaked}));
  rows.push(ctx.token
    ? await actualRow(ctx,{step:12,kind:'normal',path:'/api/war-room',auth:'token',expected:'승인 기기 세션이면 HTTP 200 작전실 요약',
        ok:r=>r.status===200,observe:r=>`HTTP ${r.status} · 작전실 요약 응답(본문은 표에 저장하지 않음)`})
    : notRun(12,'normal','GET /api/war-room (로그인·승인 기기)','HTTP 200','ALEPH_STUDENT_TOKEN 미설정'));
  rows.push(notRun(12,'forbidden','ALEPH 총공세 41종','41종 모두 심판 실측 결과로 판정',
    '심판의 41종 공격 목록과 실행 결과를 이 스크립트가 임의 생성하지 않음'));

  return rows;
}

export function renderMarkdown(rows,{commit='현재 검사 커밋'}={}){
  const counts={
    match:rows.filter(r=>r.result==='match').length,
    mismatch:rows.filter(r=>r.result==='mismatch').length,
    not_run:rows.filter(r=>r.result==='not_run').length,
  };
  const lines=[
    '# BYTE BACK · 1~11단계 재검증 표',
    '',
    `검사 기준: ${commit}`,
    `요약: 기대와 일치 ${counts.match} · 다름 ${counts.mismatch} · 미실행 ${counts.not_run}`,
    '',
    '| 단계 | 종류 | 요청 | 기대 결과 | 실제 결과 | 판정 | 근거 | 요청 ID | 확인 시각 |',
    '| ---: | --- | --- | --- | --- | --- | --- | --- | --- |',
    ...rows.map(r=>`| ${r.step} | ${clean(r.kind)} | ${clean(r.request)} | ${clean(r.expected)} | ${clean(r.observed)} | ${r.result==='match'?'기대와 일치':r.result==='mismatch'?'기대와 다름':'미실행'} | ${r.basis==='actual_api'?'실제 API':r.basis==='local_practice'?'로컬 연습':'-'} | ${clean(r.requestId)} | ${clean(r.at)} |`),
    '',
    '> 로컬 연습은 실제 API 응답이나 ALEPH 심판 판정이 아닙니다. 41종 총공세는 심판이 실행하기 전에는 미실행입니다.',
  ];
  return `${lines.join('\n')}\n`;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const rows=await buildReconRows();
  mkdirSync(join(ROOT,'artifacts'),{recursive:true});
  const output=join(ROOT,'artifacts','recon-table.md');
  writeFileSync(output,renderMarkdown(rows,{commit:currentCommit()}),'utf8');
  const bad=rows.filter(r=>r.result==='mismatch').length;
  const notRunCount=rows.filter(r=>r.result==='not_run').length;
  process.stdout.write(`재검증 표 생성: ${output}\n실행 결과 불일치 ${bad} · 미실행 ${notRunCount} · 총공세 41종은 심판 전 미실행\n`);
  if(bad)process.exitCode=1;
}
