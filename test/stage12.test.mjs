import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import config from '../aleph.config.json' with { type:'json' };
import policy from '../backup/policy.v1.json' with { type:'json' };
import notes from '../backup/note.v1.json' with { type:'json' };
import { createOpsApi, recoverySummary, logLineOf } from '../src/ops-api.mjs';
import { summarizeAttempts } from '../src/attack-check.mjs';
import { runRuleCheck } from '../src/rule-check.mjs';

const ITEMS=[
  {attackId:'a',stage:3,kind:'live_api',request:'GET /x',expected:'401',observed:'HTTP 401',result:'blocked',requestId:'r1',checkedAt:'2026-10-14T00:00:00.000Z'},
  {attackId:'b',stage:4,kind:'not_run',request:'GET /y',expected:'404',observed:'not_run',result:'not_run',requestId:null,checkedAt:'2026-10-14T00:00:01.000Z'},
];

test('작전실 요약과 가린 기록은 같은 점검 목록에서 계산된다',async()=>{
  const recovery=recoverySummary({policy,notes,config});
  assert.equal(recovery.policy.valid,true);
  assert.equal(recovery.notes.valid,true);
  const summary=summarizeAttempts(ITEMS);
  const rules={count:3,ids:['device_registered','step_up_required','resource_zone']};
  const line=logLineOf({summary,rules,recovery,commit:'abcdef123456'});
  assert.match(line,/total=2/u);
  assert.match(line,/blocked=1/u);
  assert.match(line,/not_run=1/u);

  const response={
    code:null,body:null,headers:{},
    setHeader(k,v){this.headers[k.toLowerCase()]=v},
    status(code){this.code=code;return this},
    json(body){this.body=body;return this},
  };
  const handler=createOpsApi({
    config,policy,notes,commit:'abcdef123456',
    now:()=>new Date('2026-10-14T00:00:02.000Z'),
    collect:async()=>ITEMS,
  });
  await handler({method:'GET'},response);
  assert.equal(response.code,200);
  assert.equal(response.body.schema,'aleph.ops.v1');
  assert.deepEqual(response.body.summary,summary);
  assert.deepEqual(response.body.items,ITEMS);
  assert.equal(response.body.logLine,logLineOf({
    summary:response.body.summary,
    rules:response.body.rules,
    recovery:response.body.recovery,
    commit:response.body.commit,
  }));
  assert.doesNotMatch(JSON.stringify(response.body),/"content"|"body"|"owner_id"|"device_id"/u);
});

test('고정 가상 규칙은 정상 허용과 금지 거부를 모두 확인한다',async()=>{
  assert.equal((await runRuleCheck('s08-own-note')).decision,'allow');
  assert.equal((await runRuleCheck('s06-unregistered')).decision,'deny');
  assert.equal((await runRuleCheck('s07-compound')).decision,'step_up');
  assert.equal((await runRuleCheck('s09-burst-read')).action,'propose_revocation');
  assert.equal(await runRuleCheck('unknown'),null);
});

test('화면은 /api/ops 실제 응답을 읽고 미실행을 별도로 표시한다',async()=>{
  const [ops,war]=await Promise.all([
    readFile(new URL('../public/ops.html',import.meta.url),'utf8'),
    readFile(new URL('../public/war-room.js',import.meta.url),'utf8'),
  ]);
  assert.match(ops,/fetch\('\/api\/ops'/u);
  assert.match(ops,/요청 ID/u);
  assert.match(ops,/확인 시각/u);
  assert.match(ops,/미실행/u);
  assert.match(war,/fetch\('\/api\/ops'/u);
  assert.match(war,/41종 총공세/u);
  assert.doesNotMatch(ops+war,/localStorage|sessionStorage|indexedDB|document\.cookie/u);
});
