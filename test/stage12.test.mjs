import assert from 'node:assert/strict';
import { test } from 'node:test';
import config from '../aleph.config.json' with { type: 'json' };
import policy from '../backup/policy.v1.json' with { type: 'json' };
import notes from '../backup/note.v1.json' with { type: 'json' };
import { buildWarRoomSummary, handleWarRoom, recordOf, warRoomLogLine } from '../src/war-room.mjs';
import { readFile } from 'node:fs/promises';

const USER='11111111-1111-4111-8111-111111111111';
const db={
  from(name){
    assert.equal(name,'devices');
    return {
      select(){return this},
      eq(){
        return Promise.resolve({data:[
          {owner_id:USER,status:'approved'},
          {owner_id:USER,status:'pending'},
          {owner_id:USER,status:'revoked'},
          {owner_id:'22222222-2222-4222-8222-222222222222',status:'approved'},
        ],error:null});
      }
    };
  }
};
const fakeResponse=()=>({
  statusCode:null,body:null,
  status(code){this.statusCode=code;return this},
  json(body){this.body=body;return this},
});

test('작전실은 실제 DB 회수 상태와 검증 사본을 요약하고 미실행을 0으로 꾸미지 않는다',()=>{
  const summary=buildWarRoomSummary({
    devices:[
      {status:'approved'},{status:'pending'},{status:'revoked'}
    ],policy,notes,config
  });
  assert.equal(summary.decider.status,'listed');
  assert.equal(summary.decider.ruleCount,3);
  assert.deepEqual(summary.decider.ruleIds,['device_registered','step_up_required','resource_zone']);
  assert.equal(summary.detect.status,'not_run');
  assert.equal(summary.detect.events,null);
  assert.deepEqual(summary.revocation,{status:'confirmed',approved:1,pending:1,revoked:1});
  assert.equal(summary.recovery.policy.verified,true);
  assert.equal(summary.recovery.policy.changed,0);
  assert.equal(summary.recovery.notes.verified,true);
  assert.equal(summary.recovery.notes.entries,4);
  assert.equal(summary.totalAssault.status,'not_run');
  assert.equal(summary.totalAssault.expectedAttackTypes,41);
  assert.equal(summary.totalAssault.completedAttackTypes,null);
});

test('화면 수치와 가린 서버 기록은 같은 요약에서 생성된다',async()=>{
  const response=fakeResponse();
  const now=new Date('2026-10-14T01:00:00.000Z');
  await handleWarRoom({user:{userId:USER},db},response,{policy,notes,config,requestId:'req-test-1',now});
  assert.equal(response.statusCode,200);
  assert.equal(response.body.checkedAt,now.toISOString());
  const record=recordOf(response.body);
  assert.equal(response.body.logLine,warRoomLogLine('req-test-1',record));
  assert.match(response.body.logLine,/rules=3/u);
  assert.match(response.body.logLine,/revocation_approved=1/u);
  assert.match(response.body.logLine,/policy_verified=true/u);
  const serialized=JSON.stringify(response.body);
  assert.doesNotMatch(serialized,/"title"|"content"|"body"|"owner_id"|"userId"|"device_id"/u);
});

const publicText=path=>readFile(new URL(`../public/${path}`,import.meta.url),'utf8');
test('12단계 화면 스크립트는 실제 API 상태와 미실행을 분리하고 비밀 브라우저 저장소를 쓰지 않는다',async()=>{
  const script=await publicText('war-room.js');
  assert.match(script,/\/api\/war-room/u);
  assert.match(script,/미실행\/미연결/u);
  assert.match(script,/총공세/u);
  assert.match(script,/logLine/u);
  assert.doesNotMatch(script,/localStorage|sessionStorage|indexedDB|document\.cookie/u);
});
