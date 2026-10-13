import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function responseValid(request, response, ids) {
  return response && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(rule => ids.includes(rule));
}

// 가상 요청만 시험합니다. 사용자의 실제 토큰/자료/심판 통과 증거가 아닙니다.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !['device_registered',
      'step_up_required', 'resource_zone'].every(rule => ruleIds.includes(rule))) {
    throw new Error('6~8단계 규칙 ID를 확인해 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const changed = (overrides = {}) => ({ ...normal, requestId: randomUUID(), ...overrides });
  const notice = { service: 'notices', method: 'PUT',
    path: '/notices/notice-demo', route: 'PUT /notices/:id' };
  const b = { subjectId: 'other_learner_fixture' };
  const validUuid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const cases = [
    { name: '등록 기기의 정상 자기 메모 조회', request: normal, decision: 'allow' },
    { name: '미등록 기기 거부', request: changed({ deviceRegistered: false }),
      decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '문자열로 위조된 기기 등록 거부',
      request: changed({ deviceRegistered: 'true' }),
      decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '복합 이상 접속 추가 인증', request: suspicious,
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '추가 인증된 복합 이상 접속 허용', request: { ...suspicious,
      requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow' },
    { name: '인증 시간이 초과된 위험 접속은 재확인',
      request: { ...suspicious, requestId: randomUUID(),
        stepUp: { verified: true, authAgeSeconds: 901 } },
      decision: 'step_up' },
    { name: '지역만 다른 정상 접속 허용',
      request: changed({ signals: { source: 'judge_fixture', region: 'foreign',
        network: 'usual', hour: 14 } }), decision: 'allow' },
    { name: 'A 자기 메모 수정 허용',
      request: changed({ method: 'PUT', route: 'PUT /notes/:id' }), decision: 'allow' },
    { name: 'A 자기 메모 삭제 허용',
      request: changed({ method: 'DELETE', route: 'DELETE /notes/:id' }), decision: 'allow' },
    { name: 'B의 A 메모 조회 거부',
      request: changed(b), decision: 'deny', reasonCode: 'route_not_allowed' },
    { name: 'B의 A 메모 수정 거부',
      request: changed({ ...b, method: 'PUT', route: 'PUT /notes/:id' }),
      decision: 'deny' },
    { name: 'B의 A 메모 삭제 거부',
      request: changed({ ...b, method: 'DELETE', route: 'DELETE /notes/:id' }),
      decision: 'deny' },
    { name: '다른 기기의 A 메모 조회 거부',
      request: changed({ deviceId: 'b'.repeat(16) }), decision: 'deny' },
    { name: '다른 반의 A 메모 조회 거부',
      request: changed({ classId: 'different_class' }), decision: 'deny' },
    { name: '다른 프로젝트의 A 메모 조회 거부',
      request: changed({ projectId: 'different_project' }), decision: 'deny' },
    { name: 'A 본인 메모 목록 허용',
      request: changed({ path: '/notes', route: 'GET /notes' }), decision: 'allow' },
    { name: 'A 기존 API 메모 목록 허용',
      request: changed({ path: '/api/notes', route: 'GET /api/notes' }), decision: 'allow' },
    { name: 'A 새 메모 추가 허용',
      request: changed({ method: 'POST', path: '/notes', route: 'POST /notes' }),
      decision: 'allow' },
    { name: 'B의 A 메모 목록 거부',
      request: changed({ ...b, path: '/notes', route: 'GET /notes' }), decision: 'deny' },
    { name: 'B의 A 메모 추가 구역 거부',
      request: changed({ ...b, method: 'POST', path: '/notes', route: 'POST /notes' }),
      decision: 'deny' },
    { name: '정상 UUID라도 소유권 미확인 조회 거부',
      request: changed({ path: '/notes/' + validUuid }), decision: 'deny' },
    { name: '정상 UUID라도 소유권 미확인 수정 거부',
      request: changed({ method: 'PUT', route: 'PUT /notes/:id',
        path: '/notes/' + validUuid }), decision: 'deny' },
    { name: '기능 경로 export가 메모 ID로 통과하지 않음',
      request: changed({ path: '/notes/export' }), decision: 'deny' },
    { name: '추가 쿼리로 구역을 전환할 수 없음',
      request: changed({ queryLength: 7, querySha256: 'f'.repeat(64) }), decision: 'deny' },
    { name: '쿼리 해시 위조 거부',
      request: changed({ querySha256: '0'.repeat(64) }), decision: 'deny' },
    { name: '학생의 강사 공지 읽기 허용',
      request: changed({ service: 'notices', path: '/notices',
        route: 'GET /notices' }), decision: 'allow' },
    { name: '학생의 강사 공지 수정 거부',
      request: changed(notice), decision: 'deny' },
    { name: '본문 role=instructor로 강사 권한 위조 불가',
      request: changed({ ...notice, role: 'instructor' }), decision: 'deny' },
    { name: '등록 강사 주체/기기 공지 수정 허용',
      request: changed({ ...notice, subjectId: 'instructor_fixture',
        deviceId: 'b'.repeat(16) }), decision: 'allow' },
    { name: '강사 주체지만 다른 기기이면 공지 수정 거부',
      request: changed({ ...notice, subjectId: 'instructor_fixture' }), decision: 'deny' },
    { name: '강사 주체/기기도 다른 프로젝트에서는 거부',
      request: changed({ ...notice, subjectId: 'instructor_fixture',
        deviceId: 'b'.repeat(16), projectId: 'other_project' }), decision: 'deny' },
    { name: '강사 기기 등록이 해제되면 공지 수정 거부',
      request: changed({ ...notice, subjectId: 'instructor_fixture',
        deviceId: 'b'.repeat(16), deviceRegistered: false }), decision: 'deny' },
    { name: '미등록 공지 경로 수정 거부',
      request: changed({ ...notice, subjectId: 'instructor_fixture',
        deviceId: 'b'.repeat(16), path: '/notices/export' }), decision: 'deny' },
  ];
  const results = [];
  for (const c of cases) {
    const verdict = await decide(c.request);
    results.push({ name: c.name,
      passed: responseValid(c.request, verdict, ruleIds)
        && verdict.decision === c.decision
        && (!c.reasonCode || verdict.reasonCode === c.reasonCode)
        && (verdict.decision === 'allow' ? verdict.ruleIds.includes('resource_zone') : true),
    });
  }
  return results;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) {
      process.stdout.write((item.passed ? '통과' : '확인 필요') + ' · ' + item.name + '\n');
    }
    process.stdout.write('가상 사건 연습이며 ALEPH 심판 점수가 아닙니다.\n');
    if (results.some(x => !x.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write('판정기 연습 첫 오류: ' + error.message + '\n');
    process.exitCode = 1;
  }
}
