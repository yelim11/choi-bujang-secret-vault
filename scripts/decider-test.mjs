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

export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function'
      || !['device_registered', 'step_up_required', 'resource_zone']
        .every(rule => ruleIds.includes(rule))) {
    throw new Error('6~8단계 규칙 ID를 확인해 주세요.');
  }

  const { normal, suspicious } = fixtureRequests();
  const changed = (overrides = {}) => ({
    ...normal,
    requestId: randomUUID(),
    ...overrides,
  });
  const cases = [
    { name: '등록 기기의 정상 메모 단건 조회', request: normal, decision: 'allow' },
    { name: '미등록 기기 거부', request: changed({ deviceRegistered: false }),
      decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '복합 이상 접속 추가 인증', request: suspicious,
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '추가 인증 뒤 정상 허용', request: { ...suspicious, requestId: randomUUID(),
      stepUp: { verified: true, authAgeSeconds: 60 } }, decision: 'allow' },
    { name: 'UUID가 아닌 심판 메모 ID도 단건이면 허용',
      request: changed({ path: '/notes/fixture-note-a' }), decision: 'allow' },
    { name: 'API 메모 단건 경로 허용',
      request: changed({ path: '/api/notes/demo', route: 'GET /api/notes/:id' }),
      decision: 'allow' },
    { name: '다른 주체도 단건 구역 판정은 통과하고 소유권은 API가 확인',
      request: changed({ subjectId: 'another_subject' }), decision: 'allow' },
    { name: '메모 전체 목록 거부',
      request: changed({ path: '/notes', route: 'GET /notes' }), decision: 'deny' },
    { name: 'API 메모 전체 목록 거부',
      request: changed({ path: '/api/notes', route: 'GET /api/notes' }), decision: 'deny' },
    { name: '본인 전용 목록도 판정기 구역에는 두지 않음',
      request: changed({ path: '/api/my/notes', route: 'GET /api/my/notes' }), decision: 'deny' },
    { name: '메모 생성 경로는 판정기에서 거부',
      request: changed({ method: 'POST', path: '/notes', route: 'POST /notes' }), decision: 'deny' },
    { name: '메모 export 기능 경로 거부',
      request: changed({ path: '/notes/export' }), decision: 'deny' },
    { name: '쿼리로 기능 선택 거부',
      request: changed({ queryLength: 3, querySha256: 'f'.repeat(64) }), decision: 'deny' },
    { name: '반 공지 목록 GET 허용', request: changed({ service: 'notices',
      path: '/notices', route: 'GET /notices' }), decision: 'allow' },
    { name: '반 공지 단건 GET 허용', request: changed({ service: 'notices',
      path: '/notices/notice-a', route: 'GET /notices/:id' }), decision: 'allow' },
    { name: '학생 공지 PUT 거부', request: changed({ service: 'notices', method: 'PUT',
      path: '/notices/notice-a', route: 'PUT /notices/:id' }), decision: 'deny' },
    { name: '강사처럼 보이는 주체라도 판정기 공지 PUT 거부', request: changed({
      subjectId: 'instructor_fixture', service: 'notices', method: 'PUT',
      path: '/notices/notice-a', route: 'PUT /notices/:id' }), decision: 'deny' },
    { name: '강사 자료 서비스는 모두 거부', request: changed({
      service: 'instructor-materials', path: '/materials/m1', route: 'GET /materials/:id' }),
      decision: 'deny' },
    { name: '서비스와 경로가 섞이면 거부', request: changed({ service: 'notices' }), decision: 'deny' },
    { name: '계약 밖 role 값은 신뢰하지 않고 거부',
      request: changed({ role: 'instructor' }), decision: 'deny' },
  ];

  const results = [];
  for (const c of cases) {
    const verdict = await decide(c.request);
    results.push({
      name: c.name,
      passed: responseValid(c.request, verdict, ruleIds)
        && verdict.decision === c.decision
        && (!c.reasonCode || verdict.reasonCode === c.reasonCode),
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
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write('판정기 연습 첫 오류: ' + error.message + '\n');
    process.exitCode = 1;
  }
}
