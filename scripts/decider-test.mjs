import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id));
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered')) {
    throw new Error('6단계 device_registered 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow' },
    { name: '미등록 기기의 가상 요청', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered' },
  ];
  if (ruleIds.includes('step_up_required')) {
    checks.push(
      { name: '복합 이상 접속', request: suspicious, decision: 'step_up',
        reasonCode: 'step_up_required' },
      { name: '다시 확인한 복합 이상 접속', request: { ...suspicious,
        requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow' },
    );
  }
  if (ruleIds.includes('resource_boundary')) {
    checks.push(
      { name: '알 수 없는 자료 구역 거부',
        request: { ...normal, requestId: randomUUID(),
          service: 'notices', path: '/notices/notice-1',
          route: 'PUT /notices/:id', method: 'PUT' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '기능 경로를 메모 ID로 위장한 요청 거부',
        request: { ...normal, requestId: randomUUID(),
          path: '/notes/export', route: 'GET /notes/:id' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '타 구역 이름을 메모 ID로 위장한 조회 거부',
        request: { ...normal, requestId: randomUUID(),
          path: '/notes/other-user-note', route: 'GET /notes/:id' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '타 구역 메모 ID 명칭 거부',
        request: { ...normal, requestId: randomUUID(),
          path: '/notes/other', route: 'GET /notes/:id' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '정상 형식 UUID의 타인 메모 GET 기본 거부',
        request: { ...normal, requestId: randomUUID(),
          path: '/notes/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', route: 'GET /notes/:id' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '엔진 실서비스 출처에서 소유권 없는 UUID GET 거부',
        request: { ...normal, requestId: randomUUID(),
          signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 },
          path: '/notes/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', route: 'GET /notes/:id' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '허용 목록 경로라도 쿼리로 다른 구역 조회 요청 시 거부',
        request: { ...normal, requestId: randomUUID(),
          path: '/notes', route: 'GET /notes', method: 'GET',
          queryLength: 7, querySha256: 'f'.repeat(64) },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '개별 메모 가상 경로에도 허가되지 않은 쿼리 거부',
        request: { ...normal, requestId: randomUUID(),
          queryLength: 7, querySha256: 'f'.repeat(64) },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '정상 메모 목록 쿼리 없음 허용',
        request: { ...normal, requestId: randomUUID(),
          path: '/notes', route: 'GET /notes', method: 'GET' },
        decision: 'allow' },
      { name: '해시 불일치 요청 거부',
        request: { ...normal, requestId: randomUUID(),
          path: '/notes', route: 'GET /notes', method: 'GET',
          queryLength: 0, querySha256: '0'.repeat(64) },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '실제 API 정상 메모 목록 구역 허용',
        request: { ...normal, requestId: randomUUID(),
          path: '/api/notes', route: 'GET /api/notes', method: 'GET' },
        decision: 'allow' },
      { name: '강사 공지 읽기 구역 정상 허용',
        request: { ...normal, requestId: randomUUID(),
          service: 'notices', path: '/notices', route: 'GET /notices', method: 'GET' },
        decision: 'allow' },
      { name: '공지 조회도 검증할 수 없는 쿼리 구역 변경 거부',
        request: { ...normal, requestId: randomUUID(),
          service: 'notices', path: '/notices', route: 'GET /notices',
          method: 'GET', queryLength: 8, querySha256: 'f'.repeat(64) },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '일반 학생의 공지 쓰기 구역 거부',
        request: { ...normal, requestId: randomUUID(),
          service: 'notices', path: '/notices/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          route: 'PUT /notices/:id', method: 'PUT' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '정확하지 않은 경로 메서드 조합 거부',
        request: { ...normal, requestId: randomUUID(), method: 'PUT' },
        decision: 'deny', reasonCode: 'route_not_allowed' },
      { name: '지역만 변경된 자기 메모 경로 허용',
        request: { ...normal, requestId: randomUUID(),
          signals: { source: 'judge_fixture', region: 'foreign',
            network: 'usual', hour: 14 } }, decision: 'allow' },
    );
  }
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && (!item.reasonCode || response.reasonCode === item.reasonCode);
    results.push({ name: item.name, passed: valid });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
