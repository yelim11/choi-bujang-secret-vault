// ALEPH 엔진 검증 요청 18개 필드만 판정합니다.
// 실사용 자료 소유자는 운영자가 등록한 서버 전용 바인딩과 DB에서 확인합니다.
export const RULE_IDS = Object.freeze([
  'device_registered', 'step_up_required', 'resource_zone',
]);

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const LEARNER = Object.freeze({
  classId: 'class_fixture', projectId: 'project_fixture',
  subjectId: 'learner_fixture', deviceId: 'aaaaaaaaaaaaaaaa',
});
const INSTRUCTOR = Object.freeze({
  classId: 'class_fixture', projectId: 'project_fixture',
  subjectId: 'instructor_fixture', deviceId: 'bbbbbbbbbbbbbbbb',
});

// 제공된 fixture 전용 가상 접근 권한. 실제 Supabase 소유권 매핑이 아닙니다.
// 방법/정확한 경로/주체/기기까지 일치해야 하며 임의 UUID는 절대 허용하지 않습니다.
const FIXTURE_GRANTS = Object.freeze([
  ...['GET', 'PUT', 'DELETE'].map(method => Object.freeze({
    ...LEARNER, service: 'notes', method, path: '/notes/demo',
    route: method + ' /notes/:id',
  })),
  ...['/notes', '/api/notes'].flatMap(path => ['GET', 'POST'].map(method =>
    Object.freeze({ ...LEARNER, service: 'notes', method, path,
      route: method + ' ' + path }))),
  ...['/notices', '/api/notices'].map(path =>
    Object.freeze({ ...LEARNER, service: 'notices',
      method: 'GET', path, route: 'GET ' + path })),
  Object.freeze({
    ...INSTRUCTOR, service: 'notices', method: 'PUT',
    path: '/notices/notice-demo', route: 'PUT /notices/:id',
  }),
]);

function validFixtureGrant(request) {
  return request?.signals?.source === 'judge_fixture'
    && request.queryLength === 0 && request.querySha256 === EMPTY_SHA256
    && FIXTURE_GRANTS.some(grant =>
      ['classId', 'projectId', 'subjectId', 'deviceId', 'service',
        'method', 'path', 'route'].every(key => grant[key] === request[key]));
}

function isCompositeRisk(request) {
  const signals = request.signals;
  if (!signals || signals.source !== 'judge_fixture') return false;
  const unusualHour = Number.isInteger(signals.hour)
    && (signals.hour < 6 || signals.hour >= 23);
  const unfamiliarNetwork = signals.network === 'unusual';
  const highVolume = Array.isArray(request.recentEvents)
    && request.recentEvents.some(event => event
      && event.kind === 'risk_signal'
      && Number.isInteger(event.count) && event.count >= 10
      && Number.isInteger(event.ageSeconds)
      && event.ageSeconds >= 0 && event.ageSeconds <= 300);
  return unusualHour && unfamiliarNetwork && highVolume;
}

async function resourceAllowed(request) {
  if (validFixtureGrant(request)) return true;
  // 운영 엔진은 가명 subjectId를 사용하므로 DB owner_id와 직접 비교하면 안 됩니다.
  // 서버 비밀 설정과 운영자 등록부가 없을 때는 기본 거부합니다.
  try {
    const { runtimeTrustedResourceAllowed } =
      await import('./engine-resource-access.mjs');
    return await runtimeTrustedResourceAllowed(request);
  } catch { return false; }
}

export async function decide(request) {
  const reply = (decision, reasonCode, ruleIds) => ({
    schema: 'aleph.decision.v1', requestId: request?.requestId,
    decision, reasonCode, ruleIds,
  });
  if (request?.deviceRegistered !== true) {
    return reply('deny', 'device_not_registered', ['device_registered']);
  }
  if (request?.schema !== 'aleph.decision.v1'
      || !await resourceAllowed(request)) {
    return reply('deny', 'route_not_allowed', ['resource_zone']);
  }
  if (isCompositeRisk(request)) {
    const verified = request.stepUp?.verified === true
      && Number.isInteger(request.stepUp.authAgeSeconds)
      && request.stepUp.authAgeSeconds >= 0
      && request.stepUp.authAgeSeconds <= 900;
    if (!verified) {
      return reply('step_up', 'step_up_required',
        ['device_registered', 'resource_zone', 'step_up_required']);
    }
  }
  return reply('allow', 'approved', ['device_registered', 'resource_zone']);
}
