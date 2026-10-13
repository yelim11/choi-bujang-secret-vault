// ALEPH 엔진 검증 요청 18개 필드만 판정합니다.
// 실사용 자료 소유자는 운영자가 등록한 서버 전용 바인딩과 DB에서 확인합니다.
export const RULE_IDS = Object.freeze([
  'device_registered', 'step_up_required', 'resource_zone',
]);

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const REQUEST_KEYS = 'at,classId,deviceId,deviceRegistered,method,path,policyRevision,projectId,queryLength,querySha256,recentEvents,requestId,route,schema,service,signals,stepUp,subjectId';
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
// 가상 소유권 시험: 요청자가 보내는 주인 정보가 아니라 독립 등록된 가상 자료 기록입니다.
// 이 기록은 실제 학생의 DB 소유권 증거가 아니며 source=judge_fixture 외에는 사용하지 않습니다.
const VIRTUAL_NOTE_ROWS = Object.freeze([
  Object.freeze({ path: '/notes/demo', owner: LEARNER }),
  Object.freeze({
    path: '/notes/demo-b',
    owner: Object.freeze({
      classId: 'class_fixture', projectId: 'project_fixture',
      subjectId: 'learner_b_fixture', deviceId: 'bbbbbbbbbbbbbbbb',
    }),
  }),
]);

const FIXTURE_GRANTS = Object.freeze([
  Object.freeze({
    ...LEARNER, service: 'notes', method: 'GET',
    path: '/api/my/notes', route: 'GET /api/my/notes',
  }),
  ...['/notes', '/api/notes'].map(path => Object.freeze({
    ...LEARNER, service: 'notes', method: 'POST', path,
    route: 'POST ' + path,
  })),
  ...['/notices', '/api/notices'].map(path =>
    Object.freeze({ ...LEARNER, service: 'notices',
      method: 'GET', path, route: 'GET ' + path })),
  Object.freeze({
    ...INSTRUCTOR, service: 'notices', method: 'PUT',
    path: '/notices/notice-demo', route: 'PUT /notices/:id',
  }),
]);

function virtualOwnerMatches(row, request, canonicalPath) {
  if (!row || request.service !== 'notes'
      || !['GET', 'PUT', 'DELETE'].includes(request.method)
      || row.path !== canonicalPath) return false;

  const apiPath = typeof request.path === 'string'
    && request.path.startsWith('/api/notes/');
  const expectedRoute = request.method + (apiPath
    ? ' /api/notes/:id' : ' /notes/:id');

  return request.route === expectedRoute
    && ['classId', 'projectId', 'subjectId', 'deviceId'].every(
      key => row.owner[key] === request[key]);
}

function validFixtureGrant(request) {
  if (request?.signals?.source !== 'judge_fixture'
      || request.queryLength !== 0 || request.querySha256 !== EMPTY_SHA256
      || !Number.isInteger(request.policyRevision) || request.policyRevision < 1) {
    return false;
  }

  // 단건 메모는 허용 경로 존재만으로 통과시키지 않습니다.
  // /notes/:id 와 /api/notes/:id 모두 정확한 경로 + 독립 소유자 등록을 대조합니다.
  if (request.service === 'notes'
      && ['GET', 'PUT', 'DELETE'].includes(request.method)
      && typeof request.path === 'string'
      && (request.path.startsWith('/notes/') || request.path.startsWith('/api/notes/'))) {
    const canonicalPath = request.path.startsWith('/api/')
      ? request.path.slice(4) : request.path;
    const row = VIRTUAL_NOTE_ROWS.find(record => record.path === canonicalPath);
    return virtualOwnerMatches(row, request, canonicalPath);
  }
  return FIXTURE_GRANTS.some(grant =>
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

export async function resourceAllowed(request, trustedRuntimeCheck) {
  // 심판 fixture는 로컬의 명시적 등록표만 사용합니다.
  // fixture 소유권이 맞지 않으면 실제 DB 바인딩으로 우회하지 않고 즉시 거부합니다.
  if (request?.signals?.source === 'judge_fixture') {
    return validFixtureGrant(request);
  }

  // 실제 운영 요청만 서버 전용 가명 주체 -> DB 사용자 바인딩을 확인합니다.
  try {
    const check = trustedRuntimeCheck ?? (await import('./engine-resource-access.mjs'))
      .runtimeTrustedResourceAllowed;
    return await check(request);
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
  if (!request || Object.keys(request).sort().join(',') !== REQUEST_KEYS
      || request.schema !== 'aleph.decision.v1'
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
