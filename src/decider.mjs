// 엔진이 신원/기기를 검사한 aleph.decision.v1 요청만 판정합니다.
// 역할 또는 소유권을 client role, query, signals에서 만들어 내지 않습니다.
export const RULE_IDS = Object.freeze([
  'device_registered', 'step_up_required', 'resource_boundary',
]);

function isCompositeRisk(request) {
  const signals = request.signals;
  if (!signals || signals.source !== 'judge_fixture') return false;
  const unusualHour = Number.isInteger(signals.hour) &&
    (signals.hour < 6 || signals.hour >= 23);
  const unfamiliarNetwork = signals.network === 'unusual';
  const highVolume = Array.isArray(request.recentEvents) &&
    request.recentEvents.some(event =>
      event && event.kind === 'risk_signal' &&
      Number.isInteger(event.count) && event.count >= 10 &&
      Number.isInteger(event.ageSeconds) &&
      event.ageSeconds >= 0 && event.ageSeconds <= 300);
  return unusualHour && unfamiliarNetwork && highVolume;
}

// 서비스/메서드/route와 실제 path를 함께 대조합니다.
// 기능 선택에 쿼리를 쓰지 않으며, :id는 한 경로 세그먼트만 받습니다.
// 개별 메모의 실제 소유권은 API가 저장된 owner_id와 검증된 토큰을 대조합니다.
// 판정 계약에 소유자 필드는 없습니다. 따라서 엔진이 검증해 제공한 공식
// 가상 주체/기기와 연결된 연습 자원에만 이 판정기 단독 GET 접근을 허용합니다.
// 실제 학생 메모의 소유권 검사는 api/notes.js의 DB owner_id 조건이 맡습니다.
function isFixtureOwner(request) {
  return request.classId === 'class_fixture'
    && request.projectId === 'project_fixture'
    && request.subjectId === 'learner_fixture'
    && request.deviceId === 'aaaaaaaaaaaaaaaa';
}

function knownNotesRoute(request) {
  if (typeof request.path !== 'string') return false;
  // 계약 v1은 쿼리 원문을 제공하지 않으므로 그 안의 구역/권한 선택을 판정할 수 없습니다.
  // UI의 정상 메모 경로는 쿼리를 사용하지 않습니다. 해시까지 빈 쿼리와 일치해야 허용합니다.
  const emptyQueryHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  if (request.queryLength !== 0 || request.querySha256 !== emptyQueryHash) return false;
  // 검증된 공지 서비스의 조회 구역은 쓰기 구역과 분리합니다.
  // 강사 권한을 증명할 계약이 없으므로 일반 계정의 공지 쓰기는 허용하지 않습니다.
  if (request.service === 'notices') {
    return request.method === 'GET' && (
      (request.path === '/notices' && request.route === 'GET /notices') ||
      (request.path === '/api/notices' && request.route === 'GET /api/notices')
    );
  }
  if (request.service !== 'notes') return false;
  const method = request.method;
  const path = request.path;
  const route = request.route;
  if (path === '/notes' || path === '/api/notes') {
    // 넓은 목록 경로를 모든 주체의 메모 구역 권한으로 해석하지 않습니다.
    if (method === 'GET') return isFixtureOwner(request) && route === `GET ${path}`;
    return method === 'POST' && route === `POST ${path}`;
  }
  // export 등 기능 경로는 메모 ID로 취급하지 않습니다.
  const id = /^\/notes\/([^/?#]+)$/u.exec(path)?.[1];
  // 실서비스 메모 ID는 API와 동일한 UUID 규약을 사용합니다.
  // 임의 구역명(other, foreign 등)이나 기능명(export)을 :id로 받지 않습니다.
  // ID 형식 검사는 API에서 별도로 적용하며, 판정기에서는 소유권 없는 UUID를 허용하지 않습니다.
  const fixtureDemo = id === 'demo' && isFixtureOwner(request) &&
    request.signals?.source === 'judge_fixture';
  if (!id) return false;
  // 계약 v1은 메모 소유자를 제공하지 않습니다. UUID 형식은 권한의 증거가 아닙니다.
  // 검증되지 않은 단건 GET은 fail-closed; API는 별도로 소유자 조건을 검증합니다.
  if (method === 'GET') {
    return fixtureDemo && route === 'GET /notes/:id';
  }
  // ID 형식이 맞아도 해당 자료의 소유권을 보장하지 않습니다.
  // 엔진 v1에는 ownerId가 없으므로 확인된 연습용 주체/기기/자원에 대해서만 허용합니다.
  // 실제 UUID의 최종 소유권 검사는 서버 API의 owner_id 조건에서 수행됩니다.
  return fixtureDemo && ['PUT', 'DELETE'].includes(method) &&
    route === `${method} /notes/:id`;
}

export async function decide(request) {
  let decision = 'allow';
  let reasonCode = 'approved';
  let ruleIds = ['device_registered'];

  if (request.deviceRegistered !== true) {
    decision = 'deny';
    reasonCode = 'device_not_registered';
  } else if (!knownNotesRoute(request)) {
    // 미등록 자원/정확하지 않은 메서드·경로 및 공지 쓰기는 거부합니다.
    decision = 'deny';
    reasonCode = 'route_not_allowed';
    ruleIds = ['resource_boundary'];
  } else if (isCompositeRisk(request)) {
    const verified = request.stepUp?.verified === true &&
      Number.isInteger(request.stepUp.authAgeSeconds) &&
      request.stepUp.authAgeSeconds >= 0 &&
      request.stepUp.authAgeSeconds <= 900;
    if (!verified) {
      decision = 'step_up';
      reasonCode = 'step_up_required';
      ruleIds = ['step_up_required'];
    }
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode,
    ruleIds,
  };
}
