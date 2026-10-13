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
function knownNotesRoute(request) {
  if (request.service !== 'notes' || typeof request.path !== 'string') return false;
  const method = request.method;
  const path = request.path;
  const route = request.route;
  if (path === '/notes') {
    return (method === 'GET' && route === 'GET /notes')
      || (method === 'POST' && route === 'POST /notes');
  }
  // export 등 기능 경로는 메모 ID로 취급하지 않습니다.
  const id = /^\/notes\/([^/?#]+)$/u.exec(path)?.[1];
  if (!id || ['export', 'import', 'admin', 'notices'].includes(id)) return false;
  return ['GET', 'PUT', 'DELETE'].includes(method) &&
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
    // /notices 등 강사 공지 구역은 검증된 강사 권한 계약이 없으므로 허용하지 않습니다.
    decision = 'deny';
    reasonCode = 'resource_not_allowed';
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
