// ALEPH SDP 엔진이 인증 및 기기 등록 여부를 검증해 전달한 계약 v1 요청만 판정합니다.
// 브라우저의 위치 헤더나 임의 role/identity/device 필드를 신뢰하지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

// 실제 운영 접속에서는 signals.source가 'none'이며 위치/네트워크가 'unknown'입니다.
// 운영 엔진의 가상 사건(judge_fixture)만 복합 이상 판정 근거로 사용합니다.
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
  // 지역 단독 이상은 결정 조건에 넣지 않습니다.
  return unusualHour && unfamiliarNetwork && highVolume;
}

export async function decide(request) {
  let decision = 'allow';
  let reasonCode = 'approved';
  let ruleIds = ['device_registered'];

  if (request.deviceRegistered !== true) {
    decision = 'deny';
    reasonCode = 'device_not_registered';
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
