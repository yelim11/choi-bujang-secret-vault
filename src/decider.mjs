// ALEPH SDP 엔진이 신원·기기·경로를 검증한 뒤 전달한 요청만 판정합니다.
// 실제 mTLS 인증서 확인과 subjectId/deviceId 바인딩은 운영 엔진의 책임입니다.
// 토큰, 기기 개인키, 자료 내용은 판정기에서 다루지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  const registered = request.deviceRegistered === true;
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}
