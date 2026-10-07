import patterns from './patterns.json' with { type: 'json' };
import { askJev } from './jev.mjs';
import { readAlerts } from './read-alerts.mjs';

const RAPID = patterns.patterns.find((item) => item.name === 'rapid-same-source-failures');
const SPRAY = patterns.patterns.find((item) => item.name === 'password-spray');

const SPRAY_HINT = /여러 계정|계정\s*\d+개|서로 다른 계정|계정 이름을 바꿔|같은 비밀번호/u;
const FAILURE_HINT = /로그인 실패|비밀번호.*실패|실패.*로그인/u;
const SHORT_OR_CLEAR_HINT = /\d+분 안|\d+분 동안|같은 주소|성공은 없습니다|같은 주소와 같은 계정|비밀번호를 한 글자씩/u;

const countOf = (alert) => {
  const value = Number.parseInt(alert?.data?.count, 10);
  return Number.isFinite(value) && value >= 0 ? value : null;
};

const isT1110 = (alert) => Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');

const actionFor = (confidence) => confidence >= 0.85
  ? 'block'
  : confidence >= 0.5
    ? 'alert'
    : 'record';

const reason = (pattern, detail) => `${pattern.name}: ${detail}`;

export async function decide(alert) {
  const level = Number(alert?.rule?.level) || 0;
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const count = countOf(alert);

  if (!isT1110(alert)) {
    return {
      action: 'record',
      confidence: 0.05,
      reason: 'no-supported-pattern: T1110 로그인 실패 패턴이 아님',
    };
  }

  const spray = level >= 10 && SPRAY_HINT.test(description);
  const rapid = level >= 10
    && count !== null
    && count >= 15
    && FAILURE_HINT.test(description)
    && (SHORT_OR_CLEAR_HINT.test(description) || count >= 50);

  if (spray) {
    const confidence = level >= 12 ? 0.94 : 0.9;
    return {
      action: 'block',
      confidence,
      reason: reason(SPRAY, '여러 계정에 반복되는 동일 비밀번호/로그인 서명이 명확함'),
    };
  }

  if (rapid) {
    const confidence = count >= 50 ? 0.96 : 0.88;
    return {
      action: 'block',
      confidence,
      reason: reason(RAPID, '짧은 시간의 고수준 반복 로그인 실패가 명확함'),
    };
  }

  const [safe] = await readAlerts({
    schema: 'aleph.xdr.fixture.v1',
    moduleKey: 'brute-force',
    alerts: [alert],
  });
  const candidate = SPRAY_HINT.test(description) ? SPRAY : RAPID;
  const jevConfidence = await askJev({
    alert: safe,
    pattern: {
      name: candidate.name,
      condition: candidate.condition,
      basis: candidate.basis,
    },
  });

  if (jevConfidence === null) {
    return {
      action: 'alert',
      confidence: 0.5,
      reason: reason(candidate, 'Jev 응답 없음; 차단하지 않고 확인 필요'),
    };
  }

  return {
    action: actionFor(jevConfidence),
    confidence: Number(jevConfidence.toFixed(2)),
    reason: reason(candidate, 'Jev 확신도에 따른 보조 판단'),
  };
}
