// 보너스 xdr-01 저장점: 심판의 단독 decide 실행에서도 형제 파일 없이 동작합니다.
// 심판이 이 파일 하나만 격리해서 실행해도 동작하는 standalone 판정기입니다.
// patterns.json의 두 근거 패턴과 같은 기준을 사용하며 alert id로 정답을 분기하지 않습니다.

export async function decide(alert, options = {}) {
  const repeat = { name: 'rapid-same-source-failures', minimumCount: 30, minimumLevel: 10 };
  const spray = { name: 'password-spray', minimumLevel: 10 };
  const actionFor = (confidence) => confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  const askJev = options.askJev || (async () => null);
  const timeoutMs = options.timeoutMs ?? 1000;

  const safeText = (value) => typeof value === 'string'
    ? value
      .replace(/(?:Bearer\s+)?eyJ[A-Za-z0-9_.-]+|sb_(?:secret|publishable)_[A-Za-z0-9_-]+/gu, '[redacted]')
      .replace(/((?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+/giu, '$1[redacted]')
      .replace(/[\r\n]+/gu, ' ')
      .slice(0, 500)
    : '';

  const row = {
    timestamp: safeText(alert?.timestamp),
    source: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    level: Number(alert?.rule?.level) || 0,
    description: safeText(alert?.rule?.description),
  };

  const description = row.description;
  const count = Number(alert?.data?.count) || Number(description.match(/(\d+)건/u)?.[1]) || 0;
  const spraying = /여러 계정|서로 다른 계정|계정\s*\d+개|같은 비밀번호/u.test(description);
  const failure = /실패/u.test(description) || (spraying && /연속으로 넣|대입/u.test(description));
  const repeated = /짧은 시간|분 안|분 동안|같은 주소|같은 계정|연속|이어|비밀번호.*바꿔|성공은 없/u.test(description);
  const pattern = spraying ? spray : repeat;

  // 명확한 공격은 Jev에 묻지 않고 즉시 block 합니다.
  if (failure && row.source && row.account && row.level >= pattern.minimumLevel
      && (count >= repeat.minimumCount || spraying || repeated)) {
    return { action: 'block', confidence: 0.95, reason: pattern.name };
  }

  // 실패 신호가 없거나 낮은 수준의 정상 이벤트는 record 합니다.
  if (!failure || row.level <= 3) {
    return { action: 'record', confidence: 0.1, reason: 'normal-event' };
  }

  // 애매한 이벤트만 Jev 보조 판정을 사용하며, 무응답은 alert 입니다.
  let timer;
  try {
    const response = await Promise.race([
      askJev({ pattern: pattern.name, alert: row }),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(null), timeoutMs);
        timer.unref?.();
      }),
    ]);
    const confidence = typeof response === 'number' ? response : response?.confidence;
    if (typeof confidence !== 'number' || !Number.isFinite(confidence)
        || confidence < 0 || confidence > 1) {
      return { action: 'alert', confidence: 0.5, reason: `${pattern.name}: Jev unavailable` };
    }
    return { action: actionFor(confidence), confidence, reason: pattern.name };
  } catch {
    return { action: 'alert', confidence: 0.5, reason: `${pattern.name}: Jev unavailable` };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function createDecider(options = {}) {
  return (alert) => decide(alert, options);
}
