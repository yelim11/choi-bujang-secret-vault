// 9단계 탐지기: 판정기(decide)와 별개의 탐지 결과만 만듭니다.
// 공식 연습 계약(at, method, identity.sub)은 그대로 지원하고, 운영 가상 사건이 제공하는
// 기기·판정·네트워크는 형식이 맞을 때만 선택적으로 읽습니다. 메모 본문·토큰·실명은 복사하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const BURST_LIMIT = 120;
const REASON_CODE = 'burst_read';
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const DECISIONS = new Set(['allow', 'deny', 'step_up']);
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const PSEUDONYM = /^[^\s@]{1,200}$/u;
const SECRET_LIKE = /^(?:eyJ|Bearer|sb_secret_|sk-|-----BEGIN)/iu;

const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const safePseudonym = value => typeof value === 'string'
  && PSEUDONYM.test(value) && !SECRET_LIKE.test(value);

function readNetwork(event) {
  const raw = typeof event.network === 'string' ? event.network
    : plainObject(event.signals) && typeof event.signals.network === 'string'
      ? event.signals.network : null;
  if (raw === null || raw === '' || raw === 'unknown') return null;
  return raw === 'usual' ? 'usual' : 'unusual';
}

function readEvent(event) {
  if (!plainObject(event)) return null;
  const subject = plainObject(event.identity) ? event.identity.sub : undefined;
  const at = typeof event.at === 'string' ? Date.parse(event.at) : Number.NaN;
  const method = typeof event.method === 'string' ? event.method.toUpperCase() : '';
  if (!safePseudonym(subject) || !Number.isFinite(at) || !METHODS.has(method)) return null;
  return Object.freeze({
    at,
    method,
    subject,
    deviceId: typeof event.deviceId === 'string' && DEVICE_ID.test(event.deviceId)
      ? event.deviceId : null,
    decision: DECISIONS.has(event.decision) ? event.decision : null,
    network: readNetwork(event),
  });
}

export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const safe = [];
  let dropped = 0;
  for (const raw of events) {
    const item = readEvent(raw);
    if (item) safe.push(item);
    else dropped += 1;
  }
  safe.sort((a, b) => a.at - b.at);
  return Object.freeze({ events: Object.freeze(safe), dropped });
}

function firstSuspiciousWindow(readEvents) {
  const bySubject = new Map();
  for (const event of readEvents) {
    if (event.method !== 'GET') continue;
    const list = bySubject.get(event.subject) ?? [];
    list.push(event);
    bySubject.set(event.subject, list);
  }

  let found = null;
  for (const [subject, list] of bySubject) {
    const hasNetworkInfo = list.some(event => event.network !== null);
    let start = 0;
    for (let end = 0; end < list.length; end += 1) {
      while (list[end].at - list[start].at >= WINDOW_MS) start += 1;
      const windowEvents = list.slice(start, end + 1);
      if (windowEvents.length <= BURST_LIMIT) continue;
      // 운영 사건에 네트워크 정보가 있으면 '평소와 다른 네트워크 + 다량 조회'가 함께 있어야 합니다.
      // 공식 로컬 계약에는 네트워크 값이 없으므로 그 경우에는 문서의 120건 초과 규칙만 적용합니다.
      if (hasNetworkInfo && !windowEvents.some(event => event.network === 'unusual')) continue;
      const candidate = { subject, at: list[end].at, events: windowEvents };
      if (!found || candidate.at < found.at) found = candidate;
      break;
    }
  }
  return found;
}

function oneConfirmedDevice(windowEvents) {
  const devices = new Set(windowEvents.map(event => event.deviceId));
  return devices.size === 1 && !devices.has(null) ? [...devices][0] : null;
}

export function detect(events) {
  const { events: safeEvents } = readDetectionEvents(events);
  const found = firstSuspiciousWindow(safeEvents);
  if (!found) return { action: 'observe' };
  const result = {
    action: 'propose_revocation',
    reasonCode: REASON_CODE,
    subject: found.subject,
  };
  const deviceId = oneConfirmedDevice(found.events);
  if (deviceId) result.deviceId = deviceId;
  return result;
}

// 별도 회수 제안: 확인된 가상 기기가 정확히 한 개일 때만 기기 대상 제안을 냅니다.
// 실제 회수·세션 무효화·시간 측정은 하지 않습니다.
export function proposeRevocation(events) {
  const { events: safeEvents } = readDetectionEvents(events);
  const found = firstSuspiciousWindow(safeEvents);
  if (!found) return null;
  const deviceId = oneConfirmedDevice(found.events);
  if (!deviceId) return null;
  return Object.freeze({
    action: 'propose_revocation',
    reasonCode: REASON_CODE,
    subject: found.subject,
    deviceId,
  });
}
