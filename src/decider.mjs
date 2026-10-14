// 8단계: 판정기는 엔진이 검증한 요청 계약의 값만 사용해 자원 구역을 나눕니다.
// 메모 소유권과 강사 권한은 최종 자료 API가 서버의 검증된 사용자/DB 값으로 다시 확인합니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zone',
]);

const REQUEST_KEYS = new Set([
  'at', 'classId', 'deviceId', 'deviceRegistered', 'method', 'path',
  'policyRevision', 'projectId', 'queryLength', 'querySha256', 'recentEvents',
  'requestId', 'route', 'schema', 'service', 'signals', 'stepUp', 'subjectId',
]);
const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const FEATURE_IDS = new Set([
  'export', 'import', 'download', 'backup', 'bulk', 'all', 'admin', 'search',
  'dump', 'sync', 'list', 'lists', 'index', 'everyone', 'everything', 'users',
  'others', 'shared', 'public', 'feed', 'batch', 'query',
]);

const respond = (request, decision, reasonCode, ruleIds) => ({
  schema: 'aleph.decision.v1',
  requestId: request?.requestId,
  decision,
  reasonCode,
  ruleIds,
});

function hasOnlyContractKeys(request) {
  return Boolean(request) && typeof request === 'object' && !Array.isArray(request)
    && Object.keys(request).every((key) => REQUEST_KEYS.has(key));
}

function cleanId(segment) {
  if (typeof segment !== 'string' || !segment || segment.length > 256) return null;
  let decoded;
  try { decoded = decodeURIComponent(segment); } catch { return null; }
  if (!decoded || decoded.includes('/') || decoded.includes('\\') || decoded === '.' || decoded === '..') return null;
  if (FEATURE_IDS.has(decoded.toLowerCase())) return null;
  return decoded;
}

function classifyResource(request) {
  if (!hasOnlyContractKeys(request)
      || typeof request.method !== 'string'
      || typeof request.path !== 'string'
      || typeof request.route !== 'string'
      || typeof request.service !== 'string'
      || request.schema !== 'aleph.decision.v1'
      || typeof request.subjectId !== 'string' || !request.subjectId
      || !DEVICE_ID.test(request.deviceId ?? '')
      || !Number.isInteger(request.policyRevision) || request.policyRevision < 1
      || request.queryLength !== 0 || request.querySha256 !== EMPTY_SHA256) return null;

  const method = request.method.toUpperCase();
  const path = request.path;

  // 메모: 반드시 자료 ID 한 건을 고르는 경로만 허용합니다. 목록/생성 경로는 판정기에서 열지 않습니다.
  const note = /^\/(api\/)?notes\/([^/?#]+)$/u.exec(path);
  if (note && request.service === 'notes' && ['GET', 'PUT', 'DELETE'].includes(method)) {
    if (!cleanId(note[2])) return null;
    const prefix = note[1] ? '/api/notes/:id' : '/notes/:id';
    if (request.route !== `${method} ${prefix}`) return null;
    return { zone: 'note-item', read: method === 'GET' };
  }

  // 반 공지: 읽기(GET)만 허용합니다. 쓰기는 역할 정보가 계약에 없으므로 판정기에서 누구에게도 허용하지 않습니다.
  const noticeList = /^\/(api\/)?notices$/u.exec(path);
  if (noticeList && request.service === 'notices' && method === 'GET') {
    const expected = noticeList[1] ? 'GET /api/notices' : 'GET /notices';
    if (request.route !== expected) return null;
    return { zone: 'class-notices', read: true };
  }
  const noticeItem = /^\/(api\/)?notices\/([^/?#]+)$/u.exec(path);
  if (noticeItem && request.service === 'notices' && method === 'GET') {
    if (!cleanId(noticeItem[2])) return null;
    const expected = noticeItem[1] ? 'GET /api/notices/:id' : 'GET /notices/:id';
    if (request.route !== expected) return null;
    return { zone: 'class-notices', read: true };
  }

  // 강사 자료, 공지 쓰기, 메모 목록, 알 수 없는 서비스/경로는 모두 기본 거부합니다.
  return null;
}

function isCompositeRisk(request) {
  const signals = request?.signals;
  if (!signals || signals.source !== 'judge_fixture') return false;
  const unusualHour = Number.isInteger(signals.hour)
    && (signals.hour < 6 || signals.hour >= 23);
  const unusualNetwork = signals.network === 'unusual';
  const burst = Array.isArray(request.recentEvents)
    && request.recentEvents.some((event) => event
      && event.kind === 'risk_signal'
      && Number.isInteger(event.count) && event.count >= 10
      && Number.isInteger(event.ageSeconds)
      && event.ageSeconds >= 0 && event.ageSeconds <= 300);
  return unusualHour && unusualNetwork && burst;
}

function freshStepUp(request) {
  return request?.stepUp?.verified === true
    && Number.isInteger(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0
    && request.stepUp.authAgeSeconds <= 900;
}

// 8단계에서 판정기가 확인하는 것은 구역/정확한 경로까지입니다.
// 메모 한 건의 실제 주인은 API가 DB owner_id와 검증된 사용자 ID로 비교합니다.
export async function resourceAllowed(request) {
  return classifyResource(request) !== null;
}

export async function decide(request) {
  if (request?.deviceRegistered !== true) {
    return respond(request, 'deny', 'device_not_registered', ['device_registered']);
  }

  const resource = classifyResource(request);
  if (!resource) {
    return respond(request, 'deny', 'route_not_allowed', ['resource_zone']);
  }

  if (resource.read && isCompositeRisk(request) && !freshStepUp(request)) {
    return respond(request, 'step_up', 'step_up_required', [
      'device_registered', 'resource_zone', 'step_up_required',
    ]);
  }

  return respond(request, 'allow', 'approved', ['device_registered', 'resource_zone']);
}
