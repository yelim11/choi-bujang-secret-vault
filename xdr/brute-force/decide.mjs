import patterns from './patterns.json' with { type: 'json' };
import { askJev } from './jev.mjs';
import { readAlerts } from './read-alerts.mjs';

const RAPID = patterns.patterns.find((item) => item.name === 'rapid-same-source-failures');
const SPRAY = patterns.patterns.find((item) => item.name === 'password-spray');
const WINDOW_MS = 5 * 60 * 1000;
const AGGREGATE_BLOCK_COUNT = 30;
const windows = new Map();

const SPRAY_HINT = /여러 계정|계정\s*\d+개|서로 다른 계정|계정 이름을 바꿔|같은 비밀번호|same password|password\s*spray/iu;
const FAILURE_HINT = /로그인\s*실패|비밀번호[^\n]*실패|실패[^\n]*로그인|failed\s*(?:login|logon|authentication)|login\s*fail|authentication\s*fail/iu;
const SUCCESS_HINT = /성공|succeeded|successful/iu;
const NO_SUCCESS_HINT = /성공은\s*없|성공\s*없|no\s*success/iu;
const CLEAR_CONTEXT_HINT = /\d+분\s*(?:안|동안|내)|\d+초\s*(?:안|동안|내)|같은 주소|같은 출발|같은 계정|same\s*(?:source|address|account)|비밀번호를 한 글자씩|one character/iu;

const descriptionOf = (alert) => typeof alert?.rule?.description === 'string'
  ? alert.rule.description
  : typeof alert?.description === 'string' ? alert.description : '';

const levelOf = (alert) => {
  const value = Number(alert?.rule?.level ?? alert?.ruleLevel);
  return Number.isFinite(value) ? value : 0;
};

const sourceOf = (alert) => typeof alert?.data?.srcip === 'string'
  ? alert.data.srcip
  : typeof alert?.sourceAddress === 'string' ? alert.sourceAddress : '';

const accountOf = (alert) => typeof alert?.data?.srcuser === 'string'
  ? alert.data.srcuser
  : typeof alert?.account === 'string' ? alert.account : '';

const timestampOf = (alert) => typeof alert?.timestamp === 'string' ? alert.timestamp : '';

const countOf = (alert, description) => {
  const direct = Number.parseInt(alert?.data?.count, 10);
  if (Number.isFinite(direct) && direct >= 0) return direct;
  const values = [...description.matchAll(/(\d+)\s*건/gu)].map((match) => Number.parseInt(match[1], 10));
  return values.length ? Math.max(...values.filter(Number.isFinite)) : null;
};

const minutesOf = (description) => {
  const minutes = description.match(/(\d+)\s*분\s*(?:안|동안|내)?/u);
  if (minutes) return Number.parseInt(minutes[1], 10);
  const seconds = description.match(/(\d+)\s*초\s*(?:안|동안|내)?/u);
  if (seconds) return Number.parseInt(seconds[1], 10) / 60;
  return null;
};

const accountCountOf = (alert, description) => {
  const listed = typeof alert?.data?.accounts === 'string'
    ? new Set(alert.data.accounts.split(',').map((value) => value.trim()).filter(Boolean)).size
    : 0;
  const match = description.match(/계정\s*(\d+)\s*개/u);
  return Math.max(listed, match ? Number.parseInt(match[1], 10) : 0);
};

const mitreIdsOf = (alert) => {
  const mitre = alert?.rule?.mitre;
  if (Array.isArray(mitre)) return mitre.map(String);
  if (typeof mitre === 'string') return [mitre];
  if (Array.isArray(mitre?.id)) return mitre.id.map(String);
  if (typeof mitre?.id === 'string') return [mitre.id];
  return [];
};

const isT1110 = (alert) => mitreIdsOf(alert).some((value) => /^T1110(?:\.\d{3})?$/u.test(value));

const actionFor = (confidence) => confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
const reason = (pattern, detail) => `${pattern.name}: ${detail}`;

const observedFailures = (alert, failure) => {
  if (!failure) return 0;
  const source = sourceOf(alert);
  const account = accountOf(alert);
  const at = Date.parse(timestampOf(alert));
  if (!source || !account || !Number.isFinite(at)) return 0;
  const key = `${source}|${account}`;
  const fingerprint = typeof alert?.id === 'string' && alert.id
    ? alert.id
    : `${timestampOf(alert)}|${descriptionOf(alert)}`;
  const fresh = (windows.get(key) ?? []).filter((entry) => entry.at >= at - WINDOW_MS && entry.at <= at);
  if (!fresh.some((entry) => entry.fingerprint === fingerprint)) fresh.push({ at, fingerprint });
  windows.set(key, fresh.slice(-100));
  return fresh.length;
};

const safeAlertForJev = async (alert) => {
  if (typeof alert?.sourceAddress === 'string' && typeof alert?.account === 'string'
      && typeof alert?.ruleLevel === 'number' && typeof alert?.description === 'string') return alert;
  const [safe] = await readAlerts({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'brute-force', alerts: [alert] });
  return safe;
};

export async function decide(alert) {
  const level = levelOf(alert);
  const description = descriptionOf(alert);
  const count = countOf(alert, description);
  const minutes = minutesOf(description);
  const accounts = accountCountOf(alert, description);
  const t1110 = isT1110(alert);
  const failure = FAILURE_HINT.test(description);
  const successAfter = SUCCESS_HINT.test(description) && !NO_SUCCESS_HINT.test(description);
  const sprayHint = SPRAY_HINT.test(description);
  const clearContext = CLEAR_CONTEXT_HINT.test(description);
  const observed = observedFailures(alert, failure && (count === null || count <= 1));

  const spray = failure && sprayHint
    && ((accounts >= 8) || (/같은 비밀번호|same password|password\s*spray/iu.test(description)
      && /여러 계정|서로 다른 계정|multiple accounts|different accounts/iu.test(description)))
    && (t1110 || level >= 8 || accounts >= 8 || clearContext);

  const rapid = failure && count !== null
    && ((count >= 30 && (minutes === null || minutes <= 5))
      || (count >= 20 && !successAfter && (clearContext || minutes !== null && minutes <= 5))
      || count >= 50);

  const accumulated = observed >= AGGREGATE_BLOCK_COUNT;

  if (spray) {
    return { action: 'block', confidence: 0.93, reason: reason(SPRAY, '여러 계정에 같은 비밀번호를 반복 대입한 패턴이 명확함') };
  }
  if (rapid || accumulated) {
    return { action: 'block', confidence: count !== null && count >= 50 ? 0.96 : 0.9, reason: reason(RAPID, accumulated ? '5분 안 같은 주소·계정의 실패 누적이 차단 기준을 넘음' : '짧은 시간 반복 로그인 실패가 차단 기준을 넘음') };
  }

  if (!failure && !t1110) return { action: 'record', confidence: 0.05, reason: 'no-supported-pattern: T1110 로그인 실패 패턴이 아님' };
  if (!t1110 && successAfter && (count === null || count <= 1)) return { action: 'record', confidence: 0.1, reason: 'no-supported-pattern: 소수 실패 뒤 정상 로그인' };

  const safe = await safeAlertForJev(alert);
  const candidate = sprayHint ? SPRAY : RAPID;
  const jevConfidence = await askJev({ alert: safe, pattern: { name: candidate.name, condition: candidate.condition, basis: candidate.basis } });
  if (jevConfidence === null) return { action: 'alert', confidence: 0.5, reason: reason(candidate, 'Jev 응답 없음; 차단하지 않고 확인 필요') };
  return { action: actionFor(jevConfidence), confidence: Number(jevConfidence.toFixed(2)), reason: reason(candidate, 'Jev 확신도에 따른 보조 판단') };
}
