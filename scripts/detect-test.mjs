import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';

function reads(count, { intervalSeconds = 2, owner = subject, start = START,
  deviceId = null, network = null, decision = null } = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', identity: { sub: owner },
    ...(deviceId ? { deviceId } : {}),
    ...(network ? { signals: { network } } : {}),
    ...(decision ? { decision } : {}),
  }));
}

const cases = [
  { name: '정상 조회 30건', events: reads(30), expected: { action: 'observe' } },
  { name: '10분 안에 120건', events: reads(120), expected: { action: 'observe' } },
  { name: '10분 안에 121건', events: reads(121), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '폭주 조회 200건', events: reads(200), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '서로 다른 사용자 각 100건', events: [...reads(100),
    ...reads(100, { owner: 'other_fixture' })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '10분 밖으로 흩어진 조회 200건', events: reads(200,
    { intervalSeconds: 7 }), expected: { action: 'observe' } },
];

export async function checkDetection(detect) {
  if (typeof detect !== 'function') throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  const results = [];
  for (const item of cases) {
    const actual = await detect(item.events);
    const passed = isDeepStrictEqual(actual, item.expected);
    results.push({ name: item.name, passed: Boolean(passed) });
  }
  return results;
}

export async function checkCompositeDetection({ detect, proposeRevocation, readDetectionEvents }) {
  const device = 'aaaaaaaaaaaaaaaa';
  const results = [];
  const add = (name, passed) => results.push({ name, passed: Boolean(passed) });

  add('평소 네트워크의 121건은 정상 유지', isDeepStrictEqual(
    await detect(reads(121, { deviceId: device, network: 'usual', decision: 'allow' })),
    { action: 'observe' },
  ));
  add('낯선 네트워크와 121건이 겹치면 기기 회수 제안', isDeepStrictEqual(
    await detect(reads(121, { deviceId: device, network: 'unusual', decision: 'allow' })),
    { action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId: device },
  ));
  add('확인된 기기 하나만 별도 회수 대상으로 제안', isDeepStrictEqual(
    await proposeRevocation(reads(121, { deviceId: device, network: 'unusual' })),
    { action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId: device },
  ));
  const safe = readDetectionEvents([{ at: new Date(START).toISOString(), method: 'GET',
    identity: { sub: subject }, deviceId: device, decision: 'allow',
    signals: { network: 'unusual', region: 'foreign' }, token: 'do-not-copy', body: 'do-not-copy' }]);
  add('입력 정리 결과에 토큰·본문·지역을 보존하지 않음', safe.events.length === 1
    && !Object.hasOwn(safe.events[0], 'token') && !Object.hasOwn(safe.events[0], 'body')
    && !Object.hasOwn(safe.events[0], 'region'));
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const module = await import('../src/detect.mjs');
    const results = [
      ...await checkDetection(module.detect),
      ...await checkCompositeDetection(module),
    ];
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('가상 사건 연습이며 실제 접속 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`탐지 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
