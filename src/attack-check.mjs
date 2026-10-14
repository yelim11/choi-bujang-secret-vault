// Step 5-10 self-check: only record requests actually sent to the deployed app.
const appUrl = config => {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 확인해 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 확인해 주세요.');
  }
  return app;
};

const safeJson = async response => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const deniedJson = async response => {
  const data = await safeJson(response);
  const contentType = response.headers.get('content-type') || '';
  return [401, 403].includes(response.status)
    && /application\/json/iu.test(contentType)
    && typeof data?.error === 'string'
    && !Array.isArray(data)
    && !Array.isArray(data?.notes);
};

export async function runAttackChecks(config) {
  if (![5, 6, 7, 8, 9, 10].includes(config.step)) {
    throw new Error('5~10단계 공격 점검 설정을 확인해 주세요.');
  }

  const app = appUrl(config);
  const testId = '00000000-0000-4000-8000-000000000001';

  const [listResponse, itemResponse, manifestResponse, rootResponse] = await Promise.all([
    fetch(new URL('/api/notes', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    }),
    fetch(new URL(`/api/notes/${testId}`, app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    }),
    fetch(new URL('/aleph.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    }),
    fetch(app, {
      method: 'HEAD',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    }),
  ]);

  const listDenied = await deniedJson(listResponse);
  const itemDenied = await deniedJson(itemResponse);

  const manifest = manifestResponse.ok ? await safeJson(manifestResponse) : null;
  const manifestOpen = [5, 6, 7, 8, 9, 10].includes(manifest?.step)
    && typeof manifest?.commit === 'string'
    && manifest.commit.length === 40
    && Array.isArray(manifest?.allowedRoutes)
    && manifest.allowedRoutes.length > 0
    && manifest?.originalApiUrl === config.originalApiUrl;

  const nosniff = (rootResponse.headers.get('x-content-type-options') || '').toLowerCase() === 'nosniff';
  const csp = Boolean(rootResponse.headers.get('content-security-policy'));
  const rootProtected = rootResponse.ok && (nosniff || csp);

  const results = [
    {
      attackId: 'anonymous_note_list_denied',
      expected: '무로그인 목록 GET은 JSON 오류와 함께 401 또는 403',
      observed: listDenied
        ? `무로그인 /api/notes가 JSON 오류와 HTTP ${listResponse.status}로 거부됨`
        : `무로그인 목록 거부 검증 실패 (HTTP ${listResponse.status})`,
    },
    {
      attackId: 'anonymous_note_item_denied',
      expected: '무로그인 한 건 GET은 자료 없이 401 또는 403',
      observed: itemDenied
        ? `무로그인 /api/notes/:id가 JSON 오류와 HTTP ${itemResponse.status}로 거부됨`
        : `무로그인 한 건 거부 검증 실패 (HTTP ${itemResponse.status})`,
    },
    {
      attackId: 'deployment_manifest_available',
      expected: '배포 /aleph.json에 step 5~10, allowedRoutes, originalApiUrl이 있음',
      observed: manifestOpen
        ? '배포 /aleph.json에서 기존 단계와 허용 경로·원본 API 주소를 확인함'
        : `배포 manifest 확인 실패 (HTTP ${manifestResponse.status})`,
    },
    {
      attackId: 'root_security_header',
      expected: '첫 화면 응답에 nosniff 또는 Content-Security-Policy가 있음',
      observed: rootProtected
        ? `첫 화면 보안 헤더 확인 (${nosniff ? 'X-Content-Type-Options: nosniff' : 'Content-Security-Policy'})`
        : `첫 화면 보안 헤더 확인 실패 (HTTP ${rootResponse.status})`,
    },
  ];
  if (config.step >= 8) {
    const routes = manifest?.allowedRoutes;
    const hasZone = (service, method, pathPattern, zone) =>
      Array.isArray(routes) && routes.some(entry => entry?.service === service
        && entry.method === method && entry.pathPattern === pathPattern
        && entry.zone === zone);
    const hasRoute = (service, method, pathPattern) =>
      Array.isArray(routes) && routes.some(entry => entry?.service === service
        && entry.method === method && entry.pathPattern === pathPattern);
    const zonesCorrect = hasZone('notes', 'GET', '/api/notes/:id', 'my-notes')
      && hasZone('notes', 'PUT', '/api/notes/:id', 'my-notes')
      && hasZone('notes', 'DELETE', '/api/notes/:id', 'my-notes')
      && hasZone('notices', 'GET', '/api/notices', 'class-notices')
      && hasZone('notices', 'GET', '/api/notices/:id', 'class-notices')
      && !hasRoute('notes', 'GET', '/api/notes')
      && !hasRoute('notes', 'GET', '/api/my/notes')
      && !hasRoute('notes', 'POST', '/api/notes')
      && !['POST', 'PUT', 'PATCH', 'DELETE'].some(method =>
        hasRoute('notices', method, method === 'POST' ? '/api/notices' : '/api/notices/:id'));
    const [noticesList, noticesWrite] = await Promise.all([
      fetch(new URL('/api/notices', app), {
        redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { Accept: 'application/json' },
      }),
      fetch(new URL('/api/notices/' + testId, app), {
        method: 'PUT', redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'fixture', body: 'fixture', role: 'instructor' }),
      }),
    ]);
    const noticesReadDenied = await deniedJson(noticesList);
    const noticesWriteDenied = await deniedJson(noticesWrite);
    results.push(
      {
        attackId: 'deployed_resource_zones_verified',
        expected: '실제 배포 구역은 메모 단건만 허용하고 반 공지는 GET만 허용하며 쓰기 구역은 없음',
        observed: zonesCorrect
          ? '실제 /aleph.json에서 메모 단건과 공지 읽기만 허용된 것을 확인함'
          : '배포 구역 정의 검증 실패',
      },
      {
        attackId: 'anonymous_notices_denied',
        expected: '무로그인 강사 공지 목록 조회 거부',
        observed: noticesReadDenied
          ? `무로그인 /api/notices HTTP ${noticesList.status} 거부 확인`
          : `무로그인 공지 조회 거부 검증 실패 (HTTP ${noticesList.status})`,
      },
      {
        attackId: 'forged_notice_role_denied_anonymously',
        expected: '비인증 수정 요청의 role=instructor 위조에도 공지 수정 거부',
        observed: noticesWriteDenied
          ? `비인증 role 위조 공지 수정 HTTP ${noticesWrite.status} 거부 확인`
          : `비인증 공지 수정 거부 검증 실패 (HTTP ${noticesWrite.status})`,
      },
    );
  }

  if (config.step >= 9) {
    const { detect, proposeRevocation } = await import('./detect.mjs');
    const start = Date.UTC(2026, 9, 1, 0, 0, 0);
    const reads = (count, { deviceId = null, network = null, owner = 'learner_fixture' } = {}) =>
      Array.from({ length: count }, (_, index) => ({
        at: new Date(start + index * 2000).toISOString(),
        method: 'GET',
        identity: { sub: owner },
        ...(deviceId ? { deviceId } : {}),
        ...(network ? { signals: { network } } : {}),
        decision: 'allow',
      }));
    const deviceId = 'aaaaaaaaaaaaaaaa';
    const legacyBurst = detect(reads(121));
    const usualBurst = detect(reads(121, { deviceId, network: 'usual' }));
    const compositeBurst = detect(reads(121, { deviceId, network: 'unusual' }));
    const deviceProposal = proposeRevocation(reads(121, { deviceId, network: 'unusual' }));

    results.push(
      {
        attackId: 'detector_contract_burst',
        expected: '공식 연습 계약의 같은 가명 사용자 GET 121건은 propose_revocation·burst_read 제안',
        observed: `로컬 탐지기 결과: ${JSON.stringify(legacyBurst)} (실제 회수 아님)`,
      },
      {
        attackId: 'detector_composite_network',
        expected: '네트워크 정보가 있으면 평소 네트워크 폭주는 observe, 낯선 네트워크+폭주만 회수 제안',
        observed: `평소 ${JSON.stringify(usualBurst)} / 낯선 네트워크 ${JSON.stringify(compositeBurst)}`,
      },
      {
        attackId: 'detector_single_device_proposal',
        expected: '확인된 가상 기기 한 개에만 별도 회수 제안, 정상 기기 권한은 직접 변경하지 않음',
        observed: `로컬 별도 제안: ${JSON.stringify(deviceProposal)} (회수 API·권한 변경 없음)`,
      },
      {
        attackId: 'live_revocation',
        expected: '회수 뒤 신원·세션 재시도와 다른 자원 이동이 거부되고 경과 시간이 측정됨',
        observed: '미실행: 실제 회수와 경과 시간은 운영 반 엔진·심판의 가상 사건으로 확인',
      },
    );
  }

  if (config.step >= 10) {
    const restorePath=typeof config.restoreRoute==='string'?config.restoreRoute.split(' ')[1]?.replace(':id',testId):null;
    let restoreStatus=0;if(restorePath){const rr=await fetch(new URL(restorePath,app),{redirect:'error',signal:AbortSignal.timeout(10000),headers:{Accept:'application/json'}});restoreStatus=rr.status;}
    const {loadSnapshot,diffPolicy,currentPolicy}=await import('./policy-diff.mjs');
    let plan;
    try{
      const snapshot=loadSnapshot();
      const diff=diffPolicy(snapshot,currentPolicy(config));
      plan={ok:true,version:snapshot.version,changes:Array(diff.changed).fill(null)};
    }catch(error){
      plan={ok:false,error:error.message};
    }
    results.push(
      {attackId:'anonymous_restore_denied',expected:'로그인 없는 복구 경로 호출은 거부',observed:[401,403].includes(restoreStatus)?`비로그인 복구 HTTP ${restoreStatus} 거부 확인`:`복구 거부 확인 실패 (HTTP ${restoreStatus||'미호출'})`},
      {attackId:'safe_policy_snapshot_verified',expected:'안전 정책 사본 해시 검증 후 실행 전 변경 범위 확인',observed:plan.ok?`사본 ${plan.version} 검증, 현재 차이 ${plan.changes.length}개`:`사본 검증 실패: ${plan.error}`},
      {attackId:'restore_b_note',expected:'B 메모 한 건만 ID·소유자·내용 해시가 사본과 같게 복구',observed:'미실행: B 로그인 쓰기 요청은 심판 가상 사건으로 확인. 로컬 restore:test 별도'},
      {attackId:'post_restore_retest',expected:'복구 뒤 1~9단계 정상 요청 유지·금지 요청 재거부',observed:'미실행: 로그인 계정이 필요한 전체 재시험은 README 순서대로 별도 실행'}
    );
  }

  return results;
}
