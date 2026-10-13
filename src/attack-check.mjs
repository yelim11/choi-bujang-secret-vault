// Step 5-8 self-check: only record requests actually sent to the deployed app.
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
  if (![5, 6, 7, 8].includes(config.step)) {
    throw new Error('5~8단계 공격 점검 설정을 확인해 주세요.');
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
  const manifestOpen = [5, 6, 7, 8].includes(manifest?.step)
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
      expected: '배포 /aleph.json에 step 5~8, allowedRoutes, originalApiUrl이 있음',
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
  if (config.step === 8) {
    const routes = manifest?.allowedRoutes;
    const hasZone = (service, method, pathPattern, zone) =>
      Array.isArray(routes) && routes.some(entry => entry?.service === service
        && entry.method === method && entry.pathPattern === pathPattern
        && entry.zone === zone);
    const zonesCorrect = hasZone('notes', 'GET', '/api/notes/:id', 'my-notes')
      && hasZone('notices', 'GET', '/api/notices', 'class-notices')
      && hasZone('notices', 'PUT', '/api/notices/:id', 'instructor-materials');
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
        expected: '실제 배포 구역에 notes 자기 메모와 notices 강사 공지 읽기·쓰기 구역이 분리됨',
        observed: zonesCorrect
          ? '실제 /aleph.json에서 메모/공지/강사 구역을 분리해서 확인함'
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
  return results;
}
