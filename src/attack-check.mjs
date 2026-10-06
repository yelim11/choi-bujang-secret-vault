// Step 3 self-check: record only requests actually sent to the deployed app.
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
  if (config.step !== 3) {
    throw new Error('3단계 공격 점검 설정을 확인해 주세요.');
  }

  const app = appUrl(config);
  const testId = '00000000-0000-4000-8000-000000000001';

  const [listResponse, createResponse, itemResponse, manifestResponse, rootResponse] = await Promise.all([
    fetch(new URL('/api/notes', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    }),
    fetch(new URL('/api/notes', app), {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'attack-check', body: 'training-only' }),
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
  const createDenied = await deniedJson(createResponse);
  const itemDenied = await deniedJson(itemResponse);

  const manifest = manifestResponse.ok ? await safeJson(manifestResponse) : null;
  const manifestOpen = manifest?.step === 3
    && typeof manifest?.commit === 'string'
    && manifest.commit.length === 40;

  const nosniff = (rootResponse.headers.get('x-content-type-options') || '').toLowerCase() === 'nosniff';
  const csp = Boolean(rootResponse.headers.get('content-security-policy'));
  const rootProtected = rootResponse.ok && (nosniff || csp);

  return [
    {
      attackId: 'anonymous_note_list_denied',
      expected: '무로그인 목록 GET은 JSON 오류와 함께 401 또는 403',
      observed: listDenied
        ? `무로그인 /api/notes가 JSON 오류와 HTTP ${listResponse.status}로 거부됨`
        : `무로그인 목록 거부 검증 실패 (HTTP ${listResponse.status})`,
    },
    {
      attackId: 'anonymous_note_create_denied',
      expected: '무로그인 POST는 자료 추가 없이 401 또는 403',
      observed: createDenied
        ? `무로그인 POST /api/notes가 JSON 오류와 HTTP ${createResponse.status}로 거부됨`
        : `무로그인 추가 거부 검증 실패 (HTTP ${createResponse.status})`,
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
      expected: '배포 /aleph.json이 열리고 step 3 식별 정보가 있음',
      observed: manifestOpen
        ? '배포 /aleph.json에서 step 3과 배포 커밋 식별 정보를 확인함'
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
}
