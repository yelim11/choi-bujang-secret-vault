// Step 2 self-check: do not return tokens, private keys, real names, or note bodies.
const safeJson = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

export async function runAttackChecks(config) {
  if (config.step !== 2) {
    throw new Error('2단계 공격 점검 설정을 확인해 주세요.');
  }

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const [staticResponse, identityResponse, apiResponse] = await Promise.all([
    fetch(new URL('/data.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    }),
    fetch(new URL('/aleph.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    }),
    fetch(new URL('/api/notes', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    }),
  ]);

  const staticCache = staticResponse.headers.get('cache-control') || '';
  const staticData = staticResponse.ok ? await safeJson(staticResponse) : null;
  const staticClean = Array.isArray(staticData?.notes)
    && staticData.notes.length === 0
    && Object.keys(staticData).length === 1
    && /\bno-store\b/iu.test(staticCache);

  const identityCache = identityResponse.headers.get('cache-control') || '';
  const identityData = identityResponse.ok ? await safeJson(identityResponse) : null;
  const expectedIdentityKeys = ['commit', 'judgeIssuer', 'publicAppUrl', 'repoUrl', 'schema', 'step'];
  const identityClean = identityData?.step === 2
    && Object.keys(identityData).sort().join(',') === expectedIdentityKeys.sort().join(',')
    && /\bno-store\b/iu.test(identityCache);

  const apiCache = apiResponse.headers.get('cache-control') || '';
  const apiData = apiResponse.ok ? await safeJson(apiResponse) : null;
  const publicApiCount = Array.isArray(apiData?.notes) ? apiData.notes.length : null;
  const apiNoStore = /\bno-store\b/iu.test(apiCache);

  return [
    {
      attackId: 'static_note_seed_removed',
      expected: '공개 정적 /data.json은 notes=[]만 반환하고 no-store',
      observed: staticClean
        ? '정적 /data.json은 notes=[]만 반환하고 Cache-Control=no-store'
        : `정적 /data.json 검증 실패 (HTTP ${staticResponse.status}, Cache-Control=${staticCache || '없음'})`,
    },
    {
      attackId: 'deployment_manifest_clean',
      expected: '2단계 /aleph.json은 현재 배포 식별 정보만 반환하고 no-store',
      observed: identityClean
        ? '2단계 /aleph.json은 현재 배포 식별 정보만 포함하고 Cache-Control=no-store'
        : `/aleph.json 검증 실패 (HTTP ${identityResponse.status}, Cache-Control=${identityCache || '없음'})`,
    },
    {
      attackId: 'anonymous_server_api_read',
      expected: '2단계에서는 비로그인 /api/notes 4건 조회 약점이 남고 no-store',
      observed: publicApiCount === 4 && apiNoStore
        ? '비로그인 /api/notes에서 가상 메모 4건 반환·Cache-Control=no-store'
        : `비로그인 서버 API 검증 필요 (HTTP ${apiResponse.status}, count ${publicApiCount ?? 'unknown'}, Cache-Control=${apiCache || '없음'})`,
    },
  ];
}
