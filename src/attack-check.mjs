// Step 2 self-check: do not return tokens, private keys, real names, or note bodies.
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

  const [staticResponse, apiResponse] = await Promise.all([
    fetch(new URL('/data.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { accept: 'application/json' },
    }),
    fetch(new URL('/api/notes', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { accept: 'application/json' },
    }),
  ]);

  let staticClean = false;
  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      staticClean = Array.isArray(data?.notes)
        && data.notes.length === 0
        && Object.keys(data).length === 1;
    } catch {
      // Invalid JSON remains a failed self-check.
    }
  }

  let publicApiCount = null;
  if (apiResponse.ok) {
    try {
      const data = await apiResponse.json();
      if (Array.isArray(data?.notes)) publicApiCount = data.notes.length;
    } catch {
      // Invalid JSON remains a failed self-check.
    }
  }

  return [
    {
      attackId: 'static_note_seed_removed',
      expected: '공개 정적 data.json에는 빈 notes 배열만 남음',
      observed: staticClean
        ? '공개 정적 data.json에서 메모 시드와 1단계 확인 표시가 제거됨'
        : `공개 정적 자료 제거를 확인하지 못함 (HTTP ${staticResponse.status})`,
    },
    {
      attackId: 'anonymous_server_api_read',
      expected: '2단계에서는 비로그인 서버 API 조회 약점이 아직 남아 있음',
      observed: publicApiCount === 4
        ? '비로그인 서버 API에서 가상 메모 4건 반환을 확인함'
        : `비로그인 서버 API 결과를 확인할 필요가 있음 (HTTP ${apiResponse.status}, count ${publicApiCount ?? 'unknown'})`,
    },
  ];
}
