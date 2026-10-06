import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { validateBundleNotes } from '../scripts/bundle-notes-validation.mjs';

const config = {
  step: 3,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl: 'https://student-defense.vercel.app',
  identityProvider: {
    issuer: 'https://student.supabase.co/auth/v1',
    audience: 'authenticated',
    jwksUrl: 'https://student.supabase.co/auth/v1/.well-known/jwks.json',
  },
  allowedRoutes: ['/api/notes', '/api/notes/:id'],
};

const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('step 3 deployment identity uses current Vercel metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 3,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
  });
});

test('step 3 self-check covers anonymous denial and all three bonus conditions', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init = {}) => {
      const path = new URL(String(url)).pathname;

      if (path === '/aleph.json') {
        return new Response(JSON.stringify({ step: 3, commit: 'a'.repeat(40) }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      if (path === '/') {
        return new Response('', {
          status: 200,
          headers: { 'x-content-type-options': 'nosniff' },
        });
      }

      if (path === '/api/notes' || path.startsWith('/api/notes/')) {
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
          status: 401,
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }

      return new Response('', { status: 404 });
    };

    const results = await runAttackChecks(config);
    assert.equal(results.length, 5);
    assert.match(results[0].observed, /401/u);
    assert.match(results[1].observed, /401/u);
    assert.match(results[2].observed, /401/u);
    assert.match(results[3].observed, /step 3/u);
    assert.match(results[4].observed, /nosniff/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('bundle explanation remains exactly three non-empty lines', () => {
  const explanation = [
    'Supabase Auth 로그인과 로그아웃을 붙이고 서버에서 토큰을 검증합니다.',
    '로그인 사용자는 Vercel API를 통해 가상 메모를 추가·수정·삭제합니다.',
    '3단계는 로그인만 확인하며 메모별 소유자 권한 검사는 4단계에서 추가합니다.',
  ].join('\n');
  assert.equal(validateBundleNotes({ explanation }, 3), explanation);
  assert.throws(() => validateBundleNotes({ explanation: '한 줄 설명' }, 3), /정확히 세 줄/u);
});
