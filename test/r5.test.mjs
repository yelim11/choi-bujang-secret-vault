import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { validateBundleNotes } from '../scripts/bundle-notes-validation.mjs';

const config = {
  step: 5,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl: 'https://student-defense.vercel.app',
  identityProvider: {
    issuer: 'https://student.supabase.co/auth/v1',
    audience: 'authenticated',
    jwksUrl: 'https://student.supabase.co/auth/v1/.well-known/jwks.json',
  },
  allowedRoutes: [
    'GET /api/notes',
    'POST /api/notes',
    'GET /api/notes/:id',
    'PUT /api/notes/:id',
    'DELETE /api/notes/:id',
  ],
  originalApiUrl: 'https://student.supabase.co/rest/v1/notes',
};

const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('step 5 deployment identity accepts current Vercel metadata', () => {
  assert.equal(deploymentIdentity(env, config).step, 5);
});

test('browser files contain no Supabase public key and use server routes', async () => {
  const [authClient, app] = await Promise.all([
    readFile(new URL('../public/auth-client.js', import.meta.url), 'utf8'),
    readFile(new URL('../public/app.js', import.meta.url), 'utf8'),
  ]);
  const code = authClient + app;
  assert.doesNotMatch(code, /sb_publishable_/u);
  assert.doesNotMatch(code, /SUPABASE_(?:PUBLISHABLE|ANON)_KEY/u);
  assert.doesNotMatch(code, /\/rest\/v1\/notes/u);
  assert.match(authClient, /\/api\/auth/u);
  assert.match(app, /\/api\/notes/u);
});

test('step 5 self-check covers manifest, anonymous denial, and security header', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async url => {
      const path = new URL(String(url)).pathname;

      if (path === '/aleph.json') {
        return new Response(JSON.stringify({
          step: 5,
          commit: 'a'.repeat(40),
          allowedRoutes: config.allowedRoutes,
          originalApiUrl: config.originalApiUrl,
        }), {
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
    assert.equal(results.length, 4);
    assert.match(results[0].observed, /401/u);
    assert.match(results[1].observed, /401/u);
    assert.match(results[2].observed, /허용 경로/u);
    assert.match(results[3].observed, /보안 헤더/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('bundle explanation remains exactly three non-empty lines', () => {
  const explanation = [
    '5단계에서 브라우저의 자료 요청을 Vercel 서버 함수로 모았습니다.',
    'PUBLIC·anon·authenticated의 notes 직접 권한을 회수하고 서버 역할 CRUD만 유지했습니다.',
    '/aleph.json allowedRoutes, 첫 화면 보안 헤더, 브라우저 공개 키 제거 조건을 유지합니다.',
  ].join('\n');

  assert.equal(validateBundleNotes({ explanation }, 5), explanation);
  assert.throws(
    () => validateBundleNotes({ explanation: '한 줄로만 작성한 충분히 긴 설명입니다.' }, 5),
    /정확히 세 줄/u,
  );
});
