import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { validateBundleNotes } from '../scripts/bundle-notes-validation.mjs';

const config = {
  step: 4,
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
};

const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('step 4 deployment identity uses current Vercel metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 4,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
  });
});

test('step 4 API source enforces verified owner on item operations', async () => {
  const source = await readFile(new URL('../api/notes.js', import.meta.url), 'utf8');
  assert.match(source, /ownedNote\(current\.supabase, id, identity\.userId\)/u);
  assert.match(source, /\.eq\('owner_id', identity\.userId\)/u);
  assert.doesNotMatch(source, /body\.owner_id/u);
  assert.match(source, /update\(\{ title, content, owner_id: identity\.userId \}\)/u);
});

test('step 4 self-check covers anonymous denial and all three bonus conditions', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async url => {
      const path = new URL(String(url)).pathname;

      if (path === '/aleph.json') {
        return new Response(JSON.stringify({ step: 4, commit: 'a'.repeat(40) }), {
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
    assert.match(results[2].observed, /step 4/u);
    assert.match(results[3].observed, /nosniff/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('bundle explanation remains exactly three non-empty lines', () => {
  const explanation = [
    '4단계에서 서버 API의 읽기·추가·수정·삭제를 검증된 사용자 owner_id로 제한했습니다.',
    'Supabase notes 테이블은 authenticated CRUD만 허용하고 RLS가 auth.uid()와 owner_id를 비교합니다.',
    '무로그인 JSON 401, /aleph.json, 첫 화면 nosniff 가점 조건도 그대로 유지합니다.',
  ].join('\n');

  assert.equal(validateBundleNotes({ explanation }, 4), explanation);
  assert.throws(
    () => validateBundleNotes({ explanation: '한 줄로만 작성한 충분히 긴 설명입니다.' }, 4),
    /정확히 세 줄/u,
  );
});
