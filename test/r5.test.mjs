import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 2,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('step 2 build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 2,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('step 2 attack check sees clean static data and public API weakness', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      if (path === '/data.json') {
        return new Response(JSON.stringify({ notes: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ notes: [{}, {}, {}, {}] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    const results = await runAttackChecks(config);
    assert.equal(results.length, 2);
    assert.match(results[0].observed, /제거됨/u);
    assert.match(results[1].observed, /4건/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
