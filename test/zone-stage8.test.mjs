import assert from 'node:assert/strict';
import { test } from 'node:test';
import config from '../aleph.config.json' with { type: 'json' };
import { decide, RULE_IDS } from '../src/decider.mjs';
import {
  parseResourceTarget, routeAllowed, belongsToVerifiedOwner, hasVerifiedInstructorRole,
} from '../src/resource-policy.mjs';
import { handleNoticesRequest } from '../api/notices.js';
import { handleNotesRequest } from '../api/notes.js';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const MEMO_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const MEMO_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTICE_A = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function mockDb({ instructor = false } = {}) {
  const rows = {
    notes: [
      { id: MEMO_A, owner_id: A, title: 'A', content: 'fake A' },
      { id: MEMO_B, owner_id: B, title: 'B', content: 'fake B' },
    ],
    notices: [{ id: NOTICE_A, owner_id: A, title: 'notice', content: 'fake notice' }],
  };
  const events = [];
  const db = {
    events,
    auth: { admin: { async getUserById(id) {
      return { data: { user: { id, app_metadata: instructor && id === A
        ? { role: 'instructor' } : { role: 'student' } } }, error: null };
    } } },
    from(table) {
      assert.ok(Object.hasOwn(rows, table));
      const filters = [];
      const builder = {
        select() { return builder; },
        eq(key, value) { filters.push([key, value]); return builder; },
        order() { return builder; },
        then(onFulfilled, onRejected) {
          const data = rows[table].filter(row => filters.every(([key, value]) => row[key] === value));
          return Promise.resolve({ data, error: null }).then(onFulfilled, onRejected);
        },
        async maybeSingle() {
          return { data: rows[table].find(row =>
            filters.every(([key, value]) => row[key] === value)) ?? null, error: null };
        },
        async insert(row) { rows[table].push(row); events.push(['insert', table]); return { error: null }; },
        update(changes) {
          const upd = { ...builder };
          upd.select = () => upd;
          upd.eq = (key, value) => { filters.push([key, value]); return upd; };
          upd.maybeSingle = async () => {
            const row = rows[table].find(item => filters.every(([key, value]) => item[key] === value));
            if (!row) return { data: null, error: null };
            Object.assign(row, changes); events.push(['update', table]);
            return { data: { ...row }, error: null };
          };
          return upd;
        },
        delete() {
          const del = { ...builder };
          del.select = () => del;
          del.eq = (key, value) => { filters.push([key, value]); return del; };
          del.maybeSingle = async () => {
            const index = rows[table].findIndex(item => filters.every(([key, value]) => item[key] === value));
            if (index < 0) return { data: null, error: null };
            const [row] = rows[table].splice(index, 1); events.push(['delete', table]);
            return { data: row, error: null };
          };
          return del;
        },
      };
      return builder;
    },
  };
  return db;
}

function response() {
  return { headers: {}, statusCode: 200,
    setHeader(name, value) { this.headers[name] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    end() { return this; },
  };
}

function deciderRequest(overrides = {}) {
  return {
    schema: 'aleph.decision.v1', requestId: 'req-' + Math.random(),
    classId: 'class_fixture', projectId: 'project_fixture', subjectId: 'learner_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa', service: 'notes', method: 'GET',
    path: '/notes/demo', route: 'GET /notes/:id', queryLength: 0,
    querySha256: EMPTY_SHA, at: new Date().toISOString(), policyRevision: 1,
    deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [], signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
    ...overrides,
  };
}

test('8단계 allowedRoutes는 판정기가 허용하는 5개 경로만 공개', () => {
  assert.equal(config.step, 8);
  assert.deepEqual(config.allowedRoutes, [
    { service: 'notes', method: 'GET', pathPattern: '/api/notes/:id', zone: 'my-notes' },
    { service: 'notes', method: 'PUT', pathPattern: '/api/notes/:id', zone: 'my-notes' },
    { service: 'notes', method: 'DELETE', pathPattern: '/api/notes/:id', zone: 'my-notes' },
    { service: 'notices', method: 'GET', pathPattern: '/api/notices', zone: 'class-notices' },
    { service: 'notices', method: 'GET', pathPattern: '/api/notices/:id', zone: 'class-notices' },
  ]);
});

test('8단계 판정기: 단건 메모 허용, 목록·생성·공지 쓰기·강사 자료 거부', async () => {
  assert.equal((await decide(deciderRequest())).decision, 'allow');
  assert.equal((await decide(deciderRequest({ path: '/notes/not-a-uuid' }))).decision, 'allow');
  assert.equal((await decide(deciderRequest({ path: '/notes', route: 'GET /notes' }))).decision, 'deny');
  assert.equal((await decide(deciderRequest({ method: 'POST', path: '/notes', route: 'POST /notes' }))).decision, 'deny');
  assert.equal((await decide(deciderRequest({ service: 'notices', path: '/notices', route: 'GET /notices' }))).decision, 'allow');
  assert.equal((await decide(deciderRequest({ service: 'notices', method: 'PUT', path: '/notices/n1', route: 'PUT /notices/:id' }))).decision, 'deny');
  assert.equal((await decide(deciderRequest({ service: 'instructor-materials', path: '/materials/m1', route: 'GET /materials/:id' }))).decision, 'deny');
  assert.ok((await decide(deciderRequest())).ruleIds.every(id => RULE_IDS.includes(id)));
});

test('8단계 자원 ID는 메모와 공지를 구분하고 config 허용 여부를 따른다', () => {
  const note = parseResourceTarget({ url: '/api/notes/' + MEMO_A, query: { id: MEMO_A } }, 'notes');
  const notice = parseResourceTarget({ url: '/api/notices/' + NOTICE_A }, 'notices');
  assert.equal(note.resourceId, 'notes:' + MEMO_A);
  assert.equal(notice.resourceId, 'notices:' + NOTICE_A);
  assert.equal(routeAllowed(config, note, 'GET'), true);
  assert.equal(routeAllowed(config, notice, 'GET'), true);
  assert.equal(routeAllowed(config, notice, 'PUT'), false);
  assert.equal(routeAllowed(config, parseResourceTarget({ url: '/api/my/notes' }, 'notes'), 'GET'), false);
  assert.equal(routeAllowed(config, parseResourceTarget({ url: '/api/notes' }, 'notes'), 'POST'), false);
  assert.equal(belongsToVerifiedOwner({ owner_id: A }, { userId: B }), false);
});

test('8단계 실제 메모 API는 A/B 소유권을 다시 확인하고 기존 본인 목록을 유지', async () => {
  const db = mockDb();
  const current = { supabase: db, verifyLogin: async token =>
    token === 'A' ? { kind: 'student', userId: A }
      : token === 'B' ? { kind: 'student', userId: B } : null };
  const call = (token, method, url, body) => handleNotesRequest({
    method, url, headers: { authorization: token }, ...(body ? { body } : {}),
  }, response(), current);
  assert.equal((await call('A', 'GET', '/api/notes/' + MEMO_A)).statusCode, 200);
  assert.equal((await call('B', 'GET', '/api/notes/' + MEMO_A)).statusCode, 404);
  assert.deepEqual((await call('A', 'GET', '/api/my/notes')).body.map(row => row.id), [MEMO_A]);
  assert.deepEqual((await call('B', 'GET', '/api/notes')).body.map(row => row.id), [MEMO_B]);
  const created = await call('A', 'POST', '/api/notes', { title: 'new', body: 'body' });
  assert.equal(created.statusCode, 201);
});

test('8단계 공지 쓰기는 판정기가 아니라 서버의 검증된 강사 권한에서만 처리', async () => {
  const studentDb = mockDb({ instructor: false });
  const student = { supabase: studentDb, verifyLogin: async () => ({ kind: 'student', userId: A }) };
  const forged = await handleNoticesRequest({
    method: 'PUT', url: '/api/notices/' + NOTICE_A,
    headers: { authorization: 'student' }, body: { title: 'x', body: 'y', role: 'instructor' },
  }, response(), student);
  assert.equal(forged.statusCode, 403);
  assert.equal(forged.body.error, 'INSTRUCTOR_REQUIRED');

  const instructorDb = mockDb({ instructor: true });
  const instructor = { supabase: instructorDb, verifyLogin: async () => ({ kind: 'student', userId: A }) };
  const own = await handleNoticesRequest({
    method: 'PUT', url: '/api/notices/' + NOTICE_A,
    headers: { authorization: 'instructor' }, body: { title: 'updated', body: 'content' },
  }, response(), instructor);
  assert.equal(own.statusCode, 200);
  assert.equal(await hasVerifiedInstructorRole(instructorDb, { kind: 'student', userId: A }), true);
});
