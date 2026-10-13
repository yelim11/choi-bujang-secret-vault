import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import config from '../aleph.config.json' with { type: 'json' };
import {
  parseResourceTarget, routeAllowed, belongsToVerifiedOwner, hasVerifiedInstructorRole,
} from '../src/resource-policy.mjs';
import { createTrustedEngineResourceCheck } from '../src/engine-resource-access.mjs';
import { handleNoticesRequest } from '../api/notices.js';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const MEMO_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const MEMO_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTICE_A = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function mockDb({ instructor = false, expired = false } = {}) {
  const bindings = [
    { class_id: 'cl', project_id: 'p', subject_id: 'subject_a',
      device_id: 'a'.repeat(16), user_id: A, enabled: true,
      expires_at: new Date(Date.now() + (expired ? -1000 : 90000)).toISOString() },
    { class_id: 'cl', project_id: 'p', subject_id: 'subject_b',
      device_id: 'b'.repeat(16), user_id: B, enabled: true,
      expires_at: new Date(Date.now() + 90000).toISOString() },
  ];
  const rows = {
    sdp_principal_bindings: bindings,
    notes: [
      { id: MEMO_A, owner_id: A, title: 'A', content: 'fake A' },
      { id: MEMO_B, owner_id: B, title: 'B', content: 'fake B' },
    ],
    notices: [{ id: NOTICE_A, owner_id: A, title: 'test', content: 'fake' }],
  };
  const events = [];
  const db = {
    events,
    auth: { admin: { async getUserById(id) {
      events.push(['admin.getUserById', id]);
      return { data: { user: { id, app_metadata: instructor && id === A
        ? { role: 'instructor' } : { role: 'student' } } }, error: null };
    } } },
    from(table) {
      assert.ok(Object.hasOwn(rows, table), 'unexpected table ' + table);
      const filters = [];
      const builder = {
        select() { return builder; },
        eq(column, value) { filters.push([column, value]); return builder; },
        order() { return builder; },
        async maybeSingle() {
          events.push([table, ...filters]);
          return { data: rows[table].find(row =>
            filters.every(([key, value]) => row[key] === value)) ?? null, error: null };
        },
        async insert(row) {
          events.push(['insert', table]);
          rows[table].push(row);
          return { error: null };
        },
        update(changes) {
          events.push(['update', table]);
          const upd = { ...builder };
          upd.maybeSingle = async () => {
            const existing = rows[table].find(row =>
              filters.every(([key, value]) => row[key] === value));
            if (!existing) return { data: null, error: null };
            Object.assign(existing, changes);
            return { data: { ...existing }, error: null };
          };
          upd.select = () => upd;
          upd.eq = (key, value) => { filters.push([key, value]); return upd; };
          return upd;
        },
        delete() {
          events.push(['delete', table]);
          return builder;
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
  };
}

function engineReq({ subjectId = 'subject_a', deviceId = 'a'.repeat(16),
  method = 'GET', path = '/notes/' + MEMO_A, service = 'notes' } = {}) {
  const part = path.split('/');
  const item = part.length === 3 || part.length === 4;
  return { schema: 'aleph.decision.v1', requestId: randomUUID(),
    classId: 'cl', projectId: 'p', subjectId, deviceId, service, method, path,
    route: method + ' /' + (path.startsWith('/api/') ? 'api/' : '') + service
      + (item ? '/:id' : ''),
    queryLength: 0, querySha256: EMPTY_SHA, at: new Date().toISOString(),
    policyRevision: 1, deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null },
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 },
    recentEvents: [],
  };
}

test('8단계 정확한 메모/공지 경로와 typed 자원 ID', () => {
  const target = parseResourceTarget({ url: '/api/notes/' + MEMO_A, query: { id: MEMO_A } }, 'notes');
  assert.equal(target.resourceId, 'notes:' + MEMO_A);
  assert.ok(routeAllowed(config, target, 'GET'));
  assert.ok(routeAllowed(config, target, 'PUT'));
  assert.equal(routeAllowed(config, target, 'POST'), false);
  const notice = parseResourceTarget({ url: '/api/notices/' + NOTICE_A }, 'notices');
  assert.equal(notice.resourceId, 'notices:' + NOTICE_A);
  assert.ok(routeAllowed(config, notice, 'GET'));
  assert.ok(routeAllowed(config, notice, 'PUT'));
  assert.equal(routeAllowed(config, notice, 'POST'), false);
  assert.equal(belongsToVerifiedOwner({ owner_id: A }, { userId: B }), false);
});

test('8단계 export/중복 id/알 수 없는 쿼리/대상 충돌은 거부', () => {
  const paths = [
    { url: '/api/notes/export' },
    { url: '/api/notes/' + MEMO_A + '/export' },
    { url: '/api/notes/' + MEMO_A, query: { id: MEMO_B } },
    { url: '/api/notes?id=' + MEMO_A + '&id=' + MEMO_B },
    { url: '/api/notes?role=instructor' },
    { url: '/api/notes/%65xport' },
    { url: '/api/notices/' + NOTICE_A + '?owner_id=' + A },
  ];
  for (const item of paths) {
    const kind = item.url.startsWith('/api/notices') ? 'notices' : 'notes';
    assert.equal(parseResourceTarget(item, kind).invalid, true, item.url);
  }
});

test('8단계 서버 등록부: A 자기 메모 허용, B는 A 메모 거부', async () => {
  const db = mockDb();
  const check = createTrustedEngineResourceCheck(db);
  assert.equal(await check(engineReq()), true);
  assert.equal(await check(engineReq({ subjectId: 'subject_b',
    deviceId: 'b'.repeat(16) })), false);
  assert.equal(await check(engineReq({ subjectId: 'subject_b',
    deviceId: 'b'.repeat(16), path: '/notes/' + MEMO_B })), true);
  assert.equal(await check(engineReq({ path: '/notes/' + MEMO_A, method: 'PUT' })), true);
  assert.equal(await check(engineReq({ path: '/notes/' + MEMO_A, method: 'DELETE' })), true);
  assert.equal(await check(engineReq({ subjectId: 'subject_a',
    deviceId: 'b'.repeat(16) })), false);
});

test('8단계 서버 등록부: 만료와 알 수 없는 요청은 기본 거부', async () => {
  const db = mockDb({ expired: true });
  const check = createTrustedEngineResourceCheck(db);
  assert.equal(await check(engineReq()), false);
  const unknown = engineReq();
  unknown.path = '/notes/export';
  assert.equal(await check(unknown), false);
  const query = engineReq();
  query.queryLength = 4;
  assert.equal(await check(query), false);
});

test('8단계 강사 권한은 서버 admin app_metadata로만 판단', async () => {
  const db = mockDb({ instructor: true });
  assert.equal(await hasVerifiedInstructorRole(db, { kind: 'student', userId: A }), true);
  assert.equal(await hasVerifiedInstructorRole(db, { kind: 'judge', userId: A }), false);
  assert.equal(await hasVerifiedInstructorRole(db, { kind: 'student', userId: B }), false);
  const check = createTrustedEngineResourceCheck(db);
  assert.equal(await check(engineReq({ method: 'PUT', path: '/notices/' + NOTICE_A,
    service: 'notices' })), true);
  assert.equal(await check(engineReq({ method: 'PUT', path: '/notices/' + NOTICE_A,
    service: 'notices', subjectId: 'subject_b', deviceId: 'b'.repeat(16) })), false);
});

test('8단계 API: 학생 role 위조로 강사 공지 수정 불가', async () => {
  const db = mockDb({ instructor: false });
  const current = { supabase: db, verifyLogin: async token =>
    token === 'mock-student' ? { kind: 'student', userId: A } : null };
  const req = { url: '/api/notices/' + NOTICE_A, method: 'PUT',
    headers: { authorization: 'mock-student' },
    body: { title: 'changed', body: 'fake', role: 'instructor' } };
  const out = await handleNoticesRequest(req, response(), current);
  assert.equal(out.statusCode, 403);
  assert.equal(out.body.error, 'INSTRUCTOR_REQUIRED');
  assert.equal(db.events.some(event => event[0] === 'update'), false);
});

test('8단계 API: 관리자 인증 강사만 자기 공지 수정, 타인 공지 거부', async () => {
  const db = mockDb({ instructor: true });
  const current = { supabase: db, verifyLogin: async token =>
    token === 'mock-instructor' ? { kind: 'student', userId: A } : null };
  const base = { method: 'PUT', headers: { authorization: 'mock-instructor' },
    body: { title: 'updated', body: 'content' } };
  const own = await handleNoticesRequest({ ...base,
    url: '/api/notices/' + NOTICE_A }, response(), current);
  assert.equal(own.statusCode, 200);
  const foreign = await handleNoticesRequest({ ...base,
    url: '/api/notices/' + MEMO_B }, response(), current);
  assert.equal(foreign.statusCode, 404);
  assert.equal((await handleNoticesRequest({ ...base, method: 'GET',
    headers: {} }, response(), current)).statusCode, 401);
});
