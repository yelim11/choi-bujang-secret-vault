import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import {
  UUID_PATTERN, parseResourceTarget, routeAllowed, hasVerifiedInstructorRole,
} from '../src/resource-policy.mjs';

function noStore(response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('CDN-Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

function safeBody(request) {
  let data = request.body;
  if (typeof data === 'string' && data.length <= 8192) {
    try { data = JSON.parse(data); } catch { return null; }
  }
  return data && typeof data === 'object' && !Array.isArray(data) ? data : null;
}

const publicNotice = row => ({ id: row.id, title: row.title, body: row.content });
let runtime;
function getRuntime() {
  if (runtime) return runtime;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return null;
  const supabase = createClient(url, key, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  runtime = { supabase, verifyLogin: createLoginVerifier({ config, supabaseClient: supabase }) };
  return runtime;
}

// 디펜스에서 검증한 학생 JWT에 연결된 서버측 app_metadata만 강사 신원 근거입니다.
// 현재 엔진 계약에 없는 role, 요청 본문 역할, user_metadata는 사용하지 않습니다.
export async function handleNoticesRequest(request, response, current) {
  noStore(response);
  if (!current) return response.status(503).json({ error: 'NOTICES_BACKEND_NOT_CONFIGURED' });
  const identity = await current.verifyLogin(request.headers?.authorization);
  if (!identity) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }
  const target = parseResourceTarget(request, 'notices');
  if (target.invalid) return response.status(400).json({ error: 'INVALID_RESOURCE_PATH' });
  if (!routeAllowed(config, target, request.method)) {
    return response.status(403).json({ error: 'RESOURCE_ZONE_DENIED' });
  }

  const db = current.supabase;
  if (request.method === 'GET') {
    let query = db.from('notices').select('id,title,content');
    query = target.id ? query.eq('id', target.id).maybeSingle()
      : query.order('created_at', { ascending: true }).order('id');
    const { data, error } = await query;
    if (error) return response.status(502).json({ error: 'NOTICES_BACKEND_ERROR' });
    if (target.id && !data) return response.status(404).json({ error: 'NOTICE_NOT_FOUND' });
    return response.status(200).json(target.id
      ? publicNotice(data) : (data ?? []).map(publicNotice));
  }

  // 순수 학생 계정 또는 심판 토큰은 이 구역을 수정할 수 없습니다.
  if (!await hasVerifiedInstructorRole(db, identity)) {
    return response.status(403).json({ error: 'INSTRUCTOR_REQUIRED' });
  }
  if (request.method === 'DELETE') {
    const { data, error } = await db.from('notices').delete()
      .eq('id', target.id).eq('owner_id', identity.userId)
      .select('id,owner_id').maybeSingle();
    if (error) return response.status(502).json({ error: 'NOTICES_BACKEND_ERROR' });
    if (!data || data.owner_id !== identity.userId) {
      return response.status(404).json({ error: 'NOTICE_NOT_FOUND' });
    }
    return response.status(200).json({ id: data.id });
  }

  const body = safeBody(request);
  if (!body || !Object.keys(body).every(key =>
    (request.method === 'POST' ? ['id', 'title', 'body'] : ['title', 'body']).includes(key))) {
    return response.status(400).json({ error: 'INVALID_NOTICE' });
  }
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  const content = typeof body.body === 'string' ? body.body.trim() : '';
  if (!title || title.length > 120 || !content || content.length > 2000) {
    return response.status(400).json({ error: 'INVALID_NOTICE' });
  }
  if (request.method === 'POST') {
    if (body.id !== undefined && (typeof body.id !== 'string'
        || !UUID_PATTERN.test(body.id))) {
      return response.status(400).json({ error: 'INVALID_NOTICE_ID' });
    }
    const newId = body.id ?? randomUUID();
    const { error } = await db.from('notices').insert({
      id: newId, owner_id: identity.userId, title, content,
    });
    if (error?.code === '23505') return response.status(409).json({ error: 'NOTICE_ID_EXISTS' });
    if (error) return response.status(502).json({ error: 'NOTICES_BACKEND_ERROR' });
    return response.status(201).json({ id: newId });
  }
  if (request.method === 'PUT') {
    const { data, error } = await db.from('notices').update({ title, content })
      .eq('id', target.id).eq('owner_id', identity.userId)
      .select('id,title,content,owner_id').maybeSingle();
    if (error) return response.status(502).json({ error: 'NOTICES_BACKEND_ERROR' });
    if (!data || data.owner_id !== identity.userId || data.id !== target.id) {
      return response.status(404).json({ error: 'NOTICE_NOT_FOUND' });
    }
    return response.status(200).json(publicNotice(data));
  }
  return response.status(403).json({ error: 'RESOURCE_ZONE_DENIED' });
}

export default async function handler(request, response) {
  return handleNoticesRequest(request, response, getRuntime());
}
