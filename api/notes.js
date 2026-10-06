import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function noStore(response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('CDN-Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

function jsonBody(request) {
  if (request.body && typeof request.body === 'object' && !Array.isArray(request.body)) return request.body;
  if (typeof request.body === 'string' && request.body.length <= 8192) {
    try {
      const parsed = JSON.parse(request.body);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {}
  }
  return null;
}

function noteText(value, maxLength) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized && normalized.length <= maxLength ? normalized : null;
}

function noteId(request) {
  const value = request.query?.id;
  const candidate = Array.isArray(value) ? value[0] : value;
  if (candidate == null || candidate === '') return null;
  return typeof candidate === 'string' && UUID.test(candidate) ? candidate : false;
}

let runtime;
function getRuntime() {
  if (runtime) return runtime;

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return null;

  const supabase = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  const verifyLogin = createLoginVerifier({ config, supabaseClient: supabase });
  runtime = { supabase, verifyLogin };
  return runtime;
}

const publicNote = row => ({ id: row.id, title: row.title, body: row.content });

export default async function handler(request, response) {
  noStore(response);

  const current = getRuntime();
  if (!current) return response.status(503).json({ error: 'NOTES_BACKEND_NOT_CONFIGURED' });

  const identity = await current.verifyLogin(request.headers?.authorization);
  if (!identity) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }

  const id = noteId(request);
  if (id === false) return response.status(400).json({ error: 'INVALID_NOTE_ID' });

  if (id === null) {
    if (request.method === 'GET') {
      const { data, error } = await current.supabase
        .from('notes')
        .select('id,title,content')
        .eq('owner_id', identity.userId)
        .order('created_at', { ascending: true })
        .order('id', { ascending: true });

      if (error) return response.status(502).json({ error: 'NOTES_BACKEND_ERROR' });
      return response.status(200).json((data ?? []).map(publicNote));
    }

    if (request.method === 'POST') {
      const body = jsonBody(request);
      const allowed = body && Object.keys(body).every(key => ['id', 'title', 'body'].includes(key));
      if (!allowed) return response.status(400).json({ error: 'INVALID_NOTE' });

      const title = noteText(body.title, 120);
      const content = noteText(body.body, 2000);
      const suppliedId = body.id ?? null;
      if (!title || !content
          || (suppliedId !== null && (typeof suppliedId !== 'string' || !UUID.test(suppliedId)))) {
        return response.status(400).json({ error: 'INVALID_NOTE' });
      }

      const idToInsert = suppliedId ?? randomUUID();
      const { error } = await current.supabase.from('notes').insert({
        id: idToInsert,
        owner_id: identity.userId,
        title,
        content,
      });

      if (error?.code === '23505') return response.status(409).json({ error: 'NOTE_ID_EXISTS' });
      if (error) return response.status(502).json({ error: 'NOTES_BACKEND_ERROR' });
      return response.status(201).json({ id: idToInsert });
    }

    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  if (request.method === 'GET') {
    const { data, error } = await current.supabase
      .from('notes')
      .select('id,title,content')
      .eq('id', id)
      .maybeSingle();

    if (error) return response.status(502).json({ error: 'NOTES_BACKEND_ERROR' });
    if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    return response.status(200).json(publicNote(data));
  }

  if (request.method === 'PUT') {
    const body = jsonBody(request);
    const allowed = body && Object.keys(body).every(key => ['title', 'body'].includes(key));
    if (!allowed) return response.status(400).json({ error: 'INVALID_NOTE' });

    const title = noteText(body.title, 120);
    const content = noteText(body.body, 2000);
    if (!title || !content) return response.status(400).json({ error: 'INVALID_NOTE' });

    const { data, error } = await current.supabase
      .from('notes')
      .update({ title, content })
      .eq('id', id)
      .select('id,title,content')
      .maybeSingle();

    if (error) return response.status(502).json({ error: 'NOTES_BACKEND_ERROR' });
    if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    return response.status(200).json(publicNote(data));
  }

  if (request.method === 'DELETE') {
    const { data, error } = await current.supabase
      .from('notes')
      .delete()
      .eq('id', id)
      .select('id')
      .maybeSingle();

    if (error) return response.status(502).json({ error: 'NOTES_BACKEND_ERROR' });
    if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    return response.status(200).json({ id: data.id });
  }

  response.setHeader('Allow', 'GET, PUT, DELETE');
  return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}
