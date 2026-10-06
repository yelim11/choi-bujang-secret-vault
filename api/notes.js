import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

function noStore(response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('CDN-Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

let runtime;
function getRuntime() {
  if (runtime) return runtime;

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (typeof url !== 'string' || typeof secretKey !== 'string'
      || !url.trim() || !secretKey.trim()) {
    return null;
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:') return null;

  const supabase = createClient(url.trim(), secretKey.trim(), {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });
  const verifyLogin = createLoginVerifier({ config, supabaseClient: supabase });
  runtime = { supabase, verifyLogin };
  return runtime;
}

export default async function handler(request, response) {
  noStore(response);

  const current = getRuntime();
  if (!current) {
    return response.status(503).json({ error: 'NOTES_BACKEND_NOT_CONFIGURED' });
  }

  const identity = await current.verifyLogin(request.headers?.authorization);
  if (!identity) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const { data, error } = await current.supabase
    .from('notes')
    .select('title,content')
    .order('id', { ascending: true });

  if (error) {
    return response.status(502).json({ error: 'NOTES_BACKEND_ERROR' });
  }

  return response.status(200).json({ notes: Array.isArray(data) ? data : [] });
}
