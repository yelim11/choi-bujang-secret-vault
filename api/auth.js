import { createClient } from '@supabase/supabase-js';

function noStore(response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('CDN-Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

function runtimeClient() {
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return null;

  return createClient(url, secretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
}

function bodyOf(request) {
  if (request.body && typeof request.body === 'object' && !Array.isArray(request.body)) {
    return request.body;
  }
  if (typeof request.body === 'string' && request.body.length <= 16384) {
    try {
      const parsed = JSON.parse(request.body);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    } catch {}
  }
  return null;
}

function sessionPayload(session) {
  if (!session?.access_token || !session?.refresh_token) return null;
  return {
    accessToken: session.access_token,
    refreshToken: session.refresh_token,
    expiresAt: session.expires_at ?? null,
  };
}

export default async function handler(request, response) {
  noStore(response);

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabase = runtimeClient();
  if (!supabase) {
    return response.status(503).json({ error: 'AUTH_BACKEND_NOT_CONFIGURED' });
  }

  const body = bodyOf(request);
  const action = body?.action;

  if (action === 'login') {
    const email = typeof body?.email === 'string' ? body.email.trim() : '';
    const password = typeof body?.password === 'string' ? body.password : '';
    if (!email || !password || password.length > 4096) {
      return response.status(400).json({ error: 'INVALID_LOGIN_REQUEST' });
    }

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      return response.status(401).json({ error: error.message || 'LOGIN_FAILED' });
    }

    const session = sessionPayload(data?.session);
    if (!session) return response.status(502).json({ error: 'AUTH_SESSION_MISSING' });
    return response.status(200).json({ session });
  }

  if (action === 'refresh') {
    const refreshToken = typeof body?.refreshToken === 'string' ? body.refreshToken : '';
    if (!refreshToken || refreshToken.length > 8192) {
      return response.status(400).json({ error: 'INVALID_REFRESH_REQUEST' });
    }

    const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
    if (error) {
      return response.status(401).json({ error: 'SESSION_EXPIRED' });
    }

    const session = sessionPayload(data?.session);
    if (!session) return response.status(502).json({ error: 'AUTH_SESSION_MISSING' });
    return response.status(200).json({ session });
  }

  if (action === 'logout') {
    return response.status(200).json({ ok: true });
  }

  return response.status(400).json({ error: 'INVALID_AUTH_ACTION' });
}
