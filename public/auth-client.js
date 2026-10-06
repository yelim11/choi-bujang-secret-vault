import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm';

const SUPABASE_URL = 'https://naukmhaknwezkbxvkylc.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_STdt8pIP6TrlWUGcLx0mwg_wIlnYZLW';

const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);

export async function signIn(email, password) {
  return supabase.auth.signInWithPassword({ email, password });
}

export async function signOut() {
  return supabase.auth.signOut({ scope: 'local' });
}

export async function currentSession() {
  const { data, error } = await supabase.auth.getSession();
  return { session: data?.session ?? null, error };
}

export function onAuthChange(callback) {
  return supabase.auth.onAuthStateChange((_event, session) => callback(session));
}

export async function apiRequest(path, init = {}) {
  const { data, error } = await supabase.auth.getSession();
  if (error || !data?.session?.access_token) {
    throw new Error('로그인이 필요합니다.');
  }

  const headers = new Headers(init.headers || {});
  headers.set('Accept', 'application/json');
  headers.set('Authorization', `Bearer ${data.session.access_token}`);
  if (init.body) headers.set('Content-Type', 'application/json');

  return fetch(path, {
    ...init,
    headers,
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
  });
}
