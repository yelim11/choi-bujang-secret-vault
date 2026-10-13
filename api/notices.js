import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

// 현재 저장된 강사 공지는 없습니다. 읽기 구역을 메모 API와 분리하며
// 검증된 강사 권한 계약이 없는 수정·생성 요청은 허용하지 않습니다.
let verifyLogin;
function getVerifier() {
  if (verifyLogin) return verifyLogin;
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) return null;
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  verifyLogin = createLoginVerifier({ config, supabaseClient: supabase });
  return verifyLogin;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const verifier = getVerifier();
  if (!verifier) return response.status(503).json({ error: 'NOTICES_BACKEND_NOT_CONFIGURED' });
  const identity = await verifier(request.headers?.authorization);
  if (!identity) return response.status(401).json({ error: 'UNAUTHORIZED' });
  return response.status(200).json([]);
}
