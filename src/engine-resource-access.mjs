// 엔진 가명 subjectId -> 실제 사용자 ID 바인딩은 운영자가 등록한 서버 전용 DB에서만 읽습니다.
// 판정기 요청에 실제 userId/role/ownerId를 추가하거나, 클라이언트 헤더를 연결에 쓰지 않습니다.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { UUID_PATTERN, hasVerifiedInstructorRole } from './resource-policy.mjs';

const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const DEVICE = /^[a-f0-9]{16}$/u;
const ENGINE_PATH = /^\/(api\/)?(notes|notices)(?:\/([^/?#]+))?$/u;

function engineTarget(request) {
  if (!request || request.schema !== 'aleph.decision.v1'
      || request.deviceRegistered !== true
      || !DEVICE.test(request.deviceId ?? '')
      || ['classId', 'projectId', 'subjectId'].some(k =>
        typeof request[k] !== 'string' || !request[k])
      || request.queryLength !== 0 || request.querySha256 !== EMPTY_SHA
      || !Number.isInteger(request.policyRevision) || request.policyRevision < 1
      || !Number.isFinite(Date.parse(request.at ?? ''))
      || Math.abs(Date.now() - Date.parse(request.at)) > 5000) return null;
  const match = ENGINE_PATH.exec(request.path ?? '');
  if (!match || request.service !== match[2]) return null;
  const [, api, kind, id] = match;
  if (id && !UUID_PATTERN.test(id)) return null;
  const method = request.method;
  if (id ? !['GET', 'PUT', 'DELETE'].includes(method)
    : !['GET', 'POST'].includes(method)) return null;
  if (request.route !== method + ' /' + (api ?? '') + kind
      + (id ? '/:id' : '')) return null;
  const zone = kind === 'notes' ? 'my-notes'
    : method === 'GET' ? 'class-notices' : 'instructor-materials';
  const pattern = '/api/' + kind + (id ? '/:id' : '');
  if ((config.allowedRoutes ?? []).filter(r => r.service === kind
    && r.method === method && r.pathPattern === pattern && r.zone === zone).length !== 1) {
    return null;
  }
  return { kind, id, method };
}

export function createTrustedEngineResourceCheck(db) {
  return async function trustedEngineResourceAllowed(request) {
    const target = engineTarget(request);
    if (!target) return false;
    try {
      const { data: binding, error } = await db.from('sdp_principal_bindings')
        .select('user_id,expires_at')
        .eq('class_id', request.classId)
        .eq('project_id', request.projectId)
        .eq('subject_id', request.subjectId)
        .eq('device_id', request.deviceId)
        .eq('enabled', true)
        .maybeSingle();
      if (error || !binding?.user_id || !Number.isFinite(Date.parse(binding.expires_at))
          || Date.parse(binding.expires_at) <= Date.now()) return false;
      const ownerId = binding.user_id;
      if (target.kind === 'notes' && target.id) {
        const row = await db.from('notes').select('id,owner_id')
          .eq('id', target.id).eq('owner_id', ownerId).maybeSingle();
        return !row.error && row.data?.id === target.id && row.data.owner_id === ownerId;
      }
      if (target.kind === 'notices' && target.method !== 'GET') {
        if (!await hasVerifiedInstructorRole(db, { kind: 'student', userId: ownerId })) {
          return false;
        }
        if (target.id) {
          const row = await db.from('notices').select('id,owner_id')
            .eq('id', target.id).eq('owner_id', ownerId).maybeSingle();
          return !row.error && row.data?.id === target.id && row.data.owner_id === ownerId;
        }
      }
      return true;
    } catch { return false; }
  };
}

let runtimeCheck;
export async function runtimeTrustedResourceAllowed(request) {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) return false;
  try {
    if (!runtimeCheck) {
      const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
        auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
      });
      runtimeCheck = createTrustedEngineResourceCheck(db);
    }
    return await runtimeCheck(request);
  } catch { return false; }
}
