// 자료 구역 식별과 접근 권한은 서버에서만 검증합니다.
// 본문/쿼리의 role, owner_id 및 클라이언트 입력을 신뢰하지 않습니다.
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const KINDS = new Set(['notes', 'notices']);

export function parseResourceTarget(request, kind) {
  if (!KINDS.has(kind)) return { invalid: true };
  let url;
  try { url = new URL(request?.url ?? '/api/' + kind, 'https://placeholder.invalid'); }
  catch { return { invalid: true }; }
  const prefix = '/api/' + kind;
  const path = url.pathname;
  let pathId = null;
  if (path !== prefix) {
    if (!path.startsWith(prefix + '/')) return { invalid: true };
    pathId = path.slice(prefix.length + 1);
    if (!UUID_PATTERN.test(pathId)) return { invalid: true };
  }
  const keys = [...url.searchParams.keys()];
  if (keys.some(key => key !== 'id') || url.searchParams.getAll('id').length > 1) {
    return { invalid: true };
  }
  const queryId = url.searchParams.get('id');
  if (queryId !== null && !UUID_PATTERN.test(queryId)) return { invalid: true };
  const paramId = request?.query?.id;
  if (Array.isArray(paramId) || (paramId !== undefined
      && (typeof paramId !== 'string' || !UUID_PATTERN.test(paramId)))) {
    return { invalid: true };
  }
  if (pathId && ((queryId && pathId !== queryId)
      || (paramId && pathId !== paramId))) return { invalid: true };
  if (queryId && paramId && queryId !== paramId) return { invalid: true };
  const id = pathId ?? queryId ?? paramId ?? null;
  return {
    invalid: false,
    id,
    service: kind,
    pathPattern: prefix + (id ? '/:id' : ''),
    resourceId: kind + ':' + (id ?? 'own-list'),
  };
}

export function routeAllowed(config, target, method) {
  if (!target || target.invalid || !['GET', 'POST', 'PUT', 'DELETE'].includes(method)) return false;
  if (target.id && method === 'POST') return false;
  if (!target.id && ['PUT', 'DELETE'].includes(method)) return false;
  const zone = target.service === 'notes' ? 'my-notes'
    : method === 'GET' ? 'class-notices' : 'instructor-materials';
  const matched = (config?.allowedRoutes ?? []).filter(route =>
    route && route.service === target.service && route.method === method
    && route.pathPattern === target.pathPattern && route.zone === zone);
  return matched.length === 1;
}

export function belongsToVerifiedOwner(row, identity) {
  return Boolean(row && identity?.userId && row.owner_id === identity.userId);
}

export async function hasVerifiedInstructorRole(supabase, identity) {
  if (identity?.kind !== 'student' || !identity.userId
      || typeof supabase?.auth?.admin?.getUserById !== 'function') return false;
  try {
    const { data, error } = await supabase.auth.admin.getUserById(identity.userId);
    if (error || data?.user?.id !== identity.userId) return false;
    const metadata = data.user.app_metadata;
    return metadata?.role === 'instructor'
      || (Array.isArray(metadata?.roles) && metadata.roles.includes('instructor'));
  } catch { return false; }
}
