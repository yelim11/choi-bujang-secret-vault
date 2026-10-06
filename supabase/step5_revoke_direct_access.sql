-- 5단계: 공개 키로 원본 Supabase Data API를 직접 부르는 길을 닫습니다.
-- public.notes 한 테이블만 대상으로 합니다.
-- 검토 후 Supabase SQL Editor에서 실행하세요.

-- 적용 전 확인
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

select
  has_table_privilege('anon', 'public.notes', 'SELECT') as anon_select,
  has_table_privilege('anon', 'public.notes', 'INSERT') as anon_insert,
  has_table_privilege('anon', 'public.notes', 'UPDATE') as anon_update,
  has_table_privilege('anon', 'public.notes', 'DELETE') as anon_delete,
  has_table_privilege('authenticated', 'public.notes', 'SELECT') as authenticated_select,
  has_table_privilege('authenticated', 'public.notes', 'INSERT') as authenticated_insert,
  has_table_privilege('authenticated', 'public.notes', 'UPDATE') as authenticated_update,
  has_table_privilege('authenticated', 'public.notes', 'DELETE') as authenticated_delete,
  has_table_privilege('service_role', 'public.notes', 'SELECT') as service_role_select,
  has_table_privilege('service_role', 'public.notes', 'INSERT') as service_role_insert,
  has_table_privilege('service_role', 'public.notes', 'UPDATE') as service_role_update,
  has_table_privilege('service_role', 'public.notes', 'DELETE') as service_role_delete;

-- 직접 Data API 권한 회수
begin;

revoke all on table public.notes from public, anon, authenticated;

commit;

-- 적용 후 확인
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

select
  has_table_privilege('anon', 'public.notes', 'SELECT') as anon_select,
  has_table_privilege('anon', 'public.notes', 'INSERT') as anon_insert,
  has_table_privilege('anon', 'public.notes', 'UPDATE') as anon_update,
  has_table_privilege('anon', 'public.notes', 'DELETE') as anon_delete,
  has_table_privilege('authenticated', 'public.notes', 'SELECT') as authenticated_select,
  has_table_privilege('authenticated', 'public.notes', 'INSERT') as authenticated_insert,
  has_table_privilege('authenticated', 'public.notes', 'UPDATE') as authenticated_update,
  has_table_privilege('authenticated', 'public.notes', 'DELETE') as authenticated_delete,
  has_table_privilege('service_role', 'public.notes', 'SELECT') as service_role_select,
  has_table_privilege('service_role', 'public.notes', 'INSERT') as service_role_insert,
  has_table_privilege('service_role', 'public.notes', 'UPDATE') as service_role_update,
  has_table_privilege('service_role', 'public.notes', 'DELETE') as service_role_delete;

-- 기대 결과:
-- anon: SELECT/INSERT/UPDATE/DELETE = false
-- authenticated: SELECT/INSERT/UPDATE/DELETE = false
-- service_role: 서버 함수 CRUD에 필요한 권한 유지
-- 기존 RLS와 API의 로그인/소유자 검사는 그대로 유지
