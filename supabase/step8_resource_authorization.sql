-- 8단계 자료 구역 전용 테이블. 기존 notes 자료·권한은 변경하지 않습니다.
-- 실행 전 Supabase SQL Editor에서 확인하세요. 실제 강사 권한은 운영자가 Auth app_metadata에만 부여합니다.
begin;

create table if not exists public.notices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 120),
  content text not null check (char_length(content) between 1 and 2000),
  created_at timestamptz not null default now()
);

-- SDP 엔진이 확인한 가명 사용자/기기를 실제 자료 주체에 연결하는 서버 관리 등록부입니다.
-- 브라우저·학생·심판 토큰은 등록하거나 조회할 수 없습니다.
create table if not exists public.sdp_principal_bindings (
  class_id text not null,
  project_id text not null,
  subject_id text not null,
  device_id text not null check (device_id ~ '^[0-9a-f]{16}$'),
  user_id uuid not null references auth.users(id) on delete cascade,
  enabled boolean not null default false,
  expires_at timestamptz not null,
  primary key (class_id, project_id, subject_id, device_id)
);

alter table public.notices enable row level security;
alter table public.sdp_principal_bindings enable row level security;

revoke all on table public.notices, public.sdp_principal_bindings
  from public, anon, authenticated;
grant select, insert, update, delete on table public.notices to service_role;
grant select on table public.sdp_principal_bindings to service_role;

commit;

-- 등록부는 기본 disabled입니다. 신뢰된 운영 엔진의 가명 ID와 실제 Supabase
-- 사용자 ID의 연결이 별도로 검증되기 전에는 활성화하거나 임의 ID를 생성하지 마세요.
-- 강사 등록도 관리자만 Auth app_metadata.role='instructor'로 설정해야 합니다.
