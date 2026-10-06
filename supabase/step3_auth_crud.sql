begin;

alter table public.notes
  alter column id drop identity if exists;
alter table public.notes
  alter column id drop default;
alter table public.notes
  alter column id type uuid using gen_random_uuid();
alter table public.notes
  alter column id set default gen_random_uuid();

create index if not exists notes_owner_id_idx
  on public.notes (owner_id);

alter table public.notes enable row level security;
revoke all privileges on table public.notes from public, anon, authenticated;
grant select, insert, update, delete on table public.notes to service_role;

commit;

-- 3단계는 로그인 여부만 검사합니다.
-- POST는 서버가 검증한 사용자 ID를 owner_id에 기록합니다.
-- owner별 권한 분리는 4단계에서 추가합니다.
