-- 4단계 소유자 RLS/최소 권한
-- public.notes 한 테이블만 대상으로 하며 실제 DB에 적용 완료한 정의입니다.

begin;

alter table public.notes enable row level security;

revoke all on table public.notes from public, anon, authenticated;

grant select, insert, update, delete
on table public.notes
to authenticated;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

create policy notes_select_own
on public.notes
for select
to authenticated
using (auth.uid() = owner_id);

create policy notes_insert_own
on public.notes
for insert
to authenticated
with check (auth.uid() = owner_id);

create policy notes_update_own
on public.notes
for update
to authenticated
using (auth.uid() = owner_id)
with check (auth.uid() = owner_id);

create policy notes_delete_own
on public.notes
for delete
to authenticated
using (auth.uid() = owner_id);

commit;

-- 적용 후 기대:
-- anon SELECT/INSERT/UPDATE/DELETE = false
-- authenticated SELECT/INSERT/UPDATE/DELETE = true
-- 실제 행 접근은 RLS의 auth.uid() = owner_id 조건으로 본인 행만 허용.
