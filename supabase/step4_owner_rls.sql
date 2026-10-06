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

-- Before/after verification
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'notes'
  and grantee in ('anon', 'authenticated')
order by grantee, privilege_type;

select
  has_table_privilege('anon', 'public.notes', 'select') as anon_select,
  has_table_privilege('anon', 'public.notes', 'insert') as anon_insert,
  has_table_privilege('anon', 'public.notes', 'update') as anon_update,
  has_table_privilege('anon', 'public.notes', 'delete') as anon_delete,
  has_table_privilege('authenticated', 'public.notes', 'select') as auth_select,
  has_table_privilege('authenticated', 'public.notes', 'insert') as auth_insert,
  has_table_privilege('authenticated', 'public.notes', 'update') as auth_update,
  has_table_privilege('authenticated', 'public.notes', 'delete') as auth_delete;

select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and tablename = 'notes'
order by policyname;
