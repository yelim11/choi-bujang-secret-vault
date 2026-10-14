-- 10단계 비공개 백업/감사 표 (실제 프로젝트에 적용한 재현 SQL)
begin;
create extension if not exists pgcrypto with schema extensions;
create table if not exists public.note_backups(id bigint generated always as identity primary key,note_id uuid not null,owner_id uuid not null,version integer not null check(version>=1),title text not null,content text not null,content_sha256 text not null check(content_sha256 ~ '^[0-9a-f]{64}$'),captured_at timestamptz not null default now(),unique(note_id,version));
create table if not exists public.note_audit(id bigint generated always as identity primary key,at timestamptz not null default now(),action text not null check(action in('backup','create','update','delete','restore')),note_id uuid not null,owner_id uuid,actor_id uuid,before_sha256 text,after_sha256 text,backup_version integer);
alter table public.note_backups enable row level security;alter table public.note_audit enable row level security;
revoke all on table public.note_backups from public,anon,authenticated,service_role;revoke all on table public.note_audit from public,anon,authenticated,service_role;
revoke all on sequence public.note_backups_id_seq from public,anon,authenticated;revoke all on sequence public.note_audit_id_seq from public,anon,authenticated;
grant select,insert on table public.note_backups to service_role;grant select,insert on table public.note_audit to service_role;
grant usage,select on sequence public.note_backups_id_seq to service_role;grant usage,select on sequence public.note_audit_id_seq to service_role;
insert into public.note_backups(note_id,owner_id,version,title,content,content_sha256) select n.id,n.owner_id,1,n.title,n.content,encode(extensions.digest(convert_to(n.title||E'\n'||n.content,'UTF8'),'sha256'),'hex') from public.notes n where n.owner_id is not null on conflict(note_id,version) do nothing;
insert into public.note_audit(action,note_id,owner_id,after_sha256,backup_version) select 'backup',b.note_id,b.owner_id,b.content_sha256,b.version from public.note_backups b where not exists(select 1 from public.note_audit a where a.action='backup' and a.note_id=b.note_id and a.backup_version=b.version);
commit;
select count(*) as backups,count(*) filter(where content_sha256=encode(extensions.digest(convert_to(title||E'\n'||content,'UTF8'),'sha256'),'hex')) as verified from public.note_backups;
