-- 4단계 A/B 소유자 배정 재실행용 템플릿
-- 실제 이메일은 Git에 저장하지 않습니다.
-- SQL Editor에서 실행하기 직전에 [A_EMAIL], [B_EMAIL]을 시험 계정 이메일로 바꾸세요.

begin;

do $$
declare
  a_id uuid;
  b_id uuid;
  total_notes integer;
begin
  select id into a_id
  from auth.users
  where lower(email) = lower('[A_EMAIL]')
  limit 1;

  select id into b_id
  from auth.users
  where lower(email) = lower('[B_EMAIL]')
  limit 1;

  if a_id is null or b_id is null or a_id = b_id then
    raise exception 'A/B test accounts are missing or invalid';
  end if;

  select count(*) into total_notes from public.notes;
  if total_notes <> 4 then
    raise exception 'Expected exactly 4 training notes, found %', total_notes;
  end if;

  with ranked as (
    select id, row_number() over (order by created_at asc, id asc) as rn
    from public.notes
  )
  update public.notes as n
  set owner_id = case when ranked.rn <= 3 then a_id else b_id end
  from ranked
  where n.id = ranked.id;
end
$$;

commit;

-- 기대 결과: A=3, B=1, owner_id IS NULL=0.
