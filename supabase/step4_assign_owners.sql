begin;

do $$
declare
  a_id uuid;
  b_id uuid;
  total_notes integer;
begin
  select id into a_id
  from auth.users
  where lower(email) = lower('oyelim005@gmail.com')
  limit 1;

  select id into b_id
  from auth.users
  where lower(email) = lower('oyelim44@gmail.com')
  limit 1;

  if a_id is null then
    raise exception 'A test account not found';
  end if;

  if b_id is null then
    raise exception 'B test account not found';
  end if;

  select count(*) into total_notes
  from public.notes;

  if total_notes <> 4 then
    raise exception 'Expected exactly 4 training notes, found %', total_notes;
  end if;

  with ranked as (
    select
      id,
      row_number() over (order by created_at asc, id asc) as rn
    from public.notes
  )
  update public.notes as n
  set owner_id = case when ranked.rn <= 3 then a_id else b_id end
  from ranked
  where n.id = ranked.id;
end
$$;

commit;

-- Verification: expect A=3, B=1, unowned=0.
select
  u.email,
  count(n.id)::int as note_count
from auth.users as u
left join public.notes as n on n.owner_id = u.id
where lower(u.email) in (
  lower('oyelim005@gmail.com'),
  lower('oyelim44@gmail.com')
)
group by u.email
order by u.email;

select count(*)::int as unowned_count
from public.notes
where owner_id is null;
