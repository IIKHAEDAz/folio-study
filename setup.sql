-- Run once in your own Supabase SQL Editor. No public access to user data.
begin;
create table if not exists public.folio_workspaces (
  user_id uuid primary key references auth.users(id) on delete cascade,
  payload jsonb not null,
  revision bigint not null default 1,
  updated_at timestamptz not null default now()
);
alter table public.folio_workspaces enable row level security;
revoke all on public.folio_workspaces from anon, authenticated;
grant select, insert, update on public.folio_workspaces to authenticated;
drop policy if exists folio_select on public.folio_workspaces;
drop policy if exists folio_insert on public.folio_workspaces;
drop policy if exists folio_update on public.folio_workspaces;
create policy folio_select on public.folio_workspaces for select to authenticated using ((select auth.uid()) = user_id);
create policy folio_insert on public.folio_workspaces for insert to authenticated with check ((select auth.uid()) = user_id);
create policy folio_update on public.folio_workspaces for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
-- Atomic compare-and-save: stale devices never silently overwrite newer data.
create or replace function public.folio_save(expected_revision bigint, new_payload jsonb)
returns bigint language plpgsql security invoker set search_path = '' as $$
declare result_revision bigint;
begin
  if auth.uid() is null then raise exception 'AUTH_REQUIRED'; end if;
  if jsonb_typeof(new_payload) <> 'object' then raise exception 'INVALID_PAYLOAD'; end if;
  if octet_length(new_payload::text) > 20000000 then raise exception 'WORKSPACE_TOO_LARGE'; end if;
  if expected_revision = 0 then
    insert into public.folio_workspaces(user_id,payload,revision)
    values(auth.uid(),new_payload,1) on conflict(user_id) do nothing returning revision into result_revision;
  else
    update public.folio_workspaces set payload=new_payload, revision=revision+1,updated_at=now()
    where user_id=auth.uid() and revision=expected_revision returning revision into result_revision;
  end if;
  if result_revision is null then raise exception 'FOLIO_CONFLICT'; end if;
  return result_revision;
end $$;
revoke all on function public.folio_save(bigint,jsonb) from public,anon;
grant execute on function public.folio_save(bigint,jsonb) to authenticated;
commit;
