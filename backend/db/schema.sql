-- RAMPART database schema (Supabase / PostgreSQL)
-- Run this in the Supabase SQL Editor, or with:
--   psql "$DATABASE_URL" -f backend/db/schema.sql
--
-- RLS is intentionally OFF for the POC: the backend writes with the service key and
-- enforces ownership in application code (JWT -> owner_id). If you later expose the
-- tables to Supabase's anon/authenticated roles, enable RLS and add policies FIRST.

create table users (
  id          uuid primary key default gen_random_uuid(),
  email       text unique not null,
  password    text not null,          -- bcrypt hash only, never plaintext
  is_admin    boolean not null default false,
  created_at  timestamptz not null default now()
);

create table scans (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null references users(id),
  target      text not null,
  scanner     text not null,
  status      text not null default 'done',
  counts      jsonb not null default '{}',
  verdict_summary jsonb not null default '{}',
  created_at  timestamptz not null default now()
);

create table findings (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references scans(id) on delete cascade,
  cwe_id      text,
  severity    text,
  verdict     text,
  confidence  int,
  rule_id     text,
  code_slice  text,                   -- kept local-only in the product; do not surface
  exemplar_urls jsonb not null default '[]',
  created_at  timestamptz not null default now()
);

-- Research aggregate (drives the research page without re-scanning).
create view cwe_stats as
  select cwe_id, severity, verdict, count(*) n,
         round(avg(confidence)::numeric,1) avg_conf
  from findings
  where verdict in ('Confirmed','Likely','Informational')
  group by cwe_id, severity, verdict;
