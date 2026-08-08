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
  name        text not null,          -- display name (required at signup)
  is_admin    boolean not null default false,
  plan        text not null default 'free',
  scans_used  int not null default 0,
  fixes_used  int not null default 0,
  last_fix_scan_id uuid,              -- dedupe: charge 1 fix per distinct scan
  constraint users_plan_check check (plan in ('free','pro','premium')),
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
  scope       jsonb not null default '{}',   -- {platform, stack[], priorities[]} set by the user before scanning
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

-- Codebase-type x vulnerability aggregate (categorizes what kinds of code have which issues).
create view code_stats as
  select scope->>'platform' as platform, scanner, cwe_id, severity, verdict,
         count(*) n, round(avg(confidence)::numeric,1) avg_conf
  from scans
  join findings on findings.scan_id = scans.id
  where scope is not null and verdict in ('Confirmed','Likely','Informational')
  group by 1, 2, 3, 4, 5;
