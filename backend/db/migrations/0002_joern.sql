-- 0002: provenance for the Joern CPG phase (P4 of docs/JOERN_PLAN.md).
--
-- findings.tool  which engine produced the row: 'semgrep' | 'bandit' | 'joern'. Rows written
--                before this migration are 'unknown' (they predate the CPG phase, so none of
--                them is a Joern finding, but the scanner name was never stored per finding).
-- scans.joern    the pipeline's `joern` block for that scan:
--                {used, reason, elapsed_ms, candidates, mode, rule_state, ...}. Lets history
--                say "CPG ran / skipped because <reason>" without re-scanning.
--
-- Idempotent: safe to run twice. schema.sql (0001) is unchanged and still creates a fresh DB;
-- this file brings an existing one forward. Applied automatically at backend start-up when
-- DATABASE_URL is set (app/db.py migrate()), or by hand:
--   psql "$DATABASE_URL" -f backend/db/migrations/0002_joern.sql

alter table findings add column if not exists tool  text  not null default 'unknown';
alter table scans    add column if not exists joern jsonb not null default '{}';
create index if not exists findings_tool_idx on findings (tool);

-- Research aggregate by engine: how many findings each tool produced and how the LLM judged
-- them. This is the "Joern locates, the LLM proves" table for the thesis.
create or replace view tool_stats as
  select tool, verdict, count(*) n,
         round(avg(confidence)::numeric, 1) avg_conf
  from findings
  group by tool, verdict;
