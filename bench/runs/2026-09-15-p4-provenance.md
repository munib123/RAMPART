# P4 - persistence and UI provenance, 2026-09-15

No new detection numbers: P4 changes what is *recorded* and *shown*, not what is found.

## Exit gate

| check | result |
|---|---|
| `findings.tool` populated | signed-in shopfast scan `3362ea7b…`: `joern` 5, `semgrep` 15 (20 pre-P4 rows read `unknown`) |
| `scans.joern` stored | `{used: true, mode: "server", candidates: 5, elapsed_ms: 18059, rule_state: {4 x ok}, …}` |
| `tool_stats` / `GET /api/research/tools` | `joern Confirmed 5 (avg 90.0)`, `semgrep Confirmed 7 (91.4)`, `semgrep Error 8`, `unknown Unverified 20` |
| CPG pill and badge render | SSR of the real components on the real report: `+ CPG` pill, callout "5 of these came from Joern CPG analysis …: 5 confirmed.", `CPG` badge + `is-cpg` on the 5 Joern cards, none on semgrep cards |
| Health shows Joern state pre-scan | `joernStatus(health)` → `ready` on the live backend; `missing` / `starting` / `off` texts verified on synthetic health |
| Migration idempotent | `python -m app.db` twice on the existing DB: `applied 0002_joern` then `up to date`; on a fresh DB: `0001_schema, 0002_joern`, then `up to date` |

Tests: `backend/tests/test_persistence.py` (5, no DB) + `test_health.py` joern-shape; 44 backend +
12 bench pass. Live check: `tests/check_db.py` reports migrations and findings by tool.

## Found on the way

- **jsonb came back as text.** asyncpg has no default jsonb codec, so `scans.counts`, `scope` and
  `verdict_summary` reached `/api/scans` as JSON strings; the History page's `s.counts.high` was
  always undefined and its severity bar never rendered. A codec on the pool (`app/db.py
  _init_conn`) returns objects; the encoder passes pre-serialised strings through so the routers'
  `json.dumps(...)` calls are unchanged.
- **The Setup note would lie for ~25 s.** `HealthContext` fetched once; the sidecar becomes ready
  after the first paint. It now polls every 5 s while `server.running && !ready` (max 2 min) and
  refetches on window focus - which also retires the "HealthContext never refetches" known issue.
- Gemini returned `503 high demand` for one of the two batches of this scan (8 semgrep `Error`
  verdicts, 5/5 Joern Confirmed). Same P1 hazard; the `Error` rows are stored as such.
- The `find_product` bait was Confirmed again. Still open (P7/P8 territory).
