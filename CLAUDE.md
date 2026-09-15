# RAMPART — working brief

> Full history, design decisions, and the August audit live in `D:\d\FYP\CLAUDE.md` (481 lines).
> This file is the short, current-state version for the live repo. Verified by execution 2026-09-15.

**RAMPART** — Retrieval-Augmented Multi-tier Pipeline for Application Remediation & Testing.
BS Data Science FYP, PUCIT. Pattern SAST (semgrep / bandit) → code slice → RAG grounding in
real disclosed vulns → Gemini verdict → ranked report → suggested fix with apply/revert.

## Run it

```
backend\.venv\Scripts\python.exe backend\run_server.py      # API  http://127.0.0.1:8000  (/docs)
cd frontend && npm run dev:web                              # UI   http://localhost:5173  (IPv6 only)
```

- **Python 3.13 is required** — `apply.py:73,87` use `Path.read_text(newline=)` which is 3.13+.
  The venv was built with `uv venv backend/.venv --python 3.13`.
- Node v24 / npm 11 installed. `npm run typecheck` is clean.
- `.env` holds `JWT_SECRET`, `DATABASE_URL` (a disposable Postgres 17 in Docker: `rampart-pg`,
  port 55432, user/pass/db all `rampart`), and an empty `GEMINI_API_KEY`. Without a key every
  verdict is "Unverified" and the research views are empty by construction.
- The **frontend is hard-gated on the DB**: `/setup`, `/scan`, `/history`, `/profile` need a JWT.
  Test account: `uiverify001@example.com` / `Passw0rd!2345`.

## Knowledge base — three sources, one contract

`knowledge_base/` is real code in this repo (tracked as of 2026-09-15). Only `knowledge_base/out/`
is ignored; here it is a **junction** to `D:\d\FYP\knowledge_base\out`, the 578 MB Chroma store.

| source | adapter | records → chunks | collection | has_fix |
|---|---|---|---|---|
| hackerone | `adapters/hackerone.py` | 12,061 → 30,818 | `rampart_hackerone_minilm` | false |
| nuclei | `adapters/nuclei.py` | 5,308 → 11,138 | `rampart_nuclei_minilm` | false |
| **crossvul** | `adapters/crossvul.py` | 9,313 → 8,810 → 29,512 | `rampart_crossvul_minilm` | **true** |

**71,468 vectors total.** Every adapter implements `SourceAdapter` (`adapters/base.py`) and emits
`SourceRecord`; stages b–e never see a source. To add one: one adapter file + one row in `sources.py`.

```
python run_pipeline.py --source crossvul --stages normalize,gate,chunk,embed --backend minilm-onnx --reset
python run_pipeline.py --source crossvul --stages embed --backend minilm-onnx   # RESUMES, no --reset
python run_pipeline.py --source crossvul --query "sql injection" --cwe CWE-89
```

The embed stage is **idempotent and resumable**: without `--reset` it skips chunk ids already in
the collection (`embed_store.existing_ids`). Rate ~11 chunks/s on CPU (MiniLM-ONNX, 384-dim).

### Things learned building the CrossVul adapter (do not re-learn)
- **Dedupe must include code.** `run_pipeline.stage_gate` keys the near-dup signature on
  title+description+discussion **+ code_blocks**. Prose alone collapsed 93.5% of CrossVul, whose
  description is just the CWE name. HackerOne/Nuclei are unaffected (their prose exceeds the
  800-token shingle cap in `dedupe.shingles`).
- **`has_fix` is derived**, `bool(rec.fix_ref)` in `normalize.py`. Only CrossVul sets `fix_ref`.
- **`weakness_to_cwe.json` has 253 entries** (was 202). The 51 CrossVul-only class names were
  resolved from each folder's own modal `**CWE:**` line. All 138 CrossVul folders map.
- **Section parsing anchors on known headers**, not any `## ` — 11 CrossVul files have `## `
  inside fenced code.
- **`rag.py` dedupes hits by `(uid, section)`**, not title: CrossVul titles are shared per
  class+language. It also counts the CWE-filtered early-exit **per collection** — the old
  shared accumulator starved whichever collection was listed last.
- Use `python -u` for pipeline runs you want to watch; stdout is block-buffered when redirected.

## Known issues (open)
- `main.py:41` CORS is `allow_origins=["*"]` while `/api/scan` accepts anonymous requests with an
  arbitrary local path. Restrict to `localhost:5173`, `127.0.0.1:5173`, `tauri://localhost`.
- `config.SEMGREP_CONFIG` is declared, never imported; semgrep runs `--config auto` (network fetch
  per scan, ~140 s, non-reproducible). Vendor and pin a rules dir.
- `HealthContext` refetches on window focus and polls while the Joern sidecar is starting (P4);
  there is still no periodic poll, so a backend that dies mid-session is noticed on the next focus.
- `schema.sql` disables RLS by design — never expose these tables to Supabase anon/authenticated.
  (`findings.code_slice` is deliberately **not** written; code never reaches the DB.)
- **Joern/CPG is BACK (2026-09-15, Day 1 of `docs/JOERN_PLAN.md`).** `backend/app/services/joern/`
  — `runtime.py` (self-installing portable JRE 21 + joern-cli under `tools/`, no admin, no PATH),
  `scan.py` (additive, never raises, returns `(findings, diag)`), `rules/locators.sc` (the four
  July rules **with all eight August fixes applied**, P2 done 2026-09-15: try/catch + rule_state diag,
  AUTHZ/AUTHN_ONLY split, literals out of the guard channel, `<lambda>N` excluded, `abort(401|403`,
  allow-list by name not syntax, hoisted decorator table matched as `(def <name>(`, `nameExact`). Wired in `pipeline.py` with a
  reserved `JOERN_LLM_QUOTA`; `/api/health` reports `scanners.joern`. **First real execution ever:**
  5 candidates on `testbeds/shopfast` = 4 TP + the known `find_product` bait FP, 34.7 s cold /
  14.7 s warm, bandit/joern overlap 0. Log: `bench/runs/2026-09-15-first-run.md`.
  **P1 done:** `bench/` harness, `bench/keys/shopfast.key.jsonl` (26 bugs / 29 locations + 2 baits,
  all anchors resolve, **0 adjudicated**). Baseline: bandit 12 TP, semgrep 13, joern 4 (+1 bait),
  full (with Gemini) 15 TP / F1 0.70. Engines are disjoint. **P2 done:** `testbeds/probe` 5/5 TP, 0 FP.
  **P3 done:** `server.py` = `joern --server` sidecar on 127.0.0.1:8091 (random per-process
  password; lifespan starts it, `stop()` tree-kills it), one `/query-sync` per `// @@` section of
  `locators.sc`, so a broken rule costs that rule (`rule_state=compile_error`), not the phase.
  CPG phase 8 s via API vs 19–34 s script; same candidates. Script mode is the automatic fallback
  (`JOERN_SERVER=off|auto`, `JOERN_SERVER_WAIT`). `/query-sync` says `success` even on compile
  errors - `evaluation_failed()` parses stdout. `SHIFTLEFT_OCULAR_INSTALL_DIR` must be set or
  `importCode` NPEs in server mode. Log: `bench/runs/2026-09-15-p3-server.md`; tests
  `backend/tests/test_joern.py` (no JVM). **P4 done:** `backend/db/migrations/0002_joern.sql`
  (`findings.tool`, `scans.joern`, `tool_stats` view) applied at start-up by `db.migrate()` (also
  `python -m app.db`; `schema_migrations` table; fresh DB gets `schema.sql` as 0001). asyncpg pool
  now has a jsonb codec (before it, `scans.counts` reached the UI as a string). UI: `+ CPG` pill and
  callout in `SummaryCard`, `CPG` badge in `FindingCard`, CPG state note on Setup (`utils/joern.ts`),
  `+ CPG n` in History, `HealthContext` polls while the sidecar is starting and refetches on focus.
  `GET /api/research/tools`. **P5 done (infra):** `joern/vocab/` - `schema.json` (18 slots x 7
  sinks, per-sink character class, no regex sink), `validate.py` (caps 8 KB / 64 per slot, cross-slot
  rules, union composition, canonical sha256, `packs/digests.json` allowlist, framework detection),
  `packs/_base.json` (= pre-P5 Scala vals) + `packs/flask-sqlite3.json`. `locators.sc` reads the
  pack via `ujson` in `// @@ vocab`; findings carry `meta.pack` + `meta.slots`; `diag.pack` persists in
  `scans.joern`; `bench.run --pack`. `_base` == `flask-sqlite3` on shopfast/probe (4/1, 5/0/2).
  Edit a pack → `python -m app.services.joern.vocab.validate --freeze` or tests fail.
  **P6 done:** `testbeds/djshop-dev` + `testbeds/djshop-heldout` (Django 5 + DRF; each SAST-blind bug
  next to the docs' fix as a `safe` twin), frozen via `bench/freeze.py` (`FREEZE.json`; `bench.run`
  refuses a drifted tree and logs held-out runs to `bench/runs/heldout.log`). `django.json` was
  authored AFTER the freeze by a fresh agent from Django/DRF docs only (`packs/django.prompt.md`,
  `django.transcript.json`). Scala got one general fix from DEV: pysrc2cpg renders `kw = value` with
  spaces → `norm()` in the vocab section. **Held-out, evaluated once:** SAST-blind `_base` 5/9,
  `django` 7/9, bandit/semgrep 0/9; 12 failure causes = 7 vocabulary + 5 structural (class-scope
  guard, receiver-chain ownership, cross-file bound, validation-vs-DB comparison). **Never re-run
  `djshop-heldout` after changing a pack or rule** - that is tuning on the test set; measure on DEV,
  report on a new held-out split. Log: `bench/runs/2026-09-15-p6-django-heldout.md`.
  **P7 done:** the rules now use the graph. TOCTOU = write control-dependent on a resource
  comparison + same receiver (`x.stock >= q` … `x.save()`); class scope via `typeDecl` (class body +
  bases in the guard channel; DRF `get_object` reads honour `get_queryset` text and any project class
  defining `has_object_permission`; an instantiated form's `min_value` bounds the quantity rule);
  `meta.route` = yes|no|unknown from route markers + 2 hops of `callIn`, reported never gated.
  Schema v2 (+4 slots), pack cap 16 KB. DEV/django 5 TP / 0 FP / 0 bait; regressions unchanged.
  Held-out deliberately not re-run. Log: `bench/runs/2026-09-15-p7-graph.md`.
  **P8 done:** O3 re-verification. `joern/reverify.py` - preview (scratch copy + `apply_fix` there,
  live tree untouched) or post-apply (snapshot = before); `decide()` = fired before ∧ silent after ∧
  no new candidate anywhere; reason names the guard and where it lives (`method:` / `class:` /
  `instantiated_class:`) or "sink gone" or "review by hand". `// @@ reverify` section in locators.sc;
  `POST /api/fix/verify`; FixPanel "Verify with CPG". Pattern fallback labelled when Joern is absent.
  Gate met: get_order ownership fix converges (`method:permissiondenied`), cosmetic rename and a
  docstring-only "fix" do not; 13-17 s via the sidecar. Log: `bench/runs/2026-09-15-p8-reverify.md`.
  Next: P9 docs + thesis text.
  Gemini key is in `.env` (pasted in chat 2026-09-15 - rotate it).
  Open: the `full` arm Confirmed the find_product bait; extract.py gives module-level findings
  a slice that reaches into the next function. A second process on the same machine cannot bind
  8091 and silently runs script mode - check `joern.mode` before quoting timings.
  Install on a fresh clone: `python -m app.services.joern.runtime --install`.

## Data residency
Three corpora under `data/` (HackerOne 12k, Nuclei 5.3k, CrossVul 9.3k) are tracked. The
top-level `nuclei_classified/` is an untracked leftover; the adapter reads `data/nuclei_classified/`.
`testbeds/shopfast/` (restored 2026-09-15) is the planted-vulnerability ground truth: 25 bugs, answer key
in `VULNERABILITIES.md`, bugs #22–#25 are the four SAST-blind ones the Joern rules target.
