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
- `HealthContext` fetches once and never refetches; backend availability in the SPA goes stale.
- `schema.sql` disables RLS by design — never expose these tables to Supabase anon/authenticated.
  (`findings.code_slice` is deliberately **not** written; code never reaches the DB.)
- **Joern/CPG is BACK (2026-09-15, Day 1 of `docs/JOERN_PLAN.md`).** `backend/app/services/joern/`
  — `runtime.py` (self-installing portable JRE 21 + joern-cli under `tools/`, no admin, no PATH),
  `scan.py` (additive, never raises, returns `(findings, diag)`), `rules/locators.sc` (the four
  July rules, byte-identical — the eight August fixes are P2). Wired in `pipeline.py` with a
  reserved `JOERN_LLM_QUOTA`; `/api/health` reports `scanners.joern`. **First real execution ever:**
  5 candidates on `testbeds/shopfast` = 4 TP + the known `find_product` bait FP, 34.7 s cold /
  14.7 s warm, bandit/joern overlap 0. Log: `docs/joern-runs/2026-09-15-first-run.md`.
  Next: P1 (`bench/` harness + line-anchored key), then P2 (the eight fixes, each behind a number).
  Install on a fresh clone: `python -m app.services.joern.runtime --install`.

## Data residency
Three corpora under `data/` (HackerOne 12k, Nuclei 5.3k, CrossVul 9.3k) are tracked. The
top-level `nuclei_classified/` is an untracked leftover; the adapter reads `data/nuclei_classified/`.
`testbeds/shopfast/` (restored 2026-09-15) is the planted-vulnerability ground truth: 25 bugs, answer key
in `VULNERABILITIES.md`, bugs #22–#25 are the four SAST-blind ones the Joern rules target.
