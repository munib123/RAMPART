# RAMPART

A desktop-style **security scanner** that scans code, **grounds** every finding in real
disclosed vulnerabilities (a RAG knowledge base), asks an **LLM to verify** it against
retrieved real-world exemplars, and produces a calm, ranked report. This repository is the
proof-of-concept slice of the full RAMPART pipeline.

```
scan (bandit / semgrep)  +  Joern CPG locator  ->  extract code slice  ->  RAG ground (ChromaDB)  ->  Gemini verify  ->  ranked report  ->  fix  ->  CPG re-verify
```

## Layout

```
rampart/
├── backend/                 FastAPI API (Python 3.13, venv-isolated)
│   ├── app/
│   │   ├── main.py          FastAPI app + CORS
│   │   ├── config.py        env / secrets-driven config (.env) + path resolution
│   │   ├── db.py            asyncpg pool (+ graceful no-DB degrade)
│   │   ├── core/            JWT + bcrypt, FastAPI auth deps
│   │   ├── routers/         auth, scans, scan, fix, browse, health, profile, billing
│   │   ├── schemas/         Pydantic request models
│   │   └── services/        scanner, extract, rag, gemini, pipeline, apply
│   ├── db/schema.sql        Supabase/Postgres schema v1 (users, scans, findings, cwe_stats, code_stats)
│   ├── db/migrations/       numbered forward migrations (0002_joern: findings.tool, scans.joern, tool_stats); applied at start-up
│   ├── tests/               pytest smoke + apply/revert suites
│   ├── requirements.txt     pinned Python deps
│   ├── run_server.py        start API only
│   └── .venv/               virtual environment (git-ignored)
├── frontend/                Vite + React + TS SPA (and Tauri desktop shell)
│   ├── src/                 App, pages, components, hooks, api, contexts, styles
│   └── src-tauri/           Rust/Tauri shell (spawns the backend sidecar)
├── knowledge_base/          RAG source (builds the Chroma store; README inside)
├── semgrep_test/            bundled vulnerable sample code
├── data/                    classified corpora the knowledge base is built from
│   ├── hackerone/hackerone_classified/   12k disclosed HackerOne reports
│   ├── nuclei_classified/                5.3k Nuclei templates
│   └── crossvul_classified/              9.3k CrossVul vulnerable/fixed code pairs
├── .env / .env.example      secrets config (git-ignored)
└── README.md
```

The knowledge base (`knowledge_base/`) and the bundled vulnerable sample
(`semgrep_test/`) live **inside this repo**, alongside `backend/` `frontend/` and `data/`.
Path configuration in `backend/app/config.py` resolves everything relative to this repo
root, so it works regardless of where the directory is moved.

---

## Quick start

### One-command (both processes) — from `frontend/`

```bash
cd frontend
npm run dev:all
```

This concurrently launches:

- **backend** - FastAPI on `http://127.0.0.1:8000/` (API docs at `/docs`)
- **frontend** - Vite dev server on `http://127.0.0.1:5173/`

`Ctrl+C` stops both. Sign in (the UI needs the database - see **Database** under Prereqs),
enter a folder/file path, pick a scanner, press **Start scan**. The default points at the
bundled vulnerable sample (`semgrep_test/test_code`).

### Manual / split startup

| What | Command |
|---|---|
| Backend only | `backend\.venv\Scripts\python.exe backend\run_server.py` (port 8000; set `RAMPART_PORT` for a second checkout) |
| Frontend only | `cd frontend && npm run dev:web` |
| Frontend + backend together (npm) | `cd frontend && npm run dev:all` |

### Desktop app (Tauri)

The bundled Rust/Tauri shell (`frontend/src-tauri/`) spawns the FastAPI backend as a
localhost sidecar and shows the SPA in a native window. It needs the Rust toolchain
(cargo) and the frontend deps.

| What | Command |
|---|---|
| Run in dev (hot-reload + backend sidecar) | `cd frontend && npm run dev:tauri` |
| Build an installer (NSIS/MSI in `src-tauri/target/release/bundle/`) | `cd frontend && npm run build:tauri` |

The webview talks to the backend on `127.0.0.1:8000` exactly like the browser build, so
the two share the same API base (`frontend/src/api/client.ts`). On exit the shell kills
the backend it spawned.

### Prereqs (already done in this working copy, re-run if cloning fresh)

```bash
uv venv backend/.venv --python 3.13   # Python 3.13 is REQUIRED (apply.py uses read_text(newline=), 3.13+).
                                      # `python -m venv` picks whatever `python` is on PATH (often 3.12): use uv,
                                      # or `py -3.13 -m venv backend/.venv` if the launcher lists 3.13.
backend\.venv\Scripts\pip install -r backend\requirements.txt
cd frontend && npm install            # npm 11 may skip esbuild's postinstall (allow-scripts): run
                                      # `npm approve-scripts esbuild` if `npm run dev:web` fails to start
```

**Database (required for the UI).** The API answers anonymous `POST /api/scan` and
`GET /api/health` without a database, but the SPA is gated on a signed-in JWT: `/setup`,
`/scan`, `/history` and `/profile` all need `DATABASE_URL` and `JWT_SECRET` set, so a fresh
clone without Postgres shows only the sign-in page. The team's shared database is the
**Supabase project** - ask a teammate for the `.env` values (use the IPv4 *session pooler* DSN,
`postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres`; the
direct `db.<ref>.supabase.co` host is IPv6-only). The schema and migrations are applied
automatically the first time a backend starts against it. For offline work a disposable
Postgres 17 in Docker is enough:

```bash
docker run -d --name rampart-pg -e POSTGRES_USER=rampart -e POSTGRES_PASSWORD=rampart -e POSTGRES_DB=rampart -p 55432:5432 postgres:17
python -c "import secrets; print(secrets.token_urlsafe(48))"     # -> JWT_SECRET
```

Then in `.env`: `DATABASE_URL=postgresql://rampart:rampart@127.0.0.1:55432/rampart` and
`JWT_SECRET=<the printed value>`. The schema is applied automatically when the backend starts
(`app/db.py` `migrate`), or by hand with `backend\.venv\Scripts\python.exe -m app.db` from
`backend/`; sign up once through the UI.

**Knowledge base.** The pipeline code under `knowledge_base/` is in the repo, but the built
Chroma store (`knowledge_base/out/`, ~600 MB) is git-ignored. A fresh clone has no vectors,
and the app degrades to ungrounded scans until the store exists (starting the backend or the tests
first creates an EMPTY store - copy `out/` in with the backend stopped, replacing that directory).
Either copy `out/` from a
teammate, or rebuild it from the corpora in `data/` - one command per source, run from
`knowledge_base/` with the backend venv:

```bash
cd knowledge_base
..\backend\.venv\Scripts\python.exe -u run_pipeline.py --source hackerone --stages normalize,gate,chunk,embed --backend minilm-onnx --reset
..\backend\.venv\Scripts\python.exe -u run_pipeline.py --source nuclei    --stages normalize,gate,chunk,embed --backend minilm-onnx --reset
..\backend\.venv\Scripts\python.exe -u run_pipeline.py --source crossvul  --stages normalize,gate,chunk,embed --backend minilm-onnx --reset
```

Embedding runs at ~11 chunks/s on CPU (MiniLM-ONNX, no GPU or torch needed), so the full
build is 30,818 + 11,138 + 29,512 = 71,468 chunks, roughly 1h45m in total. It is safe to
interrupt: re-running the `embed` stage **without** `--reset` resumes from the chunks already
stored. Confirm with `GET /api/health`, which lists each collection's vector count.

---

## Enable the LLM (Gemini) verdict - optional but recommended

1. Copy `.env.example` to `.env` (git-ignored).
2. Paste your **Google AI Studio** Gemini key (`AIzaSy...`) into `GEMINI_API_KEY`. Get one at
   <https://aistudio.google.com/apikey>. **Rotate any key you have shared in chat.**
3. Restart. Findings then carry a grounded verdict (Confirmed / Likely / Informational /
   False positive), a confidence score, a plain-English explanation, and a suggested fix.

Without a key the app still runs: you get findings and the retrieved real-world exemplars;
only the LLM verdict is marked "Unverified".

**Model / quota:** the default is `gemini-2.5-flash-lite` (settable via `GEMINI_MODEL`). Free-tier
limits are **per-day, per-model**. All findings are verified in **one batched call per scan**
(`gemini.analyze_batch`), so a scan costs ~1 request. Rotate models or enable billing to lift the
daily cap.

---

## Semgrep (multi-language) - runs natively from the venv

Bandit works out of the box but is **Python-only**. Semgrep covers many languages and is already
installed in the project venv (`semgrep==1.172.0` in `requirements.txt`, launched through the
venv's Python), so no extra setup is needed. The app uses `DEFAULT_SCANNER = "auto"`: it prefers
semgrep (multi-language) when it runs, and falls back to Bandit (python-only) otherwise.

If you ever need to (re)install it in the venv:

```bash
backend\.venv\Scripts\python -m pip install semgrep
```

> Note: the code keeps a thin WSL path-translation (`/mnt/d/...` <-> `D:\...`) for forward
> compatibility, but on this box semgrep runs **natively from `backend\.venv`**, not WSL.

---

## Joern CPG phase - the logic-bug locator (Python targets)

Bandit and Semgrep are pattern matchers; they cannot see "this route reads an order by id and
never checks who owns it". The Joern phase builds a Code Property Graph of the target and runs
four hand-written CPGQL rules (`backend/app/services/joern/rules/locators.sc`) for the bug
classes SAST is blind to: **IDOR** (CWE-639), **mass assignment** (CWE-915), **unchecked
quantity** (CWE-840) and **TOCTOU** (CWE-362). Joern *locates*; the Gemini verdict *proves*.
Its candidates are additive - the scanner findings are untouched - and get a reserved share of
the LLM budget (`JOERN_LLM_QUOTA`).

The runtime is portable and self-installing (Temurin JRE 21 + joern-cli 4.0.589 under
`tools/`, no admin rights, nothing on PATH). On a fresh clone:

```bash
cd backend && .venv\Scripts\python.exe -m app.services.joern.runtime --install
```

The installer picks the release asset for the host - `joern-cli-{windows-x86_64, linux-x86_64,
linux-arm64, macos-x86_64, macos-arm64}.zip` - and the matching Adoptium JRE, verifies the zip
against the published `.sha512`, and on failure prints a one-line reason plus the manual fallback
(drop the asset zip and its `.sha512` into `tools/` and re-run) rather than a traceback. Only
Windows x64 has been exercised end to end; the Linux and macOS paths are unit-tested only.

Without it the phase is skipped and `/api/health` says why (`scanners.joern.note`). By default
the backend keeps one `joern --server` sidecar alive (127.0.0.1:8091, random per-process
password) so a scan costs the CPG build only - about 8 s for a small Flask app instead of
19-34 s for a fresh JVM per scan. `JOERN_SERVER=off` (or a sidecar that fails to start)
falls back to one `joern --script` per scan with identical results. Each scan's report carries
a `joern` block: `mode`, `candidates`, `elapsed_ms` and a per-rule `rule_state`, so a rule that
breaks costs that rule, not the phase.

Provenance is kept end to end: every finding has `tool` (`semgrep` / `bandit` / `joern`), the UI
marks CPG findings with a violet **CPG** badge and the summary says "N of these came from Joern
CPG analysis, M confirmed", the Setup page shows the CPG phase's state (ready / starting / not
installed) before you scan, and a signed-in scan stores `findings.tool` and `scans.joern` so
history and the `tool_stats` research view can separate what Joern located from what the LLM
proved.

**Vocabulary is data, not code.** The Scala holds the four rule *shapes*; what an ownership
check, a lock, an allow-list or an object id *looks like* in a given framework comes from a JSON
vocabulary pack under `backend/app/services/joern/vocab/packs/` (`_base.json` = the built-in
lists, `flask-sqlite3.json` = the Flask reference pack; `django.json` follows the held-out Django
testbed). `JOERN_PACK=auto` picks one from the target's `requirements.txt` / imports. Every slot
declares the sink its values flow into and `vocab/validate.py` enforces a character class per
sink (no regex sink, no Scala), size and count caps, cross-slot rules and a digest allowlist -
a pack that breaks any rule is discarded whole and the scan runs on `_base`, saying so. Each
finding carries `meta.pack` (`<id>@<sha12>`) and `meta.slots` (which vocabulary entries fired),
so a report can be traced to the exact pack. Validate or re-freeze the digests with
`python -m app.services.joern.vocab.validate [--freeze]`.

**The rules use the graph, not just tokens.** A TOCTOU fires only when a write is
control-dependent on a comparison over the same object (`product.stock >= q … product.save()`);
an IDOR read inside a DRF ViewSet honours `get_queryset()` scoping and any project permission
class defining `has_object_permission`; a form's `min_value` in `forms.py` bounds the quantity the
view multiplies; every finding carries a route-reachability flag (`yes` / `no`, or `unknown`
when the pack's route markers do not describe the target). And after a fix, **Verify with
CPG** rebuilds the graph on the patched code and says whether the locator still fires - a
comment that claims "atomic" does not pass, a real `select_for_update()` does. The verify
inputs (file, method, class) are validated as a relative `.py` path and identifiers and
Scala-escaped before rendering, and `/api/fix/apply`, `/revert` and `/verify` refuse any path
outside the scan's own target.

The full account - what the phase is, how it runs, every measured number and where it comes
from - is [`docs/JOERN.md`](docs/JOERN.md); the plan it followed is `docs/JOERN_PLAN.md`; the
thesis paragraphs are `docs/THESIS_JOERN.md`.

The rules are measured, not trusted: `bench/` holds line-anchored answer keys for
`testbeds/shopfast` (Flask; 25 planted bugs + 1 undocumented one the key records, 2 baits), the per-fix `testbeds/probe` suite, and the
Django pair `testbeds/djshop-dev` / `testbeds/djshop-heldout` (each SAST-blind bug next to the
fix the Django docs prescribe; the held-out half is frozen - `FREEZE.json`, `bench/freeze.py` -
and evaluated once, after `django.json` was authored from documentation alone). Run
`backend\.venv\Scripts\python.exe -m bench.run --backend joern --benchmark shopfast [--pack _base]`
and see `bench/README.md` and `bench/runs/*.md` for the numbers behind every rule change.
`--pack _base` vs `--pack <framework>` on one benchmark is the vocabulary ablation with the
Scala frozen.

---

## Knowledge-base corpora (`data/`)

Every source is stored the same way - one markdown report per record, filed under a
vulnerability-class folder - so the knowledge-base builder can walk them uniformly:

| Corpus | Path | Records | Content |
|---|---|---|---|
| HackerOne | `data/hackerone/hackerone_classified/` | ~12,000 | disclosed reports (title, PoC, remediation timeline) |
| Nuclei | `data/nuclei_classified/` | ~5,300 | templates (description, exploit payload, references) |
| CrossVul | `data/crossvul_classified/` | 9,313 | real fix commits: the patch diff + the vulnerable lines around it, 21 languages |

**CrossVul** is derived from the HuggingFace dataset
[`hitoshura25/crossvul`](https://huggingface.co/datasets/hitoshura25/crossvul) (Apache-2.0):
9,313 before/after file pairs over 158 CWEs and 21 languages (top: c, php, javascript,
python, java). The upstream rows carry whole files before and after the fix - 672 MB of
source, median 31 KB a pair - so each report here keeps only what carries the security
signal: the unified diff of the fix plus the vulnerable lines around the patched hunk.

Class folders reuse the names already present in the other two corpora wherever the CWE
is known there (8,012 of 9,313 reports; 87 of the 138 folders are shared), so retrieval
sees one taxonomy rather than three. The rest fall back to the MITRE CWE name.

> **Embedded and live.** `knowledge_base/adapters/crossvul.py` (`CrossVulAdapter`) reads this
> corpus through the same `SourceAdapter` contract as HackerOne and Nuclei, and `sources.py`
> registers it as the `crossvul` source. The pipeline produced 8,810 gated records and 29,512
> chunks in the `rampart_crossvul_minilm` collection, which `backend/app/config.py` already names.
> Rebuild with:
>
> ```bash
> python run_pipeline.py --source crossvul --stages normalize,gate,chunk,embed --backend minilm-onnx --reset
> ```

---

## What each piece is

| Part | File | Notes |
|---|---|---|
| Scanner (pluggable) | `backend/app/services/scanner.py` | `auto` = semgrep (multi-language, native venv) when runnable, else bandit (python). Same normalized `Finding` shape either way. |
| CPG logic-bug locator | `backend/app/services/joern/` | `runtime.py` self-installs JRE 21 + joern-cli under `tools/`; `server.py` keeps one `joern --server` sidecar; `scan.py` runs `rules/locators.sc` (IDOR, mass assignment, unchecked quantity, TOCTOU) and returns candidates + per-rule diag; `vocab/` = schema-validated vocabulary packs the rules read as data |
| Code-slice extract | `backend/app/services/extract.py` | containing function (Python AST) or a line window |
| RAG | `backend/app/services/rag.py` | queries `rampart_hackerone_minilm` + `rampart_nuclei_minilm` Chroma collections, CWE-filtered |
| LLM verify | `backend/app/services/gemini.py` | Gemini, grounded in exemplars; key from `.env` only. Batch API for ~1 request per scan |
| Suggest a fix | `generate_fix` in `gemini.py` + `POST /api/fix` | on-demand corrected code per finding; UI shows a diff + Copy |
| Apply / revert a fix | `apply.py` + `POST /api/fix/apply`, `POST /api/fix/revert` | writes the fix into the user's codebase and can undo it; snapshots the target into `backend/.fix_snapshots/` (git-ignored) |
| Orchestration | `backend/app/services/pipeline.py` | scan -> extract -> ground -> verify -> rank |
| API | `backend/app/main.py` | FastAPI on localhost; CORS for the dev/Tauri webviews |
| Database | `backend/db/schema.sql`, `db/migrations/`, `app/db.py` | Supabase/Postgres via `DATABASE_URL`; the API degrades gracefully when unset (anonymous scans only), but the SPA's pages need a signed-in user and therefore a DB. `schema.sql` creates a fresh DB; `migrations/NNNN_*.sql` bring an existing one forward and are applied automatically at start-up (or by `python -m app.db`), recorded in `schema_migrations`. Every finding row carries `tool` (`semgrep` / `bandit` / `joern`) and every scan its `joern` block |
| Auth | `app/routers/auth.py`, `app/core/security.py` | bcrypt + JWT (email/password) |
| UI | `frontend/src` + `src-tauri/` | React SPA; the Tauri shell (`src-tauri/`) spawns the backend sidecar and loads this UI in a native window |

### API endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scan` | run a full scan; persists when signed in |
| GET | `/api/health` | scanner/LLM/RAG/db availability |
| POST | `/api/fix` | generate a fix for one finding |
| POST | `/api/fix/apply` | apply the generated fix to the codebase (snapshots the target first) |
| POST | `/api/fix/revert` | restore the pre-fix snapshot |
| POST | `/api/fix/verify` | O3: rebuild the CPG on the patched code (scratch copy before Apply, live tree after) and report whether the locator still fires, which guard appeared, and any new candidate elsewhere |
| GET | `/api/browse` | native folder picker |
| POST | `/api/auth/signup`, `/api/auth/login` | register / log in |
| GET | `/api/auth/me` | who am I (Bearer) |
| POST | `/api/auth/change-password` | change password (signed in) |
| GET / POST | `/api/scans` | list / save scans |
| GET | `/api/scans/{id}` | one saved scan |
| GET | `/api/research/overview` | CWE aggregate stats |
| GET | `/api/research/codebase` | codebase stats (platform × scanner × cwe × severity × verdict) |
| GET | `/api/research/tools` | findings per engine × verdict (`tool_stats`): what Joern located vs what the LLM proved |
| GET / PUT | `/api/profile` | read / update the signed-in profile |
| GET | `/api/billing` | current plan + usage |
| GET | `/api/billing/plans` | available plans |
| POST | `/api/billing/upgrade` | plan switch (stub, no payment) |

---

## Notes / current limits (honest)

- **Semgrep** runs **natively from the project virtual environment** (`backend\.venv`);
  `auto` prefers it (multi-language) and falls back to Bandit (python-only) when not installed.
- Embeddings use the **MiniLM placeholder** index (torch/gte-large can't build on this box);
  retrieval quality improves once a gte-large index is built on a GPU.
- Persistence is optional **for the API only**: without `DATABASE_URL` the endpoints still answer
  anonymous scans, but the SPA's `/setup`, `/scan`, `/history` and `/profile` pages require a
  JWT and are unreachable. Bring up Postgres and set `DATABASE_URL` + `JWT_SECRET` (see Prereqs)
  to use the UI.
- Apply/revert fixes are **local-only**: snapshots live in `backend/.fix_snapshots/` (git-ignored)
  keyed by scan id and are not sent to the database; deleting them removes the revert net.
- Plans/billing: per-plan scan/fix quotas (Free 10/5, Pro 30/20, Premium 500/200) enforced server-side
  with a `402 {code: plan_limit}` upsell; upgrade is a stub until payment is wired.
- LLM quota: free-tier limits are per-day per-model; a scan costs ~1 batched call to stay within budget.
- CrossVul is **live in retrieval** via `CrossVulAdapter`; it is the only source that supplies a
  fix, so it is the only one whose chunks carry `has_fix = true` (HackerOne and Nuclei leave it
  false). That makes the `has_fix` Chroma metadata filter meaningful for the first time.
- Later (per the design): more knowledge-base sources and the self-verifying remediation loop.

---

## Progress log

Newest first - what changed in the repo and why, so the state is legible without digging
through git history.

### 2026-09-15 - the Joern / CPG phase, restored and measured (P0-P9)

**What landed:** `backend/app/services/joern/` - a self-installing runtime, a `joern --server`
sidecar, four locator rules that now use the graph (control dependence, class scope, route
reachability), schema-validated vocabulary packs (`_base`, `flask-sqlite3`, `django`), O3
re-verification (`POST /api/fix/verify`), persistence (`findings.tool`, `scans.joern`) and UI
provenance. `bench/` - the evaluation harness: line-anchored answer keys for four testbeds
(`shopfast`, `probe`, `djshop-dev`, `djshop-heldout`), five arms, frozen trees and a once-only
held-out log. Every number in `docs/JOERN.md` and `docs/THESIS_JOERN.md` cites a run artifact
under `bench/runs/`.

**Why:** the August repo had removed Joern entirely for environment friction, and the only
detection numbers ever quoted were hand-traced. The phase is back with no admin install, no
PATH change, an 8 s per-scan cost in server mode, and measured - not asserted - recall on the
bugs pattern scanners cannot see. Open: 0 of 90 answer-key rows adjudicated; the `full` arm
not run on Django (Gemini quota); the post-P7 rules not scored on a held-out split yet.

### 2026-08-19 - CrossVul added as a third knowledge-base corpus

**What landed:** `data/crossvul_classified/` - 9,313 markdown reports across 138
vulnerability-class folders (26.8 MB), built from the HuggingFace dataset
[`hitoshura25/crossvul`](https://huggingface.co/datasets/hitoshura25/crossvul) (Apache-2.0,
2 parquet shards, 223 MB). Same `<Class>/Report_<id>.md` layout and same header/section
shape as the HackerOne and Nuclei corpora, so the knowledge-base builder needs no
special-casing.

**Decisions:**

- *Patch, not whole files.* The upstream rows hold complete before/after files - 672 MB of
  source, median 31 KB per pair, max 1 MB. Each report keeps the unified diff of the fix
  (median ~600 chars, capped at 8 KB) plus the vulnerable lines around the first patched
  hunk (±20 lines, capped at 60). That is the part carrying security signal, and it keeps
  the corpus at 27 MB instead of ~700 MB of mostly-unrelated file content.
- *One taxonomy, not three.* Class folders were matched to the CWE -> folder names already
  used in `nuclei_classified/` and `hackerone_classified/` (136 CWEs covered), so e.g.
  CWE-94 files into the existing `Code Injection` folder. 8,012 of 9,313 reports reuse an
  existing class name; 87 of the 138 folders are shared with the older corpora. The
  remainder fall back to the MITRE CWE name from the dataset's own `cwe_description`.
- *Data only, no tooling.* The fetch/process scripts and the raw parquet staging copy were
  deliberately removed after the run, by request. Consequence: the corpus is **not
  regenerable from inside this repo** - redoing it means re-downloading the dataset and
  rewriting the processing. Nothing is lost for retrieval (every report carries its CWE,
  language, and upstream `file_pair_id`), only reproducibility.

**Verified:** all 9,313 files parse with the expected header, a `**CWE:** CWE-nnn` line, a
non-empty diff block, and a non-empty vulnerable-code excerpt.

**Closed 2026-09-14 - adapter + embedding.** `knowledge_base/adapters/crossvul.py` implements
`CrossVulAdapter` against the shared `SourceAdapter` contract; `adapters/__init__.py` exports it and
`sources.py` registers the `crossvul` source (outdir `out/crossvul`, collections
`rampart_crossvul_minilm` / `rampart_crossvul`). Three supporting changes were needed:

- *Taxonomy.* 51 of CrossVul's 138 class folders were absent from `adapters/weakness_to_cwe.json`
  (735 files, 7.9%). Each was resolved from the modal `**CWE:**` line of its own records and added,
  taking the table from 202 to 253 entries. All 138 folders now map, so retrieval still sees one
  taxonomy across the three corpora.
- *Dedupe.* `run_pipeline.py` keyed the near-duplicate signature on `title + description +
  discussion` only. CrossVul's description is just the CWE name and its title only
  `<Class> in <language>`, so prose alone collapsed **8,704 of 9,313 records (93.5%)** into 434
  clusters. The signature now appends `code_blocks`. HackerOne and Nuclei are unaffected: their
  prose exceeds the 800-token shingle cap in `dedupe.shingles()`, so the appended code is never
  reached. CrossVul now keeps **8,810 (94.6%)**, dropping 503 genuine duplicates.
- *has_fix.* `adapters/normalize.py` hardcoded `has_fix=False`. It is now derived as
  `bool(rec.fix_ref)`. CrossVul sets `fix_ref`, so all 8,810 records carry `has_fix = true`;
  HackerOne and Nuclei leave `fix_ref` None and are unchanged.

**Result:** 8,810 gated records -> 29,512 chunks (8,810 description + 20,702 code).

---

*Verification: `npm run build` (tsc + vite) passes; backend smoke tests live under `backend/tests/`.*