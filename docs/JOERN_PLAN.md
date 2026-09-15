# Joern / CPG in RAMPART — implementation plan v2

**Date:** 2026-09-15 · **Status:** ready to execute · **Supersedes:** the August design notes in
`D:/d/FYP/CLAUDE.md` §7, `D:/d/FYP/rampart_poc/JOERN.md`, and TDD §8.8.

---

## 0. What this plan stands on

### 0.1 The August research, and what still holds

The August work (a 14-agent design evaluation plus a hand-built prototype) established these
facts. None of them have changed; the plan assumes them rather than re-deriving them.

| Established in August | Status now |
|---|---|
| Joern's shipped query DB has **zero Python queries** (`io.joern.scanners`: c, android, java, kotlin, php, ghidra). CodeQL has none for the logic CWEs either. | Still true. Verified against the jar on disk. |
| Four hand-written intraprocedural CPGQL rules — IDOR (CWE-639), mass assignment (915), unchecked quantity (840), TOCTOU (362) — measured **4/4 recall** on `testbeds/shopfast` bugs #22–#25, plus one correctly-cleared FP. Contract: *"Joern LOCATES, the LLM PROVES."* | The code exists at `D:/d/FYP/rampart_poc/backend/joern_queries.sc`. The result was **hand-traced, never executed on this machine**. |
| **Rejected:** runtime LLM generation of CPGQL (arbitrary code execution inside a security product; train-on-test by construction; never runs in a measured config). **Rejected:** a 200-query corpus (wrong unit — the four shapes fire 9/12 unmodified across Django / FastAPI+SQLAlchemy / Flask+SQLAlchemy; 12 of 17 failure causes are vocabulary, 5 structural, and the structural 5 collapse to three traversals added once). | Stands. |
| **Adopted:** hand-written, hashed Scala reading a schema-validated JSON **vocabulary pack** as data via `ujson`. Every slot declares its sink; per-sink character class; no regex sink; no raw-Scala escape hatch. | Stands. Full spec in TDD §8.8 and §3.3 of the August synthesis. |
| The four rules as written contain **no graph traversal** — no `reachableBy`, `controlledBy`, `dominatedBy`, `cfgNext`, `caller`. They are AST token heuristics run through a graph database. Semgrep could express ~all of it. | Stands, and it is the most important sentence in this plan. Joern earns its place only on the four things below. |
| Joern's irreplaceable jobs: (1) control dependence, (2) cross-file type/class resolution, (3) route reachability, (4) **O3 post-fix re-verification** — does the guard now dominate the sink? | Stands. (4) is now concrete because `apply.py` exists. |
| Eight correctness fixes to the rules (try/catch, AUTHN/AUTHZ split, docstring literals out of the guard blob, `nameNot` index digits, `abort(401|403`, drop `" in ["` from ALLOWLIST, hoist the decorator lookup, `filenameExact`). | Not yet applied anywhere. |
| An evaluation harness with a line-anchored, human-adjudicated answer key is the **prerequisite** for every claim. | Still does not exist. |

### 0.2 What changed since August

| Then | Now |
|---|---|
| `rampart_poc/backend/joern_scan.py` + `joern_queries.sc`, wired into `pipeline.run_scan` at line 52, `+ CPG` pill in the UI | **Removed entirely** in the backend rewrite (`ef9acde1`, 2026-08-07). Zero references in `backend/`, `frontend/`, or the README. |
| `testbeds/shopfast` (25 planted bugs, the answer key) in the repo | **Not in the new repo.** Exists only at `D:/d/FYP/testbeds/shopfast/`. |
| Flat `sys.path` modules | Proper package: `backend/app/{routers,services,schemas,core}` with a `lifespan` startup hook (`main.py:25`). |
| Vanilla-JS UI with CPG badges | React/TS UI. `types.ts:72` has `tool?: string` but nothing renders it. |
| No persistence | Postgres via `db.py`. `findings` has `rule_id`, `cwe_id`, … but **no `tool` column** — engine provenance is dropped on save. |
| No fix application | `services/apply.py`: `snapshot_target()`, `apply_fix()`, `revert_snapshot()`. This is the O3 hook. |
| Java missing | **Java still missing.** Joern 4.0.589 (1.83 GB) is intact at `D:/d/FYP/tools/joern-cli` but has never executed on this machine. |

### 0.3 New facts from this research (September)

- **Server mode is documented and stable** ([docs.joern.io/server](https://docs.joern.io/server/)): `joern --server --server-host H --server-port P --server-auth-username U --server-auth-password W`. `POST /query-sync {"query": ...}` → `{"success": bool, "stdout": str, "stderr": str}`, with *single-request compilation and execution*. That gives per-query isolation: one bad query costs one request, not the run. The docs say plainly that the server "does not implement sandboxing" — fine here because every query is hand-written and hashed, never generated, and it binds to localhost with auth.
- **JDK 21** is the documented requirement ("other versions might work, but have not been properly tested").
- Latest Joern is **v4.0.627** (2026-09-12); releases are daily. Our 4.0.589 is the same line — no upgrade needed for this plan.
- The official `cpgqls-client` PyPI package is at 0.0.9 and thin; a ~40-line `requests` client is a smaller dependency than the package.

### 0.4 Why it was removed, and the constraint that follows

The rewrite commit is titled *"consolidated paths, native-venv semgrep, README cleanup, Supabase setup, jwt auth."* Its theme is removing environment friction — semgrep moved from WSL to the venv. Joern was the other external-runtime dependency: a JDK, a 1.8 GB install, a 25–30 s cold start, an env var pointing at a hard-coded Adoptium path. It was cut for the same reason WSL was.

**So the governing constraint is not detection quality. It is friction.** If this plan does not make Joern install itself, start itself, degrade silently-but-visibly when absent, and never slow down a scan that does not need it, the team will remove it a second time and be right to. Every phase below is checked against that.

---

## 1. Target architecture

```
backend/app/services/joern/            NEW package
  __init__.py
  runtime.py        locate JRE + joern-cli; install both into tools/ if absent; health probe
  server.py         start/stop the joern --server sidecar; readiness; auth token
  client.py         query(scala) -> (ok, stdout, stderr)   ~40 lines over requests
  scan.py           the locator phase: build CPG, run rules, parse TSV, return list[Finding]
  reverify.py       O3: rebuild CPG on the patched copy, assert locator no longer fires
  rules/
    locators.sc     the four rules, with the eight fixes, reading a vocab pack via ujson
    reverify.sc     the post-fix assertion
  vocab/
    schema.json     the closed grammar (the security boundary)
    validate.py     pure stdlib, no JVM
    packs/_base.json  flask-sqlite3.json  django.json
tools/                                 git-ignored, created by runtime.py
  jre-21/           portable Temurin JRE (no admin, no PATH change)
  joern-cli/        the distribution
bench/                                 NEW, the oracle
testbeds/shopfast/                     RESTORED from D:/d/FYP
```

**Runtime shape.** `main.py` `lifespan` starts the Joern server sidecar once (if the runtime is
present and `JOERN_ENABLED != off`), exactly as the Tauri shell starts the backend. The JVM cold
start is paid once per backend process, not per scan. Each scan then costs a CPG build for the
target (seconds for a small repo) plus the queries. When the runtime is absent the sidecar does not
start, `/api/health` says why, and scans run without the phase — visibly, never silently.

**Pipeline shape.** Unchanged from August in spirit: the CPG phase is **additive** and runs after
`scanner.scan()`. Two corrections to the old wiring that the August audit found:
- `enabled()` returns `(ok, reason)` and the reason reaches the scan response and `/api/health`.
- A reserved LLM quota for CPG candidates. `pipeline.py` sorts by severity with a stable sort and
  Joern findings are appended, so on any repo bigger than the testbed every CPG candidate falls
  past `MAX_LLM_FINDINGS=60` into "Unverified". The phase that exists to find what semgrep cannot
  is the first thing starved.

**Where the LLM sits.** Exactly where it sits today: adjudicating candidates. It never writes Scala,
never writes a traversal, never runs on the detection path. Offline and human-gated it may propose
vocabulary-pack entries from framework documentation (P5) and answer-key rows (P1).

---

## 2. Phases

Ordered so that something runs end-to-end on day 1 and the first *measured* number exists on
day 7. Estimates are for one person. **P0–P4 (10 days) is a defensible deliverable on its own.**

| Phase | Days | Exit gate |
|---|---|---|
| **P0** Runtime that installs itself; first real execution | 1 | `POST /api/scan` on shopfast prints `JOERN_FINDINGS=n`, n ≥ 4 |
| **P1** Restore the ground truth; build the oracle | 3 | `bench/run.py` reproduces JOERN.md §8 exactly (4 TP + 1 bait FP + 0 on `user_by_name`) |
| **P2** Port the driver; apply the eight fixes behind the harness | 3 | Each fix landed as its own commit with a before/after bench number |
| **P3** Server-mode sidecar | 1.5 | Second scan of shopfast completes in < 15 s; a deliberately broken query returns `success:false` without affecting the others |
| **P4** Persistence + UI provenance | 1.5 | `findings.tool` populated; CPG pill and badge render; health shows Joern state pre-scan |
| **P5** Vocabulary packs as data | 3 | `--pack flask-sqlite3` vs `--pack django` ablation runs on the same frozen Scala |
| **P6** Django testbed under the held-out protocol | 4 | DEV/HELD-OUT split committed; HELD-OUT touched once |
| **P7** The graph capabilities | 3 | Rule 4 requires check-dominates-write; DRF `permission_classes` recognised via `typeDecl`; `route_reachable` on every finding |
| **P8** O3 re-verification | 2 | Applying a fix to `orders.get_order` flips the locator from firing to not firing on the patched copy, and the report says so |
| **P9** Docs + thesis text | 1 | README, `JOERN.md` regenerated from real runs, thesis paragraphs |
| | **~23** | |

Slip budget goes to P6, never to P1. If P0–P2 have not landed by day 7, stop and reassess.

---

## 3. Phase specifications

### P0 — a runtime that installs itself (1 day)

The friction constraint, addressed first.

**`backend/app/services/joern/runtime.py`**

```python
JRE_URL   = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse"
JOERN_ZIP = "https://github.com/joernio/joern/releases/download/v4.0.589/joern-cli.zip"

def locate() -> RuntimeInfo:
    """Resolve java + joern in this order: JOERN_JAVA_HOME / JOERN_HOME env; tools/jre-21 +
    tools/joern-cli; a java on PATH with major version 21. Returns paths and a reason if absent."""

def install(progress=print) -> RuntimeInfo:
    """Download the portable JRE and joern-cli into tools/. Verify sha512 of the joern zip
    against the published .sha512. No admin, no PATH change, no registry. Idempotent."""

def probe(info: RuntimeInfo) -> tuple[bool, str]:
    """`java -version` reports 21; `joern.bat --help` exits 0. Cached per process."""
```

Ship a one-shot entry point: `python -m app.services.joern.runtime --install`. The README
Prereqs gets one line. The 1.63 GB zip already sitting in `D:/d/FYP/tools/` means the first run on
this machine copies rather than downloads.

**`config.py` additions**

```python
JOERN_ENABLED    = os.environ.get("JOERN_ENABLED", "auto")      # auto | on | off
JOERN_HOME       = os.environ.get("JOERN_HOME", str(FYP / "tools" / "joern-cli"))
JOERN_JAVA_HOME  = os.environ.get("JOERN_JAVA_HOME", str(FYP / "tools" / "jre-21"))
JOERN_TIMEOUT    = int(os.environ.get("JOERN_TIMEOUT", "360"))
JOERN_LLM_QUOTA  = int(os.environ.get("JOERN_LLM_QUOTA", "20"))  # reserved verify slots
JOERN_SERVER_PORT = int(os.environ.get("JOERN_SERVER_PORT", "8091"))
```

No hard-coded `C:\Program Files\Eclipse Adoptium\jre-21.0.11.10-hotspot` anywhere.

**Exit gate.** Copy the August driver in as-is (P2 replaces it), run one real scan of
`testbeds/shopfast`, paste the output into a `bench/runs/` log. This is the first time the
Joern phase will have executed on this laptop. Everything downstream is fiction until this passes.

Also run the four probes the August plan named, because three design decisions hang on them:

```scala
cpg.method.nameExact("checkout").parameter.code.l                       // does Depends(...) appear?
cpg.method.nameExact("get").typeDecl.member.name.l                      // does typeDecl resolve?
cpg.method.nameExact("checkout").call.name("<operator>.greaterEqualsThan")
   .headOption.map(_.controlledBy.size)                                 // is controlflow usable?
cpg.method.nameExact("get_order").callIn.l.size                         // is the call graph populated?
```

`workspace/*/overlays/` on the August tree shows `base callgraph controlflow dataflowOss typerel`
as marker dirs, so `controlledBy` should work with nothing to enable — but nobody has run it.

### P1 — restore the ground truth, build the oracle (3 days)

**Restore `testbeds/shopfast/`** from `D:/d/FYP/testbeds/shopfast/` (11 files, 43 KB). It is
the only thing the four rules were ever measured against and it is not in the repo.

**`bench/`** — the harness, exactly as specified in TDD §9. Minimum viable set:

```
bench/
  keys/shopfast.key.jsonl      line-anchored answer key
  validate_key.py              resolve each verbatim `anchor` by unique string search; drop unresolvable
  match.py                     enclosing_function() via Python ast, qualified by class; cwe_family()
  run.py                       backend -> candidates -> match -> metrics -> runs/<id>.json
  report.py                    runs/*.json -> markdown table
  backends/{joern,semgrep,bandit,null}.py     LocatorBackend ABC
```

Key rows carry a **verbatim `anchor` string, never a line number**; `validate_key.py` resolves it
and drops any row whose anchor is missing or non-unique. Record `route_reachable` per row — bugs
#24 and #25 have no Flask route reaching them. Record the 26th undocumented bug (`app.py:35–38`,
`/login` discards `verify_login`'s return value) and both bait rows on `db.find_product` /
`db.user_by_name`. **A human adjudicates every row**; if the LLM proposes the key and is evaluated
against it, every number is circular.

**Exit gate.** `bench/run.py --backend joern --benchmark shopfast` reproduces JOERN.md §8 exactly.
If the harness disagrees with the number already known by hand, the harness is wrong.

### P2 — port the driver; land the eight fixes behind the harness (3 days)

**`scan.py`** is the August `joern_scan.py` moved into the package, with:
- `from app.services.scanner import Finding` (same dataclass; `tool="joern"`).
- `enabled(path) -> tuple[bool, str]`. The old version swallowed `available()`'s reason at line 127.
- Per-scan `diag.json` read back and logged: `rule_state` per rule (`ok | threw | skipped`), pack id
  and hash, rules sha256, method count. A rule that threw must not look like a rule that found
  nothing.
- `_parse_tsv` unchanged for columns 1–8; columns 9–11 (`pack_id@hash`, `slot_trace`, notes) free.

**`rules/locators.sc`** is `joern_queries.sc` with the eight fixes, each its own commit, each with
a bench number before and after:

1. **Per-rule and per-method `try { } catch { case NonFatal(e) => ... }`**, writing a status row.
   Today one throw skips the `os.write` at line 100 and the whole target reports UNSCANNED.
2. **Split `AUTH` into `authz_guard` (suppresses) and `authn_only` (evidence, never suppresses).**
   IDOR is by definition a bug in already-authenticated code; `login_required` in the suppressor
   list silences the rule on every decorated view — every view in a real app. Shopfast cannot show
   this because it has no decorators. **Likely the single largest recall delta in the plan.**
3. **Docstring literals out of the guard channel.** Shopfast plants business-justification
   docstrings; a docstring reading "runs inside a transaction" must not satisfy the atomic guard.
4. **`nameNot("<.*>\\d*", "__.*__")`** — `<lambda>0` is currently scanned as a user method.
5. **`abort(401` / `abort(403`** instead of `abort(` — a not-found guard reads as an authz guard.
6. **Drop `" in ["`, `" in ("`, `" in {"` from ALLOWLIST** — any `for x in [...]` kills CWE-915.
7. **Hoist the module-scope decorator lookup out of the per-method loop** (quadratic today; the
   first thing that dies on a 50k-LOC repo) and match the lowered decorator as `"(" + name + ")"`.
8. **`filenameExact` / `nameExact`** everywhere a name is compared. The regex hazard that once
   zeroed a whole run is deletable, not just avoidable.

**Pipeline wiring** (`services/pipeline.py`, after `findings_raw = scanner.scan(path)`):

```python
joern_used, joern_why, joern_diag = False, "", {}
ok_j, joern_why = joern.enabled(path)
if ok_j:
    joern_raw, joern_diag = joern.scan(path)      # never raises; [] on failure
    if joern_raw:
        joern_used = True
        findings_raw = list(findings_raw) + joern_raw
...
# reserve verify slots for CPG candidates BEFORE the severity truncation
j = sorted([x for x in prepared if x["tool"] == "joern"], key=sev, reverse=True)
o = sorted([x for x in prepared if x["tool"] != "joern"], key=sev, reverse=True)
q = min(config.JOERN_LLM_QUOTA, len(j))
to_verify = j[:q] + o[:config.MAX_LLM_FINDINGS - q]
...
return {..., "joern": {"used": joern_used, "reason": joern_why, **joern_diag}, ...}
```

`/api/health` gains `scanners.joern = {available, note, server}`.

**Tests** (`backend/tests/test_joern.py`): `_parse_tsv` on a fixture; `_error_summary` on a
captured stack; `enabled()` returns the reason when the runtime is absent; the pipeline still
returns `ok: true` with `joern.used: false` when Joern is off. None of these need a JVM.

### P3 — server-mode sidecar (1.5 days)

**`server.py`** starts `joern.bat --server --server-host 127.0.0.1 --server-port {port}
--server-auth-username rampart --server-auth-password {random per process}` from `lifespan`,
waits for `/query-sync` to answer `1+1`, and stops it on shutdown. Spawn with
`CREATE_NEW_PROCESS_GROUP` and kill with `taskkill /T /F` — `Popen.terminate()` on a `.bat` kills
`cmd.exe` and leaves the JVM alive holding the workspace (the same defect the TDD found for scan
cancellation).

**`client.py`**: `query(scala: str, timeout: int) -> tuple[bool, str, str]` over
`requests.post(f"http://127.0.0.1:{port}/query-sync", json={"query": scala}, auth=(user, pw))`.

**`scan.py`** in server mode: `importCode.python(dir, proj)` as one query, each rule as its own
query, `delete(proj)` at the end. A compile error in one rule costs that rule. The script-mode path
stays as the fallback when the server is not up, so P2's behaviour is never lost.

**Exit gate.** Second scan of shopfast in the same backend process completes in under 15 s (first
one pays the CPG build only, not the JVM). A rule with a deliberate syntax error returns
`success:false` and `diag.rule_state[rule] == "threw"` while the other three report normally.

**Status 2026-09-15: DONE.** As specified, with three deviations learned from the real server:
`client.py` folded into `server.py` (`JoernServer.query`, urllib, no `requests` dependency);
`/query-sync` returns `success:true` even for compile errors, so `evaluation_failed()` parses the
stdout banner and the broken rule reports `rule_state = "compile_error"` (a new state beside
`ok|threw|not_run`, because "never compiled" and "ran and threw" are different diagnoses);
and `SHIFTLEFT_OCULAR_INSTALL_DIR` must be exported or `importCode` NPEs under `--server`.
Measured: CPG phase 8.0–8.2 s on the second and third API scans (script: 19–34 s); identical
candidates on shopfast and probe; broken mass-assignment section isolates, 4 candidates survive.
Log: `bench/runs/2026-09-15-p3-server.md`.

### P4 — persistence and UI provenance (1.5 days)

**Schema** (`backend/db/migrations/0002_joern.sql`; today the schema is one file, so this is also
the moment to start numbering):

```sql
alter table findings add column tool text not null default 'unknown';
alter table scans    add column joern jsonb not null default '{}';   -- {used, reason, elapsed_ms, rule_state, pack}
create index findings_tool_idx on findings (tool);
```

`routers/scans.py` writes `f.get("tool")` and the pipeline's `joern` dict.

**Frontend**: `SummaryCard.tsx` renders a `+ CPG` pill when `r.joern.used`, and a callout
("N of these came from Joern CPG analysis, M confirmed") — the old UI had this; it was lost.
`FindingCard.tsx` renders a `CPG` badge when `f.tool === "joern"`. `HealthContext` exposes
`scanners.joern` so the Setup page can say "Joern: ready" or "Joern: not installed — run
`python -m app.services.joern.runtime --install`" **before** the user starts a scan.

**Status 2026-09-15: DONE.** `backend/db/migrations/0002_joern.sql` (+ `tool_stats` view and
`GET /api/research/tools`), applied by a small runner in `app/db.py` at start-up and by
`python -m app.db` (records `schema_migrations`; a fresh DB gets `schema.sql` as 0001). Both
persistence paths write `tool` and `joern`. Two things the spec did not foresee: asyncpg returned
jsonb as text, so `scans.counts/scope` reached the History page as strings (its severity bar never
rendered) - a jsonb codec on the pool fixes all of them; and `HealthContext` had to poll while the
sidecar is `running && !ready`, or the Setup note would say "starting" until a reload. Verified: a
signed-in shopfast scan stores 5 `joern` + 15 `semgrep` rows and the `joern` block; the summary
callout, `+ CPG` pill, `CPG` badge and Setup note render (SSR check against the real JSON).

### P5 — vocabulary packs as data (3 days)

Exactly the TDD §8.8 / August §3.3 spec. Summary of the load-bearing rules:

- Every slot declares its **sink** (`call_name`, `param_exact`, `param_suffix`, `exec_sql_kw`,
  `token`, `signal_text`, `guard_text`) and the validator enforces a different character class
  per sink. A `text` token can never reach a regex-taking accessor.
- No value under 3 chars; no `authz_guard` value may prefix an `authn_only` value; `qty_terms`
  and `price_terms` disjoint; ≤ 64 values per slot; ≤ 8 KB per pack; sorted + deduplicated before
  hashing so composition is order-independent. Anything failing is **discarded whole**.
- The Scala reads the pack with `ujson.read` (already on Joern's classpath) **after** `importCode`,
  inside try/catch, falling back to `_base.json` — so a malformed pack degrades, never aborts.
- `scan.py` resolves the pack from the target's imports / `requirements.txt` (`django` → django;
  `flask` → flask-sqlite3; else `_base`), writes it into the scratch dir, passes its path.
- `flask-sqlite3.json` is hand-written (the reference). `django.json` is LLM-drafted **from Django
  documentation only**, under the held-out protocol (P6), validated, human-reviewed, transcript
  committed as `packs/django.transcript.json`.

**Exit gate.** Same frozen Scala, same frozen key: `--pack flask-sqlite3` vs `--pack django` on
the Django testbed. That is the headline measured claim.

**Status 2026-09-15: infrastructure DONE; the Django half waits for P6 by design.**
`vocab/schema.json` (18 slots x 7 sinks: call_name, param_exact, param_suffix, exec_sql_kw,
token, signal_text, guard_text), `vocab/validate.py` (pure stdlib; per-sink class, caps, cross-slot
rules, union composition, canonical sha256, digest allowlist, framework detection),
`packs/_base.json` (= the pre-P5 Scala vals, 82 values) and `packs/flask-sqlite3.json` (+70 from
the Flask/Flask-Login/Flask-SQLAlchemy/WTForms/sqlite3 docs). `locators.sc` reads the pack in a
`// @@ vocab` section via `ujson` after `importCode`, falls back to `_base.json` in try/catch,
and writes `pack_tag` + `slot_trace` as TSV columns 9-10 (→ `Finding.meta`). `scan.py` resolves
the pack (`JOERN_PACK=auto`: requirements/imports → flask-sqlite3 | django | _base), validates in
Python before anything reaches the JVM, and records `diag.pack`; `bench.run --pack`.
Measured: `_base` and `flask-sqlite3` both give shopfast 4/0/1 and probe 5/0/2 (non-regression;
the testbeds contain only base vocabulary). `django.json` is NOT authored: the held-out protocol
says the testbed freezes first, so the `flask-sqlite3` vs `django` ablation runs at the end of
P6. Log: `bench/runs/2026-09-15-p5-vocab-packs.md`; tests `backend/tests/test_vocab.py` (31).

### P6 — Django testbed, held-out (4 days)

`testbeds/djshop/`. For each of the four SAST-blind CWEs, **a vulnerable function and the
framework's canonical fix**: `get_object_or_404(Order, pk=pk)` vs `…, user=request.user`; a
`setattr` loop over `request.POST` vs a `ModelForm` with explicit `fields`; unbounded
`price * quantity` vs `PositiveIntegerField`; `save()` after a stock check vs `F("stock") - qty`.
Add a DRF `ViewSet` with `permission_classes` (exercises P7's class-scope traversal).

Protocol, non-negotiable: author and freeze the testbed **before** `django.json` exists; the
pack's authoring prompt contains framework docs and `flask-sqlite3.json` as a schema example,
never testbed source; split DEV / HELD-OUT; touch HELD-OUT once, at the end.

This is where three of the four rules will be found to **fire on correctly fixed code** — a
result shopfast structurally cannot show, and one of the best results available to the thesis.

**Status 2026-09-15: DONE, protocol kept.** Testbeds frozen at `0249a60b`, pack authored from
docs by a walled-off agent at `9d03ce96` (prompt + transcript committed), one DEV-informed Scala
fix (`kw = value` normalisation, `82921d1f`), held-out evaluated once (`bench/runs/heldout.log`).
Held-out, 9 SAST-blind rows: `_base` 5/9, `flask-sqlite3` 5/9, **`django` 7/9**; bandit and
semgrep 0/9. Failure causes with the Django pack: 12 = 7 vocabulary (`get` excluded by the
author for precision; `=request.user` scoping kwarg missing; `request.post` signal too broad) +
5 structural (class-scope guard, receiver-chain ownership, cross-file bound, validation-vs-DB
comparison ×2). Kill criterion (structural > half) not met, but close: the structural residue is
exactly P7's three traversals. The prediction held - the rules fire on 3 correctly fixed twins
(`invoice_detail_safe`, `refund_line_form`, `WalletViewSet.statement`).
Log: `bench/runs/2026-09-15-p6-django-heldout.md`. Do not re-run `9b4f52b3f5f1` after a pack change.

### P7 — the graph capabilities (3 days)

In order of reliability on `pysrc2cpg`:

1. **Control dependence** (`controlledBy` / `dominatedBy`). Rule 4 gets an ordering constraint —
   today it accepts any comparison plus any write in any order. Join through the
   `ControlStructure`'s condition node, not raw node indices.
2. **Class scope** (`m.typeDecl.member`, `inheritsFromTypeFullName`). DRF `permission_classes`,
   `LoginRequiredMixin`, `Meta.fields`, pydantic `conint(gt=0)`. It is a type lookup, not
   dataflow, so pysrc2cpg's weak interprocedural edges do not block it.
3. **Route reachability** (`callIn`), emitted as `route_reachable` on every finding and as a
   harness metric (*reachable-subset recall*). Report it, never gate on it — the call graph is
   name-based.

**Status 2026-09-15: DONE.** The three probes ran (controlledBy returns the comparison call;
typeDecl bodies/members/bases resolve; callIn resolves Flask cross-module calls, Django views are
found via urls.py references). TOCTOU = control dependence + receiver identity (`product.stock >= q`
… `product.save()`; raw SQL keeps the token test). Class scope: class body + bases join the guard
channel; for a scoped read (slot `scoped_read_calls`, DRF get_object) the `queryset_hooks` body and
any `object_permission_hooks` class named in the body count as authz; the body of any instantiated
project class joins the positive-guard channel (min_value in forms.py). Route flag = TSV column 11 →
`meta.route` (yes|no|unknown), agreement with the key reported per run (10/10 where routes exist).
Schema v2: four slots; pack cap 16 KB. DEV/django: 5 TP / 2 FP / 2 bait → **5 / 0 / 0**;
shopfast, probe, DEV _base/flask unchanged. Held-out NOT re-run (rules were written after reading
its failures); the receiver-chain case (`request.user.invoices…`) remains unaddressed.
Log: `bench/runs/2026-09-15-p7-graph.md`.

### P8 — O3 re-verification (2 days)

The strategic phase: it gives Joern a second graded objective.

**`reverify.py`**: after `apply_fix()` writes the patched file into the snapshot copy
(`apply.py:112`), rebuild the CPG on that copy and run `rules/reverify.sc` scoped to the one
method: *does the locator still fire, and does a guard token now dominate the sink?*
`locator_refires == false and guard_dominates_sink == true` is convergence. Expose it as
`POST /api/fix/verify {scan_id, path, function}` → `{converged, reverify_method: "cpg" |
"pattern", evidence}`. The frontend's FixPanel shows the result next to Apply.

This is the check no pattern matcher can perform, and it is the difference between "the text
pattern vanished" and "the exploitable path is gone." In server mode a re-verification is one CPG
build of one file plus two traversals.

**Status 2026-09-15: DONE.** `reverify.py` (preview on a scratch copy, or post-apply against the
snapshot; whole-target regression diff; `decide()` pure), `// @@ reverify` section (guards by
family with location, sink counts, route), `POST /api/fix/verify`, FixPanel "Verify with CPG".
Exit gate met: the ownership fix to `orders.get_order` flips the locator to silent with
`method:permissiondenied` as evidence; a cosmetic rename does not converge; a docstring claiming
`atomic` does not converge. Through the API in server mode: 13-17 s (two CPG builds). The
"guard dominates sink" question is answered structurally for TOCTOU (the P7 control-dependence
rule) and by guard presence/location for IDOR, where the check legitimately follows the fetch.
Log: `bench/runs/2026-09-15-p8-reverify.md`.

### P9 — docs and thesis text (1 day)

Regenerate `JOERN.md` from real runs (the current §8 is hand-traced). README section. The three
thesis paragraphs from the August synthesis, verbatim: the zero-traversal admission, the
AUTHN/AUTHZ conflation, and the vocabulary-not-structure finding.

**Status 2026-09-15: DONE.** `docs/JOERN.md` regenerated - every number cites a `bench/runs/`
artifact, the August hand-traced §8 is gone; `docs/THESIS_JOERN.md` - the three August paragraphs
verbatim with their September status, then design / protocol / results / threats-to-validity
paragraphs for the thesis; README - pipeline line, Joern section, progress-log entry;
`bench.report` is pack- and split-aware. The three documents are un-ignored and tracked.
All nine phases of this plan are complete. Owed by the team, not by code: adjudicate the 90 key
rows; run the `full` arm on the Django splits when the Gemini quota allows; score the post-P7
rules on a NEW held-out split.

---

## 4. What this plan does not do

- **No multi-language.** `importCode.python` only; scope agreed in August. All 14 frontends are
  installed and a future `importCode.jssrc2cpg` is one line in `scan.py`, but every rule's
  vocabulary and every testbed is Python.
- **No taint / `reachableByFlows`.** `pysrc2cpg` ships no Python dataflow semantics
  (`DefaultSemantics` is language-agnostic operators + C stdlib + Java), so every Python external
  call has no flow summary. That is the precision ceiling; the plan uses control dependence.
- **No guard-as-configuration.** Django `urls.py` wrappers, DRF `DEFAULT_PERMISSION_CLASSES`,
  Flask `before_request`. The guard is in another file's data structure. This produces FPs on
  mature codebases and no vocabulary edit fixes it. State it.
- **No cross-function guards.** The check in the caller, the query in a repository module. This
  generalises the `find_product` FP. State it.
- **Atomicity is not syntactic.** TOCTOU stays a heuristic.

---

## 5. Risks and kill criteria

| Risk | Signal | Response |
|---|---|---|
| P0 fails — Joern will not run here | `joern.bat --help` non-zero after install | Try `joern-cli` v4.0.627; if still failing, the JVM path (Windows Defender / SAC) is the blocker and the phase is deferred, documented |
| The four probes in P0 return empty | `controlledBy.size == 0` on every comparison | P7 (1) and P8 lose their basis; keep the AST rules, drop the "graph" claim from the thesis honestly |
| Harness disagrees with JOERN.md §8 | anything but 4 TP + 1 bait FP | Fix the harness, not the rules — the by-hand number is known |
| Structural failures exceed ~half on the Django testbed | most misses need a new traversal, not a new token | The vocabulary-pack conclusion is wrong for these domains; cut P5, spend the time on P7 |
| Team will not adjudicate key rows by hand | rows stay `proposed_by: llm` | Stop. Every metric is circular; the days are better spent on a visible feature |
| Anyone proposes LLM-written Scala | a PR with a `regex` sink or a raw-Scala slot | No, and the reason is on record in `D:/d/FYP/CLAUDE.md` §7 |
| Cold start makes demos painful | first scan > 60 s | P3 is the fix; move it earlier if needed |

---

## 6. Day 1

1. `runtime.py --install` (copies the zip from `D:/d/FYP/tools/`, downloads the portable JRE).
2. `cp -r D:/d/FYP/testbeds/shopfast testbeds/` and commit it.
3. Drop the August `joern_scan.py` + `joern_queries.sc` into `app/services/joern/` unchanged, add
   the six lines to `config.py`, the eight-line additive block to `pipeline.py`.
4. `POST /api/scan {"path": "testbeds/shopfast", "scanner": "bandit"}` — watch for
   `JOERN_FINDINGS=` in the log. Paste it into `bench/runs/2026-09-15-first-run.md`.

That is the first time this project's flagship phase will have executed on the machine it is
demoed from. Everything after is measurement.
