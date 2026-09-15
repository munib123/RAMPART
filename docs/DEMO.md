# RAMPART — demo runbook

For showing the project to the team. Everything below was executed on 2026-09-15 on this
machine (Windows 11, Python 3.13 venv, Node 24, Joern 4.0.589 under `tools/`, the team's
Supabase project as the database).

## 0. Ten minutes before: start everything

Open **two terminals** in `D:\d\RAMPART`.

**Terminal 1 - backend (leave it running):**
```
backend\.venv\Scripts\python.exe backend\run_server.py
```
Wait for `Application startup complete` and, ~25 s later, the Joern sidecar. Confirm in a
browser or a third terminal:
```
curl http://127.0.0.1:8000/api/health
```
You want: `"db_enabled": true`, `"llm_enabled": true`, `"model": "gemini-2.5-flash"`,
`scanners.joern.server.ready: true`, and three collections totalling **71,468** vectors.
If `collections` is empty or a count is missing, call `/api/health` once more - the first
call after start-up can hit Chroma before it is ready and the backend now retries.

**Terminal 2 - frontend:**
```
cd frontend
npm run dev:web
```
Open **http://localhost:5173** (the dev server is IPv6-only: `localhost`, not `127.0.0.1`).

**Sign in** as `demo@rampart.dev` / `RampartDemo!2026` (plan `pro`: 30 scans, 20 fixes).
Anyone can also **Sign up** live - accounts go to Supabase.

**Do not** have Docker's `rampart-pg` in `.env` - `DATABASE_URL` must be the Supabase pooler
DSN (it is). **Do not** run the bench harness during the demo: its sidecar cannot bind 8091
while the backend holds it, so it silently uses the slower script mode.

## 1. The story in five screens (~10 minutes)

### Screen 1 - Landing (30 s)
Point at the status strip: **semgrep · llm · gemini-2.5-flash**, and the three corpora
(hackerone 30,818 · nuclei 11,138 · crossvul 29,512). The pipeline nodes read
*Scan → Ground → Verify*; the Scan chip says `semgrep · bandit · joern CPG`.

> "Three engines. Two are pattern matchers. The third is a code property graph - it finds the
> bugs the other two structurally cannot see."

### Screen 2 - Setup (1 min)
Pick **E-commerce**, **Python**, **Access control + Injection**. Path:
```
D:\d\RAMPART\testbeds\shopfast
```
Scanner: **Auto** (= semgrep, ~2 min) or **Bandit** (~1 min) if time is short.
Point at the note under the scanner: **"Joern CPG phase is ready (server mode) · IDOR, mass
assignment, unchecked quantity, TOCTOU."** - the graph engine is reported *before* the scan.

### Screen 3 - Scanning (1-2 min, talk over it)
The captions name the CPG step (`joern · building the code property graph…`). While it runs:

> "shopfast is our Flask testbed: 25 planted bugs plus one we found ourselves, with a
> line-anchored answer key. Bandit finds 12, semgrep 13 - and neither finds the four logic bugs:
> an IDOR, a mass assignment, an unchecked quantity, a check-then-write race. Joern finds
> exactly those four."

### Screen 4 - Report (4 min) - the core of the demo
Top: the summary says **"N of these came from Joern CPG analysis: 4 confirmed, 1 cleared by
the LLM"** and the `+ CPG` pill. Then:

1. Scroll to a card with the violet **CPG** badge - `orders.py:5 get_order`, *Insecure direct
   object reference*, **Confirmed 95**. Hover the badge: it names the rule, the vocabulary pack
   (`flask-sqlite3`) and the entries that fired (`id_param_suffix=_id; orm_read_calls=fetchone`),
   and that a route reaches it.
   > "Joern located it structurally - a read by a caller-supplied id with no ownership check
   > anywhere in the method, its class, or its decorator. The LLM proved it, grounded in real
   > disclosed vulnerabilities - open the exemplars."
2. Find `db.py:13 find_product` - CPG badge, **False positive 90**.
   > "Same rule fired here. Products are public, so there is no ownership to check. Joern
   > cannot know that; the LLM can. Joern locates, the LLM proves - this is the design working."
3. On `get_order`, click **Suggest a fix** → the diff. Then **Verify with CPG**.
   ~15-20 s. The verdict line: *"Verified on a scratch copy: the locator no longer fires.
   guard now present (method:permissiondenied…)"*.
   > "That is not a text match. We applied the fix to a copy, rebuilt the graph, and asked
   > whether the exploitable path is gone. A comment that says 'authorized' would fail this."
   (If the generated fix is unusual and does not converge, the verdict says why - *"the locator
   still fires"* - which is also a fine thing to show. Regenerate and try once more.)
4. Optionally **Apply fix** (writes the file; a snapshot makes **Revert** possible), then
   **Re-verify with CPG** on the live tree, then **Revert changes**. Only do this on the
   testbed, never on a real project during the demo.

### Screen 5 - History (30 s)
The saved scan with its `+ CPG 5` pill, next to the team's earlier scans - all in Supabase.

## 2. If someone asks "prove it" - the numbers in one terminal

Run **after** the UI part, or in a third terminal while nobody is scanning (see the 8091 note):
```
backend\.venv\Scripts\python.exe -m bench.report --latest
```
The rows to point at (all committed under `bench/runs/`):

| benchmark | arm | result |
|---|---|---|
| shopfast | bandit / semgrep / joern | 12 / 13 / **4 TP** - Joern's four are the SAST-blind bugs #22-25, disjoint from both |
| shopfast | full (`gemini-2.5-flash`) | **17 TP / 0 FP / F1 0.79**, bait cleared - run `171358` |
| probe | joern | 5/5 - the eight rule fixes, one per function |
| djshop-heldout (Django, unseen, evaluated once) | joern `_base` → `django` pack | **5/9 → 7/9** SAST-blind; bandit and semgrep 0/9 |
| djshop-dev | joern `django` pack after the graph work | 5 TP / **0 FP / 0 bait** (was 5/2/2) |
| djshop-dev | full (`gemini-2.5-flash`) | 7 TP / 2 FP / F1 0.67 - run `171532` |

The write-ups: `docs/JOERN.md` (every number cites a run), `docs/THESIS_JOERN.md`.

## 3. Things that can go wrong, and what to do

| symptom | cause | do |
|---|---|---|
| Verdicts all read **Error** | Gemini quota (`429`) or a `503` blip | The backend now retries 503s. For `429`: switch `GEMINI_MODEL` in `.env` to another 2.5 model (quotas are per model - `flash-lite` was exhausted on 09-15, `flash` had quota) and restart the backend. The scan, grounding and CPG findings are unaffected either way. |
| Setup note says **"CPG starting"** | the sidecar takes ~25 s after the backend starts | wait; the note flips on its own. A scan started now still runs the CPG in script mode (slower, same results). |
| **"CPG not installed"** | `tools/` missing on this machine | `cd backend && .venv\Scripts\python.exe -m app.services.joern.runtime --install` (Windows x64; downloads a 46 MB JRE and the 1.7 GB joern-cli, sha512-verified) |
| Port 8000 busy | an old backend still running | `netstat -ano \| findstr :8000` → `taskkill /T /F /PID <pid>`, or set `RAMPART_PORT` |
| Sign-in fails | `.env` `DATABASE_URL` / `JWT_SECRET` | check `/api/health` shows `db_enabled: true`; the demo account is in Supabase |
| Scan takes > 3 min | semgrep `--config auto` fetches rules over the network | use **Bandit** for the demo scan |
| `/api/health` collections empty | Chroma not ready at first call | call it again; fixed to retry on 09-15 |

## 4. What to say the MVP can do (one breath each)

1. Scans Python projects with semgrep and bandit **plus a code-property-graph locator** for the
   four logic-bug classes pattern scanners cannot see.
2. Grounds every finding in **71,468 vectors of real disclosed vulnerabilities** and has Gemini
   verify it with a confidence, an explanation and a fix.
3. **Suggests, applies, reverts and re-verifies fixes** - re-verification rebuilds the graph
   and rejects a fix that only changes text.
4. Shows **provenance** everywhere - which engine, which vocabulary entry, whether a route
   reaches it - and persists it to Supabase for the research views.
5. Is **measured, not asserted**: an evaluation harness with frozen answer keys, a held-out
   Django testbed, and every number in the docs traceable to a run file.

And what it does not do yet (say it before they ask): 0 of 90 answer-key rows are adjudicated
by a human; the post-graph rules have not been scored on a fresh held-out split; Python only;
the free-tier LLM is quota-bound and model-sensitive.
