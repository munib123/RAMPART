# RAMPART — the Joern / CPG phase

How RAMPART finds the **SAST-blind logic bugs** that pattern scanners structurally cannot see,
using Joern's Code Property Graph as the *locator*, a data-only vocabulary pack as the
framework knowledge, and the LLM as the *prover*.

This is the September 2026 rewrite of the August document. Every number below comes from a
run artifact under `bench/runs/` (run ids in brackets); the August §8 was hand-traced and is
superseded. Phase logs: `bench/runs/2026-09-15-*.md`; rules v2 (the split into `rules/*.sc` and
the eight call-anchored rules): `bench/runs/2026-10-05-rules-v2.md`. Plan and status:
`docs/JOERN_PLAN.md`.

---

## 1. Why a CPG phase at all

semgrep and bandit spot a *dangerous thing that is present* — an `eval`, a `shell=True`, an
f-string in SQL. They are blind to the opposite class: a **safe thing that is absent**.

| Bug | What is missing | CWE | rule |
|---|---|---|---|
| IDOR / broken object-level authorization | an *ownership check* before reading a record by id | CWE-639 | `joern-idor-missing-ownership` |
| Mass assignment | a *field allow-list* before writing a caller-supplied mapping | CWE-915 | `joern-mass-assignment` |
| Unchecked quantity | a *lower bound* on a count that money is computed from | CWE-840 | `joern-unchecked-quantity` |
| Race condition / TOCTOU | a *lock or atomic transaction* around a check-then-write | CWE-362 | `joern-toctou-check-then-write` |

Measured, not asserted: on `testbeds/shopfast` bandit finds 12 of 26 bugs (25 planted + 1 undocumented) and semgrep
13, and **neither finds any of the four above** [`083330`, `083415`]. On both Django splits the
pattern arms find 0 of the 8 / 9 SAST-blind rows [`122402`, `122417`, `125014`, `125031`]. The
engines are disjoint; their union on shopfast is 19 of 26.

A second class is invisible to them for a different reason: the bug is **in how a value flows**,
not in any one line. The value passes through a parameter, a local, or a constant in another
module. Since 2026-10 eight call-anchored rules cover it (§5.1):

| Bug | What a pattern cannot see | CWE | rule |
|---|---|---|---|
| Ignored credential check | the check's return value is never used | CWE-287 | `joern-ignored-auth-result` |
| Hard-coded credential | the compared value is `config.NAME`, a literal in another file | CWE-798 | `joern-hardcoded-credential-compare` |
| SSRF | the URL is a parameter whose caller passes `request.form[...]` | CWE-918 | `joern-ssrf-request-url` |
| Path traversal | the same, into `open` / `send_file` | CWE-22 | `joern-path-traversal` |
| CORS wildcard | the header value is a constant `"*"` defined elsewhere | CWE-942 | `joern-cors-wildcard` |
| Cleartext transport | the client URL is an `http://` constant defined elsewhere | CWE-319 | `joern-cleartext-transport` |
| XXE | the parser keyword resolves to an unsafe setting | CWE-611 | `joern-xxe-parser` |
| Debug server | `run(debug=config.DEBUG)` with `DEBUG = True` | CWE-489 | `joern-debug-exposed` |

On shopfast, six of the bugs these find (#10, #11, #12, #19, #21, #26) were missed by bandit,
semgrep and the `full` arm alike [`171841`].

## 2. The contract: Joern **locates**, the LLM **proves**

Joern emits *candidates* in the same normalized `Finding` shape as a scanner finding. They then
flow through the existing pipeline — containing-function slice → RAG grounding → batched Gemini
verdict → ranked report — with a **reserved share of the LLM budget** (`JOERN_LLM_QUOTA`) so a
large repo's semgrep noise cannot push them out. The phase is **additive and never raises**: a
dead JVM means fewer findings and a `joern.reason` in the response, never a failed scan.

```
 Joern (structural)                          LLM (semantic)
 "reads a record by a caller-supplied id,    "orders are user-owned and nothing checks the
  no ownership token in the method, its      caller → CONFIRMED IDOR (95)"
  class, or its decorator"             ───▶  "products are public → not a bug"
```

The second line is the `db.find_product` bait in shopfast. In P1's `full` run with
`gemini-2.5-flash-lite` the LLM **Confirmed** it instead of clearing it [`084600`]; with
`gemini-2.5-flash` (the model the demo uses, after the lite tier's daily quota ran out) the same
pipeline **clears it** as a False positive, and shopfast's full arm reaches 17 TP / 0 FP /
F1 0.79 [`171358`]. The verdict tier is model-sensitive; both runs are kept.

## 3. How it runs

`backend/app/services/joern/`:

| file | role |
|---|---|
| `runtime.py` | finds or **installs** a portable Temurin JRE 21 and joern-cli 4.0.589 under `tools/` — no admin, nothing on PATH. `python -m app.services.joern.runtime --install`. Picks the per-platform release asset (`joern-cli-{windows-x86_64,linux-x86_64,linux-arm64,macos-x86_64,macos-arm64}.zip`) and the matching Adoptium JRE, verifies the zip against the published `.sha512`, and on failure prints a one-line reason plus the manual fallback (drop the asset zip and its `.sha512` into `tools/`) instead of a traceback. Only Windows x64 has been exercised end to end; the Linux/macOS paths are unit-tested only |
| `server.py` | one `joern --server` **sidecar per backend process** (127.0.0.1:8091, random per-process Basic-auth password, tree-killed on shutdown). Started by the FastAPI lifespan; `/api/health` shows `scanners.joern.server` |
| `scan.py` | renders the rules program (`rules/*.sc`, concatenated in file-name order), picks and validates the vocabulary pack, runs the rules (one `/query-sync` per `// @@` section in server mode; one `joern --script` as the fallback), parses the TSV, returns `(findings, diag)` |
| `rules/*.sc` | the rule **shapes**: one program in twelve files, 956 lines (627 non-blank, non-comment) of hand-written, hashed Scala, with zero framework vocabulary. `00_prelude` (helpers, the `RULES` registry, `perItem`), `10_import`, `20_vocab`, `30_context` (per-method `Ctx`, class scope, routes), `35_flow` (constants across files, def-use, caller arguments), `40_access_control`, `45_business_logic`, `50_authentication`, `55_untrusted_input`, `60_insecure_config`, `80_reverify`, `90_finish`. `scan.rules_sha256()` hashes every file name + LF-normalised content and is recorded as `rules_sha256` in every run artifact. Today's is `643ba2888183758e`; the single-file `locators.sc` it replaced was `11befcda9b9cf6bd` |
| `vocab/` | `schema.json`, `validate.py`, `packs/{_base,flask-sqlite3,django}.json` + `digests.json` |
| `reverify.py` | O3: rebuild the CPG on patched code and ask whether the locator still fires. The target method is class-qualified (`Class.method`); `file`, `method` and `class` are validated as a relative `.py` path / identifiers and Scala-escaped before they reach the rule |

**Server mode** pays the JVM once. CPG phase per scan: shopfast **8.0–8.2 s** warm (19–34 s in
script mode), djshop-dev **14.7 s**; sidecar ready ~25 s after the backend starts, without
blocking it. A compile error in one rule costs that rule (`rule_state = compile_error`), not
the phase [`2026-09-15-p3-server.md`].

Two facts about `/query-sync` that the docs do not say: `success` is HTTP success, not
evaluation success (compile errors and exceptions arrive with `success: true`; `server.py`
parses the stdout banner), and `importCode` NPEs in server mode unless
`SHIFTLEFT_OCULAR_INSTALL_DIR` is set.

## 4. Vocabulary is data

The rules hold *shapes*: "a single-object read + an id-like parameter + no authorization
guard in scope". What an authorization guard, a lock, an allow-list, an ORM read or an object
id **looks like** in a framework is a JSON pack the Scala reads with `ujson` after
`importCode`:

- **32 slots, 10 sinks** (schema v3), each sink with its own character class (`call_name` → `nameExact`
  only; `guard_text` → `String.contains` on the method's calls + identifiers, never its
  literals). No regex sink, no Scala. A test greps the Scala to prove no regex-taking accessor
  ever sees a pack value. Schema v3 added `call_path` (a dotted call path, matched by
  `startsWith(v + "(")`), `origin_text` (where a value came from, `contains`) and `kwarg_flow`
  (`call:keyword=value` after constant resolution, `==` only).
- **Caps and cross-slot rules**: 16 KB, 64 values per slot; no authz token may sit inside an
  authn token; count and money terms disjoint; text sinks lower-case. A pack that breaks any
  rule is **discarded whole** and the scan runs on `_base`, saying so in `diag.pack.fallback`.
- **Composition** is a per-slot union with the parent, sorted and de-duplicated before hashing:
  the digest does not depend on author order. `packs/digests.json` is the allowlist.
- **Provenance**: every finding carries `meta.pack` (`django@b5df755be580`) and `meta.slots` —
  which entries fired it (`id_param_suffix=_id;orm_read_calls=get_object_or_404`).

| pack | values | authored from | digest |
|---|---|---|---|
| `_base` | 165 | the July/August Scala vals, verbatim, plus (schema v3) framework-neutral values for the eight call-anchored rules: stdlib, requests, httpx, lxml, Werkzeug, common auth helpers | `caf7008bd4f7` (was `ef5ac270285a` before v3) |
| `flask-sqlite3` | 251 | Flask / Flask-Login / Flask-SQLAlchemy / WTForms / sqlite3 docs, hand-written | `f2117bd54752` (v3: the schema version and the inherited `_base` values; no value of its own changed. Before that `433e82b50aa9`, and before that `2b4dde8c2e83` before 2026-09-16: two single-quote twins of the `g.user["id"]` / `session["user_id"]` scoped-query tokens, added after a generated fix used `g.user['id']` and did not converge; guard text is matched as source text and pysrc2cpg keeps the author's quotes. shopfast joern arm unchanged at 4 TP + bait, probe 5/5, run `20260916T063414Z`) |
| `django` | 289 | Django 5.1 + DRF docs, drafted by a walled-off agent under the held-out protocol (§7), reviewed, not tuned | `8ba7f75feead` (today's: v3 adds `request_sources` from the request-response and DRF requests docs); `b5df755be580` with the four P7 slots; the held-out run scored `b38082f8d2b6`, the pack as it was before P7 |

`JOERN_PACK=auto` picks the pack from `requirements.txt` / imports. `--pack _base` on any
benchmark is the *no-vocabulary* ablation arm.

One representation fact every pack author needs: pysrc2cpg renders keyword arguments as
`user = request.user` (spaces around `=`). The rules normalise both text and tokens, so the
source spelling `user=request.user` matches [`82921d1f`].

## 5. The rules use the graph

The August audit's most important sentence was that the four rules contained **no graph
traversal** — they were AST token heuristics run through a graph database. Three capabilities
were added in P7, and only those, after running the probes nobody had run:

1. **Control dependence** (`controlledBy`). A TOCTOU fires only for a write that is
   control-dependent on a comparison over a resource term, and — for an ORM write `x.save()` —
   whose receiver `x` is the object that was compared. `if qty <= 0: return` followed by an
   unrelated `create()` is no longer a race. Raw SQL writes keep the token test.
2. **Class scope** (`typeDecl`, `member`, `inheritsFromTypeFullName`). A method's class *body*
   — member initialisers, a nested `Meta`, the bases — joins the guard channel, never its
   sibling methods' bodies, so one method's ownership check cannot silence an IDOR in its
   siblings; a DRF `get_object()` read honours the class's
   `get_queryset()` scoping and any project class it names that defines
   `has_object_permission` — a cross-file type lookup. A direct `Model.objects.get()` in the
   same class still fires, correctly: DRF never runs the object permission for it. The body of
   a form the view instantiates contributes its `min_value=1` to the quantity rule.
3. **Route reachability** (`callIn` + route markers, matched against module-level calls only).
   `meta.route` = `yes | no | unknown` on every finding; agrees with the key in 10 of 10
   comparable cases (shopfast with `_base`, djshop-dev with the Django pack); everywhere else
   — probe, which has no routes, and a Django target scanned with the `_base` or Flask pack,
   whose markers do not describe Django routes — the flag is `unknown` rather than a guess
   [`150728`, `150819`, `151058`]. **Reported, never a gate** — the call graph is name-based.

Effect on the Django DEV split with the Django pack: 5 TP / 2 FP / 2 bait → **5 TP / 0 FP /
0 bait** [`131151`]; shopfast, probe and the other packs unchanged
[`2026-09-15-p7-graph.md`].

### 5.1 Value flow (rules v2, 2026-10)

The four rules above ask one method one question. The eight in `rules/50-60` start from a
**call** and ask where its value comes from. All of them read four shared tables in `35_flow.sc`,
each built once per scan:

- `resolveConst`: what an expression evaluates to when it is a literal, a module constant of its
  file, or `module.NAME` of another project module. A name assigned twice with different
  values, or ever assigned something computed, is not a constant.
- `originOf`: local def-use, up to three assignments deep, and the parameters a value reaches.
- `callerArgs`: for a parameter, the argument each caller passes. This is one hop of the
  name-based call graph, used to *name* request input as the source, never to suppress.
- `valueUsed`: whether a call's value is consumed. pysrc2cpg lowers chained calls into
  expression blocks (`tmp0 = request.args; tmp0.get(...)`), so "the parent is a block" is not
  "discarded". The last expression of an expression block is the block's value.

Value-flow findings about configuration are reported where the value is **defined**
(`config.py:29`), with the sink named in the message, because that is the line a fix changes.
SSRF and path traversal report the sink. A sanitiser counts anywhere on the value's path: in the
sink's method, or in the origin text a caller contributed.

Two design choices:
- A CORS wildcard is reported only when written **unconditionally**. starlette's own middleware
  writes `"*"` under `if allow_all_origins:`, a configured policy, and fired the first version.
- The hard-coded-credential rule never echoes the value, only its length.

Results: §7. Testbed: `testbeds/probe-flow` (one vulnerable function and one fixed twin per rule).

## 6. The eight correctness fixes (P2), each measured

`testbeds/probe` was built so that exactly one fix flips each of five vulnerable functions and
two safe counterparts stay quiet. shopfast is the regression guard (must stay 4 TP / 1 bait).

| # | fix | shopfast | probe TP / TN |
|---|---|---|---|
| – | July rules | 4 / 1 bait | 0 / 2 |
| 1 | per-rule + per-method try/catch, `rule_state` diag | 4 / 1 | 0 / 2 |
| 2 | **authentication is not authorization**: `AUTHZ` vs `AUTHN_ONLY`; `login_required` becomes evidence, never a suppressor | 4 / 1 | **1** / 2 |
| 3 | string literals out of the guard channel (a docstring saying "lock" no longer suppresses) | 4 / 1 | **2** / 2 |
| 4 | `nameNot("<.*>\d*")` — `<lambda>0` is not a user method | 4 / 1 | 2 / 2 |
| 5 | `abort(401` / `abort(403`, not `abort(` | 4 / 1 | **3** / 2 |
| 6 | an allow-list is named, not `" in ["` syntax | 4 / 1 | **4** / 2 |
| 7 | decorator lowering matched as `(def <name>(`, not `contains(name)` | 4 / 1 | **5** / 2 |
| 8 | `nameExact` everywhere; the regex hazard deleted | 4 / 1 | 5 / 2 |

[`2026-09-15-p1-baseline.md`, P2 addendum]

## 7. Results

### shopfast (Flask + sqlite3; 26 bugs over 29 locations + 2 baits; 0 of 31 rows adjudicated)

| arm | TP | FN | FP | bait | TN | recall | precision | F1 | s | run |
|---|---|---|---|---|---|---|---|---|---|---|
| null | 0 | 26 | 0 | 0 | 2 | 0.00 | – | 0.00 | 0.0 | `083329` |
| bandit | 12 | 14 | 2 | 0 | 2 | 0.46 | 0.86 | 0.60 | 0.8 | `083330` |
| semgrep | 13 | 13 | 0 | 0 | 2 | 0.50 | 1.00 | 0.67 | 28.6 | `083415` |
| joern (`_base`) | 4 | 22 | 0 | 1 | 1 | 0.15 | 0.80 | 0.26 | 37.0 | `131241` |
| full (bandit + joern + RAG + Gemini, `gemini-2.5-flash-lite`) | 15 | 11 | 1 | 1 (bait Confirmed) | 1 | 0.58 | 0.88 | 0.70 | 37.9 | `084600` |
| **full** (semgrep + joern + RAG + Gemini, `gemini-2.5-flash`) | **17** | 9 | 0 | 0 (bait **cleared**) | 2 | 0.65 | 1.00 | **0.79** | 109.5 | `171358` |

Joern's four are exactly bugs #22–#25 — the four the testbed documents as SAST-blind — plus
the `find_product` bait, by design. bandit's two FPs are import noise; semgrep's apparent FP was a
CWE-96-vs-1336 labelling difference, fixed in the family map.

### Django, held-out (billing domain; 15 vuln rows = 9 SAST-blind + 6 pattern; 14 fixed twins as safe rows; evaluated **once**, tree `9b4f52b3f5f1`, Django pack at digest `b38082f8d2b6`)

| arm | pack | TP | FN | FP | bait | TN | recall | precision | run |
|---|---|---|---|---|---|---|---|---|---|
| joern | `_base` | 5 | 10 | 0 | 2 | 12 | 0.33 | 0.71 | `124848` |
| joern | `flask-sqlite3` | 5 | 10 | 0 | 2 | 12 | 0.33 | 0.71 | `124929` |
| joern | **`django`** | **7** | 8 | 7 | 3 | 11 | **0.47** | 0.41 | `125012` |
| bandit | – | 4 | 11 | 2 | 0 | 14 | 0.27 | 0.67 | `125014` |
| semgrep | – | 3 | 12 | 2 | 0 | 14 | 0.20 | 0.60 | `125031` |

On the 9 SAST-blind rows: `_base` 5, **`django` 7**, bandit and semgrep 0. The Flask pack
equals `_base` on Django — vocabulary is framework-specific, as it should be. Of the twelve
failure causes with the Django pack, **7 are vocabulary** (the author excluded `get` for
precision and said so; `=request.user` scoping kwargs; `request.post` as a wholesale-write
signal) and **5 are structural** — four of which P7 then built (the queryset-hook scope, the
cross-file bound, the two validation-vs-resource comparisons); the fifth, ownership carried in
a receiver chain (`request.user.invoices.filter(…)`), is not addressed. The rules also fired on
three *correctly fixed* twins, the result shopfast structurally cannot show. On the three
engines together: Joern is disjoint from both pattern arms, but bandit and semgrep overlap on
#10 and #11, so the union is 12 of 15 (misses #2, #3, #15).
These were the numbers **before** P7; P7 was written after reading this failure list, so the
held-out split was **not** re-run — the post-P7 number belongs to a new held-out split. The
pack scored here is `b38082f8d2b6`; the shipped `django.json` (`b5df755be580`) gained its four
P7 slots afterwards and has never been scored on the held-out split
[`2026-09-15-p6-django-heldout.md`].

### Django, DEV split (the iteration split)

Full pipeline (semgrep + joern + RAG + `gemini-2.5-flash`): 7 TP / 5 FN / 2 FP / 0 bait / 11 TN,
F1 0.67 [`171532`]; both FPs are semgrep labelling (`tainted-sql-string` tagged CWE-915 on the
real SQL injection; `missing-throttle-config`), every Joern candidate Confirmed and every fixed
twin left alone.

| pack | before P7 | after P7 | run |
|---|---|---|---|
| `_base` | 2 / 0 / 1 bait | 2 / 0 / 1 | `131402` |
| `flask-sqlite3` | 3 / 0 / 1 | 3 / 0 / 1 | `131447` |
| `django` | 5 / 2 FP / 2 bait | **5 / 0 / 0** | `131151` |

### Rules v2 (2026-10-05, rules `643ba2888183758e`) [`2026-10-05-rules-v2.md`]

The four original rules give identical candidates (rule, file, line, slots, route, class) before
and after the split on every DEV benchmark and pack. The new rules:

| benchmark | pack | TP / FN / FP / bait / TN | run |
|---|---|---|---|
| shopfast | `_base` | **11** / 15 / 1 / 1 / 1 (was 4 / 22 / 0 / 1 / 1) | `171841` |
| probe-flow (new) | `_base` | **10 / 0 / 0 / 0 / 12** | `171940` |
| djshop-dev | `_base` / `flask-sqlite3` / `django` | unchanged (2/0/1, 3/0/1, 5/0/0): no new candidate | `172024`, `172046`, `172109` |

The shopfast FP is bug #17 (`is_admin_login`) labelled CWE-798 by the rule and CWE-1188 by the
key. That puts it in a different scoring family, so it counts as one FP and #17 stays an FN.
The key was not edited. The context phase on an 82 k-line codebase (fastapi + starlette + httpx +
pydantic) went from 3.3 s to 1.3 s, with the eight new rules and their tables adding about
0.4 s; the CPG build (~30 s) dominates either way. `djshop-heldout` was not run.

### Regression after the 2026-09-15 review fixes (rules `11befcda9b9cf6bd`, LF-normalised)

| benchmark | pack | TP / FP / bait | route flags | run |
|---|---|---|---|---|
| shopfast | `_base` | 4 / 0 / 1 | 5/5 agree | `150728` |
| probe | `_base` | 5 / 0 / 0 (2 TN) | all `unknown` (no routes) | `150819` |
| djshop-dev | `_base` | 2 / 0 / 1 | `unknown` (pack has no Django markers) | `150912` |
| djshop-dev | `flask-sqlite3` | 3 / 0 / 1 | `unknown` (pack has no Django markers) | `151005` |
| djshop-dev | `django` | 5 / 0 / 0 | 5/5 agree | `151058` |

### O3 re-verification (P8)

| target | candidate fix | verdict |
|---|---|---|
| shopfast `get_order` | ownership check after the fetch | converged — `method:permissiondenied` |
| shopfast `get_order` | owner in the WHERE clause | converged — `method:owner_id` |
| shopfast `get_order` | cosmetic rename | **rejected** — still fires |
| djshop-dev `checkout` | `transaction.atomic()` + `select_for_update()` | converged — guards named, 17 s |
| djshop-dev `checkout` | conditional `UPDATE … F()` | converged — no control-dependent write left, 13 s |
| djshop-dev `checkout` | docstring claims "atomic", code unchanged | **rejected** — still fires |

[`2026-09-15-p8-reverify.md`]

## 8. What the LLM receives, and what the UI shows

A Joern finding's `message` names the suspected absence and the sink (`[code: …]`), plus
`AUTHENTICATED_NOT_AUTHORIZED(login_required)` when a login-only guard was seen. From there it is
an ordinary finding. In the UI: a violet **CPG** badge whose tooltip names the rule, the pack and
the entries that fired; a `+ CPG` pill and a callout ("N of these came from Joern CPG analysis:
M confirmed") in the summary; the CPG state on the Setup page *before* a scan; **Verify with
CPG** in the fix panel. In the database: `findings.tool`, `scans.joern` (the whole diag block,
pack included), and the `tool_stats` view.

## 9. Configuration

| setting | default | meaning |
|---|---|---|
| `JOERN_ENABLED` | `auto` | run when the runtime exists and the target has `.py` files; `on` / `off` |
| `JOERN_SERVER` | `auto` | keep the sidecar; `off` = one `joern --script` per scan |
| `JOERN_SERVER_PORT` / `JOERN_SERVER_WAIT` | `8091` / `0` | port; seconds a scan waits for a starting sidecar before falling back |
| `JOERN_PACK` | `auto` | detect the framework; or a pack id / path |
| `JOERN_PACK_ALLOW_UNLISTED` | unset | load a pack whose digest is not in `digests.json` (authoring only; flagged in the diag) |
| `JOERN_TIMEOUT` | `360` | seconds for CPG build + rules |
| `JOERN_LLM_QUOTA` | `20` | LLM slots reserved for CPG candidates |
| `JOERN_HOME` / `JOERN_JAVA_HOME` | `tools/…` | only if the runtime lives elsewhere |

## 10. Limitations, stated

- **Intraprocedural by design.** pysrc2cpg's interprocedural edges are name-based and weak;
  the rules reason within one method plus its class scope. A guard in the caller, or a query in
  a repository module, is invisible. `find_product` is the canonical example.
- **Guard-as-configuration is only partly solved.** DRF `permission_classes` and
  `get_queryset()` are handled (P7). Django `urls.py` wrappers, DRF `DEFAULT_PERMISSION_CLASSES`
  and Flask `before_request` are not.
- **Ownership in a receiver chain (`request.user.invoices.filter(…)`) is not addressed.** It
  was the fifth structural cause on the held-out split and the one P7 did not build: it needs
  the origin of the *receiver*, not of the compared value. `request.user.` as a token would
  silence every IDOR, so it is not a vocabulary fix either.
- **Token bags cannot say which call they guarded.** `user=request.user` on a
  `Cart.objects.get_or_create` suppresses an IDOR on a `Product` read in the same method — the
  right answer for the wrong reason.
- **Atomicity is a heuristic.** Control dependence + receiver identity is far better than the
  July "any comparison plus any write", and still not a proof.
- **0 of 90 answer-key rows are adjudicated.** Every number above is against `proposed` rows.
  Adjudication is a human task the harness records but cannot do.
- **Gemini varies.** Two of three identical scans on 2026-09-15 returned `503` / `429` for a
  batch. The `full` arm was run once on shopfast and not at all on the Django splits.
- **No multi-language.** `importCode.python` only.
- **Value flow is bounded.** `originOf` follows three local assignments; `callerArgs` follows one
  caller up, by name. Request input that crosses two function boundaries, or passes through a
  container (`cfg["url"]`), an attribute (`self.url`) or a framework hook, is not traced. The SSRF
  and path-traversal rules stay quiet rather than guess.
- **Constant resolution is module-level only.** `config.X` resolves when `X = <literal>` at
  module scope of a project module named `config`. It does not resolve through class
  attributes, `os.environ` defaults, settings objects (`settings.X` in Django is a
  `LazySettings`; it resolves only because the module is also named `settings`), or `from
  config import X` aliases bound under another name.
- **The kwarg rules match the call's name, not its receiver.** `debug_kwargs` contains
  `run:debug=true`, so `asyncio.run(main(), debug=True)` would be reported as a debug server.
- **Security boundaries, as of the 2026-09-15 review.** Re-verification inputs (`file`,
  `method`, `class`) are validated as a relative `.py` path and identifiers, and every
  placeholder is Scala-escaped before it is rendered into the rule; `/api/fix/apply`, `/revert`
  and `/verify` refuse any path outside the scan's own target; server-mode scans are serialised
  with a lock, because the sidecar is a single REPL; a script-mode timeout kills the whole JVM
  tree; pack values may not be whitespace-only or contain double spaces, and a deeply nested
  JSON pack is refused without raising. The rule hash is LF-normalised so the same Scala hashes
  the same on every checkout.

## 11. Adding a rule, a pack, or a framework

- **A rule**: one `// @@ rule <name>` section in the `rules/NN_family.sc` file of its family,
  written as `perItem(name)(items) { item => if (signal && !guard) add(...) }`. `items` is `ctxs`
  for a per-method rule, or a sink list from `35_flow` (`callsAt(SLOT)`, `callsByLowerName`)
  for a call-anchored one. Then add its id to `RULES` in `00_prelude.sc` and a title in
  `scan._TITLES`; `test_joern.py` fails until all three agree. It gets isolation, provenance
  columns and the UI badge for free. Re-verification needs a row in `reverify._RULE_GUARD`
  naming its guard family and its sink counts in `80_reverify.sc`.
- **Shared machinery** (a table or helper more than one rule reads) goes in `35_flow.sc`, built
  with `table(name, empty) { ... }`. In server mode a rule section that fails to compile takes
  its own definitions down with it.
- **A pack**: extend `_base`, one value per documented idiom, run
  `python -m app.services.joern.vocab.validate --freeze`. Never edit a pack after reading a
  held-out failure list and re-run that split.
- **A framework the rules do not reach**: the answer is a new slot with a sink and a class-scope
  rule, not a regex and not a Scala escape hatch. Both are refused by the validator and the
  tests, on purpose.
