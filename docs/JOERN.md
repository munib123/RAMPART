# RAMPART — the Joern / CPG phase

How RAMPART finds the **SAST-blind logic bugs** that pattern scanners structurally cannot see,
using Joern's Code Property Graph as the *locator*, a data-only vocabulary pack as the
framework knowledge, and the LLM as the *prover*.

This is the September 2026 rewrite of the August document. Every number below comes from a
run artifact under `bench/runs/` (run ids in brackets); the August §8 was hand-traced and is
superseded. Phase logs: `bench/runs/2026-09-15-*.md`. Plan and status: `docs/JOERN_PLAN.md`.

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

Measured, not asserted: on `testbeds/shopfast` bandit finds 12 of 26 planted bugs and semgrep
13, and **neither finds any of the four above** [`083330`, `083415`]. On both Django splits the
pattern arms find 0 of the 8 / 9 SAST-blind rows [`122402`, `122417`, `125014`, `125031`]. The
engines are disjoint; their union on shopfast is 19 of 26.

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

The second line is the `db.find_product` bait in shopfast. In P1's `full` run the LLM
**Confirmed** it instead of clearing it [`084600`] — an open item for the prompt, recorded
rather than hidden.

## 3. How it runs

`backend/app/services/joern/`:

| file | role |
|---|---|
| `runtime.py` | finds or **installs** a portable Temurin JRE 21 and joern-cli 4.0.589 under `tools/` — no admin, nothing on PATH. `python -m app.services.joern.runtime --install` |
| `server.py` | one `joern --server` **sidecar per backend process** (127.0.0.1:8091, random per-process Basic-auth password, tree-killed on shutdown). Started by the FastAPI lifespan; `/api/health` shows `scanners.joern.server` |
| `scan.py` | renders `rules/locators.sc`, picks and validates the vocabulary pack, runs the rules (one `/query-sync` per `// @@` section in server mode; one `joern --script` as the fallback), parses the TSV, returns `(findings, diag)` |
| `rules/locators.sc` | the four rule **shapes** — 277 lines of hand-written, hashed Scala; zero framework vocabulary |
| `vocab/` | `schema.json`, `validate.py`, `packs/{_base,flask-sqlite3,django}.json` + `digests.json` |
| `reverify.py` | O3: rebuild the CPG on patched code and ask whether the locator still fires |

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

- **22 slots, 7 sinks**, each sink with its own character class (`call_name` → `nameExact`
  only; `guard_text` → `String.contains` on the method's calls + identifiers, never its
  literals). No regex sink, no Scala. A test greps the Scala to prove no regex-taking accessor
  ever sees a pack value.
- **Caps and cross-slot rules**: 16 KB, 64 values per slot; no authz token may sit inside an
  authn token; count and money terms disjoint; text sinks lower-case. A pack that breaks any
  rule is **discarded whole** and the scan runs on `_base`, saying so in `diag.pack.fallback`.
- **Composition** is a per-slot union with the parent, sorted and de-duplicated before hashing:
  the digest does not depend on author order. `packs/digests.json` is the allowlist.
- **Provenance**: every finding carries `meta.pack` (`django@b5df755be580`) and `meta.slots` —
  which entries fired it (`id_param_suffix=_id;orm_read_calls=get_object_or_404`).

| pack | values | authored from | digest |
|---|---|---|---|
| `_base` | 83 | the July/August Scala vals, verbatim | `ef5ac270285a` |
| `flask-sqlite3` | 159 | Flask / Flask-Login / Flask-SQLAlchemy / WTForms / sqlite3 docs, hand-written | `edd46a9ed63d` |
| `django` | 202 | Django 5.1 + DRF docs, drafted by a walled-off agent under the held-out protocol (§7), reviewed, not tuned | `b5df755be580` |

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
2. **Class scope** (`typeDecl`, `member`, `inheritsFromTypeFullName`). A method's class body
   and bases join the guard channel; a DRF `get_object()` read honours the class's
   `get_queryset()` scoping and any project class it names that defines
   `has_object_permission` — a cross-file type lookup. A direct `Model.objects.get()` in the
   same class still fires, correctly: DRF never runs the object permission for it. The body of
   a form the view instantiates contributes its `min_value=1` to the quantity rule.
3. **Route reachability** (`callIn` + route markers). `meta.route` = `yes | no | unknown` on
   every finding; agrees with the answer keys 10/10 where routes exist. **Reported, never a
   gate** — the call graph is name-based.

Effect on the Django DEV split with the Django pack: 5 TP / 2 FP / 2 bait → **5 TP / 0 FP /
0 bait** [`131151`]; shopfast, probe and the other packs unchanged
[`2026-09-15-p7-graph.md`].

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
| **full** (semgrep + joern + RAG + Gemini) | **15** | 11 | 1 | 1 | 1 | 0.58 | 0.88 | **0.70** | 37.9 | `084600` |

Joern's four are exactly bugs #22–#25 — the four the testbed documents as SAST-blind — plus
the `find_product` bait, by design. bandit's two FPs are import noise; semgrep's apparent FP was a
CWE-96-vs-1336 labelling difference, fixed in the family map.

### Django, held-out (billing domain; 15 vuln rows = 9 SAST-blind + 6 pattern; 14 fixed twins as safe rows; evaluated **once**, tree `9b4f52b3f5f1`)

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
signal) and **5 are structural** — and those five are exactly what P7 then built. The rules
also fired on three *correctly fixed* twins, the result shopfast structurally cannot show.
These were the numbers **before** P7; P7 was written after reading this failure list, so the
held-out split was **not** re-run — the post-P7 number belongs to a new held-out split
[`2026-09-15-p6-django-heldout.md`].

### Django, DEV split (the iteration split)

| pack | before P7 | after P7 | run |
|---|---|---|---|
| `_base` | 2 / 0 / 1 bait | 2 / 0 / 1 | `131402` |
| `flask-sqlite3` | 3 / 0 / 1 | 3 / 0 / 1 | `131447` |
| `django` | 5 / 2 FP / 2 bait | **5 / 0 / 0** | `131151` |

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
  `get_queryset()` are handled (P7). Django `urls.py` wrappers, DRF `DEFAULT_PERMISSION_CLASSES`,
  Flask `before_request`, and ownership carried in a receiver chain
  (`request.user.invoices.filter(…)`) are not.
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

## 11. Adding a rule, a pack, or a framework

- **A rule**: one `// @@ rule <name>` section in `locators.sc` — `ctxs.foreach { c =>
  guarded(name) { if (signal && !guard) add(...) } }` — and a title in `scan._TITLES`. It gets
  isolation, provenance columns, the UI badge and re-verification for free.
- **A pack**: extend `_base`, one value per documented idiom, run
  `python -m app.services.joern.vocab.validate --freeze`. Never edit a pack after reading a
  held-out failure list and re-run that split.
- **A framework the rules do not reach**: the answer is a new slot with a sink and a class-scope
  rule, not a regex and not a Scala escape hatch. Both are refused by the validator and the
  tests, on purpose.
