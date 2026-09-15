# Thesis text — the Joern / CPG contribution

Draft paragraphs for the design and evaluation chapters. Every number cites a run artifact in
`bench/runs/` (run ids in brackets, `YYYYMMDDTHHMMSSZ`); every design claim cites a commit.
Written so the team can paste, then edit for voice. Section 1 is quoted **verbatim** from the
August design synthesis (`D:\d\FYP\CLAUDE.md` §7, 2026-08-04), as the plan required; the rest was
written after the September measurements.

**Caveat that must appear wherever these numbers do:** 0 of the 90 answer-key rows have been
adjudicated by a human. Every metric is against `proposed` rows derived from the testbeds'
own `VULNERABILITIES.md` and source. The harness records adjudication state on every run and
reports it in every table; the thesis must not quote a number without it.

---

## 1. Three findings from the August design phase (verbatim)

### 1.1 The zero-traversal admission

> `joern_queries.sc` contains **zero graph traversal**. Grep for `reachableBy`, `controlledBy`,
> `dominatedBy`, `cfgNext`, `ddgIn`, `.caller`, `.callee` → no hits. All four rules enumerate
> methods, read parameter names, match call names, match one operator, and run `String.contains`
> over a token bag. Those are AST operations. Semgrep can express effectively all of it, and three
> of the four become *more* precise in YAML because metavariable unification does the AND-NOT join
> better than a shared blob.
>
> So Joern must be repositioned onto the four things a pattern matcher structurally cannot do:
> 1. **Control dependence** (`controlledBy`/`dominatedBy`). Rule 4 has *no ordering constraint*
>    today. The common guard idiom `if qty <= 0: abort(400)` then use has no encoding in semgrep
>    taint mode.
> 2. **Cross-file type/class resolution** (`m.typeDecl`, `inheritsFromTypeFullName`) — DRF
>    `permission_classes`, `LoginRequiredMixin`, `Meta.fields`, pydantic `conint(gt=0)`. No
>    comparison operator exists in that code, so no token list can ever reach it.
> 3. **Route reachability** (`callIn`) — report reachable-subset recall alongside raw recall.
> 4. **O3 re-verification** — patch a copy, rebuild the CPG, assert the guard now dominates the
>    sink.

*Status in September:* items 1–3 landed in P7 (commit `e24c1f8b`), item 4 in P8 (`07110c7c`). The
rules file now contains `controlledBy`, `typeDecl` (×4), `inheritsFromTypeFullName` and `callIn`
(×3); the grep that returned nothing in August returns nine hits.

### 1.2 The authentication / authorization conflation

> **split `AUTH` into authz-suppressors vs authn-only** — `login_required` currently silences the
> IDOR rule on every decorated view, and IDOR is by definition a bug in already-authenticated
> code (shopfast cannot show this: it has no decorators)

*Status:* landed as P2 fix 2 (`e25c7645`). It is the single most consequential change to the
rules: on the probe suite it turned the first vulnerable function from missed to found, and on
Django — where every view is decorated — the rule would otherwise have been silent everywhere.
The Django pack's author, working from the DRF documentation alone, independently placed
`permission_classes` and `LoginRequiredMixin` in the authentication-only list.

### 1.3 The vocabulary-not-structure finding

> **Rejected: a 200-query corpus.** Right instinct (curated, versioned, reviewed artifacts), wrong
> unit. Measured over 12 hand-authored variants across Django / FastAPI+SQLAlchemy /
> Flask+SQLAlchemy: the four rule shapes fire **9/12 unmodified**, and of 17 root causes **12 are
> vocabulary, 5 structural** — the structural residue collapsing to three traversals added *once*,
> not per framework. A corpus multiplies shapes when there are only four, and multiplies review
> load without multiplying coverage.

*Status:* this is the hypothesis the held-out Django experiment (§4) tested. The September
ratio on unseen code was 7 vocabulary : 5 structural — the same shape as the August estimate.
Four of the five structural causes fell to the three traversals the paragraph predicted; the
fifth, ownership carried in a receiver chain, did not and remains open (§5).

---

## 2. Design (for the design chapter)

### 2.1 The division of labour

Pattern scanners detect the *presence* of a dangerous construct. The highest-impact web
vulnerabilities — insecure direct object reference, mass assignment, unchecked business
quantities, check-then-write races — are *absences*: an ownership check, an allow-list, a lower
bound, a lock that is not there. No regular expression matches the absence of a thing; the
signal is the shape of the whole function. A Code Property Graph represents exactly that shape.

RAMPART therefore gives Joern one job: to **locate** candidates structurally. It never decides
whether a candidate is a vulnerability — whether an `Order` is user-owned is a semantic question
a graph query cannot answer. The candidate flows through the same pipeline as every scanner
finding (containing-function slice, retrieval of disclosed vulnerabilities, a batched LLM
verdict) and the LLM **proves** or clears it. The phase is additive and never raises: a failed
CPG build produces fewer findings and a reason in the response, never a failed scan.

### 2.2 Rules are shapes; vocabulary is data

The four locator rules are hand-written Scala, hashed and frozen (`rules_sha256` in every run
artifact). They contain no framework-specific string. What an authorization guard, a lock, an
allow-list, a single-object read or an object id *looks like* in Flask or Django is a JSON
**vocabulary pack** the Scala reads at runtime. This is decision D7 of the design document:
the LLM may author a pack offline, from framework documentation, but it never writes Scala and
never runs on the detection path.

The pack grammar (`vocab/schema.json`) is the security boundary. Every slot declares the *sink*
its values flow into, and the validator enforces a character class per sink: a value bound
for `String.contains` can never reach `call.name(...)`, which treats its argument as a regular
expression, and nothing from a pack is ever compiled. There is no regex sink and no raw-Scala
escape hatch. Caps (16 KB, 64 values per slot), cross-slot rules (no authorization token may be a
substring of an authentication token, or an authentication construct would satisfy the
authorization guard), order-independent hashing, and a digest allowlist complete the boundary;
a pack that violates any rule is discarded whole and the scan runs on the framework-neutral base
pack, saying so. (Commit `e7490a53`; threat T-10 in the TDD.)

### 2.3 What the graph adds that tokens cannot

Three traversals, each added once and shared by every framework (commit `e24c1f8b`):

1. **Control dependence.** A check-then-write race is reported only when a database write is
   control-dependent on a comparison over a resource term *and* — for an ORM write `x.save()` —
   `x` is the object that was compared. The July rule accepted any comparison plus any write in
   any order; an input validation followed by an unrelated insert was a "race".
2. **Class scope.** A method's class body — its member initialisers, nested `Meta` and bases,
   not its sibling methods' bodies — joins its guard channel, so a permission declared on a
   Django REST Framework view class, or a mixin, is visible to the rule while one method's
   ownership check cannot silence an IDOR in another. A read that
   goes through the framework's queryset hook honours `get_queryset()` scoping and any project
   class that defines `has_object_permission()` — a cross-file type lookup. A form the view
   instantiates contributes its declared `min_value` to the bound check.
3. **Route reachability.** Names referenced by module-level route-registering calls, registered
   view classes, and two hops of the call graph. Emitted on every finding and compared with the
   answer key, never used to suppress — the call graph is name-based.

### 2.4 Re-verification after a fix (objective O3)

After the LLM proposes a fix, RAMPART applies it to a scratch copy of the whole target, rebuilds
the graph there, and asks whether the locator still fires on that method (class-qualified, so
`Order.get` and `Invoice.get` are distinct targets) — and, when it does not,
whether a guard now sits in the method's guard channel (or its class, or a form it instantiates),
or the sink itself has gone. The whole-target re-scan is diffed so a fix that moves a bug is a
regression, not a success. A fix that renames a variable, or a docstring that claims a
transaction, changes neither the sink nor the guard channel and does not converge. When the
Joern runtime is absent the endpoint still answers, labelled as a weaker text search.
(Commit `07110c7c`.)

---

## 3. Evaluation protocol (for the methodology chapter)

- **Answer keys are line-anchored by verbatim source strings**, never line numbers; a row whose
  anchor does not resolve uniquely, or whose declared function does not contain it, is dropped
  and reported, never guessed. Scoring matches on enclosing function and CWE *family*, not exact
  CWE, because engines label the same defect differently. Safe rows — deliberate false-positive
  bait and the correctly fixed twins — are scored separately (`bait_fp`, `TN`) so precision is a
  measured quantity.
- **Five arms**, plus a pack ablation, run against the same frozen keys: `null`, `bandit`, `semgrep`, `joern` (the
  locator alone), `full` (the whole pipeline, verdict-gated), and `joern --pack <p>` for the
  vocabulary ablation. Every run artifact carries the code hash, the rules hash, the pack digest,
  the key version and adjudication state, and every candidate with its outcome and the
  vocabulary entries that fired it.
- **Held-out protocol** (commits `0249a60b` → `9d03ce96`, in that order): the Django testbed was
  authored and frozen — a tree hash in `FREEZE.json` that the runner refuses to violate — *before*
  the Django vocabulary pack existed. The pack was then drafted by an agent whose only inputs
  were the schema, the two existing packs, and seventeen pages of the official Django and DRF
  documentation; it never read the testbed, and its prompt and transcript are committed. The
  held-out split was evaluated once; every run of it is appended to `bench/runs/heldout.log`. The
  pack scored there is digest `b38082f8d2b6`. The rules were later improved (P7) after reading
  that split's failure list, and the pack gained four P7 slots (today's `b5df755be580`); the
  split was deliberately **not** re-run with either: that number belongs to a new held-out
  split.

---

## 4. Results (for the evaluation chapter)

### 4.1 The engines are disjoint

On the Flask testbed (25 planted bugs + 1 undocumented one the key records, 2 baits) bandit found 12 bugs, semgrep 13, and Joern's
four rules found 4 — bugs #22–#25, the four the testbed documents as SAST-blind — and neither
pattern scanner found any of those four [`083330`, `083415`, `131241`]. The whole pipeline
(bandit + Joern + RAG + Gemini) found 15 with F1 0.70 [`084600`]. On both Django splits the
pattern arms found 0 of the 8 and 9 SAST-blind rows [`122402`, `122417`, `125014`, `125031`].
"Disjoint" is a statement about Joern against the pattern arms; bandit and semgrep overlap
with each other (#10 and #11 on the held-out split), so the three-engine union there is 12 of
15, not the sum. "Overlap by exactly zero" is a `GROUP BY`, not a sentence.

### 4.2 Each rule fix, measured

Eight correctness fixes to the July rules were each landed as one commit against a probe suite
built so that exactly one fix flips each of five vulnerable functions while two safe counterparts
stay quiet; the Flask testbed was the regression guard. Fixes 2, 3, 5, 6 and 7 each moved the
probe by exactly one (0 → 5 of 5); fixes 1, 4 and 8 were structural and moved nothing; no safe
counterpart ever fired; shopfast stayed at 4 / 1 bait throughout [`2026-09-15-p1-baseline.md`].
Two probes were first built on the wrong mechanism and corrected before any fix was measured —
recorded because the process caught what reading would not have.

### 4.3 Vocabulary transfers; structure does not (the held-out result)

On the unseen Django split (9 SAST-blind rows, 14 fixed twins), with the Scala frozen at the
same hash:

| pack | SAST-blind found | FP | bait |
|---|---|---|---|
| `_base` (no framework vocabulary) | 5 / 9 | 0 | 2 |
| `flask-sqlite3` | 5 / 9 | 0 | 2 |
| `django` (docs-only, walled off; digest `b38082f8d2b6`) | **7 / 9** | 7 | 3 |

[`124848`, `124929`, `125012`]. The Flask pack equals the base pack on Django code: vocabulary is
framework-specific, as it should be. The Django pack's two additional hits are the two
check-then-write races, found only because the pack names `save()` as a write. Its two misses
are both `Manager.get()`, which the pack's author excluded for precision and documented. Of the
twelve failure causes, seven were vocabulary and five structural: a permission scope on a view
class via `get_queryset`, ownership carried in a receiver chain, a bound declared in another
file, and two input validations read as resource checks. Three correctly fixed twins fired — the
result the Flask testbed structurally cannot show, because its guards are all in the method.

The plan had fixed a kill criterion in advance: if structural causes exceeded half, the
vocabulary-pack conclusion would be wrong for these domains. They did not, but the margin is
narrow, and the honest statement is that vocabulary takes the locator from 5 to 7 of 9 on unseen
code, would take it to 9 of 9 with two more tokens, and pays for that with precision that only a
graph traversal buys back.

### 4.4 The graph buys the precision back (DEV split)

On the development split, after the three traversals of §2.3 were added — with shopfast, the
probe suite and the base-pack arms unchanged — the Django-pack arm went from 5 TP / 2 FP / 2 bait
to **5 TP / 0 FP / 0 bait** [`131151` vs `124738`]. Every development-split false alarm of a
kind the held-out analysis had called structural was removed by the capability it named; the
receiver-chain case has no development-split twin and is not addressed. The route flag agrees
with the key in 10 of 10 comparable cases (shopfast with its pack, djshop-dev with the Django
pack); everywhere else — a target with no routes, or a pack whose markers do not describe the
target's framework — the flag is "unknown" rather than a guess [`150728`, `151058`].

### 4.5 Re-verification distinguishes a fix from a rewrite

For the IDOR in `orders.get_order`, an ownership check after the fetch converged with the guard
named, a scoped WHERE clause converged, and a cosmetic rename did not — the locator still fired.
For the race in Django's `checkout`, both documented fixes converged (row lock inside
`transaction.atomic()`; conditional `UPDATE` with `F()`, which removes the control-dependent
write altogether) in 13–17 s each through the sidecar, and a docstring claiming atomicity was
rejected: string literals never reach the guard channel, the same property P2 fix 3 introduced
[`2026-09-15-p8-reverify.md`].

### 4.6 Cost

The JVM is paid once per backend process. The CPG phase of a scan is 8.0–8.2 s on the Flask
testbed and 14.7 s on the Django split in server mode, against 19–34 s per scan in script mode
[`2026-09-15-p3-server.md`]. A re-verification is two CPG builds.

---

## 5. Threats to validity (for the discussion chapter)

- **Unadjudicated keys.** 0 of 90 rows are `accepted`. The same author wrote the testbeds, the
  keys and the rules; the harness prevents circular *locations* (anchors are string-resolved) but
  not circular *labels*. Adjudication by the two other team members is the prerequisite for
  quoting any number in the thesis body.
- **Small testbeds.** 26 + 12 + 15 vulnerable rows. Every ratio above has wide intervals; the
  claims are about mechanism (which cause, which capability), not about population recall.
- **Author overlap on the held-out split.** The rules and the held-out testbed share an author;
  the pack does not. The protocol isolates the pack, which is the variable the experiment
  measures; neither the post-P7 rules nor the post-P7 pack (`b5df755be580`) were scored on it.
- **One structural cause is open.** Ownership carried in a receiver chain
  (`request.user.invoices.filter(…)`) needs the origin of the receiver, which the rules do not
  compute; a token would silence every IDOR. Four of the five held-out structural causes were
  addressed, not five.
- **LLM variability.** Identical scans on the same day returned `503` / `429` for whole batches
  from the Gemini free tier; the `full` arm was run once on shopfast and not on Django. The
  locator numbers do not depend on the LLM; the pipeline numbers do, and were not repeated.
- **Name-based call graph.** Route reachability and regressions rely on pysrc2cpg's
  name-based resolution; a dynamically dispatched call is invisible to both.
- **The bait the LLM confirmed.** `db.find_product` — the deliberate public-object IDOR bait —
  was Confirmed by the verdict step in the one `full` run, against the design intent. The
  locator behaved as designed; the prover did not, and the prompt is the open item.
