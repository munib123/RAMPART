# Authoring prompt for `django.json` (held-out protocol)

You are drafting a **vocabulary pack** for RAMPART's Joern/CPG logic-bug locator. Read this whole
brief before touching anything.

## The one rule that matters

**You are working under a held-out evaluation protocol.** The pack you write will be scored on a
Django testbed you must never see. Therefore:

- **Do NOT open, list, grep, or otherwise read anything under `testbeds/` or `bench/`** in the
  repository, or any file named `VULNERABILITIES.md`, `*.key.jsonl`, `FREEZE.json`, or anything
  in `bench/runs/`. Do not run `bench.run`. Do not scan any code with Joern.
- Your only inputs are: (1) the three files named below, (2) your knowledge of the **official
  Django and Django REST Framework documentation**, and (3) if you want to check something, the
  official docs themselves at https://docs.djangoproject.com/en/5.1/ and
  https://www.django-rest-framework.org/ (fetching those pages is allowed; nothing else is).
- If you catch yourself reasoning "what would a testbed contain", stop: reason instead about what
  the Django docs tell developers to write.

Everything you read and every decision you make is recorded as the authoring transcript and
committed next to the pack. Write your reasoning plainly.

## Read these three files, nothing else in the repo

1. `backend/app/services/joern/vocab/schema.json` — the grammar. Every slot, its sink, the character
   class per sink, caps, and cross-slot rules. **The validator enforces all of it; a pack that
   breaks any rule is discarded whole.**
2. `backend/app/services/joern/vocab/packs/_base.json` — the framework-neutral base every pack
   extends. A child pack can only ADD values; it inherits everything in `_base`.
3. `backend/app/services/joern/vocab/packs/flask-sqlite3.json` — the reference pack, hand-written
   for Flask. Copy its *shape* exactly (`pack_id`, `schema_version`, `authored_from`, `extends`,
   `description`, `sources`, `slots` with `sink` + `values` + optional `note`).

## What the four rules do with each slot (so you know what a value must LOOK like)

The rules are intraprocedural token heuristics over one Python method at a time. Every value is
matched as a plain substring or exact name — never a regex.

| slot | sink | how it is matched | what it means |
|---|---|---|---|
| `orm_read_calls` | `call_name` | exact call name (`x.first()` → `first`) | a **single-object read** by id: the IDOR sink. The rule fires when a method has such a read AND a parameter that looks like an id AND no `authz_guard` token. |
| `id_param_exact` / `id_param_suffix` | `param_exact` / `param_suffix` | lower-cased parameter name `==` / `endswith` | which parameter names are object ids |
| `authz_guard` | `guard_text` | substring of the method's calls+identifiers (lower-cased, **no string literals**), or of the decorator call wrapping the method | proves the caller may touch *this* object → suppresses the IDOR candidate. **Be strict: a token that merely proves login must NOT go here.** |
| `authn_only` | `guard_text` | same text | proves only that the caller is logged in; never suppresses, becomes evidence for the LLM |
| `mass_assign_signal` | `signal_text` | substring of calls+literals+identifiers | a caller-supplied mapping being written wholesale |
| `mapping_iter_calls` | `call_name` | exact call name | iterating a mapping's entries (`items`) |
| `dyn_write_calls` | `call_name` | exact call name | a dynamic attribute/field write (`setattr`, `update`) |
| `allowlist_guard` | `guard_text` | substring | an explicit allow-list of writable fields → suppresses mass assignment |
| `qty_terms` / `price_terms` | `token` | substring of the operands of `*` and comparison operators | count-like / money-like names (must stay disjoint) |
| `positive_guard` | `guard_text` | substring | a lower-bound check on a quantity |
| `commit_calls` | `call_name` | exact call name | a **write** to the database (for the TOCTOU rule: check-then-write with no lock) |
| `lock_guard` | `guard_text` | substring | a lock / atomic transaction around the check-then-write → suppresses TOCTOU |
| `exec_calls`, `sql_read_kw`, `sql_write_kw`, `sql_delete_kw` | `call_name` / `exec_sql_kw` | raw SQL execution and its keywords | |

Text-sink values are matched against **lower-cased** text, so write them lower-case
(`request.user`, not `request.User`). Guard text contains **calls and identifiers only** — a
keyword argument like `user=request.user` appears in the call's code, so `user=request.user` is a
legitimate guard token; a docstring is not in the text at all.

## What to produce

Write `backend/app/services/joern/vocab/packs/django.json` with:
- `"pack_id": "django"`, `"schema_version": 1`, `"authored_from": "framework_docs"`, `"extends": "_base"`,
  `"transcript": "django.transcript.json"`, a one-paragraph `description`, and a `sources` list of
  the documentation pages you relied on.
- Values for every slot where Django / DRF has vocabulary the base lacks. Think about: the ORM's
  single-object reads and the shortcuts around them; how the docs say to scope a lookup to the
  requesting user; what the docs' authorization decorators, mixins, and DRF permission hooks are
  called (and which of them are *only* authentication); how the docs say to bound a numeric input;
  how the docs say to make a check-then-write safe (transactions, row locks, `F()` expressions,
  conditional updates); what the docs' request-data objects are called; how a `ModelForm` or a
  serializer declares which fields are writable; what the ORM's write methods are called.
- Keep every value general to the framework. Do not add values that only make sense for one
  imaginary application.
- Prefer precision over recall for `authz_guard`, `allowlist_guard`, `lock_guard`,
  `positive_guard`: these SUPPRESS findings, so a too-generic token silently hides real bugs.
  A `note` on any slot where you made a judgement call.

Then validate it and iterate until it passes:

```
cd backend
.venv\Scripts\python.exe -m app.services.joern.vocab.validate app/services/joern/vocab/packs/django.json
```

("UNLISTED" is expected and fine — do **not** run `--freeze`; the maintainer does that after
review.) Fix every error the validator prints; it tells you the slot, the value, and the rule.

## Your final report

Return, in this order:
1. The complete final `django.json` content.
2. A slot-by-slot rationale: for each value you added, the documentation idiom it comes from.
3. Anything you deliberately left out and why (e.g. a token that would be too generic).
4. The validator's final output line.
