# P6 - the Django testbed under the held-out protocol, 2026-09-15

The question P5 and P6 exist to answer: **when the four locator rules move from Flask to Django,
is the gap vocabulary (fixable by a data pack) or structure (needs a new traversal)?**

## Protocol, as executed (git history is the evidence)

| step | commit | what |
|---|---|---|
| 1 | `0249a60b` | `testbeds/djshop-dev` (12 vuln + 11 safe rows) and `testbeds/djshop-heldout` (15 + 14) authored; every SAST-blind bug next to the fix the Django docs prescribe; both **frozen** (`FREEZE.json`, tree hashes `e824a99673d9` / `9b4f52b3f5f1`). One DEV sanity run with `_base`. Held-out untouched. |
| 2 | `9d03ce96` | `django.json` authored by a fresh agent whose only repository inputs were `django.prompt.md`, `schema.json`, `_base.json`, `flask-sqlite3.json`, and whose knowledge source was 17 pages of the official Django 5.1 / DRF docs (all listed). It never opened `testbeds/` or `bench/`. Prompt and transcript committed. Reviewed for schema sanity and docs grounding, **not edited**. |
| 3 | `82921d1f` | DEV runs exposed a representation gap: pysrc2cpg renders `kw = value` with spaces, so no `kw=value` token from any pack could ever match. Fixed in the Scala (`norm`), a general change validated on shopfast/probe (unchanged) and DEV. Held-out still untouched. |
| 4 | this log | **Held-out evaluated once**: joern × {`_base`, `flask-sqlite3`, `django`}, bandit, semgrep, back to back. Every run is in `bench/runs/heldout.log`. Nothing was changed afterwards. |

The same `locators.sc` for every Joern run below (see each artifact's `rules_sha256`; the hash
first quoted here was computed on CRLF bytes, and rule hashes are now LF-normalised in
`bench/backends/__init__.py`, so it no longer applies). The Django pack scored is digest
`b38082f8d2b6` - the pack as authored, before P7 added four slots; the shipped `django.json`
(`b5df755be580`) has never been scored on the held-out split. 0 of 52 Django key rows are
adjudicated (all `proposed`), same caveat as shopfast.

## The numbers

### HELD-OUT (`djshop-heldout`, 15 vuln rows: 9 SAST-blind + 6 pattern; 14 safe twins)

| arm | pack | TP | FN | FP | bait | TN | recall | precision | F1 |
|---|---|---|---|---|---|---|---|---|---|
| joern | `_base` | 5 | 10 | 0 | 2 | 12 | 0.33 | 0.71 | 0.45 |
| joern | `flask-sqlite3` | 5 | 10 | 0 | 2 | 12 | 0.33 | 0.71 | 0.45 |
| joern | **`django`** | **7** | 8 | 7 | 3 | 11 | **0.47** | 0.41 | 0.44 |
| bandit | - | 4 | 11 | 2 | 0 | 14 | 0.27 | 0.67 | 0.38 |
| semgrep | - | 3 | 12 | 2 | 0 | 14 | 0.20 | 0.60 | 0.30 |

On the **9 SAST-blind rows only**: `_base` 5/9, `django` **7/9**. bandit and semgrep find 0 of 9.
Joern disjoint from both pattern arms again: joern {1,4,5,6,7,8,9}, bandit {10,11,13,14},
semgrep {10,11,12}; bandit and semgrep overlap on #10 and #11, so the union is 12 of 15
(misses #2, #3, #15).

### DEV (`djshop-dev`, 12 vuln: 8 SAST-blind + 4 pattern; 11 safe twins)

| arm | pack | TP | FN | FP | bait | TN |
|---|---|---|---|---|---|---|
| joern | `_base` | 2 | 10 | 0 | 1 | 10 |
| joern | `flask-sqlite3` | 3 | 9 | 0 | 1 | 10 |
| joern | **`django`** | **5** | 7 | 2 | 2 | 9 |
| bandit | - | 3 | 9 | 0 | 0 | 11 |
| semgrep | - | 2 | 10 | 3 | 0 | 11 |

SAST-blind rows: `_base` 2/8, `django` 5/8.

## What each failure is - vocabulary or structure

Every held-out Joern outcome with the `django` pack, from the slot traces in the run JSON:

**Found (7):** #1 `invoice_detail` (`first`, base vocabulary), #4 `ticket_update` and #5
`WalletViewSet.settings` (`items` + `setattr`, base), #6 `refund_line` and #7 `topup_bonus`
(`price * qty`, base), **#8 `redeem_coupon` and #9 `withdraw` (TOCTOU) - found only because the
Django pack names `save` as a write.** That is the pack doing exactly what it was for.

**Missed (2):** #2 `Attachment….get(pk=…)`, #3 `Wallet.objects.get(pk=pk)`. Both are `Manager.get`,
which the pack author **deliberately excluded** ("shares its exact name with dict.get /
request.POST.get; every method with an id parameter would become a candidate"). Vocabulary -
a precision trade the author made from the docs, and the transcript says so. On DEV the same
decision costs #2, #3, #4.

**False alarms (10 candidates, 12 causes counting the same function twice):**

| candidate | cause | class |
|---|---|---|
| `refund_line`, `refund_line_form`, `refund_line_safe`, `receipt_pdf` → IDOR | the lookup IS scoped - `invoice__customer=request.user`, `customer=request.user` - but the pack's authz tokens are `user=…`/`owner=…`; the kwarg name is application-specific. A generic token exists (`=request.user`, the value side) and is not in the pack. | **vocabulary** (4) |
| `withdraw_safe` → mass assignment | `request.post` as a wholesale-write signal is too broad: one POST field + one `.update(F(...))` fires it. `_base` has the same breadth for Flask's `request.form`. | **vocabulary** (1) |
| `WalletViewSet.statement` → IDOR (bait) | `self.get_object()`; the owner scope is `get_queryset()` on the class | **structural**: class-scope guard |
| `invoice_detail_safe` → IDOR (bait) | `request.user.invoices.filter(pk=…).first()`; ownership is the receiver chain, not a token. `request.user.` as a token would silence every IDOR. | **structural**: receiver/data-flow origin |
| `refund_line_form` → quantity (bait) | `min_value=1` lives in `forms.py` | **structural**: cross-file guard |
| `refund_line_safe`, `topup_bonus_safe` → TOCTOU | `if qty < 1` / `if amount <= 0` are validation bounds, not a check on a value read from the database; `save()` completes the shape | **structural**: needs "compared value was read from the DB" (data-flow) |

**Tally on held-out: 12 failure causes, 7 vocabulary, 5 structural.** The plan's kill criterion
was "structural failures exceed ~half → the vocabulary-pack conclusion is wrong". It is not
exceeded, but it is close, and the honest reading is: **vocabulary takes Joern from 5/9 to 7/9 on
unseen Django code and would take it to 9/9 with two tokens (`get`, `=request.user`) - at the price
of precision that only a graph traversal can buy back.** Four of the five structural causes fall
inside the three capabilities P7 was scoped for: class-scope resolution (`permission_classes`,
`get_queryset`), origin of the compared value (DB read vs request input), and the cross-file
guard (`forms.py`, `serializers.py`). The fifth - ownership carried in a receiver chain
(`request.user.invoices.filter(...)`) - needs the origin of the *receiver*, which none of the
three provides; it stays open after P7.

`flask-sqlite3` equals `_base` on both Django splits: the Flask pack neither helps nor hurts
Django code, which is what "framework vocabulary" should mean.

## What must NOT happen next

The two vocabulary gaps above (`get`, `=request.user`) and the over-broad `request.post` are
now *known from the held-out set*. Adding them to `django.json` and re-running
`djshop-heldout` would be tuning on the test set. The path is: change the pack (a new digest, a
new `authored_from` note that says the change was informed by evaluation), measure on DEV, and
report the next held-out number on a **new** held-out split. `heldout.log` will show any
re-run of `9b4f52b3f5f1`.

## Side findings

- The `kw = value` rendering gap (commit `82921d1f`) was invisible on shopfast and probe: neither
  testbed uses a keyword-argument guard. It took a second framework to surface it - an argument
  for the held-out design itself.
- The `user=request.user` token now suppresses an IDOR on `add_to_cart` (DEV) by matching a
  *different* call in the same method (`Cart.objects.get_or_create(user=request.user)`). Right
  answer, wrong reason; a per-method token bag cannot tell which call it guarded.
- semgrep's `tainted-sql-string` carries CWE-915 in its metadata; it is the same SQL injection as
  key #10 and is charged as an FP by family. bandit flags `import subprocess` (B404) and `/tmp`
  (B108) - import-noise, as on shopfast.
- Gemini quota was exhausted today; no `full` arm was run on the Django splits. The `bait` rows
  above are what the LLM tier exists to clear, and that number is still owed.

Run ids: held-out `20260915T124848Z…_base`, `…124929Z…flask-sqlite3`, `…125012Z…django`,
`…125014Z-bandit`, `…125031Z-semgrep`; DEV `20260915T1246…`–`1247…` (joern ×3), `…122402Z-bandit`,
`…122417Z-semgrep`.
