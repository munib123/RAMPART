# P5 - vocabulary packs as data, 2026-09-15

The claim P5 exists to make measurable: *the four locator rules are framework-neutral shapes;
what varies per framework is vocabulary, and vocabulary can be data.* So the Scala is now frozen
and hashed, every token list comes from a JSON pack the Scala reads with `ujson` after
`importCode`, and `--pack A` vs `--pack B` on one benchmark is a clean ablation.

## What a pack is

`backend/app/services/joern/vocab/schema.json` - 18 slots, each bound to one of 7 sinks:

| sink | reaches | class |
|---|---|---|
| `call_name` | `call.nameExact(v: _*)` | `[A-Za-z_][A-Za-z0-9_]{1,63}` |
| `param_exact` / `param_suffix` | `==` / `endsWith` on lower-cased parameter names | lower identifiers |
| `exec_sql_kw` | `contains` on upper-cased `execute(...)` code | `[A-Z]{3,16}` |
| `token` | `contains` on lower-cased operator operands | `[a-z][a-z0-9_]{2,31}` |
| `signal_text` / `guard_text` | `contains` on the method's lower-cased call/identifier text | printable ASCII 3-48, no `\` `` ` `` `$` |

No regex sink. No accessor that treats its argument as a regex ever sees a pack value
(`test_rules_file_has_no_hardcoded_vocabulary` greps the Scala for `.name(` / `.code(` /
`.filename(` outside comments and for every `slot("...")`). Caps: 8 KB per file, 64 values per
slot, extends depth 3. Cross-slot: no `authz_guard` value inside an `authn_only` value;
`qty_terms` ∩ `price_terms` = ∅; text sinks lower-case, SQL keywords upper-case. Composition is a
per-slot union with the parent, sorted + de-duplicated before hashing - a shuffled, duplicated
copy of `flask-sqlite3.json` hashes to the same `4a85ea8346ac`. `packs/digests.json` is the
allowlist; an unlisted pack loads only with `JOERN_PACK_ALLOW_UNLISTED=1` and is flagged.

Shipped: `_base` (82 values - exactly the pre-P5 Scala vals, hash `88796c2a63cd`) and
`flask-sqlite3` (extends `_base`, +70 values from Flask / Flask-Login / Flask-SQLAlchemy /
WTForms / sqlite3 docs, hash `4a85ea8346ac`).

## Exit gate as run today

Same frozen Scala (`locators.sc`), same frozen keys, script mode (the bench's own sidecar could
not bind 8091 while the backend held it):

| benchmark | pack | TP | FN | FP | bait | TN | run json |
|---|---|---|---|---|---|---|---|
| shopfast | `_base@88796c2a63cd` | 4 | 22 | 0 | 1 | 1 | 20260915T110413Z-shopfast-joern-pack-_base |
| shopfast | `flask-sqlite3@4a85ea8346ac` | 4 | 22 | 0 | 1 | 1 | 20260915T110543Z-shopfast-joern-pack-flask-sqlite3 |
| probe | `_base@88796c2a63cd` | 5 | 0 | 0 | 0 | 2 | 20260915T110448Z-probe-joern-pack-_base |
| probe | `flask-sqlite3@4a85ea8346ac` | 5 | 0 | 0 | 0 | 2 | 20260915T110623Z-probe-joern-pack-flask-sqlite3 |

- **Non-regression:** `_base` reproduces P2's numbers exactly, so moving the vocabulary out of
  the Scala changed nothing the rules do. Both testbeds exercise only base vocabulary, so the
  Flask pack is identical on them - as it should be; its extra 70 values are for code these
  testbeds do not contain (`current_user.id ==`, `get_or_404`, `populate_obj`, `pk`, …).
- **Provenance per finding** (new columns 9-10 of the TSV → `Finding.meta`):
  `db.py:13 id_param_suffix=_id;orm_read_calls=fetchone`,
  `orders.py:11 mapping_iter_calls;sql_write_kw=UPDATE`,
  `cart.py:14 qty_terms=quantity;price_terms=price`,
  `cart.py:22 qty_terms=quantity;sql_write_kw=UPDATE`. The report can now say *which entry*
  fired, which is what a vocabulary ablation needs to explain a delta.
- Through the API (server mode, warm): 9.8 s then 4.3 s for the CPG phase; the response's
  `joern.pack` = `{requested: auto, resolved: flask-sqlite3, reason: "flask in project metadata",
  tag, chain: [_base, flask-sqlite3], listed, loaded, source: pack}` and it is persisted in
  `scans.joern` (P4), so the pack is part of every stored scan's provenance.

**The headline gate in the plan - `flask-sqlite3` vs `django` on the Django testbed - cannot be
run yet and must not be faked:** the held-out protocol requires the Django testbed to be
authored and frozen *before* its pack exists, and P6 (the testbed) has not started. So
`django.json` is deliberately absent; a Django target resolves to `_base` with reason
"django in project metadata" (`test_resolve_django_without_a_shipped_pack_falls_to_base` pins
this), and the ablation runs at the end of P6.

## Degradation, proven

| case | result |
|---|---|
| value too short (`"a"` in `authz_guard`, the T-10 flood) | refused whole → `_base`, `diag.pack.fallback` names the value |
| text token re-routed into `call_name` (`".*"`) | refused: "sink must be 'call_name'" |
| 65 values / 9 KB file | refused: cap |
| valid but unlisted draft pack | refused without the allow flag; with it: used, `unlisted: true`, tag `draft@869f8835a16b` |
| pack file vanishes between validation and the JVM read | Scala falls back to `_base.json`, `pack_source = base_fallback:NoSuchFileException` |
| both files unreadable | the `vocab` section fails → the phase reports it did not run (rules never execute with empty guard lists) |

Tests: `backend/tests/test_vocab.py` (31, no JVM); 75 backend + 12 bench pass; `tsc` clean.

## Notes

- Gemini free-tier quota for `gemini-2.5-flash-lite` was exhausted late in the day
  (`429 RESOURCE_EXHAUSTED`), so today's API scans carry `Error` verdicts. The `full` arm should
  not be re-run until the quota resets; nothing in P5 touches the LLM path.
- `lock_guard` still contains `lock` (matches `block`, `clock`, `unlock`); inherited from the
  July list, kept in `_base` for non-regression, worth tightening in a reviewed pack change with
  a bench run.
