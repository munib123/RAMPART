# bench/ — the evaluation harness

The oracle. Every detection claim in the thesis is a number this directory produced, traceable
to the exact rules, model, answer key and commit that produced it. Until this existed, every
"4/4" figure in the project was hand-traced.

```
bench/
  keys/
    shopfast.key.jsonl     the answer key: 26 bugs over 29 locations + 2 safe (bait) rows
    cwe_families.json      CWE id -> family; scoring matches on family, not exact id
  validate_key.py          resolve every verbatim anchor to a line by unique string search
  match.py                 scoring policy (enclosing function recomputed by ast; per-bug TP/FN)
  backends/                LocatorBackend ABC + null | bandit | semgrep | joern | full
  run.py                   one arm x one benchmark -> runs/<stamp>-<benchmark>-<arm>.json
  report.py                runs/*.json -> markdown table
  runs/                    committed artifacts; one JSON per experiment
```

Run from the repo root with the backend venv:

```bash
backend\.venv\Scripts\python.exe -m bench.validate_key shopfast --check
backend\.venv\Scripts\python.exe -m bench.run --backend joern  --benchmark shopfast
backend\.venv\Scripts\python.exe -m bench.run --backend bandit --benchmark shopfast
backend\.venv\Scripts\python.exe -m bench.run --backend full   --benchmark shopfast --scanner bandit
backend\.venv\Scripts\python.exe -m bench.report --latest
```

## The answer key

One JSON row per **location**; a **bug** is a `key_no` and may have several locations
(bug 20 is `DEBUG`/`HOST` defined in `config.py` and consumed by `app.run()` in `app.py` —
flagging either has found it). TP and FN are counted per bug, never per row.

The load-bearing field is `anchor`: a **verbatim substring of the source line, never a line
number**. `validate_key.py` resolves it by unique string search and writes `resolved_line` and
the file's sha256. A row whose anchor is missing or ambiguous becomes `status: unresolvable`
and is dropped by the scorer — reported on every result, never guessed at, never folded into
FN. A hallucinated location dies to a failed string search rather than to trust.

Other fields that matter:

- `label`: `vuln` or `safe`. Safe rows are precision tests. `db.user_by_name` (bug 101) is the
  testbed's documented injection bait — a correctly parameterised query. `db.find_product`
  (bug 102) is **locator** bait: products are public data, so an id-keyed read with no
  ownership check is not an IDOR; the Joern rule fires there by design and the LLM is
  expected to clear it.
- `route_reachable`: 11 of the 26 bugs sit in functions no Flask route reaches. A
  reachability-aware tool legitimately misses them, so `reachable_recall` is always reported
  next to raw recall.
- `difficulty`: `easy` / `medium` / `hard` from `VULNERABILITIES.md`, `sast_blind` for
  #22–#25, `undocumented` for #26 (`/login` discards `verify_login()`'s return value — absent
  from the team's key; a scanner reporting it was a false positive before this row existed).
- `status`, `adjudicated_by`, `adjudicated_at`: **every row is `proposed` until a human reviews
  it.** The rows were derived from the team-authored `VULNERABILITIES.md` and the source, but
  if the same model family proposes the key and is graded against it, every number is circular.
  `run.py` prints the adjudication state on every result so this is never hidden.

## Scoring (match.py)

A candidate matches a row when the file, the **enclosing function**, and the **CWE family**
all agree. The enclosing function is recomputed by the harness with Python's `ast` from
(file, line) — Joern reports the `def` line, bandit and semgrep report the sink line, and
recomputing absorbs the difference. Module-level code is `<module>`. Methods are qualified by
class so Django class-based views cannot be credited against the wrong class.

Families (`cwe_families.json`) exist because tools label the same defect differently: bandit
says `eval()` is CWE-78, the key says CWE-95; both are `injection`.

| outcome | meaning |
|---|---|
| TP | a vuln bug matched by ≥1 reported candidate at any of its locations |
| FN | a vuln bug matched at none |
| FP | a reported candidate matching no vuln row |
| bait_fp | an FP that matches a `safe` row — the precision signal the testbed was built for |
| TN | a safe bug matched by nothing reported |
| cleared | a candidate with verdict Informational / False positive that matches a safe row: the LLM did its job |

**Verdict gating.** Bare locator arms (`joern`, `bandit`, `semgrep`, `null`) produce no verdicts,
so every candidate counts as reported. The `full` arm is gated: only `Confirmed` / `Likely`
count; `Informational` / `False positive` are *cleared*, not charged as FP. That is the whole
point of "Joern locates, the LLM proves" — a candidate the LLM correctly rejects must not be
scored against the hybrid arm, and the `joern` arm exists precisely to show what the rules find
before anything clears them.

Metrics: `recall = tp/(tp+fn)`, `reachable_recall`, `precision = tp/(tp+fp+bait_fp)`, `f1`.
`None` when a denominator is zero, never an error.

## Adding a benchmark

1. `testbeds/<name>/` — the code.
2. `bench/keys/<name>.key.jsonl` — rows with verbatim anchors; run `validate_key --check`.
3. Adjudicate: a human sets `status: accepted`, `adjudicated_by`, `adjudicated_at` per row.
4. `run.py --backend <arm> --benchmark <name>`.

For the Django testbed (plan P6) the key is authored and frozen **before** its vocabulary pack
exists, and split DEV / HELD-OUT with HELD-OUT touched once.
