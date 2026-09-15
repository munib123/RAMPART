"""
Resolve every answer-key row's verbatim `anchor` to a line number by unique substring search.

The key never stores a line number a human (or an LLM) typed. It stores the text of the line,
and this script finds it. A row whose anchor is absent, or occurs more than once so that
`anchor_occurrence` cannot disambiguate it, is flipped to status=unresolvable and the scorer
drops it - reported on every result, never folded into FN, never guessed at.

    python -m bench.validate_key shopfast            # resolve in place, print a summary
    python -m bench.validate_key shopfast --check    # exit 1 if anything is unresolvable

Writes `resolved_line`, `resolved_against_sha256` (of the file) and `status` back into the
row. Everything else in the row is left untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from bench import paths


def _read_key(key_path: Path) -> list[dict]:
    rows = []
    with open(key_path, encoding="utf-8") as fh:
        for ln, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as e:
                sys.exit(f"{key_path}:{ln}: bad JSON: {e}")
    return rows


def _write_key(key_path: Path, rows: list[dict]) -> None:
    with open(key_path, "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def resolve_row(row: dict, target_root: Path) -> dict:
    """Mutates and returns `row` with resolved_line / resolved_against_sha256 / status."""
    rel = row["relative_path"].replace("\\", "/")
    src = target_root / rel
    anchor = row["anchor"]
    want = int(row.get("anchor_occurrence") or 1)

    if not src.is_file():
        row.update(status="unresolvable", resolved_line=None, resolved_against_sha256=None,
                   unresolvable_reason=f"file not found: {rel}")
        return row

    data = src.read_bytes()
    text = data.decode("utf-8", errors="replace")
    hits = [i + 1 for i, line in enumerate(text.splitlines()) if anchor in line]

    if not hits:
        reason = "anchor not found"
    elif len(hits) < want:
        reason = f"anchor occurs {len(hits)}x, occurrence {want} requested"
    elif len(hits) > 1 and want == 1 and row.get("anchor_occurrence") is None:
        reason = f"anchor is not unique ({len(hits)} matches) and no anchor_occurrence given"
    else:
        reason = ""

    if reason:
        row.update(status="unresolvable", resolved_line=None, resolved_against_sha256=None,
                   unresolvable_reason=reason)
        return row

    row["resolved_line"] = hits[want - 1]
    row["resolved_against_sha256"] = hashlib.sha256(data).hexdigest()
    # the scorer matches candidates to rows by ENCLOSING FUNCTION; a row whose declared
    # function does not contain its own anchor could never match and must not be scored
    from bench.match import enclosing_function
    actual = enclosing_function(str(src), row["resolved_line"])
    if actual != row.get("enclosing_function"):
        row.update(status="unresolvable", resolved_line=None, resolved_against_sha256=None,
                   unresolvable_reason=f"anchor is inside {actual!r}, row says {row.get('enclosing_function')!r}")
        return row
    row.pop("unresolvable_reason", None)
    # never promote to accepted here; that is the adjudicator's job
    if row.get("status") == "unresolvable":
        row["status"] = "proposed"
    return row


def validate(benchmark: str, check: bool = False, quiet: bool = False) -> int:
    key_path = paths.key_file(benchmark)
    target = paths.testbed_dir(benchmark)
    rows = _read_key(key_path)
    for r in rows:
        resolve_row(r, target)
    _write_key(key_path, rows)

    ok = [r for r in rows if r.get("status") != "unresolvable"]
    bad = [r for r in rows if r.get("status") == "unresolvable"]
    accepted = [r for r in ok if r.get("status") == "accepted"]
    print(f"[key] {benchmark}: {len(rows)} rows | resolved {len(ok)} | unresolvable {len(bad)} "
          f"| accepted {len(accepted)} | proposed {len(ok) - len(accepted)}")
    for r in (ok if not quiet else []):
        print(f"   #{r['key_no']:<4} {r['relative_path']}:{r['resolved_line']:<4} "
              f"{r['enclosing_function']:20} {r['cwe_family']:16} {r['label']}")
    for r in bad:
        print(f"   #{r['key_no']:<4} UNRESOLVABLE  {r['relative_path']}  "
              f"{r.get('unresolvable_reason')}  anchor={r['anchor'][:60]!r}")
    if not accepted:
        print("[key] NOTE: no row is adjudicated yet. Set adjudicated_by/adjudicated_at and "
              "status=accepted after a human reviews each row. Scoring runs against resolved rows "
              "regardless, and reports the adjudication state.")
    return 1 if (check and bad) else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("benchmark")
    ap.add_argument("--check", action="store_true", help="exit 1 if any row is unresolvable")
    a = ap.parse_args(argv)
    return validate(a.benchmark, a.check)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
