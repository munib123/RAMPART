"""
Matching policy: which candidate counts against which key row.

A candidate matches a key row when ALL of:
  1. same file (repo-relative, forward slashes);
  2. the enclosing function is the same - and the harness RECOMPUTES the enclosing function
     with Python's ast from (file, line), never trusting the tool. Joern reports the def line,
     semgrep reports the sink line, bandit reports the sink line; recomputing absorbs all of it.
     Module-level code (config.py constants, the app.run() guard) is the function "<module>".
     Methods are qualified by class ("OrderDetail.get"), so a Django class-based view with
     three get() methods cannot be credited against the wrong class;
  3. the CWE FAMILY is the same (see keys/cwe_families.json), because scanners label the same
     defect with different CWE ids.

Verdict gating: a candidate is "reported" if the backend produces no verdicts (a bare locator
arm - joern_only, bandit, semgrep) or if its verdict is Confirmed or Likely. Informational and
False positive count as "not reported": for recall they are misses, and they are EXCLUDED from
FP. That is the point of the two-tier design - a candidate the LLM correctly clears (the
db.find_product IDOR bait) must not be charged as a false positive against the hybrid arm.

Outcomes, per TDD section 9.4:
  TP        a vuln key row matched by >= 1 reported candidate
  FN        a vuln key row with no such match
  FP        a reported candidate matching no vuln key row
  bait_fp   an FP that matches a safe key row (counted separately; it is the precision signal)
  TN        a safe key row not matched by any reported candidate
  cleared   a candidate with verdict Informational/False positive that matches a safe row
            (the LLM did its job; reported for the hybrid arm)
"""
from __future__ import annotations

import ast
import json
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from bench import paths

REPORTED_VERDICTS = {"Confirmed", "Likely"}
CLEARED_VERDICTS = {"Informational", "False positive"}


# --------------------------------------------------------------------------- #
# CWE families
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=1)
def _family_index() -> dict[str, str]:
    data = json.loads(paths.families_file().read_text(encoding="utf-8"))
    idx: dict[str, str] = {}
    for fam, cwes in data["families"].items():
        for c in cwes:
            if c in idx:
                raise SystemExit(f"cwe_families.json: {c} listed under both {idx[c]} and {fam}")
            idx[c.upper()] = fam
    return idx


def cwe_family(cwe_id: str) -> str:
    if not cwe_id:
        return "unknown"
    c = cwe_id.strip().upper()
    if not c.startswith("CWE-"):
        c = "CWE-" + c
    return _family_index().get(c, "unknown")


# --------------------------------------------------------------------------- #
# enclosing function, recomputed by the harness
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=256)
def _function_spans(path: str) -> list[tuple[int, int, str]]:
    """[(start, end, qualified_name)] for every def in the file, innermost last-wins by sort."""
    try:
        src = Path(path).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except (OSError, SyntaxError):
        return []
    spans: list[tuple[int, int, str]] = []

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{child.name}"
                spans.append((child.lineno, child.end_lineno or child.lineno, name))
                walk(child, name + ".")
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}{child.name}.")
            else:
                walk(child, prefix)

    walk(tree, "")
    return spans


def enclosing_function(path: str, line: int) -> str:
    """Innermost def containing `line`, qualified by class; "<module>" if none."""
    best: Optional[tuple[int, int, str]] = None
    for s, e, name in _function_spans(str(path)):
        if s <= line <= e and (best is None or (e - s) < (best[1] - best[0])):
            best = (s, e, name)
    return best[2] if best else "<module>"


# --------------------------------------------------------------------------- #
# candidates and key rows
# --------------------------------------------------------------------------- #

@dataclass
class Candidate:
    tool: str
    rule_id: str
    path: str            # absolute
    line: int
    end_line: int
    cwe_id: str
    verdict: Optional[str] = None      # None = backend produces no verdicts
    confidence: Optional[int] = None
    meta: dict = field(default_factory=dict)   # engine provenance (joern: pack tag + slot trace)
    # filled by the matcher
    rel_path: str = ""
    function: str = ""
    family: str = ""
    reported: bool = True
    outcome: str = ""                  # tp | fp | bait_fp | cleared | ignored
    matched_key: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KeyRow:
    key_no: int
    relative_path: str
    resolved_line: Optional[int]
    enclosing_function: str
    cwe_family: str
    label: str
    route_reachable: bool
    difficulty: str
    status: str
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def usable(self) -> bool:
        return self.status != "unresolvable" and self.resolved_line is not None


def load_key(benchmark: str) -> list[KeyRow]:
    rows = []
    for raw in paths.key_file(benchmark).read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        r = json.loads(raw)
        rows.append(KeyRow(
            key_no=int(r["key_no"]),
            relative_path=r["relative_path"].replace("\\", "/"),
            resolved_line=r.get("resolved_line"),
            enclosing_function=r["enclosing_function"],
            cwe_family=r["cwe_family"],
            label=r["label"],
            route_reachable=bool(r.get("route_reachable", True)),
            difficulty=r.get("difficulty", ""),
            status=r.get("status", "proposed"),
            raw=r,
        ))
    return rows


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #

@dataclass
class Score:
    tp: int = 0
    fn: int = 0
    fp: int = 0
    bait_fp: int = 0
    tn: int = 0
    cleared: int = 0
    unresolvable_keys: int = 0
    reachable_tp: int = 0
    reachable_fn: int = 0
    vuln_rows: int = 0
    safe_rows: int = 0
    candidates: int = 0
    reported: int = 0
    matched_keys: list[int] = field(default_factory=list)
    missed_keys: list[int] = field(default_factory=list)

    @property
    def recall(self) -> Optional[float]:
        d = self.tp + self.fn
        return round(self.tp / d, 4) if d else None

    @property
    def reachable_recall(self) -> Optional[float]:
        d = self.reachable_tp + self.reachable_fn
        return round(self.reachable_tp / d, 4) if d else None

    @property
    def precision(self) -> Optional[float]:
        d = self.tp + self.fp + self.bait_fp
        return round(self.tp / d, 4) if d else None

    @property
    def f1(self) -> Optional[float]:
        d = 2 * self.tp + self.fp + self.bait_fp + self.fn
        return round(2 * self.tp / d, 4) if d else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(recall=self.recall, reachable_recall=self.reachable_recall,
                 precision=self.precision, f1=self.f1)
        return d


def score(candidates: list[Candidate], key: list[KeyRow], target_root: Path,
          verdict_gated: bool) -> Score:
    s = Score()
    root = Path(target_root).resolve()

    usable = [k for k in key if k.usable]
    s.unresolvable_keys = len(key) - len(usable)
    vuln = [k for k in usable if k.label == "vuln"]
    safe = [k for k in usable if k.label == "safe"]

    by_slot: dict[tuple[str, str, str], list[KeyRow]] = {}
    for k in usable:
        by_slot.setdefault((k.relative_path, k.enclosing_function, k.cwe_family), []).append(k)

    hit_vuln: set[int] = set()
    hit_safe: set[int] = set()

    for c in candidates:
        s.candidates += 1
        try:
            c.rel_path = Path(c.path).resolve().relative_to(root).as_posix()
        except ValueError:
            c.rel_path = Path(c.path).as_posix()
        c.function = enclosing_function(c.path, c.line)
        c.family = cwe_family(c.cwe_id)
        if verdict_gated and c.verdict is not None:
            c.reported = c.verdict in REPORTED_VERDICTS
        else:
            c.reported = True

        slot = by_slot.get((c.rel_path, c.function, c.family), [])
        v_rows = [k for k in slot if k.label == "vuln"]
        s_rows = [k for k in slot if k.label == "safe"]

        if not c.reported:
            if s_rows and c.verdict in CLEARED_VERDICTS:
                nearest = min(s_rows, key=lambda k: abs((k.resolved_line or 0) - c.line))
                c.outcome = "cleared"; c.matched_key = nearest.key_no; s.cleared += 1
            else:
                c.outcome = "ignored"
            continue

        s.reported += 1
        if v_rows:
            # Two DIFFERENT bugs can share a (file, function, family) slot (orders.update_profile
            # is both #3 and #23 on shopfast only across families, but a function with two
            # injection sinks is one slot). One candidate credits ONE bug: the one whose
            # resolved line is nearest the candidate. Rows of that same bug (its other
            # locations) are credited with it.
            nearest = min(v_rows, key=lambda k: abs((k.resolved_line or 0) - c.line))
            c.outcome = "tp"; c.matched_key = nearest.key_no
            hit_vuln.update(k.key_no for k in v_rows if k.key_no == nearest.key_no)
        elif s_rows:
            nearest = min(s_rows, key=lambda k: abs((k.resolved_line or 0) - c.line))
            c.outcome = "bait_fp"; c.matched_key = nearest.key_no
            hit_safe.update(k.key_no for k in s_rows if k.key_no == nearest.key_no); s.bait_fp += 1
        else:
            c.outcome = "fp"; s.fp += 1

    # A BUG is a key_no; a bug may have several rows (locations). Bug #20 is DEBUG/HOST defined
    # in config.py and consumed by app.run() in app.py - a tool flagging either has found it.
    # TP/FN are counted per bug, never per row, so a bug found at two locations is one TP and
    # a bug with two locations found at neither is one FN. A bug is route-reachable if any of
    # its locations is.
    bugs: dict[int, list[KeyRow]] = {}
    for k in vuln:
        bugs.setdefault(k.key_no, []).append(k)
    s.vuln_rows = len(bugs)
    for no, rows in sorted(bugs.items()):
        reachable = any(k.route_reachable for k in rows)
        if no in hit_vuln:
            s.tp += 1; s.matched_keys.append(no)
            if reachable:
                s.reachable_tp += 1
        else:
            s.fn += 1; s.missed_keys.append(no)
            if reachable:
                s.reachable_fn += 1
    safe_bugs = {k.key_no for k in safe}
    s.safe_rows = len(safe_bugs)
    s.tn = sum(1 for no in safe_bugs if no not in hit_safe)
    s.matched_keys.sort(); s.missed_keys.sort()
    return s
