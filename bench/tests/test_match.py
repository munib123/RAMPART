"""Scoring-policy tests. No JVM, no scanners: exercises match.py against the real shopfast key
and synthetic candidates, so a change to the policy shows up as a failing test, not as a
quietly different thesis number.

    backend\\.venv\\Scripts\\python.exe -m pytest bench/tests -q
"""
from __future__ import annotations

from pathlib import Path

import pytest

from bench import paths
from bench.match import (Candidate, cwe_family, enclosing_function, load_key, score)

SF = paths.testbed_dir("shopfast")


def _cand(rel: str, line: int, cwe: str, verdict=None, tool="x") -> Candidate:
    return Candidate(tool=tool, rule_id="r", path=str(SF / rel), line=line, end_line=line,
                     cwe_id=cwe, verdict=verdict)


# ---- enclosing function is recomputed, never trusted -------------------------------------

def test_enclosing_function_def_line_and_body_line_agree():
    # Joern reports the def line, bandit/semgrep the sink line; both must resolve identically
    assert enclosing_function(SF / "orders.py", 5) == "get_order"     # def line
    assert enclosing_function(SF / "orders.py", 8) == "get_order"     # body line
    assert enclosing_function(SF / "orders.py", 11) == "update_profile"
    assert enclosing_function(SF / "orders.py", 15) == "update_profile"


def test_enclosing_function_module_level():
    assert enclosing_function(SF / "config.py", 20) == "<module>"
    assert enclosing_function(SF / "app.py", 77) == "<module>"        # the __main__ guard


def test_enclosing_function_qualifies_methods_by_class(tmp_path: Path):
    src = tmp_path / "views.py"
    src.write_text("class A:\n    def get(self):\n        return 1\n\nclass B:\n    def get(self):\n        return 2\n")
    assert enclosing_function(src, 3) == "A.get"
    assert enclosing_function(src, 7) == "B.get"


# ---- families ------------------------------------------------------------------------

def test_cwe_family_absorbs_tool_labelling_differences():
    assert cwe_family("CWE-89") == "injection"
    assert cwe_family("CWE-78") == "injection"          # bandit labels eval() as 78
    assert cwe_family("CWE-95") == "injection"          # the key labels it 95
    assert cwe_family("CWE-96") == cwe_family("CWE-1336") == "xss"   # both are SSTI
    assert cwe_family("639") == "authz"                 # bare number tolerated
    assert cwe_family("") == "unknown"
    assert cwe_family("CWE-9999") == "unknown"


# ---- the key itself ------------------------------------------------------------------

def test_key_resolves_and_has_the_documented_shape():
    key = load_key("shopfast")
    usable = [k for k in key if k.usable]
    assert len(usable) == len(key), "run validate_key first; unresolvable rows present"
    bugs = {k.key_no for k in key if k.label == "vuln"}
    assert bugs == set(range(1, 27)), "26 bugs: 25 documented + the undocumented /login one"
    assert {k.key_no for k in key if k.label == "safe"} == {101, 102}
    # the four SAST-blind rows are what the CPG phase targets
    fam = {k.key_no: k.cwe_family for k in key if k.label == "vuln"}
    assert (fam[22], fam[23], fam[24], fam[25]) == ("authz", "mass-assign", "logic-bound", "race")


# ---- scoring semantics ---------------------------------------------------------------

def test_locator_arm_counts_every_candidate_as_reported():
    key = load_key("shopfast")
    cands = [_cand("orders.py", 5, "CWE-639"),          # get_order -> bug 22
             _cand("db.py", 13, "CWE-639"),             # find_product -> bait 102
             _cand("cart.py", 3, "CWE-502")]            # import pickle at module level -> FP
    s = score(cands, key, SF, verdict_gated=False)
    assert (s.tp, s.bait_fp, s.fp) == (1, 1, 1)
    assert s.matched_keys == [22]
    assert s.tn == 1                                    # user_by_name untouched


def test_verdict_gated_arm_clears_instead_of_charging():
    key = load_key("shopfast")
    cands = [_cand("orders.py", 5, "CWE-639", verdict="Confirmed"),
             _cand("db.py", 13, "CWE-639", verdict="False positive"),   # LLM cleared the bait
             _cand("cart.py", 3, "CWE-502", verdict="Informational")]   # LLM downgraded noise
    s = score(cands, key, SF, verdict_gated=True)
    assert (s.tp, s.bait_fp, s.fp, s.cleared) == (1, 0, 0, 1)
    assert s.tn == 2                                    # both safe rows untouched by REPORTED findings


def test_unverified_is_neither_reported_nor_cleared():
    key = load_key("shopfast")
    s = score([_cand("orders.py", 5, "CWE-639", verdict="Unverified")], key, SF, verdict_gated=True)
    assert (s.tp, s.fp, s.cleared) == (0, 0, 0)
    assert 22 in s.missed_keys


def test_multi_location_bug_is_one_tp_and_one_fn():
    key = load_key("shopfast")
    # bug 20 lives at config.py (HOST=0.0.0.0) AND app.py (app.run); finding both is ONE tp
    both = [_cand("config.py", 8, "CWE-605"), _cand("app.py", 77, "CWE-489")]
    s = score(both, key, SF, verdict_gated=False)
    assert s.tp == 1 and s.matched_keys == [20]
    # finding neither is ONE fn, not two
    s0 = score([], key, SF, verdict_gated=False)
    assert s0.fn == 26 and s0.missed_keys.count(20) == 1


def test_same_function_two_families_are_separate_bugs():
    key = load_key("shopfast")
    # orders.update_profile is bug 3 (injection) AND bug 23 (mass-assign)
    s = score([_cand("orders.py", 15, "CWE-89")], key, SF, verdict_gated=False)
    assert s.matched_keys == [3] and 23 in s.missed_keys
    s = score([_cand("orders.py", 14, "CWE-915")], key, SF, verdict_gated=False)
    assert s.matched_keys == [23] and 3 in s.missed_keys


def test_reachable_recall_excludes_unroutable_bugs():
    key = load_key("shopfast")
    s = score([], key, SF, verdict_gated=False)
    # 26 bugs, 11 of them in functions no route reaches (per VULNERABILITIES.md analysis)
    assert s.reachable_fn + s.reachable_tp < s.fn + s.tp
    assert s.reachable_recall == 0.0 and s.recall == 0.0


def test_unknown_family_never_matches():
    key = load_key("shopfast")
    s = score([_cand("orders.py", 5, "CWE-9999")], key, SF, verdict_gated=False)
    assert s.tp == 0 and s.fp == 1
