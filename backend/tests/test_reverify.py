"""P8 / O3 re-verification. decide() is the convergence policy and is pure - every branch is
pinned here without a JVM. The one integration test rebuilds real CPGs on a scratch copy of
testbeds/shopfast and is skipped when the Joern runtime is not installed. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_reverify.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.joern import reverify as rv          # noqa: E402

IDOR = "joern-idor-missing-ownership"
TOCTOU = "joern-toctou-check-then-write"


def _m(guards=None, sinks=None, found=True):
    return {"found": found, "methods": [{"name": "f", "guards": guards or {}, "sinks": sinks or {}}] if found else []}


# ---- the policy -------------------------------------------------------------------------

def test_converges_when_guard_appears():
    v = rv.decide(IDOR, [{"rule_id": IDOR}], [], _m({"authz": ["method:permissiondenied"]}, {"reads": 1}), [])
    assert v["converged"] and not v["locator_refires"] and v["fired_before"] is True
    assert v["guard_present"] and v["guard_evidence"] == ["method:permissiondenied"]
    assert "guard now present" in v["reason"]


def test_converges_when_sink_vanishes():
    v = rv.decide(IDOR, [{"rule_id": IDOR}], [], _m({"authz": []}, {"reads": 0, "exec_reads": 0}), [])
    assert v["converged"] and not v["guard_present"] and v["sink_present"] is False
    assert "sink is gone" in v["reason"]


def test_still_fires_never_converges():
    """A cosmetic edit leaves the locator firing; no amount of guard text elsewhere changes that."""
    v = rv.decide(IDOR, [{"rule_id": IDOR}], [{"rule_id": IDOR}], _m({"authz": ["method:owner_id"]}, {"reads": 1}), [])
    assert not v["converged"] and v["locator_refires"]
    assert "still fires" in v["reason"]


def test_silent_but_unexplained_is_flagged_for_review():
    v = rv.decide(IDOR, [{"rule_id": IDOR}], [], _m({"authz": []}, {"reads": 1}), [])
    assert v["converged"]                                   # the locator is silent
    assert not v["guard_present"] and v["sink_present"] is True
    assert "review by hand" in v["reason"]


def test_regression_blocks_convergence():
    reg = [{"path": "cart.py", "line": 30, "method": "checkout", "rule_id": TOCTOU}]
    v = rv.decide(IDOR, [{"rule_id": IDOR}], [], _m({"authz": ["method:is_owner"]}, {"reads": 1}), reg)
    assert not v["converged"] and v["regressions"] == reg
    assert "new candidate" in v["reason"]


def test_did_not_fire_before_is_not_convergence():
    v = rv.decide(IDOR, [], [], _m({"authz": ["method:is_owner"]}, {"reads": 1}), [])
    assert not v["converged"] and v["fired_before"] is False
    assert "did not fire before" in v["reason"]


def test_unknown_before_state_can_still_converge():
    """Post-apply with no snapshot: before is unknown, the after-state alone decides."""
    v = rv.decide(TOCTOU, None, [], _m({"lock": ["method:select_for_update"]}, {"ctl_writes": 0}), [])
    assert v["converged"] and v["fired_before"] is None


def test_renamed_method_is_not_convergence():
    v = rv.decide(IDOR, [{"rule_id": IDOR}], [], _m(found=False), [])
    assert not v["converged"] and not v["method_found"]
    assert "not found" in v["reason"]


def test_other_rule_firing_is_not_this_rules_refire():
    v = rv.decide(IDOR, [{"rule_id": IDOR}], [{"rule_id": TOCTOU}], _m({"authz": ["class:isowner"]}, {"reads": 1}), [])
    assert v["converged"] and not v["locator_refires"]


# ---- helpers ------------------------------------------------------------------------------

def test_method_name_is_bare():
    assert rv._method_of("OrderViewSet.cancel") == "cancel"
    assert rv._method_of("get_order") == "get_order"
    assert rv._method_of("") == ""


def test_path_must_be_inside_target(tmp_path):
    r = rv.verify(str(tmp_path), str(tmp_path.parent / "elsewhere.py"), "f", IDOR)
    assert not r["ok"] and "not inside" in r["error"]


def test_preview_refuses_stale_slice(tmp_path, monkeypatch):
    """The content guard from apply_fix applies to the scratch copy too."""
    (tmp_path / "a.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    r = rv.verify(str(tmp_path), str(tmp_path / "a.py"), "f", IDOR, fixed_code="def f(x):\n    return 1\n",
                  start_line=1, end_line=2, original_code="def f(x):\n    return 2")
    assert not r["ok"] and r.get("code") == "file_changed" and r.get("mode") == "preview"


def test_pattern_fallback_when_joern_unavailable(tmp_path, monkeypatch):
    from app.services.joern import scan as joern_scan
    monkeypatch.setattr(joern_scan, "enabled", lambda p: (False, "no JRE 21 found"))
    (tmp_path / "views.py").write_text(
        "def get_order(order_id):\n    row = fetch(order_id)\n    return row\n", encoding="utf-8")
    fixed = "def get_order(order_id):\n    row = fetch(order_id)\n    if not is_owner(row):\n        raise PermissionDenied()\n    return row"
    r = rv.verify(str(tmp_path), str(tmp_path / "views.py"), "get_order", IDOR,
                  fixed_code=fixed, start_line=1, end_line=3, pack="_base")
    assert r["ok"] and r["reverify_method"] == "pattern" and r["converged"]
    assert "text:is_owner" in r["guard_evidence"] and "text:permissiondenied" in r["guard_evidence"]
    assert "pattern fallback" in r["reason"]


def test_every_guard_mapping_names_a_real_rule():
    """_RULE_GUARD / _RULE_SLOTS are keyed by rule id; a typo would silently fall back to
    'review by hand'. Every key must be a rule the program runs."""
    from app.services.joern import scan as joern_scan
    assert set(rv._RULE_GUARD) <= set(joern_scan._TITLES)
    assert set(rv._RULE_SLOTS) <= set(rv._RULE_GUARD)
    for rule in ("joern-ignored-auth-result", "joern-hardcoded-credential-compare",
                 "joern-ssrf-request-url", "joern-path-traversal"):
        assert rule in rv._RULE_GUARD, rule


def test_ignored_auth_result_converges_when_the_result_is_used():
    """The fix for a discarded check adds no guard token: it USES the value. The reverify block
    then counts no discarded check left in the method - the sink-gone path."""
    rule = "joern-ignored-auth-result"
    rvb = {"found": True, "methods": [{"guards": {}, "sinks": {"auth_discarded": 0}}]}
    d = rv.decide(rule, [{"rule_id": rule}], [], rvb, [])
    assert d["converged"] and d["sink_present"] is False and "sink is gone" in d["reason"]
    rvb_bad = {"found": True, "methods": [{"guards": {}, "sinks": {"auth_discarded": 1}}]}
    d2 = rv.decide(rule, [{"rule_id": rule}], [{"rule_id": rule}], rvb_bad, [])
    assert not d2["converged"] and d2["locator_refires"]


def test_ssrf_converges_on_a_url_guard():
    rule = "joern-ssrf-request-url"
    rvb = {"found": True, "methods": [{"guards": {"url": ["method:urlparse("]}, "sinks": {"http_calls": 1}}]}
    d = rv.decide(rule, [{"rule_id": rule}], [], rvb, [])
    assert d["converged"] and d["guard_evidence"] == ["method:urlparse("]


# ---- the real thing (needs the Joern runtime; ~2-3 min in script mode) ------------------

def _joern_available() -> bool:
    from app.services.joern import runtime
    ok, _, _ = runtime.probe()
    return ok


@pytest.mark.skipif(not _joern_available(), reason="Joern runtime not installed")
def test_exit_gate_shopfast_get_order():
    """P8 exit gate: applying the ownership fix to orders.get_order flips the locator from
    firing to not firing on the patched copy, and the report says so; a cosmetic rename does not."""
    root = Path(__file__).resolve().parents[2] / "testbeds" / "shopfast"
    path = root / "orders.py"
    lines = path.read_text(encoding="utf-8").splitlines()
    original = "\n".join(lines[4:8])
    assert original.startswith("def get_order(order_id):")
    fix = ('def get_order(order_id, current_user_id):\n'
           '    """Fetch an order by its id for the order-details page."""\n'
           '    conn = db.get_db()\n'
           '    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()\n'
           '    if row is None or row["user_id"] != current_user_id:\n'
           '        raise PermissionDenied("not your order")\n'
           '    return row')
    r = rv.verify(str(root), str(path), "get_order", IDOR, fixed_code=fix,
                  start_line=5, end_line=8, original_code=original, pack="_base")
    assert r["ok"] and r["reverify_method"] == "cpg" and r["mode"] == "preview", r
    assert r["fired_before"] is True and r["locator_refires"] is False and r["converged"], r
    assert r["guard_present"] and r["guard_evidence"] == ["method:permissiondenied"]
    assert r["regressions"] == []
    assert path.read_text(encoding="utf-8").splitlines()[4:8] == lines[4:8]   # the real tree is untouched

    cosmetic = ('def get_order(order_id):\n'
                '    """Fetch an order by its id for the order-details page."""\n'
                '    connection = db.get_db()\n'
                '    return connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()')
    r2 = rv.verify(str(root), str(path), "get_order", IDOR, fixed_code=cosmetic,
                   start_line=5, end_line=8, original_code=original, pack="_base")
    assert r2["ok"] and r2["locator_refires"] is True and not r2["converged"], r2


# ---- review fixes: input validation, single-file targets, docstring-blind fallback ---------

@pytest.mark.parametrize("path_tail,function", [
    ('x"; System.exit(3); val zz = "y.py', "f"),
    ("views.py", 'f"; System exit 1; val q = "'),
    ("views.py", "Cls.f; bad"),
    ("views.txt", "f"),
])
def test_verify_refuses_unsafe_names_before_any_scan(tmp_path, path_tail, function):
    (tmp_path / "views.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    r = rv.verify(str(tmp_path), str(tmp_path / path_tail), function, IDOR)
    assert not r["ok"] and r.get("code") in ("bad_request", "not_found"), r


def test_verify_refuses_non_cpg_rules(tmp_path):
    (tmp_path / "views.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    r = rv.verify(str(tmp_path), str(tmp_path / "views.py"), "f", "python.lang.security.x")
    assert not r["ok"] and r["code"] == "not_cpg"


def test_split_function_carries_the_class():
    assert rv._split_function("OrderViewSet.cancel") == ("OrderViewSet", "cancel")
    assert rv._split_function("get_order") == ("", "get_order")
    assert rv._split_function("a.b.c") == ("b", "c")


def test_single_file_target_resolves_to_its_name(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("def f():\n    return 1\n", encoding="utf-8")
    assert rv._rel(str(f), str(f)) == "app.py"
    assert rv._rel(str(f), str(tmp_path / "other.py")) is None


def test_hits_are_class_qualified():
    class F:  # a Finding-like object
        def __init__(self, cls): self.d = {"path": "D:/t/api.py", "rule_id": IDOR, "line": 1, "cwe_id": "CWE-639",
                                            "meta": {"method": "get", "class": cls}}
        def to_dict(self): return self.d
    fs = [F("A"), F("B")]
    assert [h["class"] for h in rv._hits(fs, "api.py", "get")] == ["A", "B"]
    assert [h["class"] for h in rv._hits(fs, "api.py", "get", "B")] == ["B"]


def test_pattern_fallback_ignores_docstrings_and_comments(tmp_path, monkeypatch):
    from app.services.joern import scan as joern_scan
    monkeypatch.setattr(joern_scan, "enabled", lambda p: (False, "no JRE 21 found"))
    (tmp_path / "views.py").write_text("def get_order(order_id):\n    return fetch(order_id)\n", encoding="utf-8")
    liar = ('def get_order(order_id):\n'
            '    """Only the owner may read this: is_owner is checked, else PermissionDenied."""\n'
            '    # TODO: abort(403) when not the owner\n'
            '    return fetch(order_id)')
    r = rv.verify(str(tmp_path), str(tmp_path / "views.py"), "get_order", IDOR,
                  fixed_code=liar, start_line=1, end_line=2, pack="_base")
    assert r["ok"] and r["reverify_method"] == "pattern"
    assert not r["converged"] and r["guard_evidence"] == []
    honest = 'def get_order(order_id):\n    row = fetch(order_id)\n    if not is_owner(row):\n        raise PermissionDenied()\n    return row'
    r2 = rv.verify(str(tmp_path), str(tmp_path / "views.py"), "get_order", IDOR,
                   fixed_code=honest, start_line=1, end_line=2, pack="_base")
    assert r2["converged"] and "text:is_owner" in r2["guard_evidence"]


def test_config_flow_rules_say_verify_is_not_supported(tmp_path):
    """A config-flow finding sits on a module-level definition (method "<module>"); the answer
    must be a clear not_supported, not an identifier-validation error."""
    (tmp_path / "settings.py").write_text('DEBUG = True\n', encoding="utf-8")
    r = rv.verify(str(tmp_path), str(tmp_path / "settings.py"), "<module>", "joern-debug-exposed")
    assert not r["ok"] and r["code"] == "not_supported" and "re-scan" in r["error"]
