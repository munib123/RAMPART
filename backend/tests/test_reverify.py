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
