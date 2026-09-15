"""Vocabulary packs (P5): the validator IS the security boundary between LLM-authored data and
the frozen Scala, so every rule in vocab/schema.json is pinned here. No JVM. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_vocab.py -q
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.joern.vocab import validate as v      # noqa: E402
from app.services.joern import scan as joern_scan        # noqa: E402


def _base() -> dict:
    return json.loads(v.pack_path("_base").read_text(encoding="utf-8"))


def _child(**slots) -> dict:
    return {"pack_id": "t", "schema_version": 2, "authored_from": "hand_written",
            "extends": "_base", "slots": slots}


def _write(tmp_path: Path, pack: dict, name: str = "t.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(pack), encoding="utf-8")
    return p


# ---- the shipped packs -------------------------------------------------------------------

def test_shipped_packs_valid_and_listed():
    for pid in v.shipped():
        eff, info = v.load(pid)
        assert eff is not None, (pid, info["errors"])
        assert info["listed"], f"{pid}: digest drifted - run validate --freeze"
        assert set(eff["slots"]) == set(v.schema()["slots"])


def test_base_has_no_parent_and_flask_extends_it():
    b, _ = v.load("_base")
    f, _ = v.load("flask-sqlite3")
    assert b["chain"] == ["_base"] and f["chain"] == ["_base", "flask-sqlite3"]
    for n, body in b["slots"].items():                       # a child can only ADD
        assert set(body["values"]) <= set(f["slots"][n]["values"]), n


def test_base_is_exactly_the_pre_p5_lists():
    """The July/August lists the rules were measured with. Changing these changes the
    no_vocab_pack arm - do it in a reviewed commit that re-runs the bench."""
    b, _ = v.load("_base")
    s = b["slots"]
    assert set(s["qty_terms"]["values"]) | set(s["price_terms"]["values"]) == {
        "qty", "quantity", "amount", "count", "total", "price", "subtotal", "balance", "stock"}
    assert set(s["orm_read_calls"]["values"]) == {"fetchone", "first", "one", "scalar"}
    assert "abort(401" in s["authz_guard"]["values"] and "abort(" not in s["authz_guard"]["values"]
    assert "login_required" in s["authn_only"]["values"] and "login_required" not in s["authz_guard"]["values"]
    assert " in [" not in s["allowlist_guard"]["values"]


# ---- per-sink character classes ----------------------------------------------------------

@pytest.mark.parametrize("slot,sink,value,msg", [
    ("authz_guard", "guard_text", "a", "shorter than 3"),                 # tiny substring = suppress everything
    ("authz_guard", "guard_text", "own\\er", "forbidden character"),
    ("authz_guard", "guard_text", "own`er", "forbidden character"),
    ("authz_guard", "guard_text", "$owner", "forbidden character"),
    ("authz_guard", "guard_text", "Is_Owner", "must be lower-case"),
    ("qty_terms", "token", "qty(", "does not match token class"),        # token is identifier-only
    ("qty_terms", "token", "Qty", "must be lower-case"),
    ("orm_read_calls", "call_name", "fetch.*", "does not match call_name class"),  # never a regex
    ("orm_read_calls", "call_name", "fetch one", "does not match call_name class"),
    ("sql_read_kw", "exec_sql_kw", "select", "must be upper-case"),
    ("id_param_suffix", "param_suffix", "_ID", "must be lower-case"),
    ("id_param_exact", "param_exact", "1id", "does not match param_exact class"),
])
def test_value_rejected(tmp_path, slot, sink, value, msg):
    eff, info = v.load(str(_write(tmp_path, _child(**{slot: {"sink": sink, "values": [value]}}))), allow_unlisted=True)
    assert eff is None
    assert any(msg in e for e in info["errors"]), info["errors"]


def test_sink_must_match_schema(tmp_path):
    """A pack cannot re-route a text token into the call_name accessor (or vice versa)."""
    bad = _child(orm_read_calls={"sink": "guard_text", "values": [".*"]})
    eff, info = v.load(str(_write(tmp_path, bad)), allow_unlisted=True)
    assert eff is None and any("sink must be 'call_name'" in e for e in info["errors"])


def test_unknown_slot_and_sink_rejected(tmp_path):
    eff, info = v.load(str(_write(tmp_path, _child(raw_scala={"sink": "guard_text", "values": ["x.l"]}))), allow_unlisted=True)
    assert eff is None and any("unknown slot" in e for e in info["errors"])
    eff, info = v.load(str(_write(tmp_path, _child(authz_guard={"sink": "regex", "values": ["own.*"]}))), allow_unlisted=True)
    assert eff is None and any("sink must be" in e for e in info["errors"])


def test_caps(tmp_path):
    many = _child(authz_guard={"sink": "guard_text", "values": [f"guard_{i:03d}" for i in range(65)]})
    eff, info = v.load(str(_write(tmp_path, many)), allow_unlisted=True)
    assert eff is None and any("exceeds cap 64" in e for e in info["errors"])
    big = _child(); big["description"] = "x" * 17000
    eff, info = v.load(str(_write(tmp_path, big)), allow_unlisted=True)
    assert eff is None and any("exceeds cap 16384" in e for e in info["errors"])


def test_cross_slot_rules(tmp_path):
    # an authz token inside an authn value would let "login_required" satisfy the authz guard
    p = _child(authz_guard={"sink": "guard_text", "values": ["login_req"]})
    eff, info = v.load(str(_write(tmp_path, p)), allow_unlisted=True)
    assert eff is None and any("substring of authn_only" in e for e in info["errors"])
    p = _child(qty_terms={"sink": "token", "values": ["price"]})
    eff, info = v.load(str(_write(tmp_path, p)), allow_unlisted=True)
    assert eff is None and any("overlap" in e for e in info["errors"])


def test_malformed_json_and_missing_parent(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    eff, info = v.load(str(bad), allow_unlisted=True)
    assert eff is None and "JSONDecodeError" in info["errors"][0]
    p = _child(); p["extends"] = "nonexistent"
    eff, info = v.load(str(_write(tmp_path, p)), allow_unlisted=True)
    assert eff is None and any("not found in packs" in e for e in info["errors"])


# ---- composition + hashing ---------------------------------------------------------------

def test_hash_is_order_independent(tmp_path):
    fl = json.loads(v.pack_path("flask-sqlite3").read_text(encoding="utf-8"))
    sh = copy.deepcopy(fl)
    for b in sh["slots"].values():
        b["values"] = list(reversed(b["values"])) + [b["values"][0]]      # reorder + duplicate
    sh["slots"] = dict(reversed(list(sh["slots"].items())))
    e1, i1 = v.load("flask-sqlite3")
    e2, i2 = v.load(str(_write(tmp_path, sh, "flask-sqlite3.json")), allow_unlisted=True)
    assert i1["sha256"] == i2["sha256"]
    assert i2["listed"]                                     # same content -> same digest -> listed


def test_child_only_adds_and_hash_changes(tmp_path):
    p = _child(id_param_suffix={"sink": "param_suffix", "values": ["_ref"]})
    eff, info = v.load(str(_write(tmp_path, p)), allow_unlisted=True)
    base, binfo = v.load("_base")
    assert "_ref" in eff["slots"]["id_param_suffix"]["values"]
    assert "_id" in eff["slots"]["id_param_suffix"]["values"]
    assert info["sha256"] != binfo["sha256"]
    assert not info["listed"]


def test_unlisted_refused_unless_allowed(tmp_path):
    p = _child(id_param_suffix={"sink": "param_suffix", "values": ["_ref"]})
    path = str(_write(tmp_path, p))
    eff, info = v.load(path)
    assert eff is None and "not in packs/digests.json" in info["errors"][0]
    eff, info = v.load(path, allow_unlisted=True)
    assert eff is not None and info["listed"] is False


# ---- resolution -----------------------------------------------------------------------

def test_resolve_from_requirements_then_imports(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.0\n", encoding="utf-8")
    assert v.resolve(str(tmp_path)) == ("flask-sqlite3", "flask in project metadata")
    d = tmp_path / "imp"; d.mkdir()
    (d / "views.py").write_text("from flask import Flask\n", encoding="utf-8")
    pid, why = v.resolve(str(d))
    assert pid == "flask-sqlite3" and "imported in 1 file" in why
    e = tmp_path / "plain"; e.mkdir()
    (e / "x.py").write_text("import os\n", encoding="utf-8")
    assert v.resolve(str(e)) == ("_base", "no known framework imported")


def test_resolve_django_without_a_shipped_pack_falls_to_base(tmp_path):
    """The Django pack is authored AFTER the Django testbed is frozen (held-out protocol, P6);
    until then a Django target must run on _base and say why, never on the Flask pack."""
    (tmp_path / "requirements.txt").write_text("django>=5\n", encoding="utf-8")
    pid, why = v.resolve(str(tmp_path))
    if v.pack_path("django").is_file():
        assert pid == "django"
    else:
        assert pid == "_base" and why == "django in project metadata"


def test_resolve_explicit_request_wins(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask\n", encoding="utf-8")
    assert v.resolve(str(tmp_path), "_base") == ("_base", "requested")
    assert v.resolve(str(tmp_path), "AUTO")[0] == "flask-sqlite3"


# ---- what reaches the Scala -------------------------------------------------------------

def test_prepare_pack_falls_back_to_base_with_reason(tmp_path, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "JOERN_PACK_ALLOW_UNLISTED", False)
    bad = _write(tmp_path, _child(authz_guard={"sink": "guard_text", "values": ["a"]}), "evil.json")
    pf, info = joern_scan.prepare_pack(str(tmp_path), str(bad), tmp_path)
    assert info["id"] == "_base" and "shorter than 3" in info["fallback"]
    assert pf is not None and json.loads(pf.read_bytes())["pack_id"] == "_base"
    assert info["tag"].startswith("_base@")


def test_prepare_pack_writes_canonical_composed_form(tmp_path):
    pf, info = joern_scan.prepare_pack(str(tmp_path), "flask-sqlite3", tmp_path)
    doc = json.loads(pf.read_bytes())
    assert doc["pack_id"] == "flask-sqlite3" and doc["chain"] == ["_base", "flask-sqlite3"]
    assert "fetchone" in doc["slots"]["orm_read_calls"]["values"]          # parent merged in
    assert doc["slots"]["orm_read_calls"]["values"] == sorted(set(doc["slots"]["orm_read_calls"]["values"]))
    assert info["tag"] == f"flask-sqlite3@{info['sha256'][:12]}"


def test_render_substitutes_pack_placeholders(tmp_path):
    r = joern_scan._render("C:/t", tmp_path / "f.tsv", tmp_path / "d.json", "p",
                           tmp_path / "pack.json", "flask-sqlite3@abc")
    for ph in ("__PACK_FILE__", "__BASE_PACK_FILE__", "__PACK_TAG__"):
        assert ph not in r
    assert 'val packTag      = "flask-sqlite3@abc"' in r
    assert "_base.json" in r


def test_rules_file_has_no_hardcoded_vocabulary():
    """The Scala holds rule SHAPES only. Every token list must come from a slot()."""
    src = joern_scan.RULES.read_text(encoding="utf-8")
    for tok in ('"is_owner"', '"login_required"', '"fetchone"', '"request.form"', '"whitelist"',
                '"select_for_update"', '"quantity"', 'nameExact("execute")', 'nameExact("setattr")'):
        assert tok not in src, f"hard-coded vocabulary in locators.sc: {tok}"
    for name in v.schema()["slots"]:
        assert f'slot("{name}")' in src, f"slot {name} never read by the Scala"
    # no regex-taking accessor anywhere: .name( / .code( / .filename( treat their argument as a
    # regex; the one deliberate regex is nameNot() on the synthetic-scope filter, which takes
    # literals, never a slot. Slot values reach nameExact(...: _*), contains, == and endsWith only.
    import re
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("//"))
    assert re.findall(r"\.(?:name|code|filename)\(", code) == []
    assert re.findall(r"nameNot\([^)]*slot\(", code) == []


def test_tsv_provenance_columns_reach_meta(tmp_path):
    row = "\t".join(["CWE-639", "high", "orders.py", "5", "get_order", "joern-idor-missing-ownership",
                     "msg", "ev", "flask-sqlite3@4a85ea8346ac", "id_param_suffix=_id;orm_read_calls=fetchone", "yes"])
    old = "\t".join(["CWE-639", "high", "orders.py", "5", "get_order", "joern-idor-missing-ownership", "msg", "ev"])
    fs = joern_scan._parse_tsv(row + "\n" + old + "\n", str(tmp_path))
    assert fs[0].meta == {"pack": "flask-sqlite3@4a85ea8346ac", "slots": "id_param_suffix=_id;orm_read_calls=fetchone", "route": "yes"}
    assert fs[1].meta == {}                                  # 8-column rows still parse
    assert "meta" in fs[0].to_dict()
