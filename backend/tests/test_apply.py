"""Unit tests for backend/app/services/apply.py (snapshot / apply / revert).
Pure-local: no DB, no LLM, no network. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_apply.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import apply as apply_svc  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_snapshot_dir(tmp_path, monkeypatch):
    """Point the snapshot store at a temp dir for every test."""
    from app import config
    monkeypatch.setattr(config, "FIX_SNAPSHOT_DIR", tmp_path / "snapshots")


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def test_apply_replaces_slice():
    src = Path.cwd() / "applyp_t1.py"
    _write(src, "def f():\n    ok = 1\n    bad = 2\n    return ok\n")
    try:
        r = apply_svc.apply_fix(str(src), 3, 3, "    good = 3", original_code="    bad = 2")
        assert r["ok"], r
        assert Path(str(src)).read_text(encoding="utf-8") == "def f():\n    ok = 1\n    good = 3\n    return ok\n"
        assert r["original_code"] == "    bad = 2"
        assert r["new_code"] == "    good = 3"
    finally:
        src.unlink(missing_ok=True)


def test_apply_preserves_crlf():
    src = Path.cwd() / "applyp_t2.py"
    _write(src, "def f():\r\n    a = 1\r\n    b = 2\r\n")
    try:
        r = apply_svc.apply_fix(str(src), 3, 3, "    b = 22", original_code="    b = 2")
        assert r["ok"], r
        assert Path(str(src)).read_bytes() == b"def f():\r\n    a = 1\r\n    b = 22\r\n"
    finally:
        src.unlink(missing_ok=True)


def test_apply_reindents_column0_rewrite():
    src = Path.cwd() / "applyp_t3.py"
    _write(src, "def f():\n    x = 1\n    return x\n")
    try:
        # LLM emits the replacement at column 0; should be re-indented to the slice's base (4).
        r = apply_svc.apply_fix(str(src), 2, 2, "x = 99", original_code="    x = 1")
        assert r["ok"], r
        text = Path(str(src)).read_text(encoding="utf-8")
        assert "    x = 99" in text
        assert "\nx = 99" not in text
    finally:
        src.unlink(missing_ok=True)


def test_apply_content_guard_refuses_changed_file():
    src = Path.cwd() / "applyp_t4.py"
    _write(src, "line one\nline two\n")
    try:
        r = apply_svc.apply_fix(str(src), 1, 1, "changed", original_code="completely different")
        assert not r["ok"]
        assert r["code"] == "file_changed"
        # file untouched
        assert Path(str(src)).read_text(encoding="utf-8") == "line one\nline two\n"
    finally:
        src.unlink(missing_ok=True)


def test_snapshot_idempotent_and_revert_dir(tmp_path):
    target = tmp_path / "code"
    (target / "src").mkdir(parents=True)
    _write(target / "src" / "a.py", "def a(): pass\n")
    _write(target / "src" / "b.txt", "b\n")
    (target / ".git").mkdir()
    _write(target / ".git" / "keep", "should-be-skipped")

    snap = apply_svc.snapshot_target("scan-1", str(target))
    assert snap["ok"], snap
    assert not snap["already"]
    # idempotent
    snap2 = apply_svc.snapshot_target("scan-1", str(target))
    assert snap2["ok"] and snap2["already"]
    # .git excluded from the copy
    tree = Path(snap["path"]) / "tree"
    assert (tree / "src" / "a.py").is_file()
    assert not (tree / ".git").exists()

    # user code changes, then revert restores byte-for-byte
    (target / "src" / "a.py").write_text("def a(): return 99\n", encoding="utf-8")
    (target / "src" / "b.txt").unlink()
    rev = apply_svc.revert_snapshot("scan-1", str(target))
    assert rev["ok"], rev
    assert (target / "src" / "a.py").read_text(encoding="utf-8") == "def a(): pass\n"
    assert (target / "src" / "b.txt").is_file()


def test_snapshot_single_file(tmp_path):
    target = tmp_path / "main.py"
    _write(target, "print('hi')\n")
    snap = apply_svc.snapshot_target("scan-file", str(target))
    assert snap["ok"], snap
    target.write_text("def f(): pass\n", encoding="utf-8")
    rev = apply_svc.revert_snapshot("scan-file", str(target))
    assert rev["ok"], rev
    assert target.read_text(encoding="utf-8") == "print('hi')\n"


def test_revert_missing_snapshot_returns_no_snapshot(tmp_path):
    r = apply_svc.revert_snapshot("nope", str(tmp_path))
    assert not r["ok"]
    assert r["code"] == "no_snapshot"