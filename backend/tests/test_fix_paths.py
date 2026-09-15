"""Path containment for /api/fix/apply, /revert and /verify: owning a scan row must never turn
into a write outside that scan's target. Pure helper tests - no DB, no server, no symlinks
(the helper resolves them; these pin the '..' and sibling cases that need no OS support).
Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_fix_paths.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.routers import fix as fix_router                 # noqa: E402


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """<tmp>/target/app/orders.py plus a sibling <tmp>/target-evil/ that shares the prefix."""
    t = tmp_path / "target"
    (t / "app").mkdir(parents=True)
    (t / "app" / "orders.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "target-evil").mkdir()
    (tmp_path / "target-evil" / "orders.py").write_text("x = 1\n", encoding="utf-8")
    return t


# ---- within_target -------------------------------------------------------------------

def test_inside_path_accepted(tree: Path):
    assert fix_router.within_target(str(tree / "app" / "orders.py"), str(tree))
    assert fix_router.within_target(str(tree / "app" / "new_file.py"), str(tree))    # need not exist yet


def test_single_file_target_is_its_own_container(tree: Path):
    f = tree / "app" / "orders.py"
    assert fix_router.within_target(str(f), str(f))
    assert not fix_router.within_target(str(tree / "app" / "other.py"), str(f))


def test_sibling_directory_rejected(tree: Path):
    """A prefix match on the string is not containment: target-evil/ starts with target."""
    evil = tree.parent / "target-evil" / "orders.py"
    assert str(evil).startswith(str(tree))
    assert not fix_router.within_target(str(evil), str(tree))


def test_dotdot_traversal_rejected(tree: Path):
    for p in (tree / "app" / ".." / ".." / "target-evil" / "orders.py",
              tree / ".." / "target-evil" / "orders.py",
              tree / "app" / ".." / ".." / ".." / "etc" / "passwd"):
        assert not fix_router.within_target(str(p), str(tree)), p


def test_dotdot_that_stays_inside_is_fine(tree: Path):
    assert fix_router.within_target(str(tree / "app" / ".." / "app" / "orders.py"), str(tree))


def test_relative_path_is_resolved_against_cwd_not_target(tree: Path, monkeypatch):
    """A bare 'app/orders.py' resolves against the process cwd - only inside when cwd IS the target."""
    monkeypatch.chdir(tree.parent)
    assert not fix_router.within_target("app/orders.py", str(tree))
    monkeypatch.chdir(tree)
    assert fix_router.within_target("app/orders.py", str(tree))


@pytest.mark.parametrize("path,target", [
    ("", "C:/t"), (None, "C:/t"), ("C:/t/a.py", ""), ("C:/t/a.py", None), ("", ""),
])
def test_empty_inputs_rejected(path, target):
    assert not fix_router.within_target(path, target)


# ---- same_target (revert) -------------------------------------------------------------

def test_revert_target_omitted_or_equal_accepted(tree: Path):
    assert fix_router.same_target(None, str(tree))
    assert fix_router.same_target("", str(tree))
    assert fix_router.same_target(str(tree), str(tree))
    assert fix_router.same_target(str(tree / "app" / ".."), str(tree))                # resolved equality
    assert fix_router.same_target(str(tree).replace("\\", "/"), str(tree))            # separator-insensitive


def test_revert_target_redirect_rejected(tree: Path):
    assert not fix_router.same_target(str(tree.parent / "target-evil"), str(tree))
    assert not fix_router.same_target(str(tree / "app"), str(tree))                   # a subdir is not the target
    assert not fix_router.same_target(str(tree.parent), str(tree))                    # nor its parent
    assert not fix_router.same_target(str(tree), None)                                # scan row without a target


def test_forbidden_payload_shape():
    assert fix_router._FORBIDDEN == {"ok": False, "code": "forbidden",
                                     "error": "path is outside the scanned target"}
