"""The held-out protocol, enforced: a frozen testbed's tree must still hash to what FREEZE.json
recorded. If this fails, a testbed was edited after it was frozen - re-freeze in a reviewed
commit that bumps the key version, or restore the tree."""
from __future__ import annotations

import json

import pytest

from bench import freeze, paths


@pytest.mark.parametrize("benchmark", freeze.frozen_benchmarks() or ["<none frozen>"])
def test_frozen_tree_unchanged(benchmark):
    if benchmark == "<none frozen>":
        pytest.skip("no frozen testbed")
    ok, why = freeze.check(benchmark)
    assert ok, f"{benchmark}: {why}"


def test_freeze_hash_ignores_line_endings_and_freeze_file(tmp_path):
    (tmp_path / "a.py").write_bytes(b"x = 1\ny = 2\n")
    h1, n1 = freeze.tree_sha256(tmp_path)
    (tmp_path / "a.py").write_bytes(b"x = 1\r\ny = 2\r\n")
    (tmp_path / freeze.FREEZE).write_text("{}")
    h2, n2 = freeze.tree_sha256(tmp_path)
    assert h1 == h2 and n1 == n2 == 1
    (tmp_path / "a.py").write_bytes(b"x = 1\ny = 3\n")
    assert freeze.tree_sha256(tmp_path)[0] != h1


def test_django_splits_are_frozen_and_labelled():
    """Both halves of the Django testbed carry a split label; the held-out half says so."""
    for bench, split in (("djshop-dev", "dev"), ("djshop-heldout", "held_out")):
        doc = freeze.read(bench)
        assert doc is not None, f"{bench} is not frozen"
        assert doc["split"] == split
        rows = [json.loads(l) for l in open(paths.key_file(bench), encoding="utf-8") if l.strip()]
        assert rows and all(r["split"] == split for r in rows)
        assert any(r["label"] == "safe" and r.get("twin_of") for r in rows), "fixed twins must be safe rows"


def test_freeze_hash_is_the_same_on_every_os(tmp_path):
    """sorted(Path) is case-insensitive on Windows and case-sensitive on POSIX, so the same tree
    once hashed differently per OS (README.md sorts before shop/ on Linux, after it on Windows).
    The order key is fixed: Windows order, case-folded, backslash-joined - the order every
    committed FREEZE.json was computed with."""
    import hashlib
    (tmp_path / "shop").mkdir()
    for rel in ("README.md", "shop/views.py", "manage.py", "Zeta.txt"):
        (tmp_path / rel).write_text(rel, encoding="utf-8")
    h = hashlib.sha256()
    for rel in ("manage.py", "README.md", "shop/views.py", "Zeta.txt"):     # case-folded order
        h.update(rel.encode() + b"\0" + hashlib.sha256(rel.encode()).digest())
    assert freeze.tree_sha256(tmp_path) == (h.hexdigest(), 4)
