"""S5: target path policy - reject roots/system trees/huge trees before any subprocess.
Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_target_policy.py -q
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config                        # noqa: E402
from app.services import target_policy        # noqa: E402


def test_a_normal_project_is_allowed(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "views.py").write_text("x = 1\n", encoding="utf-8")

    ok, why = target_policy.check(str(tmp_path))
    assert ok is True, why


def test_missing_path_is_rejected(tmp_path):
    ok, why = target_policy.check(str(tmp_path / "nope"))
    assert ok is False
    assert "does not exist" in why


def test_filesystem_root_is_rejected():
    root = Path.cwd().anchor                 # "G:\\" on Windows, "/" on POSIX
    ok, why = target_policy.check(root)
    assert ok is False
    assert "filesystem root" in why


def test_windows_system_tree_is_rejected():
    if os.name != "nt":
        pytest.skip("Windows-only deny list")
    ok, why = target_policy.check(r"C:\Windows")
    assert ok is False
    assert "system directory" in why


def test_posix_system_tree_is_rejected():
    if os.name == "nt":
        pytest.skip("POSIX-only deny list")
    ok, why = target_policy.check("/etc")
    assert ok is False
    assert "system directory" in why


def test_file_cap_rejects_a_huge_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(target_policy, "MAX_FILES", 2)
    for i in range(3):
        (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")

    ok, why = target_policy.check(str(tmp_path))
    assert ok is False
    assert "more than 2 files" in why


def test_explicit_override_allows_system_trees(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_SYSTEM_TARGETS", True)
    ok, _why = target_policy.check(r"C:\Windows" if os.name == "nt" else "/etc")
    assert ok is True


def test_symlinked_project_resolves_before_the_check(tmp_path):
    if os.name == "nt":
        pytest.skip("symlink creation needs privileges on Windows")
    real = tmp_path / "real"
    real.mkdir()
    (real / "app.py").write_text("x = 1\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    ok, why = target_policy.check(str(link))
    assert ok is True, why
