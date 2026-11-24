"""S3: the tree fingerprint + on-disk raw-scan cache. No database, no scanner, no JVM.
Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_scan_fingerprint.py -q
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config                       # noqa: E402
from app.services import scan_cache          # noqa: E402


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setattr(config, "CACHE_DIR", d)
    monkeypatch.setattr(config, "SCAN_CACHE", True)
    return d


def _key(**kw) -> str:
    args = {"fingerprint": "fp", "target": "D:/proj", "scanner": "bandit",
            "scanner_config": "", "joern": "auto:True:auto", "rules_sha256": "rules"}
    args.update(kw)
    return scan_cache.cache_key(**args)


# ---- fingerprint ---------------------------------------------------------------------

def test_fingerprint_is_stable_and_notices_content_edits(tmp_path):
    t = tmp_path / "proj"
    t.mkdir()
    f = t / "app.py"
    f.write_text("x = 1\n", encoding="utf-8")

    fp1 = scan_cache.tree_fingerprint(str(t))
    assert fp1 and fp1 == scan_cache.tree_fingerprint(str(t))

    # Same size and the mtime forced back: only the content hash can see the edit.
    st = f.stat()
    f.write_text("x = 2\n", encoding="utf-8")
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert scan_cache.tree_fingerprint(str(t)) != fp1


def test_excluded_directories_do_not_change_the_fingerprint(tmp_path):
    t = tmp_path / "proj"
    t.mkdir()
    (t / "app.py").write_text("x = 1\n", encoding="utf-8")
    fp = scan_cache.tree_fingerprint(str(t))

    for d in ("node_modules", ".venv", ".git", "__pycache__", ".cache"):
        (t / d).mkdir()
        (t / d / "noise.bin").write_text("changed", encoding="utf-8")
    assert scan_cache.tree_fingerprint(str(t)) == fp


def test_single_file_target(tmp_path):
    f = tmp_path / "one.py"
    f.write_text("x = 1\n", encoding="utf-8")
    fp = scan_cache.tree_fingerprint(str(f))
    assert fp and fp == scan_cache.tree_fingerprint(str(f))
    f.write_text("x = 2\n", encoding="utf-8")
    assert scan_cache.tree_fingerprint(str(f)) != fp


def test_missing_path_is_an_empty_fingerprint(tmp_path):
    assert scan_cache.tree_fingerprint(str(tmp_path / "nope")) == ""


# ---- cache key -----------------------------------------------------------------------

def test_key_includes_every_input(tmp_path):
    base = _key()
    assert len(base) == 32
    variants = [
        _key(fingerprint="other"),
        _key(target="D:/other"),
        _key(scanner="semgrep"),
        _key(scanner_config="p/ci"),
        _key(joern="off:False:auto"),
        _key(rules_sha256="other-rules"),
    ]
    assert len({base, *variants}) == len(variants) + 1


# ---- load/store ----------------------------------------------------------------------

def test_cache_round_trip(cache_dir):
    key = _key()
    scan_cache.store(key, [{"tool": "bandit", "path": "D:/proj/a.py", "line": 1}],
                     {"used": False, "reason": "off"})

    hit = scan_cache.load(key)
    assert hit is not None
    assert hit["findings"][0]["line"] == 1
    assert hit["joern"]["reason"] == "off"
    assert (cache_dir / "scan" / f"{key}.json").is_file()


def test_expired_entry_is_a_miss_and_is_removed(cache_dir):
    key = _key()
    scan_cache.store(key, [], {})
    p = cache_dir / "scan" / f"{key}.json"
    old = time.time() - 2 * 24 * 3600
    os.utime(p, (old, old))

    assert scan_cache.load(key) is None
    assert not p.exists()


def test_corrupt_entry_is_a_miss(cache_dir):
    key = _key()
    p = cache_dir / "scan" / f"{key}.json"
    p.parent.mkdir(parents=True)
    p.write_text("{not json", encoding="utf-8")
    assert scan_cache.load(key) is None


def test_disabled_cache_writes_and_reads_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(config, "SCAN_CACHE", False)
    key = _key()

    scan_cache.store(key, [], {})
    assert not (tmp_path / "cache" / "scan").exists()
    assert scan_cache.load(key) is None


def test_clear_removes_entries(cache_dir):
    for fp in ("a", "b"):
        scan_cache.store(_key(fingerprint=fp), [], {})
    assert scan_cache.clear() == 2
    assert scan_cache.clear() == 0
