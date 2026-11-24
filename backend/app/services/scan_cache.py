"""S3: reuse the expensive raw scan phases when the target tree has not changed.

Only the two subprocess phases are cached: the pattern scanner's raw findings and Joern's
candidates + diag. Extract, RAG grounding and Gemini verification still run on every request,
so verdicts/exemplars are never stale. Stdlib only - no new dependency.

Key = (tree fingerprint, target, scanner, scanner config, Joern mode/pack, rules hash).
The fingerprint walks the tree with the scanners' excludes, hashing relpath + size + mtime_ns
for every file and the content of files < 256 KB, capped at 20,000 entries. A second scan of
an unchanged tree therefore skips semgrep/bandit and the JVM; editing any file (or touching a
rule/config) changes the key. Entries expire after 24 h; `POST /api/scan?fresh=1` bypasses
the read. `RAMPART_SCAN_CACHE=off` disables the whole module.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from app import config

CACHE_VERSION = 1
TTL_S = 24 * 60 * 60
MAX_ENTRIES = 20_000
CONTENT_HASH_LIMIT = 256 * 1024

# Same directories the scanners skip, plus this project's own local caches (scanning the repo
# root must not invalidate the cache every time RAMPART writes its own cache/history files).
EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__",
    ".cache", ".fix_snapshots", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}


def enabled() -> bool:
    return bool(config.SCAN_CACHE)


def _file_sha256(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.digest()


def _add_entry(h, rel: str, st: os.stat_result, path: Path | None) -> None:
    h.update(rel.encode("utf-8") + b"\0")
    h.update(f"{st.st_size}\0{st.st_mtime_ns}\0".encode("utf-8"))
    if path is not None and st.st_size < CONTENT_HASH_LIMIT:
        try:
            h.update(_file_sha256(path))
        except OSError:
            pass
    h.update(b"\0")


def tree_fingerprint(path: str) -> str:
    """Stable hash of a file/folder tree; "" when the path is missing or unreadable."""
    p = Path(path)
    h = hashlib.sha256()
    h.update(f"rampart-scan-v{CACHE_VERSION}\0".encode("utf-8"))
    try:
        if p.is_file():
            _add_entry(h, p.name, p.stat(), p)
            return h.hexdigest()
    except OSError:
        return ""
    if not p.is_dir():
        return ""

    seen, truncated = 0, False
    for root, dirs, files in os.walk(p):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS)
        for name in sorted(files):
            if seen >= MAX_ENTRIES:
                truncated = True
                break
            fp = Path(root) / name
            try:
                st = fp.stat()
            except OSError:
                continue
            try:
                rel = fp.relative_to(p).as_posix()
            except ValueError:
                continue
            _add_entry(h, rel, st, fp)
            seen += 1
        if truncated:
            break
    if truncated:
        h.update(b"\0truncated\0")
    return h.hexdigest()


def cache_key(fingerprint: str, target: str, scanner: str, scanner_config: str = "",
              joern: str = "", rules_sha256: str = "") -> str:
    """Opaque file name for one (tree, target, toolchain) combination. The absolute target is
    part of the key because cached findings carry absolute paths."""
    material = json.dumps(
        [CACHE_VERSION, fingerprint, os.path.abspath(target), scanner,
         scanner_config or "", joern or "", rules_sha256 or ""],
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _entry_path(key: str) -> Path:
    return config.CACHE_DIR / "scan" / f"{key}.json"


def load(key: str) -> dict | None:
    """The cached payload, or None on a miss/expiry/corrupt entry. Never raises."""
    if not enabled() or not key:
        return None
    p = _entry_path(key)
    try:
        if time.time() - p.stat().st_mtime > TTL_S:
            p.unlink(missing_ok=True)
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("version") != CACHE_VERSION or data.get("key") != key:
        return None
    return data


def store(key: str, findings: list[dict], joern: dict) -> None:
    """Write one entry atomically. A cache failure must never break a scan, so it is silent."""
    if not enabled() or not key:
        return
    payload = {
        "version": CACHE_VERSION,
        "key": key,
        "created_at": int(time.time()),
        "findings": findings,
        "joern": joern,
    }
    p = _entry_path(key)
    tmp = p.with_name(f"{key}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
    except Exception as e:                     # a cache write must never break a scan
        print(f"[scan-cache] write failed: {type(e).__name__}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def clear() -> int:
    """Delete every cached entry; returns how many files were removed."""
    d = config.CACHE_DIR / "scan"
    removed = 0
    try:
        for p in d.glob("*.json"):
            try:
                p.unlink()
                removed += 1
            except OSError:
                pass
    except OSError:
        pass
    return removed
