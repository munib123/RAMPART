"""Local apply/revert safety net for LLM-generated fixes.

Three pure-local operations (no DB, no network, no LLM):
  - snapshot_target: copy the whole scanned target (folder or single file) into
    backend/.fix_snapshots/<scan_id>/ at the moment of the FIRST Apply for a scan.
  - apply_fix: replace the vulnerable slice (start_line..end_line) with the LLM's
    fixed_code, re-indented to match, preserving the file's EOL style.
  - revert_snapshot: restore the target from that snapshot (the durable undo).

All three run in worker threads (blocking IO) from the router.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from app import config

# Mirror the scanner exclude globs so the snapshot copy stays small and fast.
_SKIP_DIRS = {
    "__pycache__", ".git", ".hg", ".svn", "node_modules", "venv", ".venv",
    "dist", "build", ".toctree", "site-packages",
}
_META_FILE = ".snapshot_meta.json"


def _ignore_copy(adir: str, names: list[str]) -> set[str]:
    return {n for n in names if n in _SKIP_DIRS}


# --------------------------------------------------------------------------- #
# Snapshot
# --------------------------------------------------------------------------- #

def _snapshot_dir(scan_id: str) -> Path:
    return config.FIX_SNAPSHOT_DIR / str(scan_id)


def snapshot_target(scan_id: str, target_path: str) -> dict:
    """Copy the whole scanned target under .fix_snapshots/<scan_id>/. Idempotent: the
    first Apply of a scan owns the snapshot. Returns {ok, already, path, target} or {ok:False,error}."""
    dest_dir = _snapshot_dir(scan_id)
    if dest_dir.exists():
        return {"ok": True, "already": True, "path": str(dest_dir), "target": target_path}

    src = Path(target_path)
    if not src.exists():
        return {"ok": False, "error": f"snapshot source does not exist: {target_path}"}

    try:
        dest_dir.mkdir(parents=True, exist_ok=False)
        is_file = src.is_file()
        if is_file:
            shutil.copy2(src, dest_dir / src.name)
            meta = {"kind": "file", "target": str(src.resolve()), "filename": src.name}
        else:
            shutil.copytree(src, dest_dir / "tree", ignore=_ignore_copy, dirs_exist_ok=False)
            meta = {"kind": "dir", "target": str(src.resolve())}
        (dest_dir / _META_FILE).write_text(json.dumps(meta), encoding="utf-8")
        return {"ok": True, "already": False, "path": str(dest_dir), "target": str(src.resolve())}
    except OSError as e:
        shutil.rmtree(dest_dir, ignore_errors=True)
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# --------------------------------------------------------------------------- #
# Apply
# --------------------------------------------------------------------------- #

def _read_file(path: str) -> tuple[list[str], str, bool]:
    """Return (stripped lines, detected eol, ended_with_newline)."""
    text = Path(path).read_text(encoding="utf-8", errors="replace", newline="")
    eol = "\r\n" if "\r\n" in text else "\n"
    raw = text.split("\n")
    ended = bool(raw) and raw[-1] == ""
    if ended:
        raw.pop()
    lines = [l[:-1] if l.endswith("\r") else l for l in raw]
    return lines, eol, ended


def _write_file(path: str, lines: list[str], eol: str, ended: bool):
    text = eol.join(lines)
    if ended:
        text += eol
    Path(path).write_text(text, encoding="utf-8", newline="")


def _reindent(fixed_lines: list[str], region: list[str]) -> list[str]:
    """Restore the original surrounding indentation: LLM rewrites are commonly emitted
    at column 0. base = min leading whitespace of non-empty original slice lines; every
    non-blank fixed line shallower than base gets base prefixed."""
    non_empty = [l for l in region if l.strip()]
    if not non_empty:
        return fixed_lines
    base = min(len(l) - len(l.lstrip(" \t")) for l in non_empty)
    if base <= 0:
        return fixed_lines
    prefix = " " * base
    out = []
    for l in fixed_lines:
        if not l.strip():
            out.append(l)
        elif len(l) - len(l.lstrip(" \t")) < base:
            out.append(prefix + l)
        else:
            out.append(l)
    return out


def apply_fix(path: str, start_line: int, end_line: int, fixed_code: str,
              original_code: str | None = None) -> dict:
    """Replace lines [start_line, end_line] (1-based, inclusive) with fixed_code.

    Guard: when original_code is given, the region must still match it — otherwise refuse
    (covers stale lines after another fix in the same file, and edits made outside RAMPART).
    Preserves the file's EOL style. Never touches anything outside the slice.
    """
    try:
        lines, eol, ended = _read_file(path)
    except OSError as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    region = lines[start_line - 1:end_line]
    if original_code is not None and "\n".join(region) != original_code:
        return {"ok": False, "code": "file_changed",
                "error": "file changed since scan — re-scan to refresh"}

    fixed_lines = _reindent((fixed_code or "").split("\n"), region)
    new_lines = lines[:start_line - 1] + fixed_lines + lines[end_line:]

    try:
        _write_file(path, new_lines, eol, ended)
    except OSError as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    return {
        "ok": True,
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "original_code": "\n".join(region) or "",
        "new_code": "\n".join(fixed_lines) or "",
    }


# --------------------------------------------------------------------------- #
# Revert
# --------------------------------------------------------------------------- #

def revert_snapshot(scan_id: str, target_path: str) -> dict:
    """Restore the target from the snapshot taken at first Apply. {ok, restored_from, target}.
    Missing snapshot -> {ok:False, code:'no_snapshot'}."""
    dest_dir = _snapshot_dir(scan_id)
    if not dest_dir.exists():
        return {"ok": False, "code": "no_snapshot", "error": "no snapshot for this scan"}
    meta_path = dest_dir / _META_FILE
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"ok": False, "error": "snapshot metadata missing or corrupt"}

    target = Path(meta.get("target") or target_path)
    try:
        if meta.get("kind") == "file":
            src_file = dest_dir / meta.get("filename", target.name)
            if not src_file.is_file():
                return {"ok": False, "error": "snapshot file missing"}
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, target)
        else:
            tree = dest_dir / "tree"
            if not tree.is_dir():
                return {"ok": False, "error": "snapshot tree missing"}
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(tree, target, ignore=_ignore_copy, dirs_exist_ok=True)
        return {"ok": True, "restored_from": str(dest_dir), "target": str(target)}
    except OSError as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}