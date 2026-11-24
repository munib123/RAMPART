"""Target path policy for scans (S5).

``POST /api/scan`` is anonymous by default and runs local subprocesses. Without a policy any
existing path is fair game - a drive root, ``C:\\Windows``, ``/etc`` - which is both a CPU/time
sink and a way to read machine layout into a report. This module refuses:

* paths that do not exist (resolved with symlinks followed),
* filesystem / drive roots,
* OS and system-program trees (Windows/Program Files/ProgramData; /etc, /usr, ...),
* targets with more than ``MAX_FILES`` files (walk is bounded, scanner excludes are skipped).

``RAMPART_ALLOW_SYSTEM_TARGETS=1`` overrides everything for an operator who really means it.
Pure stdlib, no subprocess; safe to call before the scanner starts.
"""
from __future__ import annotations

import os
from pathlib import Path

from app import config

MAX_FILES = 20_000

# Same trees the scanners exclude; used only to make the file-count walk cheap.
_SKIP_DIRS = {
    "node_modules", ".venv", "venv", ".git", "dist", "build",
    "__pycache__", ".cache", ".fix_snapshots", ".mypy_cache", ".pytest_cache",
}


def _norm(value: Path | str) -> str:
    return os.path.normcase(os.path.abspath(str(value)))


def _within(child: Path, root: Path) -> bool:
    """True when ``child`` is ``root`` or lives below it (case-insensitive on Windows)."""
    c, r = _norm(child), _norm(root).rstrip("\\/")
    return c == r or c.startswith(r + os.sep)


def _is_root(path: Path) -> bool:
    try:
        return path.parent == path
    except (OSError, RuntimeError):
        return False


def _protected_roots() -> list[Path]:
    if os.name == "nt":
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        roots = [
            Path(drive + "Windows"),
            Path(drive + "Program Files"),
            Path(drive + "Program Files (x86)"),
            Path(drive + "ProgramData"),
        ]
        system_root = os.environ.get("SystemRoot")
        if system_root:
            roots.append(Path(system_root))
        return roots
    return [Path(p) for p in (
        "/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys",
        "/System", "/Library", "/private/etc", "/private/var",
    )]


def count_files(path: Path, limit: int = MAX_FILES) -> int:
    """Count regular files below ``path``, stopping once ``limit`` is exceeded."""
    total = 0
    for _root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        total += len(files)
        if total > limit:
            return total
    return total


def check(path: str) -> tuple[bool, str]:
    """Return ``(allowed, reason)``. ``reason`` is empty when the target is acceptable."""
    if config.ALLOW_SYSTEM_TARGETS:
        return True, ""
    if not path or not str(path).strip():
        return False, "path is required"
    try:
        resolved = Path(str(path)).expanduser().resolve(strict=True)
    except FileNotFoundError:
        return False, f"path does not exist: {path}"
    except (OSError, RuntimeError) as e:
        return False, f"path is not accessible: {e}"

    if _is_root(resolved):
        return False, "refusing to scan a filesystem root; pick a project folder"

    for root in _protected_roots():
        try:
            root = root.resolve()
        except (OSError, RuntimeError):
            pass
        if _within(resolved, root):
            return False, f"refusing to scan a system directory ({root})"

    if resolved.is_dir():
        count = count_files(resolved)
        if count > MAX_FILES:
            return False, (f"target has more than {MAX_FILES:,} files; "
                           "scan a subfolder instead")
    return True, ""
