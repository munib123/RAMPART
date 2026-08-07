"""
Pluggable static-analysis layer.

`BanditScanner` (pure-Python, works on this locked-down box) is the default; `SemgrepScanner`
is wired but blocked here by Windows Application Control (WinError 4551) - it drops in
unchanged on a machine without that policy (Docker / WSL / CI).

Both emit the same normalized Finding shape so the rest of the pipeline is scanner-agnostic.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    path: str
    line: int
    end_line: int
    severity: str          # low | medium | high | critical
    confidence: str        # low | medium | high
    cwe_id: str            # "CWE-89" or ""
    message: str
    def to_dict(self):
        return asdict(self)


_BANDIT_SEV = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


class BanditScanner:
    name = "bandit"

    def available(self) -> tuple[bool, str]:
        try:
            subprocess.run([sys.executable, "-m", "bandit", "--version"],
                           capture_output=True, text=True, timeout=60)
            return True, ""
        except Exception as e:  # pragma: no cover
            return False, str(e)

    def scan(self, path: str) -> list[Finding]:
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "bandit", "-r", path, "-f", "json",
                 "-x", "**/node_modules/**,**/.venv/**,**/venv/**,**/.git/**,**/dist/**,**/build/**,**/__pycache__/**"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("bandit timed out after 10 minutes. Try a smaller folder.")
        # bandit exits 1 when it FINDS issues - that's not an error.
        if not proc.stdout.strip():
            raise RuntimeError(f"bandit produced no output: {proc.stderr[:400]}")
        data = json.loads(proc.stdout)
        out = []
        for r in data.get("results", []):
            cwe = r.get("issue_cwe") or {}
            cwe_id = f"CWE-{cwe['id']}" if cwe.get("id") else ""
            out.append(Finding(
                tool="bandit",
                rule_id=r.get("test_id", ""),
                title=r.get("test_name", r.get("test_id", "")),
                path=r.get("filename", ""),
                line=int(r.get("line_number", 0) or 0),
                end_line=int((r.get("line_range") or [r.get("line_number", 0)])[-1] or 0),
                severity=_BANDIT_SEV.get((r.get("issue_severity") or "").upper(), "low"),
                confidence=(r.get("issue_confidence") or "").lower() or "low",
                cwe_id=cwe_id,
                message=(r.get("issue_text") or "").strip(),
            ))
        return out


_SEMGREP_SETUP = (
    "semgrep runs natively from the project virtual environment (backend\\.venv). "
    "Install it with: `backend\\.venv\\Scripts\\python -m pip install semgrep`. "
    "It must be launched with that venv's python (or exposed on PATH) so the exe is found."
)

# Local semgrep has no WSL idle cold-start; cache availability once confirmed so we never
# re-probe (and never falsely report "unavailable").
_SEMGREP_OK = None


def _semgrep_exe() -> Optional[str]:
    """Locate the semgrep executable installed in the project virtual environment.

    Tries (in order): the sibling of the active interpreter's executable (i.e. the active venv's
    Scripts/bin dir), the project's backend/.venv regardless of which python launched the app, and
    finally whatever `semgrep` resolves to on PATH.
    """
    candidates = []
    exe_dir = Path(sys.executable).parent
    for name in ("semgrep.exe", "semgrep"):
        candidates.append(exe_dir / name)
    venv_dir = Path(__file__).resolve().parent / ".venv"
    for sub in ("Scripts", "bin"):
        candidates.append(venv_dir / sub / "semgrep.exe")
        candidates.append(venv_dir / sub / "semgrep")
    for c in candidates:
        try:
            if c.is_file():
                return str(c)
        except OSError:
            continue
    return shutil.which("semgrep")


_SEV_MAP_SEMGREP = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
                    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def parse_semgrep_json(data: dict, win_root: str = "") -> list["Finding"]:
    """Map semgrep --json output to normalized Findings (host-agnostic, unit-testable)."""
    import os
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe")
        cwe_id = ""
        raw = cwe[0] if isinstance(cwe, list) and cwe else (cwe if isinstance(cwe, str) else "")
        if raw:
            cwe_id = raw.split(":")[0].strip()          # "CWE-79: ..." -> "CWE-79"
        # semgrep reports a path; it is already a host path when run natively (venv),
        # or a WSL path (/mnt/d/...) if ever run through WSL - translate the latter back.
        wsl_path = r.get("path", "")
        host_path = wsl_path
        if wsl_path.startswith("/mnt/") and len(wsl_path) > 6:
            host_path = wsl_path[5].upper() + ":" + wsl_path[6:].replace("/", "\\")
        out.append(Finding(
            tool="semgrep",
            rule_id=r.get("check_id", "").split(".")[-1],
            title=r.get("check_id", "").split(".")[-1],
            path=host_path,
            line=int(r.get("start", {}).get("line", 0) or 0),
            end_line=int(r.get("end", {}).get("line", 0) or 0),
            severity=_SEV_MAP_SEMGREP.get((extra.get("severity") or "INFO").upper(), "low"),
            confidence=(meta.get("confidence") or "medium").lower(),
            cwe_id=cwe_id,
            message=(extra.get("message") or "").strip(),
        ))
    return out


class SemgrepScanner:
    """Runs semgrep's Linux engine via WSL (Windows SAC can't block a binary inside WSL)."""
    name = "semgrep"

    def __init__(self, semgrep_config: str = "auto"):
        self.config = semgrep_config

    def available(self) -> tuple[bool, str]:
        global _SEMGREP_OK
        if _SEMGREP_OK:                       # confirmed once this process -> instant, no re-probe
            return True, ""
        ok, why = self._probe()
        if ok:
            _SEMGREP_OK = True
        return ok, why

    def _probe(self) -> tuple[bool, str]:
        # is semgrep installed in the project venv / on PATH?
        exe = _semgrep_exe()
        if not exe:
            return False, "semgrep not installed. " + _SEMGREP_SETUP
        try:
            v = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60)
            if v.returncode == 0 and v.stdout.strip():
                return True, ""
            return False, f"semgrep failed to start: {v.stderr[:200]}"
        except subprocess.TimeoutExpired:
            return False, "semgrep is slow to start (cold). Try again in a moment."
        except Exception as e:
            return False, f"{type(e).__name__}: {e}. " + _SEMGREP_SETUP

    def scan(self, path: str) -> list[Finding]:
        exe = _semgrep_exe()
        if not exe:
            raise RuntimeError("semgrep not installed. " + _SEMGREP_SETUP)
        try:
            proc = subprocess.run(
                [exe, "scan", "--config", self.config, "--json", "--quiet",
                 "--exclude", "node_modules", "--exclude", ".venv", "--exclude", "venv",
                 "--exclude", ".git", "--exclude", "dist", "--exclude", "build",
                 "--exclude", "__pycache__", path],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=900,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("semgrep timed out after 15 minutes. Try a smaller folder, or select Bandit.")
        if not proc.stdout.strip():
            raise RuntimeError(f"semgrep produced no output: {proc.stderr[:400]}")
        # be tolerant of any leading banner: grab the JSON object
        text = proc.stdout
        i = text.find("{")
        data = json.loads(text[i:] if i > 0 else text)
        return parse_semgrep_json(data)


_SCANNERS = {"bandit": BanditScanner, "semgrep": SemgrepScanner}


def get_scanner(name: str):
    """`auto` = semgrep (multi-language) if runnable, else bandit (python)."""
    if name == "auto":
        sg = SemgrepScanner()
        return sg if sg.available()[0] else BanditScanner()
    if name not in _SCANNERS:
        raise ValueError(f"unknown scanner '{name}'. known: {', '.join(_SCANNERS)}, auto")
    return _SCANNERS[name]()
