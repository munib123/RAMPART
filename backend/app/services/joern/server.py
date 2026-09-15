"""
Joern CPGQL server sidecar: one long-lived JVM per backend process instead of one per scan.

    joern --server --server-host 127.0.0.1 --server-port P
          --server-auth-username rampart --server-auth-password <random per process>

Each scan then costs the CPG build for its target plus the rule queries - not the ~10 s JVM
start and ~5 s script compilation that script mode pays every time. Queries go to
POST /query-sync {"query": ...} -> {"success": bool, "stdout": str, "stderr": str}, and each
request is compiled independently, which is what gives P3 its per-rule isolation: a compile
error in one rule section costs that rule, not the run.

Lifecycle
  ensure_started()   spawn if JOERN_SERVER allows and nothing is running; non-blocking
  wait_ready(t)      poll /query-sync with "1+1" until it answers, up to t seconds
  query(scala, t)    (ok, stdout, stderr)
  stop()             kill the PROCESS TREE. Popen.terminate() on joern.bat kills cmd.exe and
                     leaves the JVM alive holding the workspace; on Windows this uses
                     `taskkill /T /F`, on POSIX the process group.

Security: binds 127.0.0.1 only, Basic auth with a per-process random password, and every
query it ever receives is hand-written Scala from rules/*.sc. The Joern docs say the server
"does not implement sandboxing"; nothing generated reaches it. See docs/JOERN_PLAN.md.
"""
from __future__ import annotations

import atexit
import base64
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from app import config
from app.services.joern import runtime

_lock = threading.Lock()
_srv: Optional["JoernServer"] = None

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# /query-sync's "success" is HTTP success, not evaluation success: a compile error or a thrown
# exception comes back success=true with the diagnostic in stdout. These are the markers the
# Scala 3 REPL and Joern's console print for each; ok = no marker in the stripped output.
_FAIL = re.compile(
    r"(?m)^\s*(-- (\[E\d+\] )?[A-Za-z ]*Error:"                 # scala 3 compile error banner
    r"|\d+ errors? found"                              # scala 3 compile error summary
    r"|(?:[A-Za-z0-9_$]+\.)+[A-Za-z0-9_$]*(?:Exception|Error)(?::|\s*$)"   # thrown, fully-qualified
    r"|io\.joern\.console\.Error)")


def strip_ansi(s: str) -> str:
    return _ANSI.sub("", s or "")


def evaluation_failed(stdout: str) -> bool:
    return bool(_FAIL.search(strip_ansi(stdout)))


class JoernServer:
    def __init__(self, port: int):
        self.port = port
        self.user = "rampart"
        self.password = secrets.token_urlsafe(24)
        self.proc: Optional[subprocess.Popen] = None
        self.ready = False
        self.started_at: Optional[float] = None
        self.ready_at: Optional[float] = None
        self.cwd = runtime.TOOLS / "_rampart_joern_tmp" / "server"

    # ---- process ------------------------------------------------------------------

    def start(self, info: runtime.RuntimeInfo) -> None:
        self.cwd.mkdir(parents=True, exist_ok=True)
        args = [str(info.launcher), "--server",
                "--server-host", "127.0.0.1", "--server-port", str(self.port),
                "--server-auth-username", self.user, "--server-auth-password", self.password]
        kw: dict = dict(cwd=str(self.cwd), env=runtime.subprocess_env(info),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        if os.name == "nt":
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kw["start_new_session"] = True
        self.proc = subprocess.Popen(args, **kw)
        self.started_at = time.time()
        atexit.register(self.stop)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        p = self.proc
        if p is None:
            return
        self.proc = None
        self.ready = False
        if p.poll() is not None:
            return
        try:
            if os.name == "nt":
                # kill the tree: joern.bat -> cmd.exe -> java.exe. terminate() would only take cmd.
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            else:
                import signal
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    # ---- HTTP --------------------------------------------------------------------

    def _post(self, scala: str, timeout: float) -> tuple[bool, str, str]:
        body = json.dumps({"query": scala}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/query-sync", data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": "Basic " + base64.b64encode(
                         f"{self.user}:{self.password}".encode()).decode()})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8", errors="replace"))
        out = strip_ansi(d.get("stdout") or "")
        err = strip_ansi(d.get("stderr") or "")
        ok = bool(d.get("success")) and not evaluation_failed(out)
        return ok, out, err

    def query(self, scala: str, timeout: float) -> tuple[bool, str, str]:
        """Never raises: transport failures come back as (False, "", <reason>)."""
        try:
            return self._post(scala, timeout)
        except urllib.error.HTTPError as e:
            return False, "", f"HTTP {e.code}: {e.reason}"
        except Exception as e:
            return False, "", f"{type(e).__name__}: {e}"

    def wait_ready(self, timeout: float) -> bool:
        """Always probes at least once, so wait_ready(0) still notices a server that has come
        up since the last call (JOERN_SERVER_WAIT=0 is the default: don't block a scan on
        startup, but do use the sidecar as soon as it answers)."""
        if self.ready:
            return True
        deadline = time.time() + timeout
        while True:
            if not self.alive():
                return False
            ok, out, _ = self.query("1+1", timeout=5)
            if ok and "2" in out:
                self.ready = True
                self.ready_at = time.time()
                return True
            if time.time() >= deadline:
                return False
            time.sleep(0.5)


# ---- module API ---------------------------------------------------------------------

def mode() -> str:
    return (getattr(config, "JOERN_SERVER", "auto") or "auto").strip().lower()


def get() -> Optional[JoernServer]:
    return _srv


def ensure_started() -> Optional[JoernServer]:
    """Start the sidecar if the mode allows and the runtime is present. Non-blocking: returns
    the server object immediately; call wait_ready() (or let scan() do it) to know when it
    can take queries. Returns None when the sidecar is off or cannot start."""
    global _srv
    if mode() in ("off", "false", "0", "no"):
        return None
    with _lock:
        if _srv is not None and _srv.alive():
            return _srv
        ok, why, info = runtime.probe()
        if not ok:
            return None
        s = JoernServer(port=int(getattr(config, "JOERN_SERVER_PORT", 8091)))
        try:
            s.start(info)
        except Exception as e:
            print(f"[joern] server failed to start: {type(e).__name__}: {e}", file=sys.stderr)
            return None
        _srv = s
        print(f"[joern] server starting on 127.0.0.1:{s.port} (pid {s.proc.pid})", flush=True)
        return s


def ready(wait: float = 0.0) -> Optional[JoernServer]:
    """The server, if it is up and answering; otherwise None. `wait` bounds how long to give a
    starting server before falling back."""
    s = _srv
    if s is None or not s.alive():
        return None
    if s.ready or s.wait_ready(wait):
        return s
    return None


def stop() -> None:
    global _srv
    s = _srv
    _srv = None
    if s is not None:
        s.stop()
        print("[joern] server stopped", flush=True)


def status() -> dict:
    s = _srv
    if s is None:
        return {"mode": mode(), "running": False}
    running = s.alive()
    if running and not s.ready:
        s.wait_ready(0)                     # one cheap probe, so /health tells the truth
    now = time.time()
    return {"mode": mode(), "running": running, "ready": s.ready, "port": s.port,
            "pid": s.proc.pid if s.proc else None,
            "uptime_s": round(now - s.started_at, 1) if s.started_at else None,
            "startup_s": round(s.ready_at - s.started_at, 1) if s.ready_at and s.started_at else None}
