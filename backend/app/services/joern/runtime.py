"""
Joern runtime: find (or install) the JVM + joern-cli that the CPG phase needs.

The phase was dropped from RAMPART once for environment friction (a system JDK, a hard-coded
Adoptium path, a 1.8 GB download). This module removes all of it: a portable Temurin 21 JRE and
the joern-cli distribution live under <repo>/tools/, need no admin rights, touch neither PATH nor
the registry, and are installed by one command:

    python -m app.services.joern.runtime --install

Resolution order (first hit wins):
  1. JOERN_JAVA_HOME / JOERN_HOME environment variables (via config)
  2. <repo>/tools/jre-21*  and  <repo>/tools/joern-cli
  3. a `java` on PATH whose major version is 21 (joern-cli still has to be under tools/)

Joern requires JDK 21 ("other versions might work, but have not been properly tested").
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app import config

TOOLS = Path(config.FYP) / "tools"

# Adoptium's "latest GA" redirect for a portable Windows x64 JRE 21 (zip, no installer).
JRE_URL = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse"
# joern-cli distribution matching the version this project was measured with.
JOERN_VERSION = "4.0.589"
JOERN_ZIP_URL = f"https://github.com/joernio/joern/releases/download/v{JOERN_VERSION}/joern-cli.zip"

_RE_JAVA_MAJOR = re.compile(r'version "(\d+)')


@dataclass
class RuntimeInfo:
    java_home: Optional[Path] = None
    joern_home: Optional[Path] = None
    java_major: Optional[int] = None
    joern_version: Optional[str] = None
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems and self.java_home is not None and self.joern_home is not None

    @property
    def java_exe(self) -> Optional[Path]:
        if not self.java_home:
            return None
        return self.java_home / "bin" / ("java.exe" if os.name == "nt" else "java")

    @property
    def launcher(self) -> Optional[Path]:
        if not self.joern_home:
            return None
        bat = self.joern_home / "joern.bat"
        return bat if os.name == "nt" and bat.exists() else self.joern_home / "joern"

    def reason(self) -> str:
        return "; ".join(self.problems) if self.problems else ""


# --------------------------------------------------------------------------- #
# locate
# --------------------------------------------------------------------------- #

def _java_major(java_exe: Path) -> Optional[int]:
    try:
        p = subprocess.run([str(java_exe), "-version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = _RE_JAVA_MAJOR.search((p.stderr or "") + (p.stdout or ""))
    return int(m.group(1)) if m else None


def _find_portable_jre() -> Optional[Path]:
    """<tools>/jre-21 or any extracted Temurin dir (jdk-21.x.y+z-jre) containing bin/java."""
    if not TOOLS.exists():
        return None
    for cand in sorted(TOOLS.iterdir()):
        if not cand.is_dir():
            continue
        if cand.name.startswith(("jre-21", "jdk-21")) and (cand / "bin").exists():
            exe = cand / "bin" / ("java.exe" if os.name == "nt" else "java")
            if exe.exists():
                return cand
    return None


def _joern_version(joern_home: Path) -> Optional[str]:
    lib = joern_home / "lib"
    if not lib.exists():
        return None
    for jar in lib.glob("io.joern.joern-cli-*.jar"):
        m = re.search(r"joern-cli-([\d.]+)\.jar", jar.name)
        if m:
            return m.group(1)
    return None


def locate() -> RuntimeInfo:
    info = RuntimeInfo()

    # --- java ---
    env_java = os.environ.get("JOERN_JAVA_HOME", "").strip() or config.JOERN_JAVA_HOME
    cand: Optional[Path] = None
    if env_java and Path(env_java, "bin").exists():
        cand = Path(env_java)
    if cand is None:
        cand = _find_portable_jre()
    if cand is None:
        on_path = shutil.which("java")
        if on_path:
            cand = Path(on_path).resolve().parent.parent
    if cand is None:
        info.problems.append(f"no JRE 21 found (looked in JOERN_JAVA_HOME, {TOOLS}, PATH)")
    else:
        info.java_home = cand
        exe = info.java_exe
        major = _java_major(exe) if exe and exe.exists() else None
        info.java_major = major
        if major is None:
            info.problems.append(f"java at {exe} did not report a version")
        elif major != 21:
            info.problems.append(f"java at {exe} is major version {major}; Joern needs 21")

    # --- joern ---
    env_joern = os.environ.get("JOERN_HOME", "").strip() or config.JOERN_HOME
    jh = Path(env_joern) if env_joern else TOOLS / "joern-cli"
    if not jh.exists():
        jh = TOOLS / "joern-cli"
    if (jh / "joern.bat").exists() or (jh / "joern").exists():
        info.joern_home = jh
        info.joern_version = _joern_version(jh)
    else:
        info.problems.append(f"joern-cli not found at {jh}")

    return info


# --------------------------------------------------------------------------- #
# probe (cached per process; a cold JVM probe is slow)
# --------------------------------------------------------------------------- #

_PROBE: Optional[tuple[bool, str, RuntimeInfo]] = None


def probe(force: bool = False) -> tuple[bool, str, RuntimeInfo]:
    """Is Joern runnable right now? Returns (ok, reason, info). Cached after the first call."""
    global _PROBE
    if _PROBE is not None and not force:
        return _PROBE
    info = locate()
    if not info.ok:
        _PROBE = (False, info.reason(), info)
        return _PROBE
    env = dict(os.environ)
    env["JAVA_HOME"] = str(info.java_home)
    try:
        p = subprocess.run([str(info.launcher), "--help"], capture_output=True, text=True,
                           env=env, timeout=120, encoding="utf-8", errors="replace")
        if p.returncode != 0:
            tail = (p.stderr or p.stdout or "").strip().splitlines()[-3:]
            _PROBE = (False, f"joern --help exited {p.returncode}: {' | '.join(tail)}", info)
            return _PROBE
    except subprocess.TimeoutExpired:
        _PROBE = (False, "joern --help timed out (120s)", info)
        return _PROBE
    except OSError as e:
        _PROBE = (False, f"could not launch joern: {e}", info)
        return _PROBE
    _PROBE = (True, "", info)
    return _PROBE


def subprocess_env(info: RuntimeInfo) -> dict:
    env = dict(os.environ)
    if info.java_home:
        env["JAVA_HOME"] = str(info.java_home)
    if info.joern_home:
        # InstallConfig.rootPath resolves the install dir from the CodeSource of its own class,
        # which is null for REPL-compiled code - so importCode() NPEs in `--server` mode. The
        # env var is checked first and sidesteps it. Harmless in script mode.
        env["SHIFTLEFT_OCULAR_INSTALL_DIR"] = str(info.joern_home)
    return env


# --------------------------------------------------------------------------- #
# install
# --------------------------------------------------------------------------- #

def _download(url: str, dest: Path, log) -> None:
    import urllib.request
    log(f"  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "RAMPART-joern-runtime/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as fh:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
            done += len(chunk)
            if total:
                log(f"  ... {done * 100 // total}%", end="\r")
    log(f"  saved {dest.name} ({dest.stat().st_size // (1 << 20)} MB)")


def install(log=print) -> RuntimeInfo:
    """Idempotent: installs whichever of the JRE / joern-cli is missing under <repo>/tools/."""
    TOOLS.mkdir(parents=True, exist_ok=True)
    info = locate()

    if info.java_home is None or info.java_major != 21:
        log("[joern] installing portable Temurin 21 JRE")
        z = TOOLS / "jre-21.zip"
        _download(JRE_URL, z, log)
        with zipfile.ZipFile(z) as zf:
            top = sorted({n.split("/")[0] for n in zf.namelist()})
            zf.extractall(TOOLS)
        z.unlink(missing_ok=True)
        # normalise the versioned Temurin folder name to a stable path
        if len(top) == 1 and (TOOLS / top[0]).is_dir() and not (TOOLS / "jre-21").exists():
            (TOOLS / top[0]).rename(TOOLS / "jre-21")
        log("[joern] JRE ready")

    if info.joern_home is None:
        log(f"[joern] installing joern-cli {JOERN_VERSION}")
        z = TOOLS / "joern-cli.zip"
        _download(JOERN_ZIP_URL, z, log)
        with zipfile.ZipFile(z) as zf:
            zf.extractall(TOOLS)
        z.unlink(missing_ok=True)
        log("[joern] joern-cli ready")

    ok, why, info = probe(force=True)
    log(f"[joern] probe: {'OK' if ok else 'FAILED - ' + why}")
    if info.java_home:
        log(f"        java  : {info.java_home}  (major {info.java_major})")
    if info.joern_home:
        log(f"        joern : {info.joern_home}  (v{info.joern_version or '?'})")
    return info


def main(argv: list[str]) -> int:
    if "--install" in argv:
        info = install()
        return 0 if info.ok else 1
    ok, why, info = probe(force=True)
    print(f"joern runtime: {'OK' if ok else 'NOT READY - ' + why}")
    print(f"  java  : {info.java_home}  major={info.java_major}")
    print(f"  joern : {info.joern_home}  version={info.joern_version}")
    print("run with --install to fetch what is missing into tools/")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
