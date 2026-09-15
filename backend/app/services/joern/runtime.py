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

Platforms. The installer picks the joern release asset and the Adoptium JRE for the host:
windows-x86_64, linux-x86_64, linux-arm64, macos-x86_64, macos-arm64 (joern publishes nothing
else). Only Windows x64 has been exercised end to end; on Linux/macOS the JRE arrives as a
tar.gz and the zip's unix mode bits are restored after extraction, but neither has been run on
real hardware yet. The joern zip is verified against the release's published .sha512 and
refused on mismatch. If the download cannot be fetched (proxy, offline), place
`joern-cli-<os>-<arch>.zip` and its `.sha512` by hand in tools/ and re-run --install.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app import config

TOOLS = Path(config.FYP) / "tools"

# Adoptium's "latest GA" redirect for a portable JRE 21 (no installer). {os} is
# windows|linux|mac, {arch} is x64|aarch64; Windows ships a zip, the others a tar.gz.
_ADOPTIUM_URL = "https://api.adoptium.net/v3/binary/latest/21/ga/{os}/{arch}/jre/hotspot/normal/eclipse"
# joern-cli distribution matching the version this project was measured with. The release
# assets are per-platform (joern-cli-<os>-<arch>.zip) with a sibling <asset>.sha512.
JOERN_VERSION = "4.0.589"
_JOERN_RELEASE_URL = f"https://github.com/joernio/joern/releases/download/v{JOERN_VERSION}/"

# platform.system() / platform.machine() -> (joern os, joern arch, adoptium os, adoptium arch)
_PLATFORMS = {
    ("windows", "x86_64"): ("windows", "x86_64", "windows", "x64"),
    ("linux", "x86_64"):   ("linux", "x86_64", "linux", "x64"),
    ("linux", "arm64"):    ("linux", "arm64", "linux", "aarch64"),
    ("darwin", "x86_64"):  ("macos", "x86_64", "mac", "x64"),
    ("darwin", "arm64"):   ("macos", "arm64", "mac", "aarch64"),
}
_MACHINE_ALIASES = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}

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
        if not cand.name.startswith(("jre-21", "jdk-21")):
            continue
        # Temurin's macOS tarball unpacks to <top>/Contents/Home/bin/java
        for home in (cand, cand / "Contents" / "Home"):
            exe = home / "bin" / ("java.exe" if os.name == "nt" else "java")
            if exe.exists():
                return home
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

class InstallError(RuntimeError):
    """A step of install() that cannot be retried blindly: unsupported host, bad checksum."""


def host_platform(system: Optional[str] = None, machine: Optional[str] = None) -> tuple[str, str, str, str]:
    """(joern os, joern arch, adoptium os, adoptium arch) for this host, or InstallError."""
    sysname = (system or platform.system()).lower()
    mach = (machine or platform.machine()).lower()
    key = (sysname, _MACHINE_ALIASES.get(mach, mach))
    if key not in _PLATFORMS:
        supported = ", ".join(f"{a}-{b}" for a, b in _PLATFORMS)
        raise InstallError(f"no joern-cli build for {sysname}/{mach} (supported: {supported})")
    return _PLATFORMS[key]


def joern_asset(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    jos, jarch, _, _ = host_platform(system, machine)
    return f"joern-cli-{jos}-{jarch}.zip"


def joern_zip_url(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    return _JOERN_RELEASE_URL + joern_asset(system, machine)


def jre_url(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    _, _, aos, aarch = host_platform(system, machine)
    return _ADOPTIUM_URL.format(os=aos, arch=aarch)


def jre_archive(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    """Local file name for the JRE download; the suffix drives the extractor."""
    aos = host_platform(system, machine)[2]
    return "jre-21.zip" if aos == "windows" else "jre-21.tar.gz"


_RE_SHA512 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{128}(?![0-9a-fA-F])")


def parse_sha512(text: str) -> str:
    """The digest from a `sha512sum` line (`<hex>  <filename>`), lower-cased; '' if none."""
    m = _RE_SHA512.search(text or "")
    return m.group(0).lower() if m else ""


def _sha512_file(path: Path) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, log) -> None:
    """Streams to <dest>.part and renames at the end, so a killed run never leaves a truncated
    archive that looks complete. Raises urllib.error.URLError / OSError on failure."""
    import urllib.request
    log(f"  downloading {url}")
    part = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "RAMPART-joern-runtime/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r, open(part, "wb") as fh:
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
    part.replace(dest)
    log(f"  saved {dest.name} ({dest.stat().st_size // (1 << 20)} MB)")


def _fetch(url: str, dest: Path, log) -> None:
    """_download with the URL folded into the error: urllib's HTTPError says only
    "HTTP Error 404: Not Found", which is useless in a one-line install report."""
    try:
        _download(url, dest, log)
    except OSError as e:
        raise InstallError(f"could not fetch {url}: {e}") from e


def _verify_sha512(archive: Path, url: str, log) -> None:
    """Compare <archive> with the release's <url>.sha512 (a hand-placed <archive>.sha512 next
    to it wins). On mismatch the archive is deleted and InstallError raised."""
    sha_file = archive.with_name(archive.name + ".sha512")
    if not sha_file.exists():
        _fetch(url + ".sha512", sha_file, log)
    expected = parse_sha512(sha_file.read_text(encoding="utf-8", errors="replace"))
    if not expected:
        archive.unlink(missing_ok=True)
        raise InstallError(f"{sha_file.name} holds no sha512 digest; deleted {archive.name}")
    log(f"  verifying sha512 of {archive.name}")
    actual = _sha512_file(archive)
    if actual != expected:
        archive.unlink(missing_ok=True)
        raise InstallError(f"sha512 mismatch for {archive.name} (expected {expected[:16]}..., "
                           f"got {actual[:16]}...); deleted it")
    log("  sha512 OK")


def _extract_zip(archive: Path, dest: Path) -> list[str]:
    """extractall + (POSIX only) the unix mode bits zipfile drops. Returns top-level names."""
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        zf.extractall(dest)
        if os.name != "nt":
            for zi in infos:
                mode = (zi.external_attr >> 16) & 0o7777
                if mode and not zi.is_dir():
                    os.chmod(dest / zi.filename, mode)
        return sorted({zi.filename.split("/")[0] for zi in infos})


def _extract_tar(archive: Path, dest: Path) -> list[str]:
    with tarfile.open(archive, "r:*") as tf:
        tf.extractall(dest, filter="data")     # keeps exec bits, strips setuid / absolute paths
        names = [m.name[2:] if m.name.startswith("./") else m.name for m in tf.getmembers()]
        return sorted({n.split("/")[0] for n in names if n and n != "."})


def _ensure_executable(joern_home: Path) -> None:
    """POSIX belt and braces for a zip built without mode bits: the launchers and every
    frontend's bin/ get +x. No-op on Windows."""
    if os.name == "nt":
        return
    cands = [p for p in joern_home.glob("joern*") if p.suffix != ".bat"]
    cands += list(joern_home.glob("frontends/*/bin/*"))
    for p in cands:
        if p.is_file():
            st = p.stat().st_mode
            if not st & stat.S_IXUSR:
                os.chmod(p, st | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _install_jre(log) -> None:
    log("[joern] installing portable Temurin 21 JRE")
    url, z = jre_url(), TOOLS / jre_archive()
    _fetch(url, z, log)
    top = _extract_zip(z, TOOLS) if z.suffix == ".zip" else _extract_tar(z, TOOLS)
    z.unlink(missing_ok=True)
    # normalise the versioned Temurin folder name to a stable path
    if len(top) == 1 and (TOOLS / top[0]).is_dir() and not (TOOLS / "jre-21").exists():
        (TOOLS / top[0]).rename(TOOLS / "jre-21")
    log("[joern] JRE ready")


def _install_joern(log) -> None:
    log(f"[joern] installing joern-cli {JOERN_VERSION}")
    url, z = joern_zip_url(), TOOLS / joern_asset()
    hand_placed = z.exists()
    if hand_placed:
        log(f"  using existing {z}")
    else:
        _fetch(url, z, log)
    _verify_sha512(z, url, log)
    _extract_zip(z, TOOLS)
    _ensure_executable(TOOLS / "joern-cli")
    if not hand_placed:
        z.unlink(missing_ok=True)
    log("[joern] joern-cli ready")


def install(log=print) -> RuntimeInfo:
    """Idempotent: installs whichever of the JRE / joern-cli is missing under <repo>/tools/.
    Never raises for the expected failures (no build for this host, HTTP 404 / timeout, bad
    archive, checksum mismatch): the reason lands in RuntimeInfo.problems and the manual
    fallback is printed once."""
    TOOLS.mkdir(parents=True, exist_ok=True)
    info = locate()
    try:
        jos, jarch, _, _ = host_platform()
        log(f"[joern] host: {jos}-{jarch}")
        if info.java_home is None or info.java_major != 21:
            _install_jre(log)
        if info.joern_home is None:
            _install_joern(log)
    except (OSError, zipfile.BadZipFile, tarfile.TarError, InstallError) as e:
        # urllib's HTTPError / URLError and socket timeouts are all OSError subclasses
        why = f"install failed: {e}"
        log(f"[joern] {why}")
        try:
            asset = joern_asset()
            log(f"        manual fallback: download {_JOERN_RELEASE_URL}{asset} and its .sha512 "
                f"by hand into {TOOLS} and re-run --install; the JRE can be any Temurin 21 JRE "
                f"unpacked to {TOOLS / 'jre-21'} (or set JOERN_JAVA_HOME)")
        except InstallError:
            pass
        info = locate()
        info.problems.insert(0, why)
        return info

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
