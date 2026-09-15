"""No-network, no-JVM tests for the Joern runtime installer (P0). Nothing here downloads or
launches anything: these pin the per-platform asset selection (the old single joern-cli.zip URL
was a 404), the sha512 verifier, the POSIX mode-bit restore, and the promise that install()
reports a failed download in RuntimeInfo.problems instead of raising. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_runtime.py -q
"""
from __future__ import annotations

import hashlib
import io
import stat
import sys
import urllib.error
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.joern import runtime      # noqa: E402


# ---- platform -> asset / URL ---------------------------------------------------------

@pytest.mark.parametrize("system, machine, asset, jre_os, jre_arch, jre_file", [
    ("Windows", "AMD64",   "joern-cli-windows-x86_64.zip", "windows", "x64",     "jre-21.zip"),
    ("Linux",   "x86_64",  "joern-cli-linux-x86_64.zip",   "linux",   "x64",     "jre-21.tar.gz"),
    ("Linux",   "aarch64", "joern-cli-linux-arm64.zip",    "linux",   "aarch64", "jre-21.tar.gz"),
    ("Darwin",  "x86_64",  "joern-cli-macos-x86_64.zip",   "mac",     "x64",     "jre-21.tar.gz"),
    ("Darwin",  "arm64",   "joern-cli-macos-arm64.zip",    "mac",     "aarch64", "jre-21.tar.gz"),
])
def test_asset_and_jre_selection(monkeypatch, system, machine, asset, jre_os, jre_arch, jre_file):
    monkeypatch.setattr(runtime.platform, "system", lambda: system)
    monkeypatch.setattr(runtime.platform, "machine", lambda: machine)
    assert runtime.joern_asset() == asset
    assert runtime.joern_zip_url() == (
        f"https://github.com/joernio/joern/releases/download/v{runtime.JOERN_VERSION}/{asset}")
    assert runtime.jre_url() == (
        f"https://api.adoptium.net/v3/binary/latest/21/ga/{jre_os}/{jre_arch}/jre/hotspot/normal/eclipse")
    assert runtime.jre_archive() == jre_file


def test_explicit_args_bypass_host_probe():
    assert runtime.joern_asset("linux", "AMD64") == "joern-cli-linux-x86_64.zip"
    assert runtime.jre_url("Darwin", "ARM64").endswith("/mac/aarch64/jre/hotspot/normal/eclipse")


@pytest.mark.parametrize("system, machine", [
    ("Windows", "ARM64"), ("Linux", "i686"), ("FreeBSD", "amd64"), ("Darwin", "ppc"),
])
def test_unsupported_host_is_a_clear_install_error(system, machine):
    with pytest.raises(runtime.InstallError) as ei:
        runtime.joern_asset(system, machine)
    assert "supported:" in str(ei.value) and "windows-x86_64" in str(ei.value)


def test_old_platformless_url_is_gone():
    """The v4.0.589 release has no joern-cli.zip; every URL we build must carry a platform."""
    for sysname, mach in [("Windows", "AMD64"), ("Linux", "x86_64"), ("Darwin", "arm64")]:
        assert not runtime.joern_zip_url(sysname, mach).endswith("/joern-cli.zip")


# ---- sha512 ---------------------------------------------------------------------------

_HEX = "0" * 64 + "f" * 64


@pytest.mark.parametrize("text", [
    f"{_HEX}  joern-cli-windows-x86_64.zip\n",          # sha512sum format (what joern publishes)
    f"{_HEX}  target/joern-cli-linux-x86_64.zip",       # path-qualified name, no newline
    f"{_HEX} *joern-cli.zip",                           # binary-mode marker
    f"{_HEX.upper()}\n",                                # bare digest, upper-case
    f"SHA512 (x.zip) = {_HEX}",                         # BSD style
])
def test_parse_sha512_finds_the_digest(text):
    assert runtime.parse_sha512(text) == _HEX


@pytest.mark.parametrize("text", ["", "not a digest\n", "a" * 127, "a" * 129, "<html>404</html>"])
def test_parse_sha512_rejects_non_digests(text):
    assert runtime.parse_sha512(text) == ""


def _zip_bytes(names: dict[str, bytes], mode: int = 0) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in names.items():
            zi = zipfile.ZipInfo(name)
            if mode:
                zi.create_system = 3
                zi.external_attr = (mode & 0xFFFF) << 16
            zf.writestr(zi, data)
    return buf.getvalue()


def test_verify_sha512_accepts_matching_sidecar(tmp_path):
    z = tmp_path / "joern-cli-test.zip"
    z.write_bytes(_zip_bytes({"joern-cli/joern": b"#!/bin/sh\n"}))
    digest = hashlib.sha512(z.read_bytes()).hexdigest()
    (tmp_path / "joern-cli-test.zip.sha512").write_text(f"{digest}  joern-cli-test.zip\n")
    calls = []
    runtime._verify_sha512(z, "https://example.invalid/x.zip", lambda *a, **k: calls.append(a[0]))
    assert z.exists()
    assert any("sha512 OK" in c for c in calls)
    assert not any("downloading" in c for c in calls)     # the sidecar was used, no fetch


def test_verify_sha512_refuses_and_deletes_on_mismatch(tmp_path):
    z = tmp_path / "joern-cli-test.zip"
    z.write_bytes(_zip_bytes({"joern-cli/joern": b"tampered\n"}))
    (tmp_path / "joern-cli-test.zip.sha512").write_text(f"{_HEX}  joern-cli-test.zip\n")
    with pytest.raises(runtime.InstallError, match="mismatch"):
        runtime._verify_sha512(z, "https://example.invalid/x.zip", lambda *a, **k: None)
    assert not z.exists(), "a zip that fails verification must not be left for extraction"


def test_verify_sha512_fetches_sidecar_when_absent(tmp_path, monkeypatch):
    z = tmp_path / "joern-cli-test.zip"
    z.write_bytes(_zip_bytes({"joern-cli/joern": b"x"}))
    digest = hashlib.sha512(z.read_bytes()).hexdigest()
    fetched = []

    def fake_download(url, dest, log):
        fetched.append(url)
        dest.write_text(f"{digest}  target/joern-cli-test.zip\n")

    monkeypatch.setattr(runtime, "_download", fake_download)
    runtime._verify_sha512(z, "https://example.invalid/joern-cli-test.zip", lambda *a, **k: None)
    assert fetched == ["https://example.invalid/joern-cli-test.zip.sha512"]
    assert z.exists()


# ---- extraction -----------------------------------------------------------------------

def test_extract_zip_reports_top_level_and_restores_mode_bits(tmp_path):
    z = tmp_path / "a.zip"
    z.write_bytes(_zip_bytes({"joern-cli/joern": b"#!/bin/sh\n", "joern-cli/lib/x.jar": b"j"},
                             mode=0o755))
    assert runtime._extract_zip(z, tmp_path) == ["joern-cli"]
    launcher = tmp_path / "joern-cli" / "joern"
    assert launcher.read_bytes() == b"#!/bin/sh\n"
    if sys.platform != "win32":
        assert launcher.stat().st_mode & stat.S_IXUSR


@pytest.mark.skipif(sys.platform == "win32", reason="mode bits are a POSIX concept")
def test_ensure_executable_chmods_launcher_and_frontends(tmp_path):
    home = tmp_path / "joern-cli"
    (home / "frontends" / "pysrc2cpg" / "bin").mkdir(parents=True)
    for rel in ("joern", "joern.bat", "frontends/pysrc2cpg/bin/pysrc2cpg"):
        f = home / rel
        f.write_text("x")
        f.chmod(0o644)
    runtime._ensure_executable(home)
    assert (home / "joern").stat().st_mode & stat.S_IXUSR
    assert (home / "frontends/pysrc2cpg/bin/pysrc2cpg").stat().st_mode & stat.S_IXUSR
    assert not (home / "joern.bat").stat().st_mode & stat.S_IXUSR


# ---- install() failure path -----------------------------------------------------------

def _fresh_tools(monkeypatch, tmp_path):
    """Point the installer at an empty tools dir, with no env override and no java on PATH,
    so both the JRE and the joern step believe they have work to do."""
    monkeypatch.setattr(runtime, "TOOLS", tmp_path / "tools")
    monkeypatch.setattr(runtime.config, "JOERN_HOME", "")
    monkeypatch.setattr(runtime.config, "JOERN_JAVA_HOME", "")
    monkeypatch.delenv("JOERN_HOME", raising=False)
    monkeypatch.delenv("JOERN_JAVA_HOME", raising=False)
    monkeypatch.setattr(runtime.shutil, "which", lambda name: None)
    monkeypatch.setattr(runtime.platform, "system", lambda: "Windows")
    monkeypatch.setattr(runtime.platform, "machine", lambda: "AMD64")


def test_install_reports_http_404_instead_of_raising(monkeypatch, tmp_path):
    _fresh_tools(monkeypatch, tmp_path)
    attempted = []

    def boom(url, dest, log):
        attempted.append(url)
        raise urllib.error.HTTPError(url, 404, "Not Found", hdrs=None, fp=None)

    monkeypatch.setattr(runtime, "_download", boom)
    lines = []
    info = runtime.install(log=lambda *a, **k: lines.append(a[0]))

    assert isinstance(info, runtime.RuntimeInfo)
    assert not info.ok
    assert attempted == [runtime.jre_url()], "the JRE comes first; joern is not attempted after a failure"
    assert any("404" in p for p in info.problems)
    assert any(attempted[0] in p for p in info.problems), "the failing URL is in the reason"
    joined = "\n".join(lines)
    assert "manual fallback" in joined
    assert "joern-cli-windows-x86_64.zip" in joined
    assert not (tmp_path / "tools" / "jre-21").exists()


def test_install_reports_timeout_and_names_joern_asset(monkeypatch, tmp_path):
    """JRE present (fake), joern download times out: the joern URL lands in problems."""
    _fresh_tools(monkeypatch, tmp_path)
    tools = tmp_path / "tools"
    (tools / "jre-21" / "bin").mkdir(parents=True)
    (tools / "jre-21" / "bin" / ("java.exe" if sys.platform == "win32" else "java")).write_text("")
    monkeypatch.setattr(runtime, "_java_major", lambda exe: 21)

    def slow(url, dest, log):
        raise TimeoutError("timed out")

    monkeypatch.setattr(runtime, "_download", slow)
    info = runtime.install(log=lambda *a, **k: None)
    assert not info.ok
    assert info.problems[0].startswith("install failed:")
    assert "timed out" in info.problems[0]
    assert not (tools / "joern-cli").exists()


def test_install_rejects_tampered_hand_placed_zip(monkeypatch, tmp_path):
    """A zip put in tools/ by hand is used without downloading, but still verified."""
    _fresh_tools(monkeypatch, tmp_path)
    tools = tmp_path / "tools"
    (tools / "jre-21" / "bin").mkdir(parents=True)
    (tools / "jre-21" / "bin" / ("java.exe" if sys.platform == "win32" else "java")).write_text("")
    monkeypatch.setattr(runtime, "_java_major", lambda exe: 21)
    z = tools / "joern-cli-windows-x86_64.zip"
    z.write_bytes(_zip_bytes({"joern-cli/joern.bat": b"@echo off\n"}))
    (tools / "joern-cli-windows-x86_64.zip.sha512").write_text(f"{_HEX}  joern-cli-windows-x86_64.zip\n")
    monkeypatch.setattr(runtime, "_download", lambda *a, **k: pytest.fail("must not download"))

    info = runtime.install(log=lambda *a, **k: None)
    assert not info.ok
    assert "mismatch" in info.problems[0]
    assert not z.exists()
    assert not (tools / "joern-cli").exists()


def test_install_unsupported_host_does_not_download(monkeypatch, tmp_path):
    _fresh_tools(monkeypatch, tmp_path)
    monkeypatch.setattr(runtime.platform, "machine", lambda: "ARM64")
    monkeypatch.setattr(runtime, "_download", lambda *a, **k: pytest.fail("must not download"))
    info = runtime.install(log=lambda *a, **k: None)
    assert not info.ok
    assert "no joern-cli build for windows/arm64" in info.problems[0]
