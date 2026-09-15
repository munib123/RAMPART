"""No-JVM contract tests for the Joern phase (P3). Nothing here launches Java: these pin the
parts that broke or nearly broke while building the sidecar - the rules-file sectioning that
server mode depends on, the /query-sync failure detector, the readiness probe, and the
enabled() gate. Run from backend/:
    .venv\\Scripts\\python.exe -m pytest tests/test_joern.py -q
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.joern import scan as joern_scan          # noqa: E402
from app.services.joern import server as joern_server      # noqa: E402


# ---- rules file sectioning ------------------------------------------------------------

REQUIRED_KINDS = ["prelude", "import", "context", "rule", "rule", "rule", "rule", "finish"]


def test_rules_file_sections_in_order():
    """Server mode sends one /query-sync per section; the order and the set are the contract."""
    secs = joern_scan._sections(joern_scan.RULES.read_text(encoding="utf-8"))
    assert [k for k, _, _ in secs] == REQUIRED_KINDS
    rule_names = [n for k, n, _ in secs if k == "rule"]
    assert rule_names == list(joern_scan._TITLES), "rule sections must match the title table"
    assert all(body.strip() for _, _, body in secs), "no empty section"


def test_sections_only_split_on_exact_marker():
    text = ("// @@ prelude\nval a = 1\n"
            "// @@@ not a marker\n"
            "  // @@ rule indented-is-not-a-marker\n"
            "// @@ rule r1\nval b = 2\n"
            "// @@ finish   \nwrite()\n")
    secs = joern_scan._sections(text)
    assert [(k, n) for k, n, _ in secs] == [("prelude", ""), ("rule", "r1"), ("finish", "")]
    assert "@@@ not a marker" in secs[0][2]
    assert "indented-is-not-a-marker" in secs[0][2]
    assert "val b = 2" in secs[1][2]


def test_render_substitutes_every_placeholder(tmp_path):
    r = joern_scan._render(r"C:\code\target", tmp_path / "f.tsv", tmp_path / "d.json", "proj1")
    for ph in ("__INPUT_DIR__", "__OUT_FILE__", "__DIAG_FILE__", "__PROJECT__"):
        assert ph not in r
    assert "C:/code/target" in r                   # backslashes never reach Scala literals
    assert "\\code\\target" not in r


# ---- /query-sync failure detection ---------------------------------------------------

@pytest.mark.parametrize("out", [
    # scala 3 compile error banner (with and without the [E123] code), ansi-coloured too
    "-- [E006] Not Found Error: rsc line 3 -----\n3 |  foo.bar\n  |  ^^^ Not found: foo",
    "-- Error: rsc line 1 ----\n1 |  val = \n",
    "\x1b[31m-- [E040] Syntax Error: rsc line 9\x1b[0m\n",
    "1 error found",
    "3 errors found",
    # thrown exceptions, fully-qualified, with and without a message
    "java.lang.NullPointerException: Cannot invoke ...",
    "  java.util.NoSuchElementException",
    "io.shiftleft.codepropertygraph.generated.SomethingError: boom",
    "io.joern.console.Error: project not found",
])
def test_evaluation_failed_true(out):
    assert joern_server.evaluation_failed(out)


@pytest.mark.parametrize("out", [
    "",
    "val res0: Int = 2",
    'val findings: ListBuffer[String] = ListBuffer()',
    # rule bodies legitimately contain these words as plain text or identifiers
    'val AUTHZ = List("access_denied", "unauthorized", "forbidden")',
    "ruleErrors: 0   (no Error thrown)",
    "res3: String = 'try { ... } catch { case e: Exception => ... }'",
    "Detected changes in 0 file(s)",
])
def test_evaluation_failed_false(out):
    assert not joern_server.evaluation_failed(out)


def test_strip_ansi():
    assert joern_server.strip_ansi("\x1b[32mok\x1b[0m") == "ok"
    assert joern_server.strip_ansi(None) == ""


# ---- readiness probe (no process: a fake server object) -----------------------------

class _FakeServer(joern_server.JoernServer):
    def __init__(self, answers):
        super().__init__(port=0)
        self._answers = list(answers)
        self.calls = 0

    def alive(self):
        return True

    def query(self, scala, timeout):
        self.calls += 1
        ok = self._answers.pop(0) if self._answers else False
        return (True, "val res0: Int = 2", "") if ok else (False, "", "connection refused")


def test_wait_ready_zero_probes_once():
    """The P3 bug: wait_ready(0) used to return False without asking, so a started sidecar was
    never used while JOERN_SERVER_WAIT=0 (the default). It must probe at least once."""
    s = _FakeServer([True])
    assert s.wait_ready(0) is True
    assert s.calls == 1 and s.ready and s.ready_at is not None


def test_wait_ready_zero_not_up_yet():
    s = _FakeServer([False])
    assert s.wait_ready(0) is False
    assert s.calls == 1 and not s.ready


def test_wait_ready_polls_until_deadline():
    s = _FakeServer([False, False, True])
    t0 = time.time()
    assert s.wait_ready(5) is True
    assert s.calls == 3
    assert time.time() - t0 < 5


def test_wait_ready_short_circuits_once_ready():
    s = _FakeServer([True])
    assert s.wait_ready(0)
    assert s.wait_ready(0) and s.calls == 1


# ---- enabled() gate -------------------------------------------------------------------

def test_enabled_off_wins_before_runtime_probe(monkeypatch, tmp_path):
    from app import config
    monkeypatch.setattr(config, "JOERN_ENABLED", "off")
    called = []
    monkeypatch.setattr(joern_scan, "available", lambda: called.append(1) or (True, ""))
    ok, why = joern_scan.enabled(str(tmp_path))
    assert (ok, why) == (False, "JOERN_ENABLED=off")
    assert not called, "off must not touch the runtime"


def test_enabled_auto_skips_targets_without_python(monkeypatch, tmp_path):
    from app import config
    monkeypatch.setattr(config, "JOERN_ENABLED", "auto")
    monkeypatch.setattr(joern_scan, "available", lambda: (True, ""))
    (tmp_path / "index.js").write_text("console.log(1)\n")
    ok, why = joern_scan.enabled(str(tmp_path))
    assert not ok and "no Python files" in why
    (tmp_path / "app.py").write_text("x = 1\n")
    assert joern_scan.enabled(str(tmp_path)) == (True, "")


def test_enabled_reports_runtime_reason(monkeypatch, tmp_path):
    from app import config
    monkeypatch.setattr(config, "JOERN_ENABLED", "auto")
    monkeypatch.setattr(joern_scan, "available", lambda: (False, "no JRE 21 found"))
    assert joern_scan.enabled(str(tmp_path)) == (False, "no JRE 21 found")


def test_server_mode_off_never_starts(monkeypatch):
    from app import config
    monkeypatch.setattr(config, "JOERN_SERVER", "off")
    assert joern_server.ensure_started() is None
    assert joern_server.status() == {"mode": "off", "running": False}
