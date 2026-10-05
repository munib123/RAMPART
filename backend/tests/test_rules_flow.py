"""The call-anchored rules (rules/50-60) end to end on testbeds/probe-flow: every vulnerable
function found, every fixed twin quiet. Needs the Joern runtime (skipped without it); ~25 s in
script mode. The same expectation as bench/keys/probe-flow.key.jsonl, pinned as a test so a rule
edit that loses a finding or gains a twin fails here before it reaches the bench. Run from backend/:
    .venv/bin/python -m pytest tests/test_rules_flow.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.joern import runtime, scan as joern_scan     # noqa: E402

ROOT = Path(__file__).resolve().parents[2] / "testbeds" / "probe-flow"

# (rule, file, method) - config-flow findings sit on the definition in settings.py
EXPECTED = {
    ("joern-ignored-auth-result", "app.py", "login"),
    ("joern-ignored-auth-result", "auth.py", "change_email"),
    ("joern-hardcoded-credential-compare", "auth.py", "is_support_login"),
    ("joern-ssrf-request-url", "client.py", "notify"),
    ("joern-ssrf-request-url", "app.py", "preview"),
    ("joern-path-traversal", "files.py", "read_export"),
    ("joern-xxe-parser", "feeds.py", "parse_partner_feed"),
    ("joern-cleartext-transport", "settings.py", "<module>"),
    ("joern-cors-wildcard", "settings.py", "<module>"),
    ("joern-debug-exposed", "settings.py", "<module>"),
}


def _joern_available() -> bool:
    ok, _, _ = runtime.probe()
    return ok


@pytest.fixture(scope="module")
def probe_flow_scan():
    if not _joern_available():
        pytest.skip("Joern runtime not installed")
    return joern_scan.scan(str(ROOT), pack="_base")


def test_every_rule_ran_clean(probe_flow_scan):
    _, diag = probe_flow_scan
    assert diag["used"], diag.get("reason")
    assert set(diag["rule_state"]) == set(joern_scan._TITLES)
    assert all(s["state"] == "ok" for s in diag["rule_state"].values()), diag["rule_state"]
    assert not diag.get("table_errors")


def test_findings_are_exactly_the_vulnerable_functions(probe_flow_scan):
    findings, _ = probe_flow_scan
    got = {(f.rule_id, Path(f.path).name, f.meta.get("method")) for f in findings}
    assert got == EXPECTED, {"missing": EXPECTED - got, "unexpected": got - EXPECTED}


def test_provenance_names_the_flow(probe_flow_scan):
    findings, _ = probe_flow_scan
    by = {(f.rule_id, f.meta.get("method")): f for f in findings}
    ssrf = by[("joern-ssrf-request-url", "notify")]
    assert "request input passed by webhook()" in ssrf.message      # one caller hop, named
    assert "request_sources=request.form" in ssrf.meta["slots"]
    cors = by[("joern-cors-wildcard", "<module>")]
    assert "CORS_ORIGIN" in cors.message and "add_cors()" in cors.message
    cred = by[("joern-hardcoded-credential-compare", "is_support_login")]
    assert "letmein" not in cred.message and "letmein" not in cred.message.split("[code:")[-1]   # never echoed
    assert {f.cwe_id for f in findings} >= {"CWE-287", "CWE-798", "CWE-918", "CWE-22", "CWE-611", "CWE-319", "CWE-942", "CWE-489"}
