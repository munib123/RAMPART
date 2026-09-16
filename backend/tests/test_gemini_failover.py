"""Model failover on a free-tier DAILY quota (no network: the client is a stub).

The daily quota is per model and does not come back until midnight Pacific, so waiting is
useless; the process moves to the next model in GEMINI_FALLBACK_MODELS and stays there.
A per-MINUTE 429 must keep the old behaviour (backoff on the same model)."""
import json
import types

import pytest

from app import config
from app.services import gemini


DAILY = ("429 RESOURCE_EXHAUSTED. {'error': {'code': 429, 'message': 'You exceeded your current quota', "
         "'details': [{'@type': 'type.googleapis.com/google.rpc.QuotaFailure', 'violations': "
         "[{'quotaMetric': 'generativelanguage.googleapis.com/generate_content_free_tier_requests', "
         "'quotaId': 'GenerateRequestsPerDayPerProjectPerModel-FreeTier'}]}]}}")
MINUTE = DAILY.replace("PerDayPerProject", "PerMinutePerProject")


class ClientError(Exception):
    pass


class _Stub:
    """generate_content that raises per model according to `plan` and records the calls."""

    def __init__(self, plan: dict):
        self.plan, self.calls = plan, []
        self.models = types.SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        self.calls.append(model)
        beh = self.plan.get(model)
        if isinstance(beh, Exception):
            raise beh
        return types.SimpleNamespace(text=json.dumps(beh))


@pytest.fixture
def chain(monkeypatch):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "x")
    monkeypatch.setattr(config, "GEMINI_MODEL", "m-a")
    monkeypatch.setattr(config, "GEMINI_FALLBACK_MODELS", ["m-b", "m-c"])
    monkeypatch.setattr(gemini, "_model_idx", 0)
    monkeypatch.setattr(__import__("time"), "sleep", lambda s: None)   # the call sites `import time` locally

    def use(plan):
        stub = _Stub(plan)
        monkeypatch.setattr(gemini, "_client", stub)
        return stub
    return use


def test_daily_quota_moves_to_next_model_and_stays(chain):
    stub = chain({"m-a": ClientError(DAILY), "m-b": {"fixed_code": "x = 1", "summary": "ok"}})
    r = gemini.generate_fix({"cwe_id": "CWE-1", "title": "t", "message": "m"}, "x = 0")
    assert r["available"] and r["fixed_code"] == "x = 1"
    assert stub.calls == ["m-a", "m-b"]           # no backoff round on m-a, straight to m-b
    assert gemini.active_model() == "m-b"
    # the next call starts on m-b directly
    gemini.generate_fix({"cwe_id": "CWE-1", "title": "t", "message": "m"}, "x = 0")
    assert stub.calls[-1] == "m-b" and stub.calls.count("m-a") == 1


def test_minute_quota_backs_off_on_the_same_model(chain):
    stub = chain({"m-a": ClientError(MINUTE)})
    r = gemini.generate_fix({"cwe_id": "CWE-1", "title": "t", "message": "m"}, "x = 0")
    assert not r["available"]
    assert set(stub.calls) == {"m-a"} and len(stub.calls) == 4   # the four backoff attempts
    assert gemini.active_model() == "m-a"


def test_chain_exhausted_fails_fast(chain):
    stub = chain({"m-a": ClientError(DAILY), "m-b": ClientError(DAILY), "m-c": ClientError(DAILY)})
    r = gemini.generate_fix({"cwe_id": "CWE-1", "title": "t", "message": "m"}, "x = 0")
    assert not r["available"] and "429" in r["error"]
    assert stub.calls == ["m-a", "m-b", "m-c"]  # one call each, no 41 s of sleeps
    assert gemini.active_model() == "m-c"


def test_pinned_model_is_not_swapped(chain):
    stub = chain({"m-z": ClientError(DAILY)})
    r = gemini.generate_fix({"cwe_id": "CWE-1", "title": "t", "message": "m"}, "x = 0", model="m-z")
    assert not r["available"]
    assert stub.calls == ["m-z"] and gemini.active_model() == "m-a"


def test_batch_verdicts_fail_over_too(chain):
    stub = chain({"m-a": ClientError(DAILY),
                  "m-b": {"results": [{"index": 0, "verdict": "Confirmed", "confidence": 90}]}})
    out = gemini.analyze_batch([{"cwe_id": "CWE-639", "title": "IDOR", "message": "m", "code": "x"}])
    assert out[0]["available"] and out[0]["verdict"] == "Confirmed"
    assert stub.calls == ["m-a", "m-b"]


def test_health_reports_the_active_model(chain):
    chain({"m-a": ClientError(DAILY), "m-b": {"fixed_code": "y", "summary": "s"}})
    gemini.generate_fix({"cwe_id": "CWE-1", "title": "t", "message": "m"}, "x")
    from app.routers import health
    assert health.health()["model"] == "m-b"
