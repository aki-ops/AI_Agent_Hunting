"""Tests for the LLM hardening: metering and budget, fallbacks, temperature, judge votes, Prepare cache, redaction."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hunting import llm as llm_mod
from hunting.adapters.cdb_adapter import CdbAdapter
from hunting.llm import (
    METER,
    LlmSettings,
    PeakLlm,
    TokenBudgetExceeded,
    UsageMeter,
    retry_async,
)
from hunting.pipeline import run_poc
from hunting.poc import poc_from_file
from hunting.poc.judge import INCONCLUSIVE, TRUE_POSITIVE, Judgment, combine_judgments
from hunting.prepare import prepare_cache_key, run_prepare
from hunting.redact import Redactor
from tests.unit.test_pipeline import _poc

WINDOW = "2026-09-01T00:00:00Z/2026-09-02T00:00:00Z"


def _settings(**over) -> LlmSettings:
    base = {"base_url": "https://llm.example/v1", "api_key": "k", "model": "a"}
    return LlmSettings(**{**base, **over})


@pytest.fixture(autouse=True)
def _fresh_meter():
    METER.begin(None)
    yield
    METER.begin(None)


# --- settings ------------------------------------------------------------------------

def test_settings_parse_fallbacks_temperature_interval_and_locality(tmp_path: Path, monkeypatch):
    for key in llm_mod._ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    env = tmp_path / ".env"
    env.write_text(
        "LLM_ENDPOINT=http://localhost:11434/v1/chat/completions\nLLM_API_KEY=k\nLLM_MODEL=a\n"
        "LLM_MODEL_FALLBACKS= b, a ,c,b\nLLM_TEMPERATURE=0.2\nLLM_MIN_INTERVAL=1.5\n", encoding="utf-8")
    s = LlmSettings.from_env(env)
    assert s.fallbacks == ("b", "c")  # primary and duplicates dropped, order kept
    assert (s.temperature, s.min_interval, s.is_local) == (0.2, 1.5, True)
    env.write_text("LLM_ENDPOINT=https://openrouter.ai/api/v1/chat/completions\nLLM_API_KEY=k\nLLM_MODEL=a\nLLM_TEMPERATURE=none\n",
                   encoding="utf-8")
    s = LlmSettings.from_env(env)
    assert s.temperature is None and s.is_local is False and s.fallbacks == ()


def test_model_config_lists_fallbacks_and_never_the_key():
    cfg = _settings(fallbacks=("b", "c"), api_key="super-secret").model_config()
    assert list(cfg["providers"]["hunting-llm"]["models"]) == ["a", "b", "c"]
    assert "super-secret" not in json.dumps(cfg)


# --- metering and budget --------------------------------------------------------------

def _result(model="served/x", prompt=10, completion=5):
    return SimpleNamespace(model=model, usage=SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion))


def test_meter_counts_per_model_and_enforces_the_budget():
    meter = UsageMeter()
    meter.begin(20)
    meter.observe(_result("m1", 10, 5))
    meter.observe(_result("m2", 3, 1))
    meter.observe(SimpleNamespace())  # a streamed reply: counted, but no usage
    snap = meter.snapshot()
    assert (snap["calls"], snap["unmetered_calls"], snap["total_tokens"]) == (3, 1, 19)
    assert set(snap["by_model"]) == {"m1", "m2"}
    meter.check()  # 19 < 20
    meter.observe(_result("m1", 1, 0))
    with pytest.raises(TokenBudgetExceeded):
        meter.check()
    meter.begin(None)  # a new PoC starts clean and unlimited
    assert meter.total_tokens == 0 and not meter.exceeded()


def test_installed_meter_sees_the_model_that_really_answered_and_stops_at_the_budget():
    pytest.importorskip("openai")
    httpx = pytest.importorskip("httpx")
    from openai import AsyncOpenAI

    body = {
        "id": "1", "object": "chat.completion", "created": 1, "model": "provider/real-model",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))

    async def go():
        client = AsyncOpenAI(api_key="k", base_url="http://llm.test/v1", http_client=httpx.AsyncClient(transport=transport))
        await client.chat.completions.create(model="auto", messages=[{"role": "user", "content": "x"}])
        first = METER.snapshot()
        with pytest.raises(TokenBudgetExceeded):
            await client.chat.completions.create(model="auto", messages=[{"role": "user", "content": "x"}])
        return first

    assert llm_mod.install_usage_meter() is True and llm_mod.install_usage_meter() is True  # idempotent
    METER.begin(15)
    snap = asyncio.run(go())
    assert snap["by_model"]["provider/real-model"]["calls"] == 1  # asked for "auto", served by this model
    assert snap["total_tokens"] == 15


def test_retry_does_not_retry_a_spent_budget():
    calls = {"n": 0}

    async def spent():
        calls["n"] += 1
        raise TokenBudgetExceeded("over")

    with pytest.raises(TokenBudgetExceeded):
        asyncio.run(retry_async(spent, delays=(0, 0, 0)))
    assert calls["n"] == 1

    calls["n"] = 0
    METER.begin(1)
    METER.observe(_result(prompt=5, completion=5))  # budget gone while a plain error is being retried

    async def failing():
        calls["n"] += 1
        raise RuntimeError("404")

    with pytest.raises(TokenBudgetExceeded):
        asyncio.run(retry_async(failing, delays=(0, 0, 0)))
    assert calls["n"] == 1


# --- fallback models, redaction in the call path ----------------------------------------

def _fast_retry(monkeypatch):
    original = llm_mod.retry_async
    monkeypatch.setattr(llm_mod, "retry_async", lambda factory, **kw: original(factory, delays=(0, 0), **kw))
    monkeypatch.setattr(llm_mod, "configure_peak", lambda settings, work_dir: Path(work_dir) / "model_config.json")


def test_fallback_model_takes_over_and_stays(monkeypatch, tmp_path: Path):
    _fast_retry(monkeypatch)
    seen: list[str] = []

    async def fake_ask(self, prompt, system):
        seen.append(self.settings.model)
        if self.settings.model == "a":
            raise RuntimeError("404 model_not_found")
        return "ok"

    monkeypatch.setattr(PeakLlm, "_ask", fake_ask)
    llm = PeakLlm(_settings(fallbacks=("b",)), tmp_path / "model_config.json")
    assert llm("hello") == "ok"
    assert llm.settings.model == "b" and llm.model_switches == ["a -> b"]
    assert llm("again") == "ok" and seen[-1] == "b"  # sticky: no new attempt on the dead model


def test_without_a_fallback_the_error_is_raised(monkeypatch, tmp_path: Path):
    _fast_retry(monkeypatch)

    async def dead(self, prompt, system):
        raise RuntimeError("endpoint down")

    monkeypatch.setattr(PeakLlm, "_ask", dead)
    with pytest.raises(RuntimeError, match="endpoint down"):
        PeakLlm(_settings(), tmp_path / "model_config.json")("hello")


def test_redactor_masks_outbound_text_and_restores_the_reply(monkeypatch, tmp_path: Path):
    _fast_retry(monkeypatch)
    redactor = Redactor()
    redactor.learn_rows([{"host": "WS-ALICE-01", "user": "CORP\\alice", "ip": "10.1.2.3"}])
    sent: list[str] = []

    async def echo(self, prompt, system):
        sent.append(prompt)
        return "Suspicious logon of <USER_1> on <HOST_1> from <IP_1> and <IP_2>"

    monkeypatch.setattr(PeakLlm, "_ask", echo)
    llm = PeakLlm(_settings(), tmp_path / "model_config.json", redactor=redactor)
    reply = llm("Review ws-alice-01 where CORP\\alice came from 10.1.2.3 and 203.0.113.9.")
    assert "alice" not in sent[0].lower() and "ws-alice" not in sent[0].lower()
    assert "10.1.2.3" not in sent[0] and "203.0.113.9" not in sent[0]  # an unseen IPv4 is masked too
    assert reply == "Suspicious logon of CORP\\alice on WS-ALICE-01 from 10.1.2.3 and 203.0.113.9"


def test_redactor_edge_cases():
    r = Redactor()
    r.learn_values("host", ["srv-1", "ab", "-", "SYSTEM"])  # too short / placeholder values are not learned
    assert r.size == 1
    assert r.mask("host SRV-1x and srv-1.") == "host SRV-1x and <HOST_1>."  # whole tokens only
    assert r.mask("999.1.1.1 stays") == "999.1.1.1 stays"  # not a valid IPv4
    assert r.unmask("<HOST_1> / HOST_1 / <HOST_9>") == "srv-1 / srv-1 / <HOST_9>"  # unknown tokens are left alone


# --- temperature -----------------------------------------------------------------------

def test_temperature_is_sent_and_dropped_once_a_model_rejects_it(monkeypatch, tmp_path: Path):
    pytest.importorskip("autogen_core")
    factory = pytest.importorskip("peak_assistant.utils.llm_factory")
    log: list[object] = []

    class Client:
        async def create(self, messages, extra_create_args=None):
            log.append(extra_create_args)
            if extra_create_args and "temperature" in extra_create_args and Client.reject:
                raise ValueError("Unsupported parameter: 'temperature'")
            return SimpleNamespace(content="ok", usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))

        async def close(self):
            return None

    async def get_client(agent_name=None, config_path=None):
        return Client()

    monkeypatch.setattr(factory, "get_model_client", get_client)
    _fast_retry(monkeypatch)
    Client.reject = False
    llm = PeakLlm(_settings(temperature=0.0), tmp_path / "model_config.json")
    assert llm("x") == "ok" and log == [{"temperature": 0.0}]
    Client.reject = True
    log.clear()
    assert llm("y") == "ok" and log == [{"temperature": 0.0}, None]  # rejected, retried without it
    log.clear()
    assert llm("z") == "ok" and log == [None]  # and not tried again


# --- judge votes -------------------------------------------------------------------------

def _j(verdict, confidence, rationale="r"):
    return Judgment(verdict=verdict, confidence=confidence, rationale=rationale)


def test_judge_votes_majority_takes_the_lowest_confidence_of_the_majority():
    out = combine_judgments([_j(TRUE_POSITIVE, 0.95, "best"), _j(TRUE_POSITIVE, 0.80), _j(INCONCLUSIVE, 0.6)])
    assert (out.verdict, out.confidence, out.rationale) == (TRUE_POSITIVE, 0.80, "best")
    assert any("judge_votes" in n and "majority 2/3" in " ".join(out.notes) for n in out.notes)


def test_judge_votes_without_a_majority_gives_no_judgment():
    out = combine_judgments([_j(TRUE_POSITIVE, 0.9), _j(INCONCLUSIVE, 0.7), _j("FALSE_POSITIVE", 0.8)])
    assert (out.verdict, out.confidence) == (INCONCLUSIVE, 0.0) and "no_majority" in out.notes
    single = _j(TRUE_POSITIVE, 0.7)
    assert combine_judgments([single]) is single


# --- Prepare cache ------------------------------------------------------------------------

def test_prepare_cache_hit_miss_refresh_and_model_key(monkeypatch, tmp_path: Path):
    calls = {"n": 0}

    async def fake(poc, data_document, timeout, use_research, result):
        calls["n"] += 1
        result.able_markdown, result.hunt_plan_markdown = f"ABLE{calls['n']}", f"PLAN{calls['n']}"

    monkeypatch.setattr("hunting.prepare._peak_prepare", fake)
    llm = SimpleNamespace(settings=SimpleNamespace(model="m1"), calls=0, total_tokens=0)
    cache = tmp_path / "cache"
    first = run_prepare(_poc(), "data", llm, cache_dir=cache)  # type: ignore[arg-type]
    assert (first.cache, first.able_markdown, calls["n"]) == ("miss", "ABLE1", 1)
    second = run_prepare(_poc(), "data", llm, cache_dir=cache)  # type: ignore[arg-type]
    assert (second.cache, second.able_markdown, second.used_peak, calls["n"]) == ("hit", "ABLE1", True, 1)
    assert any("cache hit" in n for n in second.notes)
    refreshed = run_prepare(_poc(), "data", llm, cache_dir=cache, refresh=True)  # type: ignore[arg-type]
    assert (refreshed.cache, refreshed.able_markdown, calls["n"]) == ("refresh", "ABLE2", 2)
    assert run_prepare(_poc(), "data", llm, cache_dir=cache).able_markdown == "ABLE2"  # type: ignore[arg-type]
    other = SimpleNamespace(settings=SimpleNamespace(model="m2"), calls=0, total_tokens=0)
    assert run_prepare(_poc(), "data", other, cache_dir=cache).cache == "miss"  # type: ignore[arg-type]
    assert prepare_cache_key(_poc(), "data", "m1", False) != prepare_cache_key(_poc(), "data2", "m1", False)
    assert calls["n"] == 3


def test_a_failed_prepare_is_never_cached(monkeypatch, tmp_path: Path):
    async def boom(*args, **kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr("hunting.prepare._peak_prepare", boom)
    llm = SimpleNamespace(settings=SimpleNamespace(model="m1"), calls=0, total_tokens=0)
    result = run_prepare(_poc(), "data", llm, cache_dir=tmp_path / "c")  # type: ignore[arg-type]
    assert result.used_peak is False
    assert not list((tmp_path / "c").rglob("*.json"))


# --- end to end: nothing identifying leaves, the report keeps real names ------------------

def test_pipeline_with_redaction_votes_and_metadata(monkeypatch, tmp_path: Path):
    _fast_retry(monkeypatch)
    db = tmp_path / "t.sqlite"
    CdbAdapter(str(db)).insert_events([
        {"timestamp": f"2026-09-01T10:00:0{i}Z", "host": "WS-ALICE-01", "user": "CORP\\alice", "ip": "10.9.8.7",
         "domain": "d.com", "cmdline": f"site=d.com uri=/joomla/x{i}", "native_type": "web_request", "raw_ref": f"w{i}"}
        for i in range(3)
    ])
    poc_path = tmp_path / "poc.json"
    poc_path.write_text(json.dumps({
        "poc_id": "poc-redact", "name": "n", "kind": "ttp", "summary": "s", "topic": "t",
        "able": {"actor": "", "behavior": "b", "location": "web", "evidence": "web telemetry"},
        "research_refs": ["r"], "scope": "s", "max_duration": "3d", "plan": "p", "time_window": WINDOW,
        "steps": [{"step_id": "s1", "description": "d", "target_field": "cmdline", "op": "CONTAINS",
                   "value": "/joomla/", "source_kind": "web"}],
    }), encoding="utf-8")

    sent: list[str] = []
    reply = json.dumps({
        "verdict": "TRUE_POSITIVE", "confidence": 0.9, "rationale": "Scanner <IP_1> hit <HOST_1> as <USER_1>",
        "next_steps": [{"action": "Check <HOST_1>", "why": "w"}], "questions_for_hunter": ["q"], "risks": ["r"],
    })

    async def fake_ask(self, prompt, system):
        sent.append(prompt)
        return reply

    async def fake_prepare(poc, data_document, timeout, use_research, result):
        result.able_markdown, result.hunt_plan_markdown = "ABLE", "PLAN"

    monkeypatch.setattr(PeakLlm, "_ask", fake_ask)
    monkeypatch.setattr("hunting.prepare._peak_prepare", fake_prepare)
    redactor = Redactor()
    llm = PeakLlm(_settings(), tmp_path / "model_config.json", redactor=redactor)
    out = tmp_path / "out"
    run_poc(
        poc_from_file(poc_path), CdbAdapter(str(db)), window=WINDOW, out_dir=out, llm=llm,
        data_document="data", data_source="CDB", redactor=redactor, judge_votes=3, cache_dir=tmp_path / "cache",
    )
    assert len(sent) == 4  # 3 judge votes + 1 advisor
    blob = "\n".join(sent).lower()
    assert "ws-alice" not in blob and "alice" not in blob and "10.9.8.7" not in blob
    data = json.loads((out / "recommendation.json").read_text(encoding="utf-8"))
    assert "WS-ALICE-01" in data["judge"]["rationale"] and "10.9.8.7" in data["judge"]["rationale"]  # restored for the reader
    assert data["next_steps"][0]["action"] == "Check WS-ALICE-01"
    meta = data["meta"]
    assert meta["redacted"] is True and meta["judge_votes"] == 3 and meta["prepare_cache"] == "miss"
    assert meta["model_configured"] == "a" and meta["model_switches"] == []
    assert any("judge_votes" in n for n in data["judge"]["notes"])
    md = (out / "recommendation.md").read_text(encoding="utf-8")
    assert "che host/user/IP" in md and "WS-ALICE-01" in md
