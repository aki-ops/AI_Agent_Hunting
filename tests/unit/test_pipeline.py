"""Tests for the PEAK-driven pipeline: LLM settings, Prepare fallback, recommendation rules, CLI."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunting.adapters.cdb_adapter import CdbAdapter
from hunting.cli import main
from hunting.llm import LlmSettings, LlmUnavailable
from hunting.poc.judge import FALSE_POSITIVE, INCONCLUSIVE, TRUE_POSITIVE, Judgment
from hunting.poc.models import FieldOp, PoC, PocKind, TestStep
from hunting.prepare import run_prepare
from hunting.recommend import (
    CLOSE,
    COLLECT,
    ESCALATE,
    INVESTIGATE,
    TUNE,
    EvidenceSummary,
    StepEvidence,
    advise,
    decide,
)

WINDOW = "2026-09-01T00:00:00Z/2026-09-02T00:00:00Z"


def _poc() -> PoC:
    return PoC(
        poc_id="poc-unit", name="Encoded PowerShell", kind=PocKind.TTP, summary="powershell -enc",
        topic="t", behavior="b", location="l", evidence="process telemetry", scope="s", max_duration="3d",
        plan="p", research_refs=["r"], time_window=WINDOW,
        steps=[
            TestStep("s1", "ps", "image", FieldOp.EQUALS, "powershell.exe", source_kind="process"),
            TestStep("s2", "enc", "cmdline", FieldOp.CONTAINS, "-enc", source_kind="process"),
        ],
    )


def _ev(matched: int, total: int = 2, coverage: int | None = 100, observations: int | None = None) -> EvidenceSummary:
    steps = [
        StepEvidence(f"s{i}", "d", "f OP v", "process", 5 if i < matched else 0, coverage)
        for i in range(total)
    ]
    obs = matched * 5 if observations is None else observations
    return EvidenceSummary(
        window=WINDOW, steps=steps, matched_steps=matched, total_steps=total, observations=obs,
        first_seen="2026-09-01T10:00:00Z" if obs else None, last_seen="2026-09-01T10:05:00Z" if obs else None,
        pivots={"host": [("H1", obs)]} if obs else {}, top_values={}, samples=[],
    )


def _judge(verdict: str, conf: float) -> Judgment:
    return Judgment(verdict=verdict, confidence=conf, rationale="r")


# --- disposition rules -------------------------------------------------------

@pytest.mark.parametrize(
    ("ev", "judge", "disposition", "confidence"),
    [
        (_ev(2), _judge(TRUE_POSITIVE, 0.9), ESCALATE, "MEDIUM"),  # no outcome step: success unproven, capped
        (_ev(2), _judge(TRUE_POSITIVE, 0.75), ESCALATE, "MEDIUM"),
        (_ev(2), _judge(TRUE_POSITIVE, 0.5), INVESTIGATE, "MEDIUM"),  # judge too unsure to move the rule
        (_ev(2), _judge(FALSE_POSITIVE, 0.9), TUNE, "MEDIUM"),
        (_ev(2), _judge(INCONCLUSIVE, 0.9), INVESTIGATE, "MEDIUM"),
        (_ev(2), None, INVESTIGATE, "MEDIUM"),
        (_ev(1), _judge(TRUE_POSITIVE, 0.95), INVESTIGATE, "MEDIUM"),  # partial chain never escalates
        (_ev(1), None, INVESTIGATE, "LOW"),
        (_ev(0, coverage=0), None, COLLECT, "HIGH"),  # no data is not "clean"
        (_ev(0, coverage=500), None, CLOSE, "MEDIUM"),
        (_ev(0, coverage=None), None, CLOSE, "LOW"),
    ],
)
def test_disposition_rules(ev, judge, disposition, confidence):
    rec = decide(_poc(), ev, judge)
    assert (rec.disposition, rec.confidence) == (disposition, confidence)
    assert rec.decision_required is True
    assert rec.options[0].action == disposition
    assert [o.rank for o in rec.options] == list(range(1, len(rec.options) + 1))


def test_escalate_is_high_only_when_an_outcome_field_is_tested():
    poc = _poc()
    poc = PoC(**{**poc.__dict__, "steps": [*poc.steps, TestStep("s3", "ok", "status", FieldOp.EQUALS, "200", source_kind="process")]})
    ev = _ev(3, total=3)
    rec = decide(poc, ev, _judge(TRUE_POSITIVE, 0.9))
    assert (rec.disposition, rec.confidence) == (ESCALATE, "HIGH")


def test_empty_result_never_reads_as_clean_when_source_missing():
    rec = decide(_poc(), _ev(0, coverage=0), None)
    assert rec.disposition == COLLECT
    assert any("KHÔNG có nghĩa là sạch" in r for r in rec.reasons)


# --- advisor -----------------------------------------------------------------

def test_advisor_parses_json_and_survives_garbage():
    rec = decide(_poc(), _ev(2), None)
    reply = '```json\n{"next_steps":[{"action":"Check parent","why":"context"}],"questions_for_hunter":["Is host a server?"],"risks":["miss"]}\n```'
    advise(rec, _poc(), "able", "plan", lambda prompt, n: reply)
    assert rec.next_steps == [{"action": "Check parent", "why": "context"}]
    assert rec.questions_for_hunter == ["Is host a server?"]

    rec2 = decide(_poc(), _ev(2), None)
    advise(rec2, _poc(), "able", "plan", lambda prompt, n: "not json")
    assert rec2.next_steps == [] and "không hợp lệ" in rec2.advisor_note

    def boom(prompt, n):
        raise TimeoutError("x")

    rec3 = decide(_poc(), _ev(2), None)
    advise(rec3, _poc(), "able", "plan", boom)
    assert rec3.next_steps == [] and "lỗi" in rec3.advisor_note
    assert rec3.disposition == rec.disposition  # advisor cannot change the rules' answer


# --- LLM settings / Prepare fallback -----------------------------------------

def test_llm_settings_from_env_file(tmp_path: Path, monkeypatch):
    for key in ("LLM_ENDPOINT", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)
    env = tmp_path / ".env"
    env.write_text("LLM_ENDPOINT=https://example.test/api/v1/chat/completions\nLLM_API_KEY=k\nLLM_MODEL=m\n", encoding="utf-8")
    settings = LlmSettings.from_env(env)
    assert settings.base_url == "https://example.test/api/v1"
    cfg = settings.model_config()
    assert "SECRET-KEY-123" not in json.dumps(cfg)  # secrets stay as ${ENV} placeholders
    assert cfg["providers"]["hunting-llm"]["config"]["api_key"] == "${LLM_API_KEY}"
    assert cfg["defaults"]["model"] == "m"


def test_llm_settings_rejects_placeholders(tmp_path: Path, monkeypatch):
    for key in ("LLM_ENDPOINT", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)
    env = tmp_path / ".env"
    env.write_text("LLM_ENDPOINT=<ENDPOINT-HERE>\nLLM_API_KEY=sk-or-...HERE\nLLM_MODEL=<MODEL-HERE>\n", encoding="utf-8")
    with pytest.raises(LlmUnavailable):
        LlmSettings.from_env(env)


def test_prepare_without_llm_uses_poc_plan_and_says_so():
    result = run_prepare(_poc(), "data doc", None)
    assert result.used_peak is False
    assert "Behavior" in result.able_markdown and "powershell.exe" in result.hunt_plan_markdown
    assert any("not used" in n for n in result.notes)


def test_prepare_degrades_when_peak_agents_fail(monkeypatch):
    class DeadLlm:
        calls = 0
        total_tokens = 0

    async def boom(*args, **kwargs):
        raise RuntimeError("endpoint down")

    monkeypatch.setattr("hunting.prepare._peak_prepare", boom)
    result = run_prepare(_poc(), "data doc", DeadLlm())  # type: ignore[arg-type]
    assert result.used_peak is False
    assert any("attempt 2/2 failed" in n for n in result.notes)
    assert any("fell back" in n for n in result.notes)
    assert result.able_markdown and result.hunt_plan_markdown


def test_prepare_retries_a_transient_peak_failure(monkeypatch):
    class Llm:
        calls = 0
        total_tokens = 0

    state = {"n": 0}

    async def flaky(poc, data_document, timeout, use_research, result):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("404 model_not_found")
        result.able_markdown, result.hunt_plan_markdown = "ABLE", "PLAN"

    monkeypatch.setattr("hunting.prepare._peak_prepare", flaky)
    result = run_prepare(_poc(), "data doc", Llm())  # type: ignore[arg-type]
    assert result.used_peak is True and result.able_markdown == "ABLE"
    assert any("attempt 1/2 failed" in n for n in result.notes)


# --- source coverage on the CDB adapter -------------------------------------

def test_cdb_source_presence_and_description():
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {"timestamp": "2026-09-01T10:00:00Z", "host": "H", "native_type": "process_creation", "image": "a.exe", "raw_ref": "x"},
    ])
    assert adapter.source_presence(WINDOW, "process") == 1
    assert adapter.source_presence(WINDOW, "dns") == 0
    assert adapter.source_presence(WINDOW, "nonsense") is None
    assert "process_creation" in adapter.describe_data()


# --- CLI end to end (offline) ------------------------------------------------

def test_cli_offline_end_to_end(tmp_path: Path):
    db = tmp_path / "t.sqlite"
    adapter = CdbAdapter(str(db))
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:30Z", "host": "DESKTOP-VICTIM1", "user": "CORP\\alice",
            "image": "powershell.exe", "cmdline": "powershell.exe -W Hidden -Enc JABh", "raw_ref": "e1",
            "native_type": "process_creation",
        },
    ])
    poc = {
        "poc_id": "poc-cli-unit", "name": "n", "kind": "ttp", "summary": "s", "topic": "t",
        "able": {"actor": "", "behavior": "b", "location": "l", "evidence": "process telemetry"},
        "research_refs": ["r"], "scope": "s", "max_duration": "3d", "plan": "p", "time_window": WINDOW,
        "steps": [
            {"step_id": "s1", "description": "ps", "target_field": "image", "op": "EQUALS", "value": "powershell.exe", "source_kind": "process"},
            {"step_id": "s2", "description": "enc", "target_field": "cmdline", "op": "CONTAINS", "value": "-enc", "source_kind": "process"},
        ],
    }
    poc_file = tmp_path / "poc.json"
    poc_file.write_text(json.dumps(poc), encoding="utf-8")
    out = tmp_path / "out"
    code = main(["--poc", str(poc_file), "--db", str(db), "--offline", "--out", str(out)])
    assert code == 0
    data = json.loads((out / "poc-cli-unit" / "recommendation.json").read_text(encoding="utf-8"))
    assert data["disposition"] == INVESTIGATE  # chain complete, but no judge in offline mode
    assert data["decision_required"] is True
    assert data["peak"]["used_peak"] is False
    assert (out / "poc-cli-unit" / "recommendation.md").exists()
    assert (out / "summary.md").exists()


def test_cli_requires_a_poc(capsys):
    assert main(["--offline"]) == 2
