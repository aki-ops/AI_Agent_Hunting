"""Unit tests for the PoC-driven Auto-Hunt Agent."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunting.controller.cost import LLMUsageTracker
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.poc import PocAgent, get_poc, list_pocs, render_poc_report


def test_library_exposes_expected_pocs():
    pocs = list_pocs()
    ids = {p.poc_id for p in pocs}
    assert "poc-phishing-powershell-enc" in ids
    assert "poc-c2-beacon" in ids
    assert "poc-office-macro" in ids
    assert "poc-credential-phish" in ids


def test_get_poc_raises_on_unknown_id():
    with pytest.raises(KeyError):
        get_poc("not-a-real-poc")


def test_poc_steps_have_required_fields():
    for poc in list_pocs():
        assert poc.name
        assert poc.summary
        assert poc.steps, f"{poc.poc_id} has no steps"
        for step in poc.steps:
            assert step.step_id
            assert step.target_field
            assert step.value is not None
            assert step.op


def test_poc_renders_to_dict():
    poc = get_poc("poc-phishing-powershell-enc")
    render = poc.render()
    assert render["poc_id"] == "poc-phishing-powershell-enc"
    assert render["kind"] == "ttp"
    assert len(render["steps"]) == 3


def _seed_cdb(adapter: CdbAdapter) -> None:
    """Insert one matching row and one negative row for the PowerShell PoC."""
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:30Z",
            "host": "DESKTOP-VICTIM1",
            "user": "CORP\\alice",
            "image": "powershell.exe",
            "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc JABhID0A...",
            "raw_ref": "edr-001",
            "native_type": "process",
        },
        {
            "timestamp": "2026-09-01T11:00:00Z",
            "host": "OTHER-HOST",
            "user": "CORP\\bob",
            "image": "notepad.exe",
            "cmdline": "notepad.exe",
            "raw_ref": "edr-002",
            "native_type": "process",
        },
    ])


def test_poc_agent_runs_against_cdb(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)

    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")

    assert result.verdict == "MATCHED"
    assert result.total_observations >= 1
    assert "s1-powershell-enc" in result.matched_step_ids
    assert "s2-powershell-hidden" in result.matched_step_ids
    assert "s3-powershell-encoded" in result.matched_step_ids
    assert result.llm_calls == 0
    assert result.ledger_path is not None

    ledger = json.loads(Path(result.ledger_path).read_text(encoding="utf-8"))
    assert "graph" in ledger
    assert "result" in ledger
    assert ledger["result"]["verdict"] == "MATCHED"


def test_poc_agent_empty_no_escalation(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:30Z",
            "host": "DESKTOP-VICTIM1",
            "user": "CORP\\alice",
            "image": "notepad.exe",
            "cmdline": "notepad.exe",
            "raw_ref": "edr-002",
            "native_type": "process",
        }
    ])
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "EMPTY"
    assert result.llm_calls == 0


def test_poc_agent_escalates_when_empty(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    tracker = LLMUsageTracker(model_name="stub")

    def fake_llm(question: str, max_tokens: int) -> str:
        return "No encoded PowerShell observed in the window."

    agent = PocAgent(adapter=adapter, llm_caller=fake_llm, llm_tracker=tracker, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "ESCALATED"
    assert result.llm_calls == 1
    assert result.escalation_called is True
    assert tracker.call_count == 1


def test_poc_chain_runs_multiple_pocs(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    results = agent.run_chain(
        ["poc-phishing-powershell-enc", "poc-c2-beacon"],
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
    )
    assert len(results) == 2
    assert results[0].poc_id == "poc-phishing-powershell-enc"
    assert results[1].poc_id == "poc-c2-beacon"


def test_poc_report_renders_markdown(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    poc_render = get_poc(result.poc_id).render()
    report = render_poc_report(result, poc_render)
    assert "# PoC Hunt Report" in report
    assert "MATCHED" in report
    assert "powershell.exe" in report
