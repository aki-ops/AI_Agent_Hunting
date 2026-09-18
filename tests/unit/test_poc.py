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


def _stub_judge_tp(prompt: str, max_tokens: int) -> str:
    return json.dumps({
        "verdict": "TRUE_POSITIVE",
        "confidence": 0.85,
        "rationale": "Parent image is OUTLOOK.EXE, user is interactive, time matches email arrival.",
        "notes": ["parent=outlook", "user=interactive"],
    })


def _stub_judge_fp(prompt: str, max_tokens: int) -> str:
    return json.dumps({
        "verdict": "FALSE_POSITIVE",
        "confidence": 0.9,
        "rationale": "Parent is Microsoft Configuration Manager, scheduled baseline deployment.",
        "notes": ["parent=sccm"],
    })


def test_judge_disabled_by_default(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.judgment is None
    assert result.judgment_llm_calls == 0


def test_judge_true_positive(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_tp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.judgment is not None
    assert result.judgment.verdict == "TRUE_POSITIVE"
    assert result.judgment.confidence == 0.85
    assert "outlook" in result.judgment.rationale.lower()


def test_judge_false_positive_admin_script(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:30Z",
            "host": "SCCM-SERVER",
            "user": "CORP\\svc_admin",
            "image": "powershell.exe",
            "cmdline": "powershell.exe -NoP -W Hidden -Enc Zm9v",
            "parent_image": "C:\\Program Files\\Microsoft Configuration Manager\\bin\\CmRcViewer.exe",
            "raw_ref": "sccm-001",
            "native_type": "process",
        }
    ])
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_fp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "MATCHED"
    assert result.judgment.verdict == "FALSE_POSITIVE"
    assert result.judgment.confidence == 0.9


def test_judge_no_signal_when_empty(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_tp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert result.verdict == "EMPTY"
    assert result.judgment.verdict == "NO_SIGNAL"
    assert result.judgment_llm_calls == 0


def test_judge_parser_handles_malformed_response():
    from hunting.poc import parse_judgment
    j = parse_judgment("not even json")
    assert j.verdict == "INCONCLUSIVE"
    assert j.confidence == 0.0


def test_judge_parser_strips_markdown_fence():
    from hunting.poc import parse_judgment
    raw = "```json\n{\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.7,\"rationale\":\"x\"}\n```"
    j = parse_judgment(raw)
    assert j.verdict == "FALSE_POSITIVE"
    assert j.confidence == 0.7


def test_judge_parser_rejects_unknown_verdict():
    from hunting.poc import parse_judgment
    j = parse_judgment(json.dumps({"verdict": "MAYBE", "confidence": 0.5}))
    assert j.verdict == "INCONCLUSIVE"


def test_judge_report_section(tmp_path: Path):
    adapter = CdbAdapter(":memory:")
    _seed_cdb(adapter)
    agent = PocAgent(
        adapter=adapter,
        ledger_dir=tmp_path,
        judge_caller=_stub_judge_tp,
        enable_judge=True,
    )
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    poc_render = get_poc(result.poc_id).render()
    report = render_poc_report(result, poc_render)
    assert "LLM Judge" in report
    assert "TRUE_POSITIVE" in report


def test_poc_file_loads_and_registers(tmp_path: Path):
    """An analyst-authored PoC in JSON form is registered in the library."""
    from hunting.poc import poc_from_file, list_pocs

    spec = tmp_path / "my-poc.json"
    spec.write_text(
        """{
            "poc_id": "poc-my-test",
            "name": "Test JSON PoC",
            "kind": "behavior",
            "summary": "demo",
            "steps": [
                {"step_id": "s1", "description": "x", "target_field": "user", "op": "EQUALS", "value": "admin", "source_kind": "process"}
            ],
            "references": ["MITRE T1110"]
        }""",
        encoding="utf-8",
    )

    before = {p.poc_id for p in list_pocs()}
    poc = poc_from_file(spec)
    after = {p.poc_id for p in list_pocs()}
    assert poc.poc_id == "poc-my-test"
    assert "poc-my-test" not in before
    assert "poc-my-test" in after
    assert poc.kind.value == "behavior"
    assert poc.steps[0].value == "admin"
    assert poc.references == ["MITRE T1110"]


def test_poc_file_rejects_invalid_kind(tmp_path: Path):
    from hunting.poc import poc_from_file

    spec = tmp_path / "bad.json"
    spec.write_text(
        """{"poc_id": "poc-bad", "name": "x", "kind": "wrong", "summary": "x", "steps": [{"step_id": "s1", "description": "x", "target_field": "user", "op": "EQUALS", "value": "x", "source_kind": "process"}]}""",
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        poc_from_file(spec)


def test_poc_file_rejects_invalid_op(tmp_path: Path):
    from hunting.poc import poc_from_file

    spec = tmp_path / "bad-op.json"
    spec.write_text(
        """{"poc_id": "poc-badop", "name": "x", "kind": "ttp", "summary": "x", "steps": [{"step_id": "s1", "description": "x", "target_field": "user", "op": "WILDCARD", "value": "x", "source_kind": "process"}]}""",
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        poc_from_file(spec)


def test_analytic_poc_runs_against_botsv1_sample(tmp_path: Path):
    """An analyst PoC loaded from JSON finds the BOTS v1 brute-force rows."""
    from hunting.m5_adapter import CdbAdapter
    from hunting.poc import poc_from_file
    from scripts.seed_botsv1_sample import BOTS_SAMPLE

    adapter = CdbAdapter(":memory:")
    adapter.insert_events(BOTS_SAMPLE)

    spec = tmp_path / "bruteforce.json"
    spec.write_text(
        """{
            "poc_id": "poc-bruteforce-test",
            "name": "BF test",
            "kind": "behavior",
            "summary": "BOTS v1 brute force",
            "steps": [{"step_id": "s1-failed", "description": "Failed logon",
                       "target_field": "action", "op": "EQUALS",
                       "value": "Logon Failed", "source_kind": "authentication"}],
            "references": ["MITRE T1110"]
        }""",
        encoding="utf-8",
    )

    poc = poc_from_file(spec)
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run(
        poc.poc_id,
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
    )
    assert result.verdict == "MATCHED"
    assert result.total_observations >= 5
