"""Unit tests for PEAK Act (detection drafts, backlog, stakeholder)."""
from __future__ import annotations

from pathlib import Path

from hunting.act import (
    backlog_from_baseline,
    backlog_from_math,
    backlog_from_poc,
    spl_from_lead,
    spl_from_outlier,
    spl_from_poc_steps,
    stakeholder_summary,
)


def test_spl_from_poc_steps():
    spl = spl_from_poc_steps([
        {"target_field": "image", "op": "EQUALS", "value": "powershell.exe"},
        {"target_field": "cmdline", "op": "CONTAINS", "value": "-Enc"},
        {"target_field": "image", "op": "EXISTS", "value": ""},
    ])
    assert 'image="powershell.exe"' in spl
    assert 'match(cmdline, "(?i)-Enc")' in spl
    assert 'NOT image=""' in spl
    assert spl.startswith("search index=")


def test_spl_from_lead_sequence():
    spl = spl_from_lead({"field": "sequence", "value": "outlook.exe -> powershell.exe", "kind": "rare_sequence"})
    assert "outlook.exe" in spl and "powershell.exe" in spl


def test_spl_from_outlier():
    spl = spl_from_outlier({"field": "image", "value": "schtasks.exe"})
    assert 'image="schtasks.exe"' in spl
    assert "stats count by" in spl


def test_backlog_from_poc_flags_missed_steps():
    items = backlog_from_poc(
        {"topic": "t", "able": {"behavior": "b"}},
        matched_step_ids=["s1"],
        all_step_ids=["s1", "s2"],
    )
    assert any("s2" in i for i in items)
    assert any("Backlog" in i for i in items)


def test_backlog_from_baseline_and_math():
    assert backlog_from_baseline(
        [{"field": "image", "value": "x.exe", "count": 1, "reason": "rare_value"}],
        ["field 'domain' has no values"],
    )
    assert backlog_from_math(
        [{"lead_id": "lead-001", "kind": "lexical", "score": 6.5}],
    )


def test_stakeholder_summary_next_step_per_kind():
    assert any("detection draft" in b for b in stakeholder_summary("poc", "h", []))
    assert any("playbook" in b for b in stakeholder_summary("baseline", "h", []))
    assert any("adjudicate" in b for b in stakeholder_summary("math", "h", []))


def test_poc_report_has_act_section(tmp_path: Path):
    from hunting.m5_adapter import CdbAdapter
    from hunting.poc import PocAgent, get_poc, render_poc_report

    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-09-01T10:14:30Z", "host": "H", "user": "u",
        "image": "powershell.exe",
        "cmdline": "powershell.exe -NoP -W Hidden -Enc AAA",
        "raw_ref": "e1", "native_type": "process",
    }])
    agent = PocAgent(adapter=adapter, ledger_dir=tmp_path)
    result = agent.run("poc-phishing-powershell-enc", time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    report = render_poc_report(result, get_poc(result.poc_id).render())
    assert "## PEAK Act" in report
    assert "Detection Draft" in report
    assert "Stakeholder Summary" in report
    assert "```spl" in report


def test_baseline_and_math_reports_have_act(tmp_path: Path):
    from hunting.baseline import render_baseline_report, run_baseline
    from hunting.mathunt import render_math_report, run_math

    rows = [
        {"timestamp": "2016-08-21T01:00:00Z", "host": "h1", "user": "u1", "image": "a.exe"},
        {"timestamp": "2016-08-21T02:00:00Z", "host": "h1", "user": "u1", "image": "b.exe"},
    ]
    brep = render_baseline_report(run_baseline(
        rows, data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z", ledger_dir=tmp_path))
    assert "## PEAK Act" in brep
    mrep = render_math_report(run_math(
        rows + [{"timestamp": "2016-08-21T03:00:00Z", "host": "h1", "user": "u1",
                 "image": "powershell.exe", "cmdline": "powershell -enc AAA"}],
        data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z", ledger_dir=tmp_path))
    assert "## PEAK Act" in mrep
