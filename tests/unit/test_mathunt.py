"""Unit tests for heuristic lead scoring (stdlib detectors)."""
from __future__ import annotations

from pathlib import Path

from hunting.mathunt import render_math_report, run_math


def _rows() -> list[dict]:
    rows: list[dict] = []
    for i in range(10):
        rows.append({
            "timestamp": f"2016-08-21T03:0{i}:00Z",
            "native_type": "authentication",
            "host": "we1149srv",
            "user": "admin",
            "cmdline": "Logon Failed",
        })
    rows.append({
        "timestamp": "2016-08-21T08:14:45Z",
        "native_type": "process_creation",
        "host": "we1149srv",
        "user": "alice",
        "image": "powershell.exe",
        "cmdline": "powershell.exe -nop -w hidden -enc QUJD",
    })
    rows.append({
        "timestamp": "2016-08-21T08:14:30Z",
        "native_type": "web_request",
        "host": "we1149srv",
        "user": "alice",
        "domain": "ad.networkfilter.co",
        "cmdline": "method=GET site=ad.networkfilter.co uri=/banner/banner728.gif web-beacon",
    })
    return rows


def test_math_lexical_flags_encoded_powershell(tmp_path: Path):
    result = run_math(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        detectors=["lexical"], ledger_dir=tmp_path,
    )
    kinds = {lead.kind for lead in result.leads}
    assert "lexical" in kinds
    top = result.leads[0]
    assert "encoded-powershell" in top.reasons or "hidden-window" in top.reasons
    assert top.score >= 2.0


def test_math_rare_value_and_sequence(tmp_path: Path):
    result = run_math(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        detectors=["rare_value", "rare_sequence"], ledger_dir=tmp_path,
    )
    kinds = {lead.kind for lead in result.leads}
    assert "rare_value" in kinds
    # alice runs powershell once -> rare sequence
    seqs = [lead for lead in result.leads if lead.kind == "rare_sequence"]
    assert any("powershell.exe" in str(lead.value) for lead in seqs)


def test_math_deterministic_and_ranked(tmp_path: Path):
    kwargs = dict(
        data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        ledger_dir=tmp_path,
    )
    first = run_math(_rows(), run_id="math-a", **kwargs)
    second = run_math(_rows(), run_id="math-b", **kwargs)
    assert [lead.to_dict() for lead in first.leads] == [lead.to_dict() for lead in second.leads]
    scores = [lead.score for lead in first.leads]
    assert scores == sorted(scores, reverse=True)


def test_math_min_score_filters(tmp_path: Path):
    loose = run_math(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        min_score=0.1, ledger_dir=tmp_path,
    )
    strict = run_math(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        min_score=99.0, ledger_dir=tmp_path,
    )
    assert len(loose.leads) >= len(strict.leads)
    assert strict.leads == []


def test_math_report_renders(tmp_path: Path):
    result = run_math(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        ledger_dir=tmp_path,
    )
    report = render_math_report(result)
    assert "# Heuristic Lead Report" in report
    assert "## Leads (ranked)" in report
    assert "## Ledger" in report


def test_math_on_botsv1_sample(tmp_path: Path):
    from hunting.m5_adapter import CdbAdapter
    from scripts.seed_botsv1_sample import BOTS_SAMPLE

    adapter = CdbAdapter(":memory:")
    adapter.insert_events(BOTS_SAMPLE)
    rows = [dict(r) for r in adapter._conn.execute("SELECT * FROM events ORDER BY timestamp ASC")]
    result = run_math(
        rows, data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        ledger_dir=tmp_path,
    )
    assert result.row_count == len(BOTS_SAMPLE)
    texts = " ".join(f"{lead.value} {lead.reasons}" for lead in result.leads)
    assert "powershell" in texts.lower() or "enc" in texts.lower()
