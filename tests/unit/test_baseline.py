"""Unit tests for baseline survey (EDA)."""
from __future__ import annotations

from pathlib import Path

from hunting.baseline import render_baseline_report, run_baseline
from hunting.m5_adapter.cdb_adapter import CdbAdapter


def _rows() -> list[dict]:
    rows: list[dict] = []
    for i in range(10):
        rows.append({
            "timestamp": f"2016-08-21T03:0{i}:00Z",
            "native_type": "authentication",
            "host": "we1149srv",
            "user": "admin" if i < 9 else "root",
            "cmdline": "Logon Failed",
            "image": None,
        })
    rows.append({
        "timestamp": "2016-08-21T08:14:45Z",
        "native_type": "process_creation",
        "host": "we1149srv",
        "user": "alice",
        "cmdline": "powershell.exe -enc QUJD",
        "image": "powershell.exe",
    })
    return rows


def test_baseline_profiles_security_fields(tmp_path: Path):
    result = run_baseline(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        ledger_dir=tmp_path,
    )
    assert result.row_count == 11
    names = {f.name for f in result.fields}
    assert {"host", "user", "native_type"} <= names
    host = next(f for f in result.fields if f.name == "host")
    assert host.non_null == 11
    assert host.distinct == 1
    assert host.top_values[0] == {"value": "we1149srv", "count": 11}
    assert result.ledger_path is not None
    assert Path(result.ledger_path).exists()


def test_baseline_stack_counting_finds_rare_values(tmp_path: Path):
    result = run_baseline(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        rare_threshold=2, ledger_dir=tmp_path,
    )
    rare = {(o.field, str(o.value)) for o in result.outliers if o.reason == "rare_value"}
    assert ("user", "root") in rare
    assert ("image", "powershell.exe") in rare
    # common values are not outliers
    assert ("host", "we1149srv") not in rare


def test_baseline_gap_analysis(tmp_path: Path):
    rows = [{"timestamp": "2016-08-21T01:00:00Z", "host": None, "user": None}]
    result = run_baseline(
        rows, data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        fields=["host", "user"], ledger_dir=tmp_path,
    )
    assert any("host" in g for g in result.gaps)
    assert any("no host attribution" in g for g in result.gaps)


def test_baseline_relationships(tmp_path: Path):
    result = run_baseline(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        ledger_dir=tmp_path,
    )
    pairs = [r for r in result.relationships if r["fields"] == ["host", "native_type"]]
    assert pairs
    assert pairs[0]["top_pairs"][0] == {"pair": "we1149srv :: authentication", "count": 10}


def test_baseline_report_renders(tmp_path: Path):
    result = run_baseline(
        _rows(), data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        ledger_dir=tmp_path,
    )
    report = render_baseline_report(result)
    assert "# Baseline Report" in report
    assert "## Data Dictionary" in report
    assert "## Distributions" in report
    assert "## Outliers" in report
    assert "## Gap Analysis" in report
    assert "## Relationships" in report


def test_baseline_runs_on_botsv1_sample(tmp_path: Path):
    from scripts.seed_botsv1_sample import BOTS_SAMPLE

    adapter = CdbAdapter(":memory:")
    adapter.insert_events(BOTS_SAMPLE)
    cur = adapter._conn.execute("SELECT * FROM events ORDER BY timestamp ASC")
    rows = [dict(r) for r in cur.fetchall()]
    result = run_baseline(
        rows, data_source="cdb:events",
        time_window="2016-08-21T00:00:00Z/2016-08-22T00:00:00Z",
        ledger_dir=tmp_path,
    )
    assert result.row_count == len(BOTS_SAMPLE)
    # schtasks.exe appears once in the sample -> rare-value outlier;
    # powershell.exe x3 is above the default rare threshold of 2.
    assert any(o.value == "schtasks.exe" for o in result.outliers)
    assert not any(o.value == "powershell.exe" and o.reason == "rare_value" for o in result.outliers)
