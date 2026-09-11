"""Unit and integration tests for the Threat Hunting CLI runner."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from hunting.cli import (
    build_parser,
    create_adhoc_alert,
    parse_alert_from_file_or_content,
    run_cli,
    write_hunt_abort_artifact,
)
from hunting.contracts.hunt import HuntRequest, HuntRequestKind


def test_cli_defaults_to_api_and_auto_discovers_provider():
    """A normal hypothesis invocation must use API LLM and provider discovery."""
    args = build_parser().parse_args([
        "--hypothesis", "Attacker compromised a web server",
    ])
    assert args.llm == "api"
    assert args.provider == "auto"
    assert args.splunk_index == "auto"


def test_parse_alert_from_file_or_content(tmp_path):
    # From JSON string
    alert_json = json.dumps({
        "id": "alt-test-01",
        "source": "sysmon",
        "received_at": "2026-09-01T10:00:00Z",
        "raw": "Suspicious cmd",
        "fields": {"host": "PC-01"},
    })
    alert = parse_alert_from_file_or_content(alert_json)
    assert alert.id == "alt-test-01"
    assert alert.fields["host"] == "PC-01"

    # From file path
    f = tmp_path / "alert.json"
    f.write_text(alert_json, encoding="utf-8")
    alert_from_file = parse_alert_from_file_or_content(str(f))
    assert alert_from_file.id == "alt-test-01"
    assert alert_from_file.source == "sysmon"


def test_create_adhoc_alert():
    alert = create_adhoc_alert(host="HOST-99", user="bob", ip="10.0.0.1", source="firewall")
    assert "HOST-99" in alert.raw
    assert alert.fields["host"] == "HOST-99"
    assert alert.fields["user"] == "bob"
    assert alert.fields["ip"] == "10.0.0.1"
    assert alert.source == "firewall"


def test_cli_execution_with_alert_file(tmp_path):
    parser = build_parser()
    fixture_alert = Path(__file__).parent.parent / "fixtures" / "alert_entity_bearing.json"
    fixture_manifest = Path(__file__).parent.parent / "fixtures" / "registry_cdb.yaml"
    out_report = tmp_path / "out_report.md"

    args = parser.parse_args([
        "--llm", "stub",
        "--alert", str(fixture_alert),
        "--manifest", str(fixture_manifest),
        "--db", "data/cdb_sample.sqlite",
        "--output", str(out_report),
        "--auto-confirm",
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()
    content = out_report.read_text(encoding="utf-8")
    assert "# Threat Investigation Final Report" in content
    assert "Coverage Accounting" in content


def test_cli_execution_with_adhoc_flags(tmp_path):
    parser = build_parser()
    fixture_manifest = Path(__file__).parent.parent / "fixtures" / "registry_cdb.yaml"
    out_report = tmp_path / "adhoc_report.md"

    args = parser.parse_args([
        "--llm", "stub",
        "--host", "DESKTOP-VICTIM1",
        "--user", "CORP\\alice",
        "--manifest", str(fixture_manifest),
        "--db", "data/cdb_sample.sqlite",
        "--output", str(out_report),
        "--auto-confirm",
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()


def test_cli_execution_with_stdin_pipe(tmp_path):
    parser = build_parser()
    fixture_manifest = Path(__file__).parent.parent / "fixtures" / "registry_cdb.yaml"
    out_report = tmp_path / "stdin_report.md"

    stdin_payload = json.dumps({
        "id": "alt-pipe-01",
        "source": "crowdstrike",
        "raw": "Piped alert payload",
        "fields": {"host": "DESKTOP-VICTIM1"},
    })

    args = parser.parse_args([
        "--llm", "stub",
        "--manifest", str(fixture_manifest),
        "--db", "data/cdb_sample.sqlite",
        "--output", str(out_report),
        "--auto-confirm",
    ])

    with patch("sys.stdin.isatty", return_value=False), patch("sys.stdin.read", return_value=stdin_payload):
        exit_code = run_cli(args)
        assert exit_code == 0
        assert out_report.exists()


def test_cli_confirmation_decline_and_accept(tmp_path):
    parser = build_parser()
    fixture_manifest = Path(__file__).parent.parent / "fixtures" / "registry_cdb.yaml"

    # Test 1: Declined confirmation on MALICIOUS alert -> exits with code 2
    args_decline = parser.parse_args([
        "--llm", "stub",
        "--host", "HOST-01",
        "--manifest", str(fixture_manifest),
        "--db", "data/cdb_sample.sqlite",
        "--no-auto-confirm",
    ])
    with patch("builtins.input", return_value="n"):
        exit_code = run_cli(args_decline)
        assert exit_code == 2

    # Test 2: Accepted confirmation on MALICIOUS alert -> exits with code 0
    out_report = tmp_path / "confirmed_report.md"
    args_accept = parser.parse_args([
        "--llm", "stub",
        "--host", "HOST-01",
        "--manifest", str(fixture_manifest),
        "--db", "data/cdb_sample.sqlite",
        "--output", str(out_report),
        "--no-auto-confirm",
    ])
    with patch("builtins.input", return_value="y"):
        exit_code = run_cli(args_accept)
        assert exit_code == 0
        assert out_report.exists()


def test_cli_hypothesis_hunt_with_cve(tmp_path):
    """Test hypothesis hunting execution via CLI with --cve."""
    parser = build_parser()
    out_report = tmp_path / "cve_report.md"

    args = parser.parse_args([
        "--provider", "cdb",
        "--llm", "stub",
        "--cve", "CVE-2024-21887",
        "--host", "WEB-IVANTI-01",
        "--time-window", "2026-02-01T00:00:00Z/P1D",
        "--output", str(out_report),
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()
    content = out_report.read_text(encoding="utf-8")
    assert "# Hunt Report" in content
    assert "CVE-2024-21887" in content


def test_cli_hypothesis_hunt_with_ttp_and_entity(tmp_path):
    """Test hypothesis hunting execution via CLI with --ttp."""
    parser = build_parser()
    out_report = tmp_path / "ttp_report.md"

    args = parser.parse_args([
        "--provider", "cdb",
        "--llm", "stub",
        "--ttp", "T1059.001",
        "--host", "WORKSTATION-01",
        "--output", str(out_report),
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()
    content = out_report.read_text(encoding="utf-8")
    assert "# Hunt Report" in content


def test_cli_hypothesis_hunt_with_query(tmp_path):
    """Test hypothesis hunting execution via CLI with natural language --query."""
    parser = build_parser()
    out_report = tmp_path / "nl_report.md"

    args = parser.parse_args([
        "--provider", "cdb",
        "--llm", "stub",
        "--query", "Investigate abnormal python executions on web servers",
        "--output", str(out_report),
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()
    content = out_report.read_text(encoding="utf-8")
    assert "# Hunt Report" in content


def test_cli_auto_provider_does_not_silently_create_cdb(monkeypatch, capsys):
    """An unavailable Splunk source is explicit, never an empty SQLite hunt."""
    parser = build_parser()
    args = parser.parse_args(["--hypothesis", "Find the suspicious file"])
    monkeypatch.setattr("hunting.cli.SplunkLiveAdapter.is_available", lambda **_: False)

    assert run_cli(args) == 2
    output = capsys.readouterr()
    assert "No telemetry provider was selected" in output.err
    assert "CDB" not in output.out


def test_cli_abort_artifact_replaces_stale_report(tmp_path):
    request = HuntRequest(
        id="req-abort",
        kind=HuntRequestKind.QUESTION,
        content="Find the answer",
    )
    output = tmp_path / "report.md"
    output.write_text("old report from another run", encoding="utf-8")

    write_hunt_abort_artifact(request, str(output), "provider timeout")

    content = output.read_text(encoding="utf-8")
    assert "EXECUTION_FAILED" in content
    assert "Find the answer" in content
    assert "provider timeout" in content
    assert "old report from another run" not in content


def test_cli_hypothesis_hunt_confirmation_gate(tmp_path):
    """Test analyst decision gates during hypothesis hunting with --no-auto-confirm."""
    parser = build_parser()

    # Decline gate -> returns code 2
    args_decline = parser.parse_args([
        "--provider", "cdb",
        "--llm", "stub",
        "--cve", "CVE-2024-21887",
        "--host", "WEB-IVANTI-01",
        "--time-window", "2026-02-01T00:00:00Z/P1D",
        "--no-auto-confirm",
    ])
    with patch("builtins.input", return_value="n"):
        exit_code = run_cli(args_decline)
        assert exit_code == 2

    # Accept gate -> returns code 0 and produces report
    out_report = tmp_path / "confirmed_hunt.md"
    args_accept = parser.parse_args([
        "--provider", "cdb",
        "--llm", "stub",
        "--cve", "CVE-2024-21887",
        "--host", "WEB-IVANTI-01",
        "--time-window", "2026-02-01T00:00:00Z/P1D",
        "--output", str(out_report),
        "--no-auto-confirm",
    ])
    with patch("builtins.input", return_value="y"):
        exit_code = run_cli(args_accept)
        assert exit_code == 0
        assert out_report.exists()
