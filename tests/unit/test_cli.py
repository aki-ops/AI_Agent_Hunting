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
)


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
        "--cve", "CVE-2024-21887",
        "--host", "WEB-IVANTI-01",
        "--time-window", "2026-02-01T00:00:00Z/P1D",
        "--output", str(out_report),
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()
    content = out_report.read_text(encoding="utf-8")
    assert "Threat Hunting Investigation Final Account" in content
    assert "CVE-2024-21887" in content


def test_cli_hypothesis_hunt_with_ttp_and_entity(tmp_path):
    """Test hypothesis hunting execution via CLI with --ttp."""
    parser = build_parser()
    out_report = tmp_path / "ttp_report.md"

    args = parser.parse_args([
        "--ttp", "T1059.001",
        "--host", "WORKSTATION-01",
        "--output", str(out_report),
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()
    content = out_report.read_text(encoding="utf-8")
    assert "Threat Hunting Investigation Final Account" in content


def test_cli_hypothesis_hunt_with_query(tmp_path):
    """Test hypothesis hunting execution via CLI with natural language --query."""
    parser = build_parser()
    out_report = tmp_path / "nl_report.md"

    args = parser.parse_args([
        "--query", "Investigate abnormal python executions on web servers",
        "--output", str(out_report),
    ])

    exit_code = run_cli(args)
    assert exit_code == 0
    assert out_report.exists()
    content = out_report.read_text(encoding="utf-8")
    assert "Threat Hunting Investigation Final Account" in content

