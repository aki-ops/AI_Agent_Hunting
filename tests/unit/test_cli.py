"""Unit and integration tests for the Threat Hunting CLI runner."""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from hunting.cli import (
    _collect_semantic_candidate_options,
    _read_candidate_choice,
    build_parser,
    render_hunt_playbook,
    run_cli,
    write_hunt_abort_artifact,
)
from hunting.contracts.bindings import CandidateBinding, CandidateSet
from hunting.contracts.hunt import HuntRequest, HuntRequestKind, Hypothesis


def test_plan_only_playbook_does_not_construct_a_provider(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("plan-only must not construct SplunkLiveAdapter")

    monkeypatch.setattr("hunting.cli.SplunkLiveAdapter", forbidden)
    request = HuntRequest(id="req-plan", kind=HuntRequestKind.HYPOTHESIS, content="A service account is used interactively")
    hypothesis = Hypothesis(id="h1", statement="A service account is used interactively")
    output = tmp_path / "playbook.md"
    render_hunt_playbook(request, SimpleNamespace(), [hypothesis], [], "NOW-14d/NOW", str(output))
    text = output.read_text(encoding="utf-8")
    assert "PLAN_ONLY" in text
    assert "```spl" not in text
    assert "deferred until Prepare" in text or "not compiled in plan-only" in text


def test_invalid_prepare_override_stops_before_provider(tmp_path, monkeypatch, capsys):
    plan = tmp_path / "plan.yaml"
    plan.write_text("decision_criteria:\n  min_coverage_to_refute: 2\n", encoding="utf-8")

    def forbidden(**_kwargs):
        raise AssertionError("provider audit must not run when Prepare is invalid")

    monkeypatch.setattr("hunting.cli.SplunkLiveAdapter.is_available", forbidden)
    args = build_parser().parse_args([
        "--hypothesis", "A service account is used for interactive logon",
        "--hunt-plan", str(plan),
        "--provider", "auto",
        "--llm", "stub",
    ])
    assert run_cli(args) == 2
    assert "PREPARE" in capsys.readouterr().err


def test_cli_rejects_removed_hunt_modes():
    parser = build_parser()
    for flag in ("--poc", "--cve", "--ttp", "--ioc", "--alert", "--legacy", "--threat-actor", "--campaign"):
        with pytest.raises(SystemExit):
            parser.parse_args([flag, "sample"])


def test_cli_parses_hypothesis_and_splunk_insecure():
    args = build_parser().parse_args([
        "--hypothesis", "A service account is used for interactive logon",
        "--splunk-insecure",
    ])
    assert args.hypothesis.startswith("A service account")
    assert args.splunk_insecure is True
    from hunting.cli import _cli_splunk_verify_ssl
    assert _cli_splunk_verify_ssl(args) is False


def test_cli_dotenv_setdefault_does_not_override(monkeypatch, tmp_path):
    from hunting.cli import _apply_dotenv_setdefault

    env_file = tmp_path / ".env"
    env_file.write_text("SPLUNK_VERIFY_SSL=false\nCUSTOM_HUNT_FLAG=from-file\n", encoding="utf-8")
    monkeypatch.setenv("CUSTOM_HUNT_FLAG", "already-set")
    monkeypatch.delenv("SPLUNK_VERIFY_SSL", raising=False)
    _apply_dotenv_setdefault(str(env_file))
    assert os.environ["CUSTOM_HUNT_FLAG"] == "already-set"
    assert os.environ["SPLUNK_VERIFY_SSL"] == "false"


def test_cli_defaults_to_api_and_auto_discovers_provider():
    """A normal hypothesis invocation must use API LLM and provider discovery."""
    args = build_parser().parse_args([
        "--hypothesis", "Attacker compromised a web server",
    ])
    assert args.llm == "api"
    assert args.provider == "auto"
    assert args.splunk_index == "auto"


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


def test_cli_candidate_options_use_candidate_set_and_deduplicate_provenance():
    candidate_set = CandidateSet(variable_id="endpoint", entity_type="endpoint", cardinality="singular")
    candidate_set.add_candidate(CandidateBinding(value="host-a", entity_type="endpoint"))
    candidate_set.add_candidate(CandidateBinding(value="host-b", entity_type="endpoint"))
    result = SimpleNamespace(
        state=SimpleNamespace(candidate_sets={"endpoint": candidate_set}),
        account=SimpleNamespace(candidate_sets={}),
    )
    options = _collect_semantic_candidate_options(result, {"endpoint": "endpoint"})
    assert options == [
        ("endpoint", "host-a", "endpoint"),
        ("endpoint", "host-b", "endpoint"),
    ]


def test_cli_candidate_options_fallback_to_deduplicated_provenance():
    result = SimpleNamespace(
        state=SimpleNamespace(candidate_sets={}),
        account=SimpleNamespace(
            candidate_sets={},
            semantic_analysis={
                "binding_provenance": {
                    "endpoint": [
                        {"value": "host-a", "status": "CANDIDATE"},
                        {"value": "host-a", "status": "CANDIDATE"},
                        {"value": "host-b", "status": "CANDIDATE"},
                    ],
                },
            },
        ),
    )
    assert _collect_semantic_candidate_options(result, {"endpoint": "endpoint"}) == [
        ("endpoint", "host-a", "endpoint"),
        ("endpoint", "host-b", "endpoint"),
    ]


def test_cli_candidate_choice_eof_means_stop_without_exception():
    with patch("builtins.input", side_effect=EOFError):
        assert _read_candidate_choice("choose: ") == ""


def test_cli_hypothesis_hunt_confirmation_gate(tmp_path):
    """Analyst decision gates still apply to a free-text hypothesis."""
    parser = build_parser()
    hypothesis = tmp_path / "hypothesis.yaml"
    hypothesis.write_text(
        "statement: Adversary ran an unusual process on the host\n"
        "requirements:\n"
        "  - id: req-1\n"
        "    description: process execution\n"
        "    evidence_type: process_ancestry\n"
        "    falsification_condition: no matching process\n",
        encoding="utf-8",
    )
    common = [
        "--provider", "cdb",
        "--llm", "stub",
        "--hypothesis-file", str(hypothesis),
        "--host", "WEB-IVANTI-01",
        "--time-window", "2026-02-01T00:00:00Z/P1D",
        "--no-auto-confirm",
    ]

    args_decline = parser.parse_args(common)
    with patch("builtins.input", return_value="n"):
        assert run_cli(args_decline) == 2

    out_report = tmp_path / "confirmed_hunt.md"
    args_accept = parser.parse_args([*common, "--output", str(out_report)])
    with patch("builtins.input", return_value="y"):
        assert run_cli(args_accept) == 0
        assert out_report.exists()
