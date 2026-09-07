"""Unit tests for Phase 4 & 6: Two-tier reporting, forensic CLI commands, and proportional recommendations."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunting.cli import handle_replay_query, handle_show_observation
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    EvidenceCard,
    HuntObjective,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_analyst_report, render_final_hunt_account


def test_two_tier_reporting_does_not_dump_hundreds_of_observation_ids():
    """When hundreds of observations are cited, report truncates the list and points to observations.jsonl."""
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "main"})
    obs_list = [
        Observation(
            id=f"obs-bulk-{i:04d}",
            provider_scope=scope,
            cell_id="c1",
            timestamp="2026-09-01T12:00:00Z",
            epistemic_type=EpistemicType.OBSERVED,
            fields={"host": "we1149srv"},
        )
        for i in range(100)
    ]

    card = EvidenceCard(
        id="card-1",
        fingerprint="fp-1",
        fact_type="process_execution",
        summary="php-cgi.exe spawned cmd.exe on we1149srv",
        why_it_matters="High-fidelity webshell execution indicator",
        count=100,
        representative_observation_ids=[o.id for o in obs_list[:5]],
        field_summary={"cmdlines": ["whoami", "tasklist"]},
        entity_summary={"hosts": ["we1149srv"]},
    )

    state = HuntState(
        objective=HuntObjective(request_id="hunt-bulk-01", statement="Web compromise audit"),
        hypotheses=[
            Hypothesis(
                id="hyp-1",
                statement="Web shell execution",
                status=HypothesisStatus.SUPPORTED,
            )
        ],
        evidence_cards=[card],
        observations=obs_list,
        stopping_decision=StoppingDecision.STOP_RESOLVED,
    )

    account = build_final_hunt_account(state)
    report = render_final_hunt_account(account)

    # Core sections check
    assert "### What Was Found" in report
    assert "### Why This Matters" in report
    assert "### Missing Evidence & Telemetry Gaps" in report
    assert "php-cgi.exe spawned cmd.exe on we1149srv" in report
    assert "High-fidelity webshell execution indicator" in report

    # Invariant: Must NOT dump all 100 observations into the text
    assert "obs-bulk-0000" in report
    assert "obs-bulk-0009" in report
    assert "obs-bulk-0099" not in report
    assert "additional observations stored in audit artifact `observations.jsonl`" in report


def test_analyst_report_answers_lookup_and_keeps_only_useful_sections():
    card = EvidenceCard(
        id="card-domain",
        fingerprint="fp-domain",
        fact_type="web_request",
        summary="",
        why_it_matters="Direct web telemetry contains the requested domain.",
        count=12,
        field_summary={"domains": ["store.froth.ly"]},
        representative_observation_ids=["obs-1", "obs-2"],
    )
    state = HuntState(
        objective=HuntObjective(
            request_id="hunt-lookup",
            statement="What is the website domain that Amber Turing visited?",
            answer_spec={
                "mode": "lookup",
                "answer_type": "domain",
                "evidence_types": ["web_request"],
            },
        ),
        hypotheses=[Hypothesis(id="h1", statement="Visited website", status=HypothesisStatus.SUPPORTED)],
        evidence_cards=[card],
        queries=[],
        stopping_decision=StoppingDecision.STOP_RESOLVED,
        llm_usage={"model": "test", "calls_made": 1, "total_tokens": 20, "estimated_cost_usd": 0.001},
    )
    account = build_final_hunt_account(state)
    report = render_analyst_report(account)

    assert "**Answer (domain):** `store.froth.ly`" in report
    assert "## 1. Hypothesis / Question" in report
    assert "## 2. Hypothesis analysis" in report
    assert "## 3. Evidence and explanation" in report
    assert "## 4. Queries used" in report
    assert "## 5. Cost" in report
    assert "obs-1" in report
    assert "## 1. Coverage Accounting" not in report


def test_proportional_recommendations_tiering():
    """Recommendations scale proportionally between Monitoring, Investigation, and Containment."""
    # 1. Inconclusive State -> Tier 1 Monitoring only
    state_inconclusive = HuntState(
        objective=HuntObjective(request_id="hunt-inc", statement="Inconclusive audit"),
        hypotheses=[Hypothesis(id="h1", statement="Unconfirmed threat", status=HypothesisStatus.WEAKENED)],
        stopping_decision=StoppingDecision.STOP_EXHAUSTED_BY_BUDGET,
    )
    acc_inc = build_final_hunt_account(state_inconclusive)
    rep_inc = render_final_hunt_account(acc_inc)
    assert "Tier 1 — Monitoring & Telemetry Enhancement" in rep_inc
    assert "No Containment Actions Warranted" in rep_inc
    assert "Endpoint Isolation" not in rep_inc

    # 2. Supported State -> Tier 3 Containment with analyst sign-off
    card = EvidenceCard(
        id="c1",
        fingerprint="fp1",
        fact_type="process_execution",
        summary="Malicious execution",
        entity_summary={"hosts": ["victim-srv"]},
    )
    state_supported = HuntState(
        objective=HuntObjective(request_id="hunt-supp", statement="Confirmed attack"),
        hypotheses=[Hypothesis(id="h2", statement="Confirmed threat", status=HypothesisStatus.SUPPORTED)],
        evidence_cards=[card],
        stopping_decision=StoppingDecision.STOP_RESOLVED,
    )
    acc_supp = build_final_hunt_account(state_supported)
    rep_supp = render_final_hunt_account(acc_supp)
    assert "Tier 3 — Containment & Active Threat Neutralization (Analyst Sign-off Required)" in rep_supp
    assert "Tier 2 — Targeted Investigation & Forensic Preservation" in rep_supp
    assert "Tier 1 — Continuous Monitoring & Detection Tuning" in rep_supp


def test_cli_show_observation_and_replay_query_handlers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Forensic CLI handlers show-observation and replay-query read from hunt artifacts."""
    artifacts_dir = tmp_path / "artifacts"
    hunt_dir = artifacts_dir / "hunt-test-001"
    hunt_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create observations.jsonl
    obs_record = {
        "observation_id": "obs-forensic-101",
        "timestamp": "2026-09-01T12:00:00Z",
        "native_type": "WinEventLog:Security",
        "scope_id": "botsv1",
        "query_id": "q-101",
        "fields": {"host": "we1149srv", "cmdline": "whoami"},
        "raw_event": {"EventCode": 4688, "CommandLine": "whoami", "SubjectUserName": "SYSTEM"},
    }
    with open(hunt_dir / "observations.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps(obs_record, ensure_ascii=False) + "\n")

    # 2. Create queries.json
    queries_data = [
        {
            "query_id": "q-101",
            "requirement_id": "req-proc",
            "provider_id": "splunk",
            "operation_id": "cdb_process_lineage",
            "parameters": {"window": "2026-09-01/P1D"},
            "query_text": 'search index=botsv1 "whoami"',
        }
    ]
    with open(hunt_dir / "queries.json", "w", encoding="utf-8") as f:
        json.dump(queries_data, f, indent=2, ensure_ascii=False)

    monkeypatch.chdir(tmp_path)

    # Test show-observation handler
    ret_obs = handle_show_observation("hunt-test-001", "obs-forensic-101")
    assert ret_obs == 0

    # Test replay-query handler
    ret_q = handle_replay_query("hunt-test-001", "q-101")
    assert ret_q == 0
