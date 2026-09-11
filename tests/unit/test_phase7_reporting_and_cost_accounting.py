"""Unit tests for Phase 7: Report, Tracing, Machine Run Account, and Cost Accounting.

Covers:
- Unified StepTrace (Step A through Step J)
- Financial Cost Accounting formula C_run = C_llm + C_splunk + C_control + C_analyst
- Machine run_account.json emission
- Aborted run failure artifact emission tied to active request_id
- 6-part human report generation
"""
from __future__ import annotations

import json
from pathlib import Path

from hunting.contracts.coverage import CoverageBound
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntObjective,
    HuntOutcome,
    Hypothesis,
    StoppingDecision,
    StoppingTaxonomyState,
)
from hunting.contracts.step_trace import HuntStepName, StepTrace
from hunting.reporter.account_exporter import (
    RunCostAccounting,
    emit_aborted_run_account,
    emit_machine_run_account,
    render_six_part_report,
)


def _sample_account(req_id: str = "req-test-p7") -> FinalHuntAccount:
    obj = HuntObjective(request_id=req_id, statement="Find Tor Browser Version")
    return FinalHuntAccount(
        request_id=req_id,
        objective=obj,
        hypotheses=[Hypothesis(id="h1", statement="Tor installed")],
        evidence_cards=[],
        queries=[
            {
                "query_id": "q1",
                "native_query": 'search index="main" Image="*tor.exe*" | head 10',
                "executed_ok": True,
                "row_count": 5,
                "scan_count": 500,
            }
        ],
        supporting=["h1"],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_RESOLVED,
        observation_citations=["obs-1", "obs-2"],
        answer={"status": "ANSWERED", "value": "12.0.1", "explanation": "Tor version 12.0.1 confirmed"},
        llm_usage={"estimated_cost_usd": 0.0035, "calls_made": 2, "total_tokens": 1500},
        validated_graph={"kind": "validated_graph"},
        validation_diagnostics=[],
    )


def test_step_trace_records_steps_a_through_j() -> None:
    """Verify unified StepTrace records lifecycle steps from Freeze Request (A) through Stop (J)."""
    trace = StepTrace(request_id="req-trace-1")
    trace.record_step(HuntStepName.STEP_A_FREEZE_REQUEST, duration_ms=5.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_B_COMPILE_GOAL_GRAPH, duration_ms=120.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_C_RESOLVE_FRONTIER, duration_ms=15.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_D_BIND_CANDIDATES, duration_ms=8.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_E_COMPILE_QUERY_INTENT, duration_ms=10.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_F_EXECUTE_NATIVE_QUERY, duration_ms=45.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_G_RECORD_OBSERVATIONS, duration_ms=12.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_H_VERIFY_PROOF, duration_ms=20.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_I_CHECK_STOPPING, duration_ms=4.0, status="SUCCESS")
    trace.record_step(HuntStepName.STEP_J_REPORT_AND_ACCOUNT, duration_ms=25.0, status="SUCCESS")

    assert len(trace.steps) == 10
    d = trace.to_dict()
    assert d["request_id"] == "req-trace-1"
    assert d["step_count"] == 10
    assert d["steps"][0]["step_name"] == "STEP_A_FREEZE_REQUEST"
    assert d["steps"][9]["step_name"] == "STEP_J_REPORT_AND_ACCOUNT"


def test_financial_cost_accounting_formula() -> None:
    """Verify cost formula C_run = C_llm + C_splunk + C_control + C_analyst and waste ratio."""
    cost = RunCostAccounting(
        llm_cost_usd=0.015,
        splunk_cost_usd=0.005,
        control_cost_usd=0.002,
        analyst_cost_usd=0.010,
        waste_cost_usd=0.004,
    )

    # C_run = 0.015 + 0.005 + 0.002 + 0.010 = 0.032
    assert cost.total_cost_usd == 0.032
    # Waste ratio = 0.004 / 0.032 = 0.125
    assert cost.waste_ratio == 0.125
    d = cost.to_dict()
    assert d["formula"] == "C_run = C_llm + C_splunk + C_control + C_analyst"
    assert d["total_cost_usd"] == 0.032


def test_emit_machine_run_account(tmp_path: Path) -> None:
    """Verify emit_machine_run_account captures all required audit fields and writes JSON."""
    account = _sample_account("req-audit-123")
    trace = StepTrace(request_id="req-audit-123")
    trace.record_step(HuntStepName.STEP_A_FREEZE_REQUEST)
    trace.record_step(HuntStepName.STEP_J_REPORT_AND_ACCOUNT)

    out_file = tmp_path / "run_account.json"
    run_dict = emit_machine_run_account(account, step_trace=trace, output_path=out_file)
    assert run_dict["request_id"] == "req-audit-123"

    assert out_file.exists()
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == "v8"
    assert loaded["request_id"] == "req-audit-123"
    assert loaded["stopping_taxonomy_state"] == StoppingTaxonomyState.ANSWER_PROVED.value
    assert loaded["outcome"] == HuntOutcome.SUPPORTED.value
    assert loaded["answer_contract"]["value"] == "12.0.1"
    assert "cost_accounting" in loaded
    assert loaded["cost_accounting"]["total_cost_usd"] > 0.0
    assert len(loaded["evidence_ledger"]["citations"]) == 2
    assert len(loaded["executed_queries"]) == 1
    assert loaded["step_trace"]["step_count"] == 2


def test_emit_aborted_run_account_tied_to_request_id(tmp_path: Path) -> None:
    """Verify aborted runs emit failure artifact specifically tied to the active request ID."""
    out_file = tmp_path / "aborted_run.json"
    aborted_dict = emit_aborted_run_account(
        request_id="req-aborted-999",
        reason="Execution cancelled by user after step D",
        stopping_state=StoppingTaxonomyState.ABORTED_BY_USER,
        output_path=out_file,
    )
    assert aborted_dict["request_id"] == "req-aborted-999"

    assert out_file.exists()
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded["request_id"] == "req-aborted-999"
    assert loaded["status"] == "ABORTED"
    assert loaded["stopping_taxonomy_state"] == "ABORTED_BY_USER"
    assert "Execution cancelled" in loaded["reason"]


def test_render_six_part_report() -> None:
    """Verify render_six_part_report produces the exact 6-part human report structure."""
    account = _sample_account("req-report-6part")
    report = render_six_part_report(account)

    assert "## 1. Executive Verdict & Answer Contract" in report
    assert "## 2. Investigation Plan & Obligation Graph" in report
    assert "## 3. Evidence Ledger & Proof Chain" in report
    assert "## 4. Executed Queries & Execution Telemetry" in report
    assert "## 5. Coverage & Uncertainty Manifest" in report
    assert "## 6. Resource & Financial Cost Accounting" in report

    assert "ANSWER_PROVED" in report
    assert "12.0.1" in report
    assert "C_run = C_llm + C_splunk + C_control + C_analyst" in report
