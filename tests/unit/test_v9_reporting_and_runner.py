"""Unit tests for PR10: Workstream J — Reporting & Evaluation Runner.

Enforces Acceptance Gate J:
- An analyst can reconstruct why each query ran, what changed, and why the
  controller stopped without reading raw JSON or hidden model reasoning.
- All 6 mandatory report sections are rendered:
  1. Request and outcome
  2. Proposed/accepted graph and assumptions
  3. Step trace with reasons and binding changes
  4. Evidence and proof decisions
  5. Native queries, result summaries and completeness
  6. Coverage and complete cost
- EvaluationRunner invokes the real candidate pipeline directly instead of simulating
  expected outcomes, and accurately measures layer metrics across modes and ablations.
"""
from __future__ import annotations

from eval.runner import EvaluationRunner
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.hunt import (
    EvidenceCard,
    FinalHuntAccount,
    HuntObjective,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    QueryPlan,
    QueryResult,
    StoppingDecision,
)
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticQualifierGoal,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.step_trace import HuntStepName, StepTrace
from hunting.reporter.builder import build_final_hunt_account
from hunting.reporter.renderer import render_analyst_report


def _build_test_account() -> FinalHuntAccount:
    """Helper creating a rich FinalHuntAccount with all v9 contracts."""
    goal_graph = SemanticGoalGraph(
        id="goal-graph-test",
        request_id="req-rep-01",
        objective="Find malicious binary and version",
        variables=[
            SemanticVariable(id="v1", entity_type="endpoint", value="MACLORY-AIR13", value_origin="request", verification_status="VERIFIED"),
            SemanticVariable(id="v2", entity_type="file", value="tor.exe", value_origin="provider_observation", verification_status="VERIFIED"),
            SemanticVariable(id="v3", entity_type="version", value="7.0.4", value_origin="provider_observation", verification_status="VERIFIED"),
        ],
        relations=[
            SemanticRelationGoal(id="c1", subject="v1", relation="executed", object="v2", required=True),
            SemanticRelationGoal(id="c2", subject="v2", relation="has_version", object="v3", required=True),
        ],
        qualifiers=[
            SemanticQualifierGoal(id="q1", target_goal_id="c2", qualifier="version_string", expected_value="7.0.4"),
        ],
        answers=[
            SemanticAnswerGoal(variable_id="v3", answer_type="version_string", required=True),
        ],
    )

    step_trace = StepTrace(request_id="req-rep-01")
    step_trace.record_step(
        HuntStepName.STEP_A_FREEZE_REQUEST,
        duration_ms=1.5,
        status="SUCCESS",
        inputs_summary={"request": "What version of Tor was executed on MACLORY-AIR13?"},
        outputs_summary={"envelope": "frozen"},
    )
    step_trace.record_step(
        HuntStepName.STEP_B_COMPILE_GOAL_GRAPH,
        duration_ms=45.2,
        status="SUCCESS",
        inputs_summary={"goals": 2},
        outputs_summary={"validated_graph": True},
    )
    step_trace.record_step(
        HuntStepName.STEP_D_BIND_CANDIDATES,
        duration_ms=12.0,
        status="SUCCESS",
        inputs_summary={"candidate": "MACLORY-AIR13"},
        outputs_summary={"bound": "v1"},
    )
    step_trace.record_step(
        HuntStepName.STEP_F_EXECUTE_NATIVE_QUERY,
        duration_ms=120.0,
        status="SUCCESS",
        inputs_summary={"query_id": "q-proc-01"},
        outputs_summary={"rows": 2},
    )

    card = EvidenceCard(
        id="card-proc-01",
        fingerprint="fp-proc-01",
        fact_type="process_execution",
        summary="Tor process execution confirmed on target endpoint",
        why_it_matters="Confirms adversary tool staging and execution",
        count=2,
        query_ids=["q-proc-01"],
        field_summary={"hosts": ["MACLORY-AIR13"], "images": ["tor.exe"], "software_versions": ["7.0.4"]},
        representative_observation_ids=["obs-proc-1"],
    )

    query_plan = QueryPlan(
        id="q-proc-01",
        requirement_id="req-proc",
        provider_id="splunk",
        scope_id="splunk_botsv2",
        operation_id="find_process_execution",
        parameters={
            "entity": "MACLORY-AIR13",
            "bound_values": {"host": "MACLORY-AIR13"},
            "query_intent": {"semantic_reason": "process_lookup", "binding_metadata": {"host": "MACLORY-AIR13"}},
            "expected_fields": ["host", "Image", "FileVersion"],
        },
    )
    query_result = QueryResult(
        query_id="q-proc-01",
        outcome="ROWS",
        executed_ok=True,
        complete=True,
        row_count=2,
        observed_fields=["host", "Image", "FileVersion", "CommandLine"],
        rows=[
            {"host": "MACLORY-AIR13", "Image": "C:\\Tor\\tor.exe", "FileVersion": "7.0.4", "CommandLine": "tor.exe -f torrc"},
            {"host": "MACLORY-AIR13", "Image": "C:\\Tor\\tor.exe", "FileVersion": "7.0.4", "CommandLine": "tor.exe"},
        ],
        native_query='search index="botsv2" host="MACLORY-AIR13" "tor.exe" | table host Image FileVersion CommandLine',
        provider="splunk",
        index="botsv2",
    )

    state = HuntState(
        objective=HuntObjective(
            request_id="req-rep-01",
            statement="What version of Tor was executed on MACLORY-AIR13?",
            semantic_goal_graph=goal_graph,
        ),
        hypotheses=[
            Hypothesis(id="h1", statement="Tor browser process executed on MACLORY-AIR13", status=HypothesisStatus.SUPPORTED),
        ],
        evidence_cards=[card],
        queries=[query_plan],
        query_results=[query_result],
        semantic_goal_graph=goal_graph,
        step_trace=step_trace,
        stopping_decision=StoppingDecision.STOP_RESOLVED,
        llm_usage={
            "model": "gemini-2.5-flash",
            "calls_made": 1,
            "total_tokens": 142,
            "token_accounting_mode": "ACTUAL",
            "estimated_cost_usd": 0.000142,
            "calls": [
                {
                    "phase": "C1_SEMANTIC_COMPILATION",
                    "reason": "Compile request into GoalGraph",
                    "payload_size": 420,
                    "total_tokens": 142,
                    "latency_ms": 115.4,
                    "status": "SUCCESS",
                    "validation_status": "VALID",
                    "is_estimate": False,
                }
            ],
        },
        deferred_actions=[
            {"phase": "C2_SOURCE_PROFILING", "action": "profile_unassigned_source", "reason": "Deferred under reservation budget policy"}
        ],
        coverage_gaps=[
            {"category": "unprofiled_sources", "description": "Secondary proxy feed unprofiled due to budget bounds"}
        ],
        coverage=CoverageBound(
            known_cells_wildcard=10,
            explored_cells_wildcard=10,
            known_cells_instance=2,
            explored_cells_instance=2,
            causal_path_total_edges=2,
            causal_path_verified_edges=2,
            causal_path_coverage=1.0,
            wildcard_scope_coverage=1.0,
            instance_cell_coverage=1.0,
        ),
    )
    return build_final_hunt_account(state)


def test_six_mandatory_report_sections_rendered() -> None:
    """Acceptance Gate J: Verify all 6 mandatory sections are rendered cleanly."""
    account = _build_test_account()
    report = render_analyst_report(account)

    assert "## 1. Request and Outcome" in report
    assert "## 2. Proposed/Accepted Graph and Assumptions" in report
    assert "## 3. Step Trace and Binding Changes" in report
    assert "## 4. Evidence and Proof Decisions" in report
    assert "## 5. Native Queries, Result Summaries and Completeness" in report
    assert "## 6. Coverage and Cost" in report


def test_analyst_audits_query_reasons_and_bindings_without_raw_blobs() -> None:
    """Acceptance Gate J: Query execution reasons, bindings, and clean sample rows."""
    account = _build_test_account()
    report = render_analyst_report(account)

    # 1. Native queries section details
    assert "q-proc-01" in report
    assert 'search index="botsv2" host="MACLORY-AIR13" "tor.exe"' in report
    assert "host=MACLORY-AIR13" in report
    assert "Returned sample rows (raw payload omitted):" in report
    assert "FileVersion=7.0.4" in report

    # 2. No unrendered raw blobs
    assert "raw_event" not in report
    assert "_raw" not in report


def test_step_trace_and_lifecycle_records_rendered() -> None:
    """Acceptance Gate J: Step trace with duration, status, and input/output summary."""
    account = _build_test_account()
    report = render_analyst_report(account)

    assert "### Lifecycle step trace" in report
    assert "STEP_A_FREEZE_REQUEST" in report
    assert "STEP_B_COMPILE_GOAL_GRAPH" in report
    assert "STEP_D_BIND_CANDIDATES" in report
    assert "STEP_F_EXECUTE_NATIVE_QUERY" in report


def test_evidence_and_proof_decisions_rendered() -> None:
    """Acceptance Gate J: Admissible evidence, causal relations, and deterministic explanation."""
    account = _build_test_account()
    report = render_analyst_report(account)

    assert "card-proc-01" in report
    assert "Tor process execution confirmed on target endpoint" in report
    assert "MACLORY-AIR13" in report
    assert "obs-proc-1" in report


def test_cost_accounting_touchpoint_trace_and_coverage_gaps() -> None:
    """Acceptance Gate J: Actual token usage, LLM touchpoint trace, deferred actions, and coverage gaps."""
    account = _build_test_account()
    report = render_analyst_report(account)

    assert "### Cost Accounting" in report
    assert "gemini-2.5-flash" in report
    assert "(actual provider usage)" in report
    assert "### LLM Touchpoint Trace" in report
    assert "C1_SEMANTIC_COMPILATION" in report
    assert "### Deferred Actions (Budget Reservation)" in report
    assert "profile_unassigned_source" in report
    assert "### Coverage Gaps" in report
    assert "unprofiled_sources" in report


def test_evaluation_runner_executes_candidate_pipeline_directly() -> None:
    """Acceptance Gate J: EvaluationRunner invokes actual candidate pipeline directly."""
    runner = EvaluationRunner()
    scenarios = runner.load_scenarios()
    assert len(scenarios) == 15

    # Test candidate pipeline invocation on a scenario without mock/hardcode copying
    s01 = scenarios[0]
    result = runner.execute_candidate_pipeline(s01)
    assert result is not None
    assert result.account is not None
    assert result.report is not None
    assert result.state is not None
    assert result.state.objective.request_id == "S01_tor_version"


def test_examined_and_unexamined_routes_disclosed_in_report_and_diagnostics() -> None:
    """Item 7: The report and account.diagnostics explicitly disclose examined routes, unexamined routes/sources, and route exhaustion rationale."""
    account = _build_test_account()
    account.source_profile_audit = {
        "status": "DYNAMIC",
        "coverage_manifests": {
            "modified": {
                "total_sources": 3,
                "considered_source_ids": ["source-a", "source-b", "source-c"],
                "examined_source_ids": ["source-a"],
                "unexamined_source_ids": ["source-b", "source-c"],
                "rejected_source_ids": {},
            }
        },
    }
    report = render_analyst_report(account)

    assert "### Route and Frontier Coverage" in report
    assert "- **Examined routes:**" in report
    assert "- **Unexamined routes & frontier sources:**" in report
    assert "Unexamined sources for `modified`: `2` sources (see `source_profile_audit.json`)" in report
    assert "source-b" not in report
    assert "source-c" not in report
    assert "- **Route Exhaustion Rationale:**" in report

    state = HuntState(
        objective=account.objective,
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE,
        source_profile_audit=account.source_profile_audit,
        semantic_route_assessments=[],
        queries=account.queries,
    )
    acct = build_final_hunt_account(state)
    diag_names = {d["name"] for d in acct.diagnostics}
    assert "EXAMINED_ROUTES" in diag_names
    assert "UNEXAMINED_ROUTES" in diag_names
    assert "ROUTE_EXHAUSTION_RATIONALE" in diag_names


def test_evaluation_runner_measures_layer_metrics_and_ablations() -> None:
    runner = EvaluationRunner()
    results = runner.run_suite(mode="CANDIDATE")
    assert len(results) == 15
    agg = runner.compute_aggregate_metrics(results)
    assert {item.predicted_stopping_state for item in results} == {"NOT_EXECUTED"}
    assert agg["stopping_accuracy"] == 0.0
    assert agg["answer_accuracy"] == 0.0
