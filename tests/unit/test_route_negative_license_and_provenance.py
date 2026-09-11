"""Unit tests for route exhaustion, negative evidence licensing, and report provenance."""
from __future__ import annotations

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    HuntObjective,
    HuntState,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.semantic_route import (
    CapabilityReadiness,
    SemanticAttempt,
    SemanticRouteAssessment,
    SemanticRouteStatus,
)
from hunting.reporter.builder import (
    _semantic_negative_is_licensed,
    build_final_hunt_account,
)


def _make_graph() -> SemanticGoalGraph:
    return SemanticGoalGraph(
        id="goal-graph-1",
        request_id="req-test-route",
        objective="Find encrypted file",
        variables=[
            SemanticVariable("e1", "device", "MACLORY-AIR13"),
            SemanticVariable("e2", "artifact"),
        ],
        relations=[
            SemanticRelationGoal(
                id="goal-1",
                subject="e1",
                relation="modified",
                object="e2",
                required=True,
            ),
        ],
        answers=[SemanticAnswerGoal(variable_id="e2", answer_type="file_name", required=True)],
    )


def test_partial_attempt_is_not_execution_complete_or_route_exhausted():
    """A partial execution attempt must not be marked execution_complete or route_exhausted."""
    attempt = SemanticAttempt(
        attempt_id="att-1",
        goal_id="goal-1",
        operation_id="op-1",
        source_id="src-1",
        stage_id="stage-1",
        result_complete=False,  # partial
        row_count=5,
        trigger_reason="primary",
        no_progress_signature="sig-1",
    )
    route = SemanticRouteAssessment(
        goal_id="goal-1",
        relation="modified",
        status=SemanticRouteStatus.ATTEMPTED_PARTIAL,
        execution_complete=False,
        proof_complete=False,
        route_exhausted=False,
        attempts=[attempt],
    )
    graph = _make_graph()
    licensed = _semantic_negative_is_licensed(graph, [route])
    assert not licensed
    assert not route.execution_complete
    assert not route.route_exhausted


def test_complete_empty_without_negative_license_is_inconclusive():
    """Complete-empty results without negative_evidence_capable license yield INCONCLUSIVE."""
    attempt = SemanticAttempt(
        attempt_id="att-1",
        goal_id="goal-1",
        operation_id="op-1",
        source_id="src-1",
        stage_id="stage-1",
        result_complete=True,
        row_count=0,
        trigger_reason="primary",
        no_progress_signature="sig-1",
        negative_evidence_capable=False,  # NO LICENSE
    )
    route = SemanticRouteAssessment(
        goal_id="goal-1",
        relation="modified",
        status=SemanticRouteStatus.ROUTE_EXHAUSTED,
        execution_complete=True,
        proof_complete=False,
        route_exhausted=True,
        attempts=[attempt],
    )
    graph = _make_graph()
    licensed = _semantic_negative_is_licensed(graph, [route])
    assert not licensed

    state = HuntState(
        objective=HuntObjective(request_id="req-test-route", statement="Find encrypted file"),
        semantic_goal_graph=graph,
        semantic_route_assessments=[route],
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN,
    )
    account = build_final_hunt_account(state)
    assert account.answer["status"] == "INCONCLUSIVE"
    assert account.answer["reason"] in {"NO_VERIFIED_ANSWER_CANDIDATE", "ROUTE_NEGATIVE_NOT_LICENSED"}


def test_exhausted_complete_empty_with_negative_license_allows_not_found():
    """Complete-empty results WITH negative_evidence_capable license across all required goals licenses NOT_FOUND."""
    attempt = SemanticAttempt(
        attempt_id="att-1",
        goal_id="goal-1",
        operation_id="op-1",
        source_id="src-1",
        stage_id="stage-1",
        result_complete=True,
        row_count=0,
        trigger_reason="primary",
        no_progress_signature="sig-1",
        negative_evidence_capable=True,  # EXPLICIT LICENSE
    )
    route = SemanticRouteAssessment(
        goal_id="goal-1",
        relation="modified",
        status=SemanticRouteStatus.ROUTE_EXHAUSTED,
        execution_complete=True,
        proof_complete=False,
        route_exhausted=True,
        attempts=[attempt],
    )
    graph = _make_graph()
    licensed = _semantic_negative_is_licensed(graph, [route])
    assert licensed

    qr = QueryResult(
        query_id="q-att-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        row_count=0,
    )
    state = HuntState(
        objective=HuntObjective(request_id="req-test-route", statement="Find encrypted file"),
        semantic_goal_graph=graph,
        semantic_route_assessments=[route],
        query_results=[qr],
        stopping_decision=StoppingDecision.STOP_RESOLVED,
    )
    account = build_final_hunt_account(state)
    assert account.answer["status"] == "NOT_FOUND"
    assert "explicit negative-evidence license" in account.gap_breakdown["not_found"][0]


def test_empty_candidates_defaults_to_inconclusive():
    """When no answer candidate is found and negative evidence is not licensed, status is INCONCLUSIVE."""
    graph = _make_graph()
    state = HuntState(
        objective=HuntObjective(request_id="req-test-route", statement="Find encrypted file"),
        semantic_goal_graph=graph,
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN,
    )
    account = build_final_hunt_account(state)
    assert account.answer["status"] == "INCONCLUSIVE"
    assert account.answer["reason"] in {"NO_VERIFIED_ANSWER_CANDIDATE", "ROUTE_NEGATIVE_NOT_LICENSED"}


def test_route_assessments_are_rendered_in_markdown_and_persisted():
    """Route assessments must appear in the rendered markdown report and the account dictionary."""
    from hunting.reporter.renderer import render_analyst_report

    attempt = SemanticAttempt(
        attempt_id="att-1",
        goal_id="goal-1",
        operation_id="op_search_files",
        source_id="splunk:botsv2:file_events",
        stage_id="stage_initial",
        result_complete=True,
        row_count=0,
        trigger_reason="primary_execution",
        no_progress_signature="sig_1",
        negative_evidence_capable=False,
    )
    route = SemanticRouteAssessment(
        goal_id="goal-1",
        relation="modified",
        status=SemanticRouteStatus.ROUTE_EXHAUSTED,
        execution_complete=True,
        proof_complete=False,
        route_exhausted=True,
        readiness=CapabilityReadiness.ROUTE_EXHAUSTED,
        attempts=[attempt],
        proof_gaps=["unproven_encryption_qualifier"],
    )
    graph = _make_graph()
    state = HuntState(
        objective=HuntObjective(request_id="req-test-route", statement="Find encrypted file"),
        semantic_goal_graph=graph,
        semantic_route_assessments=[route],
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN,
    )
    account = build_final_hunt_account(state)
    assert len(account.semantic_route_assessments) == 1
    assert account.semantic_route_assessments[0].goal_id == "goal-1"
    assert account.semantic_route_assessments[0].status == SemanticRouteStatus.ROUTE_EXHAUSTED

    md = render_analyst_report(account)
    assert "### Semantic route assessments" in md
    assert "op_search_files" in md
    assert "unproven_encryption_qualifier" in md


def test_planned_query_not_reported_as_executed_query():
    """Planned queries with no QueryResult are not rendered as executed queries."""
    from hunting.contracts.hunt import QueryPlan

    qr = QueryResult(
        query_id="q-exec-01",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        native_query="index=botsv2 sourcetype=file_events | head 10",
        row_count=1,
    )
    q_planned = QueryPlan(
        id="q-planned-only",
        requirement_id="req-test",
        provider_id="splunk",
        scope_id="botsv2",
        operation_id="search",
    )
    state = HuntState(
        objective=HuntObjective(request_id="req-test-prov", statement="Test provenance"),
        queries=[q_planned],
        query_results=[qr],
    )
    account = build_final_hunt_account(state)
    # The planned-only query must have empty native_query in reporting
    planned_rec = [q for q in account.queries if q["query_id"] == "q-planned-only"][0]
    assert planned_rec["native_query"] == ""
    assert planned_rec["result_summary"] == "No execution record"


def test_observation_store_trace_uses_exact_query_id():
    """ObservationStore records observations and retrieves them by exact query ID."""
    from hunting.m1_ledger.store import ObservationStore

    store = ObservationStore()
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv2"})
    obs = Observation(
        id="obs-exact-01",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"file_name": "test.doc"},
    )
    store.add_observation(obs, query_id="q-exact-99")

    # Fetch by exact query ID
    results = store.get_by_query("q-exact-99")
    assert len(results) == 1
    assert results[0].id == "obs-exact-01"

    # Other query ID yields empty
    assert len(store.get_by_query("q-other")) == 0
