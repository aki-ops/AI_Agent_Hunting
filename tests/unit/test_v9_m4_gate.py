"""M4 gate counterexamples: adjacency, pagination/time-split, C3 quarantine, mock/live parity.

Proximity, join keys and provider multiplicity are not proof.
C3 cannot run when a deterministic plan exists.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntObjective, HuntState, LogicalQueryPlan
from hunting.contracts.native_query import NativeQueryCandidate
from hunting.contracts.outcome import FactualAnswerContract
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.search_envelope import SearchEnvelope
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.evidence_graph import EvidenceGraph
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.planner.semantic_query_compiler import query_plan_from_step, split_time_window
from hunting.query_safety.c3_admission import admit_c3_candidate


def _scope(provider: str = "mock") -> ProviderScope:
    return ProviderScope(provider, {"index": "main"}, "scope", retention_days=30)


def _op(**overrides: Any) -> ProviderOperation:
    payload: dict[str, Any] = {
        "id": "find-host",
        "provider_id": "mock",
        "scope_ids": ("scope",),
        "input_entity_kinds": ("person",),
        "output_entity_kinds": ("host",),
        "output_value_bindings": {"object": ("host",)},
        "route_mode": "EXPLORE",
    }
    payload.update(overrides)
    return ProviderOperation(**payload)


def _plan_and_step() -> tuple[LogicalPlan, PlanStep]:
    step = PlanStep(
        id="s-1",
        operation_id="find-host",
        relation="observed-on",
        advances_goal_ids=["g-1"],
        output_bindings={"host": "host"},
        mode="EXPLORE",
    )
    return LogicalPlan(id="lp-1", goal_graph_id="gg-1", provider_id="mock", steps=[step]), step


class _PagingAdapter:
    def execute_query(
        self,
        operation_id: str = "",
        entity: Any = None,
        window: str = "",
        limit: int = 100,
        query_id: str = "q",
        parameters: dict[str, Any] | None = None,
        query_intent: dict[str, Any] | None = None,
        offset: Any = 0,
        cursor: Any = None,
        **kwargs: Any,
    ) -> QueryResult:
        try:
            offset_i = int(cursor if cursor not in {None, ""} else offset or 0)
        except (TypeError, ValueError):
            offset_i = 0
        if offset_i == 0:
            return QueryResult(
                query_id=str(query_id),
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=False,
                rows=[{"host": "HOST-1", "_time": "2026-02-01T10:00:00Z"}],
                row_count=1,
                cursor="1",
            )
        return QueryResult(
            query_id=str(query_id),
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=[{"host": "HOST-2", "_time": "2026-02-01T11:00:00Z"}],
            row_count=1,
            cursor=None,
        )


class _PartialWindowAdapter:
    def __init__(self) -> None:
        self.windows: list[str] = []

    def execute_query(
        self,
        operation_id: str = "",
        entity: Any = None,
        window: str = "",
        limit: int = 100,
        query_id: str = "q",
        parameters: dict[str, Any] | None = None,
        query_intent: dict[str, Any] | None = None,
        offset: Any = 0,
        cursor: Any = None,
        **kwargs: Any,
    ) -> QueryResult:
        self.windows.append(str(window))
        return QueryResult(
            query_id=str(query_id),
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=False,
            rows=[{"host": "HOST-1", "_time": "2026-02-01T10:00:00Z", "window": window}],
            row_count=1,
            cursor=None,
        )


class _RecordingAdapter:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.intents: list[dict[str, Any]] = []
        self.logical_plans: list[dict[str, Any]] = []

    def execute_query(
        self,
        operation_id: str = "",
        entity: Any = None,
        window: str = "",
        limit: int = 100,
        query_id: str = "q",
        parameters: dict[str, Any] | None = None,
        query_intent: dict[str, Any] | None = None,
        offset: Any = 0,
        cursor: Any = None,
        **kwargs: Any,
    ) -> QueryResult:
        params = parameters or {}
        if params.get("query_intent"):
            self.intents.append(dict(params["query_intent"]))
        if params.get("logical_query_plan"):
            self.logical_plans.append(dict(params["logical_query_plan"]))
        return QueryResult(
            query_id=str(query_id),
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=list(self.rows),
            row_count=len(self.rows),
        )


def _run(adapter: Any, operations: tuple[ProviderOperation, ...], provider: str = "mock") -> HuntState:
    graph = SemanticGoalGraph(
        id="g",
        request_id="r-m4",
        objective="which host",
        variables=[
            SemanticVariable("user", "person", "alice"),
            SemanticVariable("host", "host"),
        ],
        relations=[SemanticRelationGoal("g-1", "user", "observed", "host", required=True)],
        answers=[SemanticAnswerGoal("host", "host")],
        outcome_contract=FactualAnswerContract(slots=("host",)),
    )
    plan = LogicalPlan(
        id="lp-1",
        goal_graph_id="g",
        provider_id=provider,
        steps=[
            PlanStep(
                id="s-1",
                operation_id="find-host",
                relation="observed",
                advances_goal_ids=["g-1"],
                input_bindings={"subject": "user"},
                output_bindings={"object": "host"},
                mode="EXPLORE",
            )
        ],
    )
    state = HuntState(
        objective=HuntObjective(
            request_id="r-m4",
            statement="which host",
            time_window="2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
            outcome_contract=graph.outcome_contract,
        )
    )
    state.semantic_goal_graph = graph
    state.semantic_logical_plan = plan
    state.capability_catalog = SimpleNamespace(operations=operations)
    state.search_envelope = SearchEnvelope()
    HypothesisHuntEngine().execute_semantic_plan(
        state,
        adapter,
        _scope(provider),
        ObservationLedger(),
        allow_candidate_inputs=True,
    )
    return state


def test_undeclared_fields_are_not_join_plans() -> None:
    plan, step = _plan_and_step()
    query = query_plan_from_step(
        plan, step, _scope(), "2026-02-01T00:00:00Z/2026-02-02T00:00:00Z", operation=_op()
    )
    assert query.parameters["logical_query_plan"]["adjacency"] == []


def test_declared_correlation_is_adjacency_not_proof() -> None:
    plan, step = _plan_and_step()
    query = query_plan_from_step(
        plan,
        step,
        _scope(),
        "2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
        operation=_op(correlation_roles={"host_identity": ("host", "dest_host")}),
    )
    assert query.parameters["logical_query_plan"]["adjacency"] == [{
        "kind": "declared_correlation",
        "role": "host_identity",
        "fields": ["host", "dest_host"],
        "proof_status": "NOT_PROOF",
    }]


def test_default_path_paginates_from_logical_cursor() -> None:
    adapter = _PagingAdapter()
    state = _run(adapter, (_op(pagination="cursor"),))
    trace = (state.semantic_analysis or {}).get("page_trace") or []
    assert len(trace) >= 2
    assert str(trace[0]["cursor"]) == "0"
    assert str(trace[1]["cursor"]) == "1"


def test_default_path_time_splits_partial_window() -> None:
    halves = split_time_window("2026-02-01T00:00:00Z/2026-02-02T00:00:00Z")
    assert halves is not None
    adapter = _PartialWindowAdapter()
    state = _run(adapter, (_op(pagination="none"),))
    assert "2026-02-01T00:00:00Z/2026-02-02T00:00:00Z" in adapter.windows
    assert halves[0] in adapter.windows
    assert halves[1] in adapter.windows
    trace = (state.semantic_analysis or {}).get("page_trace") or []
    assert any(item.get("time_split") for item in trace)


def test_c3_parse_allowlist_and_bounds_before_mutation() -> None:
    truncated = NativeQueryCandidate(
        provider="splunk",
        query_text='search index=botsv2 host="HOST-1" | fields host | head 10...',
        source_ids=("botsv2",),
        time_window="2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
        expected_fields=("host",),
        max_rows=10,
    )
    write_cmd = NativeQueryCandidate(
        provider="splunk",
        query_text='search index=botsv2 host="HOST-1" | delete | head 10',
        source_ids=("botsv2",),
        time_window="2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
        expected_fields=("host",),
        max_rows=10,
    )
    bounded = NativeQueryCandidate(
        provider="splunk",
        query_text='search index=botsv2 host="HOST-1" | fields host | head 10',
        source_ids=("botsv2",),
        time_window="2026-02-01T00:00:00Z/2026-02-02T00:00:00Z",
        expected_fields=("host",),
        max_rows=10,
    )
    common: dict[str, Any] = {
        "admitted": True,
        "known_sources": ["botsv2"],
        "known_fields": ["host"],
    }
    assert "truncated_model_output" in admit_c3_candidate(truncated, deterministic_plan=None, **common).reasons
    assert any(
        "forbidden_command" in reason
        for reason in admit_c3_candidate(write_cmd, deterministic_plan=None, **common).reasons
    )
    blocked = admit_c3_candidate(
        bounded,
        deterministic_plan=LogicalQueryPlan(id="p", requirement_id="g", provider="mock", scope="scope"),
        **common,
    )
    assert blocked.accepted is False
    assert "c3_blocked_deterministic_plan_exists" in blocked.reasons
    accepted = admit_c3_candidate(bounded, deterministic_plan=None, **common)
    assert accepted.accepted is True


def test_mock_and_declared_live_share_planner_and_graph_contracts() -> None:
    rows = [{"host": "HOST-1", "_time": "2026-02-01T10:00:00Z"}]
    mock = _RecordingAdapter(rows)
    live = _RecordingAdapter(rows)
    mock_state = _run(mock, (_op(provider_id="mock"),), provider="mock")
    live_state = _run(live, (_op(provider_id="splunk"),), provider="splunk")
    mock_intent = mock.intents[0]
    live_intent = live.intents[0]
    for key in ("goal_id", "operation_id", "relation", "mode", "predicates"):
        assert mock_intent[key] == live_intent[key]
    mock_logical = mock.logical_plans[0]
    live_logical = live.logical_plans[0]
    for key in ("mode", "operation_id", "filters", "cost_status", "pagination"):
        assert mock_logical[key] == live_logical[key]
    mock_graph = EvidenceGraph.from_run_account({"semantic_evidence_analysis": mock_state.semantic_analysis or {}})
    live_graph = EvidenceGraph.from_run_account({"semantic_evidence_analysis": live_state.semantic_analysis or {}})
    assert all(edge.proof_status == "NOT_PROOF" for edge in mock_graph.edges.values())
    assert all(edge.proof_status == "NOT_PROOF" for edge in live_graph.edges.values())
    assert mock_state.stopping_decision == live_state.stopping_decision
    mock_steps = [
        (item.get("observation_class"), item.get("next_action_reason"))
        for item in (mock_state.semantic_analysis or {}).get("step_actions", [])
    ]
    live_steps = [
        (item.get("observation_class"), item.get("next_action_reason"))
        for item in (live_state.semantic_analysis or {}).get("step_actions", [])
    ]
    assert mock_steps == live_steps
