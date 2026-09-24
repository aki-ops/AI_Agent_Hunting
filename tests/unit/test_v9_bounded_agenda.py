"""M3 counterexamples: one bounded agenda and one stop authority.

Default production must not run ClaimGraph, cell or adaptive loops.
Those remain only behind enable_legacy_execution=True.
"""
from __future__ import annotations

from pathlib import Path

from hunting.contracts.agenda import AgendaItem, BoundedAgenda
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntObjective, HuntRequest, HuntRequestKind, HuntState, StoppingDecision
from hunting.contracts.observation_class import ActionSignature, CoverageStatus, ObservationClass
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
from hunting.controller.loop_guard import LoopGuard
from hunting.controller.recovery_controller import RecoveryController
from hunting.engine import HypothesisHuntEngine
from hunting.m1_ledger.ledger import ObservationLedger


def _engine_source() -> str:
    return Path("src/hunting/engine.py").read_text(encoding="utf-8")


def test_engine_has_no_direct_stopping_decision_assignment() -> None:
    source = _engine_source()
    assert "state.stopping_decision =" not in source
    assert "stopping_decision=StoppingDecision." not in source


def test_legacy_while_loops_require_explicit_flag() -> None:
    source = _engine_source()
    assert "if self.enable_legacy_execution and (claim_graph_active or legacy_graph_active)" in source
    assert "while self.enable_legacy_execution and not state.stopping_decision and not native_semantic_graph:" in source
    assert source.count("while not state.stopping_decision:") == 1


def test_agenda_item_carries_route_method_bindings_and_mode() -> None:
    item = AgendaItem(
        goal_id="g1",
        step_id="s1",
        operation_id="op1",
        mode="EXPLORE",
        proof_method_id="pm-1",
        route_id="route:g1:op1",
        bindings=(("subject", "host"),),
        envelope_id="env-0",
        cursor="c1",
    )
    snapshot = item.to_dict()
    restored = AgendaItem.from_dict(snapshot)
    assert restored.proof_method_id == "pm-1"
    assert restored.route_id == "route:g1:op1"
    assert restored.bindings == (("subject", "host"),)
    assert restored.mode == "EXPLORE"
    agenda = BoundedAgenda()
    agenda.add(item)
    assert BoundedAgenda.from_dict(agenda.to_dict()).items[0].route_id == "route:g1:op1"


def test_action_signature_includes_method_provider_mode_and_cursor() -> None:
    sig = ActionSignature.from_params(
        goal_id="g1",
        op_id="op1",
        scope="scope",
        source_id="mock",
        stage="TEST",
        bindings={"host": "HOST-1"},
        time_window="2026-01-01T00:00:00Z/P1D",
        hints=["hint"],
        cursor="cursor-1",
        mode="PROVE",
        method_id="pm-1",
        provider_id="mock",
    )
    assert sig.mode == "PROVE"
    assert sig.method_id == "pm-1"
    assert sig.provider_id == "mock"
    assert sig.cursor == "cursor-1"
    assert sig.compute_hash()


def test_default_path_does_not_execute_claimgraph_operations() -> None:
    from hunting.compiler.compiler import KnowledgeBehaviorCompiler
    from hunting.m5_adapter.cdb_adapter import CdbAdapter

    response = """
    {
      "id": "claim-only",
      "claims": [
        {
          "id": "claim-process",
          "fact_type": "process_execution",
          "target_entity_type": "process",
          "required_roles": ["host", "process"],
          "observation_requirements": [
            {"id": "req-1", "fact_kind": "process_execution", "required_roles": ["host"]}
          ]
        }
      ],
      "variables": [{"id": "host", "entity_type": "host", "value": "SRV-01"}],
      "relations": [],
      "answers": []
    }
    """
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "process_creation",
        "host": "SRV-01",
        "image": "powershell.exe",
    }])
    engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda *_args, **_kwargs: response),
        configured_adapters=[adapter],
    )
    assert engine.enable_legacy_execution is False
    result = engine.execute_hunt(
        HuntRequest(
            id="req-no-legacy",
            kind=HuntRequestKind.QUESTION,
            content="Which process was observed on SRV-01?",
            provider_hints=("cdb",),
        ),
        adapter=adapter,
    )
    claim_ops = [
        q.operation_id for q in result.state.queries
        if str(q.operation_id) in {"cdb_process_search", "resolve-user-host"}
    ]
    assert claim_ops == []
    assert result.state.stopping_decision is not None
    assert result.state.stopping_decision != StoppingDecision.STOP_ANSWERED
    assert not getattr(result.state, "semantic_plan_executed", False) or not result.state.queries


def test_semantic_attempts_pass_classify_and_next_action() -> None:
    from types import SimpleNamespace

    graph = SemanticGoalGraph(
        id="g-agenda",
        request_id="req-agenda",
        objective="observe a process",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
        ],
        relations=[SemanticRelationGoal("g-obs", "host", "observed", "process", required=True)],
        answers=[SemanticAnswerGoal("process", "process")],
    )
    plan = LogicalPlan(
        id="plan-agenda",
        goal_graph_id=graph.id,
        provider_id="mock",
        steps=[
            PlanStep(
                id="s1",
                operation_id="op1",
                input_bindings={"subject": "host"},
                output_bindings={"object": "process"},
                advances_goal_ids=("g-obs",),
                mode="EXPLORE",
            ),
        ],
    )
    operation = ProviderOperation(
        "op1", "mock", ("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("process",),
        output_value_bindings={"object": ("image",)},
    )

    class Adapter:
        def execute_query(self, **kwargs):
            return QueryResult(
                kwargs.get("query_id", "q"),
                QueryOutcome.ROWS,
                True,
                True,
                rows=[{"image": "/bin/sh"}],
                row_count=1,
            )

    state = HuntState(
        objective=HuntObjective(
            request_id="req-agenda",
            statement="observe a process",
            time_window="2026-01-01T00:00:00Z/P1D",
            outcome_contract=FactualAnswerContract(slots=("process",), cardinality={"process": "singular"}),
        ),
    )
    state.semantic_goal_graph = graph
    state.semantic_logical_plan = plan
    state.capability_catalog = SimpleNamespace(operations=(operation,))
    state.search_envelope = SearchEnvelope()
    HypothesisHuntEngine().execute_semantic_plan(
        state, Adapter(), ProviderScope("mock", {"index": "main"}, "scope"), ObservationLedger(),
    )
    actions = state.semantic_analysis.get("step_actions", [])
    assert actions
    assert all(item.get("observation_class") for item in actions)
    assert all(item.get("next_action_reason") for item in actions)
    assert state.semantic_analysis.get("agenda", {}).get("dispatched")
    assert state.stopping_decision is not None


def test_no_progress_replay_exhausts_route() -> None:
    guard = LoopGuard(max_consecutive_stalls=2)
    sig = ActionSignature.from_params(
        goal_id="g1",
        op_id="op1",
        scope="scope",
        source_id="mock",
        stage="TEST",
        bindings={"host": "HOST-1"},
        time_window="2026-01-01T00:00:00Z/P1D",
        mode="EXPLORE",
        method_id="pm-1",
        provider_id="mock",
    )
    guard.record_action(sig, turn_index=1, rows_count=0, result_payload=[])
    guard.record_action(sig, turn_index=2, rows_count=0, result_payload=[])
    guard.record_action(sig, turn_index=3, rows_count=0, result_payload=[])
    assert guard.is_stalled(sig)
    assert guard.is_route_exhausted("mock", "op1")


def test_distinct_attempt_classes_keep_distinct_stops() -> None:
    controller = RecoveryController()
    mapping = [
        (True, False, False, False, StoppingDecision.STOP_BUDGET),
        (False, True, False, False, StoppingDecision.STOP_NEEDS_CLARIFICATION),
        (False, False, True, False, StoppingDecision.STOP_UNREACHABLE),
        (False, False, False, True, StoppingDecision.STOP_UNSUPPORTED),
    ]
    from hunting.controller.models import HuntBudgetLedger

    for budget, clarify, unreachable, unsupported, expected in mapping:
        stop = controller.evaluate_stop(
            obligations=["g1"],
            verified_obligations=[],
            coverage=CoverageStatus.COMPLETE,
            budgets=HuntBudgetLedger(max_queries=1, query_count=1) if budget else None,
            needs_clarification=clarify,
            unreachable=unreachable,
            unsupported=unsupported,
        )
        assert stop == expected
    empty_action = controller.choose_next_action(
        ObservationClass.EMPTY,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
    )
    assert empty_action.action_type in {"RELAX_HINT", "EXHAUST_ROUTE", "SWITCH_ROUTE"}
    fail_action = controller.choose_next_action(
        ObservationClass.QUERY_FAILURE,
        envelope=SearchEnvelope(),
        loop_guard=LoopGuard(),
    )
    assert fail_action.action_type in {"REPAIR_QUERY", "SWITCH_ROUTE"}
