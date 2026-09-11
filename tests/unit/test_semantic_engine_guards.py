from types import SimpleNamespace

from hunting.compiler.compiler import _mark_request_grounded_values
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntObjective, HuntState, Hypothesis, HypothesisOrigin
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.engine import HypothesisHuntEngine
from hunting.m1_ledger.ledger import ObservationLedger


class _Adapter:
    provider_id = "p"
    last_query_text = ""
    calls = []

    def execute_query(self, operation_id, entity, window, limit, query_id, **_kwargs):
        self.calls.append(operation_id)
        return QueryResult(
            query_id, QueryOutcome.ROWS, True, True,
            rows=[{"file_path": "/Users/mallory/critical.pptx.locked"}],
            native_query=f"search index=demo host=macbook operation={operation_id}",
        )


def test_semantic_engine_does_not_mark_unproven_restrictions_supported() -> None:
    graph = SemanticGoalGraph(
        "g", "r", "Find encrypted presentation",
        variables=[
            SemanticVariable("host", "host", "macbook-1"),
            SemanticVariable("file", "file", constraints=("format=presentation", "state=encrypted")),
        ],
        relations=[SemanticRelationGoal("changed", "host", "modified", "file")],
        answers=[SemanticAnswerGoal("file", "file")],
    )
    operation = ProviderOperation(
        "host-file", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
    )
    plan = LogicalPlan("plan", "g", "p", [PlanStep(
        "s1", "host-file", {"subject": "host"}, {"object": "file"},
        advances_goal_ids=("changed",), constraints=("format=presentation", "state=encrypted"),
    )])
    state = HuntState(
        objective=HuntObjective("r", statement="Find encrypted presentation", time_window="2026-01-01T00:00:00Z/P1D"),
        hypotheses=[Hypothesis("h", "Find encrypted presentation", HypothesisOrigin.INPUT)],
    )
    state.semantic_goal_graph = graph
    state.semantic_logical_plan = plan
    state.capability_catalog = SimpleNamespace(operations=(operation,))

    adapter = _Adapter()
    HypothesisHuntEngine().execute_semantic_plan(
        state, adapter, ProviderScope("p", {"index": "demo"}, "scope"), ObservationLedger(), limit=10,
    )

    verdict = state.semantic_analysis["goal_verdicts"][0]
    assert verdict["status"] == "INCONCLUSIVE_RESTRICTIONS_UNVERIFIED"
    assert state.semantic_analysis["unverified_restrictions"]["changed"] == ["format=presentation", "state=encrypted"]
    assert adapter.calls == ["host-file"]
    assert state.hypotheses[0].status.value != "SUPPORTED"


def test_semantic_engine_records_the_native_query_from_its_own_result() -> None:
    graph = SemanticGoalGraph(
        "g2", "r2", "Find a file",
        variables=[SemanticVariable("host", "host", "macbook-1"), SemanticVariable("file", "file")],
        relations=[SemanticRelationGoal("changed", "host", "modified", "file")],
    )
    operation = ProviderOperation(
        "host-file", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
    )
    state = HuntState(objective=HuntObjective("r2", statement="Find a file", time_window="2026-01-01T00:00:00Z/P1D"))
    state.semantic_goal_graph = graph
    state.semantic_logical_plan = LogicalPlan("plan2", "g2", "p", [PlanStep("s1", "host-file", {"subject": "host"}, {"object": "file"}, advances_goal_ids=("changed",))])
    state.capability_catalog = SimpleNamespace(operations=(operation,))

    HypothesisHuntEngine().execute_semantic_plan(
        state, _Adapter(), ProviderScope("p", {"index": "demo"}, "scope"), ObservationLedger(), limit=10,
    )

    # QueryPlan.parameters must not backfill execution provenance
    assert "query_text" not in state.queries[0].parameters
    # Executed native query is preserved in QueryResult
    assert state.query_results[0].native_query == "search index=demo host=macbook operation=host-file"


def test_llm_proposed_host_value_is_not_used_as_provider_binding() -> None:
    graph = SemanticGoalGraph(
        "g3", "r3", "Find a file on the MacBook",
        variables=[
            SemanticVariable("host", "host", "MacBook", value_origin="llm_proposal"),
            SemanticVariable("file", "file"),
        ],
        relations=[SemanticRelationGoal("changed", "host", "modified", "file")],
    )
    operation = ProviderOperation(
        "host-file", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
    )
    state = HuntState(objective=HuntObjective("r3", statement="Find a file on the MacBook", time_window="2026-01-01T00:00:00Z/P1D"))
    state.semantic_goal_graph = graph
    state.semantic_logical_plan = LogicalPlan("plan3", "g3", "p", [PlanStep("s1", "host-file", {"subject": "host"}, {"object": "file"}, advances_goal_ids=("changed",))])
    state.capability_catalog = SimpleNamespace(operations=(operation,))
    adapter = _Adapter()
    adapter.calls = []
    HypothesisHuntEngine().execute_semantic_plan(
        state, adapter, ProviderScope("p", {"index": "demo"}, "scope"), ObservationLedger(), limit=10,
    )
    assert adapter.calls == []
    assert state.semantic_analysis["unresolved_reasons"]["s1"] == "required typed binding is unavailable: host"


def test_compiler_does_not_ground_device_description_as_host() -> None:
    graph = SemanticGoalGraph(
        "g4", "r4", "Find a file on the MacBook",
        variables=[SemanticVariable("host", "host", "MacBook", value_origin="llm_proposal")],
    )
    grounded = _mark_request_grounded_values(graph, "Find a file on the MacBook", ())
    assert grounded.variables[0].value_origin == "llm_proposal"
