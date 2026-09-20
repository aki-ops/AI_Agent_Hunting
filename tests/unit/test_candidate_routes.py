from hunting.capabilities.route_resolver import CapabilityRouteResolver
from hunting.contracts.candidate_route import RouteClass
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import SemanticAnswerGoal, SemanticGoalGraph, SemanticRelationGoal, SemanticVariable
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner
from dataclasses import replace

from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.planner.semantic_executor import SemanticPlanExecutor
from hunting.planner.semantic_query_compiler import query_plan_from_step


def _graph(relation: str = "novel relation") -> SemanticGoalGraph:
    return SemanticGoalGraph(
        id="graph-1",
        request_id="request-1",
        objective="resolve a value",
        variables=[
            SemanticVariable("subject", "person", "alice"),
            SemanticVariable("answer", "artifact"),
        ],
        relations=[SemanticRelationGoal("goal-1", "subject", relation, "answer")],
        answers=[SemanticAnswerGoal("answer", "file_name")],
    )


def test_goal_bound_executable_route_bypasses_relation_string_matching() -> None:
    graph = _graph("unregistered wording")
    operation = ProviderOperation(
        id="op-typed-file",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("artifact",),
        output_roles=("file_name",),
        output_value_bindings={"object": ("name",)},
        route_goal_ids=("goal-1",),
        route_class="EXECUTABLE",
        route_mode="EXPLORE",
    )
    resolution = CapabilityRouteResolver().resolve(graph, (operation,), "mock")
    route = resolution.routes_by_goal["goal-1"][0]
    assert route.route_class is RouteClass.EXECUTABLE
    assert route.executable

    plan = SemanticGoalPlanner((operation,), "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal
    )
    assert [step.operation_id for step in plan.steps] == ["op-typed-file"]
    assert plan.unresolved_goal_ids == []


def test_route_identity_keeps_same_relation_goals_separate() -> None:
    graph = SemanticGoalGraph(
        id="graph-2",
        request_id="request-2",
        objective="resolve two values",
        variables=[
            SemanticVariable("left", "person", "alice"),
            SemanticVariable("right", "person", "bob"),
            SemanticVariable("left_answer", "artifact"),
            SemanticVariable("right_answer", "artifact"),
        ],
        relations=[
            SemanticRelationGoal("left-goal", "left", "same wording", "left_answer"),
            SemanticRelationGoal("right-goal", "right", "same wording", "right_answer"),
        ],
        answers=[
            SemanticAnswerGoal("left_answer", "file_name"),
            SemanticAnswerGoal("right_answer", "file_name"),
        ],
    )
    left = ProviderOperation(
        id="left-op", provider_id="mock", scope_ids=("scope",),
        input_entity_kinds=("person",), output_entity_kinds=("artifact",),
        output_roles=("file_name",), route_goal_ids=("left-goal",),
    )
    right = ProviderOperation(
        id="right-op", provider_id="mock", scope_ids=("scope",),
        input_entity_kinds=("person",), output_entity_kinds=("artifact",),
        output_roles=("file_name",), route_goal_ids=("right-goal",),
    )
    resolution = CapabilityRouteResolver().resolve(graph, (left, right), "mock")
    assert [route.operation_id for route in resolution.routes_by_goal["left-goal"]] == ["left-op"]
    assert [route.operation_id for route in resolution.routes_by_goal["right-goal"]] == ["right-op"]


def test_non_executable_route_cannot_be_planned_as_a_query() -> None:
    graph = _graph("unknown")
    operation = ProviderOperation(
        id="mapping-only",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("artifact",),
        route_goal_ids=("goal-1",),
        route_class="MAPPING_REQUIRED",
    )
    resolution = CapabilityRouteResolver().resolve(graph, (operation,), "mock")
    assert resolution.routes_by_goal["goal-1"][0].executable is False
    plan = SemanticGoalPlanner((operation,), "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal
    )
    assert plan.steps == []
    assert plan.unresolved_goal_ids == ["goal-1"]


def test_goal_bound_route_reaches_provider_query_without_c2() -> None:
    """Counterexample for the old zero-query path: F1 route must execute."""
    graph = SemanticGoalGraph(
        id="graph-query",
        request_id="request-query",
        objective="observe a process",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("process", "process"),
        ],
        relations=[SemanticRelationGoal("goal-query", "host", "unregistered action", "process")],
        answers=[SemanticAnswerGoal("process", "process")],
    )
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([{
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "process_creation",
        "host": "HOST-1",
        "pid": 7,
        "image": "/bin/sh",
        "cmdline": "sh -c id",
    }])
    operation = next(
        item for item in adapter.get_capability_descriptor().operations
        if item.id == "find_process_from_endpoint"
    )
    operation = replace(operation, route_goal_ids=("goal-query",))
    resolution = CapabilityRouteResolver().resolve(graph, (operation,), "cdb")
    plan = SemanticGoalPlanner((operation,), "cdb").compose(
        graph, candidate_routes=resolution.routes_by_goal
    )
    result = SemanticPlanExecutor(adapter, (operation,)).execute(
        plan,
        adapter.scope,
        "2026-02-01T00:00:00Z/P1D",
        initial_variables={"host": "HOST-1"},
        variable_types={"host": "host", "process": "process"},
        goal_graph=graph,
        allow_candidate_inputs=True,
    )
    assert plan.unresolved_goal_ids == []
    assert len(result.executions) == 1
    assert result.executions[0].result.executed_ok is True
    assert len(result.executions[0].result.rows or []) == 1


def test_admitted_route_mode_reaches_query_intent() -> None:
    graph = _graph("unregistered wording")
    operation = ProviderOperation(
        id="op-explore",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("artifact",),
        output_roles=("file_name",),
        route_goal_ids=("goal-1",),
        route_class="EXECUTABLE",
        route_mode="EXPLORE",
    )
    resolution = CapabilityRouteResolver().resolve(graph, (operation,), "mock")
    plan = SemanticGoalPlanner((operation,), "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal
    )
    assert plan.steps[0].mode == "EXPLORE"
    intent_plan = query_plan_from_step(
        plan, plan.steps[0], scope=type("Scope", (), {"scope_id": "scope"})(),
        time_window="2026-02-01T00:00:00Z/P1D", operation=operation,
    )
    assert intent_plan.parameters["query_intent"]["mode"] == "EXPLORE"


def test_production_planner_does_not_fallback_to_relation_string_matching() -> None:
    graph = _graph("resolve_person_to_account")
    operation = ProviderOperation(
        id="legacy-looking-op",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("artifact",),
        guaranteed_relations=("resolve_person_to_account",),
    )
    plan = SemanticGoalPlanner((operation,), "mock").compose(
        graph,
        candidate_routes={},
        legacy_relation_matching=False,
    )
    assert plan.steps == []
    assert plan.unresolved_goal_ids == ["goal-1"]
