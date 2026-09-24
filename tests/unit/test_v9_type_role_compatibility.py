"""Generic type/slot compatibility counterexamples.

No scenario names.  These tests encode the retrieve-then-admit kernel:
typed EXPLORE must survive admission, empty kinds are not executable, and
AND/GATE waiting is not a capability gap.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from hunting.capabilities.admission import CapabilityAdmissionGate
from hunting.capabilities.route_resolver import CapabilityRouteResolver
from hunting.capabilities.semantic_index import SemanticCapabilityIndex
from hunting.contracts.capability_query import build_capability_queries
from hunting.contracts.cells import ProviderScope
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.semantic_route import CapabilityReadiness, SemanticRouteStatus
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner
from hunting.planner.semantic_query_compiler import query_plan_from_step
from hunting.planner.semantic_readiness import assess_semantic_readiness


def _graph(
    subject_type: str,
    object_type: str,
    *,
    answer_role: str | None = None,
    relation: str = "observed",
    subject_value: str = "subject-1",
    include_answer: bool = False,
) -> SemanticGoalGraph:
    answers: list[SemanticAnswerGoal] = []
    if include_answer or answer_role:
        answers = [SemanticAnswerGoal("object", answer_role or object_type)]
    return SemanticGoalGraph(
        id="graph-typed",
        request_id="req-typed",
        objective="observe a typed relation",
        variables=[
            SemanticVariable("subject", subject_type, subject_value),
            SemanticVariable("object", object_type),
        ],
        relations=[SemanticRelationGoal("goal-1", "subject", relation, "object")],
        answers=answers,
    )


def _typed_operation(
    *,
    input_kinds: tuple[str, ...],
    output_kinds: tuple[str, ...],
    output_roles: tuple[str, ...] = (),
    output_fields: tuple[str, ...] = (),
    guaranteed_relations: tuple[str, ...] = (),
    operation_id: str = "op-typed",
    native_field_bindings: dict[str, tuple[str, ...]] | None = None,
    output_value_bindings: dict[str, tuple[str, ...]] | None = None,
    discovery_provenance: tuple[str, ...] = (),
    route_class: str = "EXECUTABLE",
    expected_cost: int | None = 5,
    query_builder: str = "mock.typed.v1",
) -> ProviderOperation:
    fields = output_fields
    return ProviderOperation(
        id=operation_id,
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=input_kinds,
        output_entity_kinds=output_kinds,
        output_roles=output_roles,
        output_fields=fields,
        native_field_bindings=native_field_bindings or ({"subject": ("subject_field",)} if input_kinds else {}),
        output_value_bindings=output_value_bindings or ({"object": fields} if fields else {"object": ("value",)}),
        guaranteed_relations=guaranteed_relations,
        route_class=route_class,
        route_mode="EXPLORE",
        discovery_provenance=discovery_provenance,
        expected_cost=expected_cost,
        query_builder=query_builder,
    )


def _resolve(graph: SemanticGoalGraph, operation: ProviderOperation, profiles=()):
    return CapabilityRouteResolver().resolve(graph, (operation,), "mock", profiles=profiles)


def _admitted_explore(resolution, goal_id: str = "goal-1") -> bool:
    routes = resolution.routes_by_goal.get(goal_id, ())
    return any(
        route.executable and str(getattr(route.mode, "value", route.mode)).upper() == "EXPLORE"
        for route in routes
    )


@dataclass(frozen=True)
class _TypePair:
    subject: str
    object_type: str
    input_kinds: tuple[str, ...]
    output_kinds: tuple[str, ...]
    output_roles: tuple[str, ...]
    output_fields: tuple[str, ...]
    answer_role: str | None = None
    include_answer: bool = False
    relation: str = "associated_with"


TYPE_PAIR_CASES = (
    _TypePair("person", "device", ("person",), ("host",), ("endpoint_identity",), ("host",)),
    _TypePair("person", "host", ("person",), ("endpoint",), ("endpoint_identity",), ("ComputerName",)),
    _TypePair("host", "artifact", ("host",), ("file",), ("file_path",), ("file_path",)),
    _TypePair("account", "endpoint", ("account",), ("host",), ("endpoint_identity",), ("host",)),
    _TypePair("endpoint", "ip", ("host",), ("ip_address",), ("ip",), ("destination_ip",)),
    _TypePair(
        "person", "file", ("person",), ("file",), ("file_path",), ("file_path",),
        answer_role="file_name", include_answer=True,
    ),
)


@pytest.mark.parametrize("case", TYPE_PAIR_CASES, ids=lambda item: f"{item.subject}->{item.object_type}")
def test_typed_pairs_admit_executable_explore(case: _TypePair) -> None:
    graph = _graph(
        case.subject,
        case.object_type,
        answer_role=case.answer_role,
        include_answer=case.include_answer,
        relation=case.relation,
    )
    operation = _typed_operation(
        input_kinds=case.input_kinds,
        output_kinds=case.output_kinds,
        output_roles=case.output_roles,
        output_fields=case.output_fields,
        guaranteed_relations=(case.relation,),
        discovery_provenance=("F0_CERTIFIED",),
    )
    resolution = _resolve(graph, operation)
    assert _admitted_explore(resolution), (
        f"{case.subject}/{case.object_type} vs {case.input_kinds}->{case.output_kinds} "
        f"must admit EXECUTABLE EXPLORE; got {resolution.routes_by_goal}"
    )


def test_identity_goal_empty_answer_role_does_not_require_device_field() -> None:
    graph = _graph("person", "device", include_answer=False)
    queries = build_capability_queries(graph)
    assert queries[0].object_type == "device"
    assert queries[0].answer_role == ""

    operation = _typed_operation(
        input_kinds=("person",),
        output_kinds=("host",),
        output_roles=("endpoint_identity",),
        output_fields=("host",),
        guaranteed_relations=("associated_with",),
        discovery_provenance=("F0_CERTIFIED",),
    )
    resolution = _resolve(graph, operation)
    assert _admitted_explore(resolution)
    route = resolution.routes_by_goal["goal-1"][0]
    assert "device" not in route.rejection_reasons
    assert "host" in {str(item).casefold() for item in operation.output_fields}


def test_file_name_slot_admits_file_kinds_and_file_path() -> None:
    graph = _graph("person", "file", answer_role="file_name", include_answer=True)
    operation = _typed_operation(
        input_kinds=("person",),
        output_kinds=("file",),
        output_roles=("file",),
        output_fields=("file_path",),
    )
    assert _admitted_explore(_resolve(graph, operation))


def test_file_name_slot_rejects_process_kinds() -> None:
    graph = _graph("person", "file", answer_role="file_name", include_answer=True)
    operation = _typed_operation(
        input_kinds=("person",),
        output_kinds=("process",),
        output_roles=("process",),
        output_fields=("image",),
    )
    resolution = _resolve(graph, operation)
    assert not _admitted_explore(resolution)


def test_attachment_name_still_census_rejects_sender_address() -> None:
    profile = TelemetrySourceProfile(
        source_id="source-nested",
        provider_id="mock",
        partition_id="scope",
        native_type="opaque",
        fields=(
            TelemetryFieldProfile(
                "f-payload-name",
                "payload_sender",
                origin="nested_payload",
                parent_field="_raw",
                nested_key="sender_address",
            ),
        ),
    )
    from hunting.contracts.source_profile import SourceCapabilityProposal

    proposal = SourceCapabilityProposal(
        source_id="source-nested",
        relation="find_attachment",
        input_roles={"message": "f-payload-name"},
        output_roles={"message": "f-payload-name"},
    )
    result = CapabilityAdmissionGate.evaluate(
        proposal,
        profile,
        {"subject_type": "message", "object_type": "file", "answer_role": "attachment_name"},
    )
    assert result.admitted is False
    assert "answer_role_not_census_backed:attachment_name" in result.reasons


@pytest.mark.parametrize(
    ("left", "right"),
    (("person", "account"), ("ip", "host"), ("process", "file")),
)
def test_kernel_rejects_incompatible_type_pairs(left: str, right: str) -> None:
    from hunting.contracts.ontology import types_are_compatible

    assert types_are_compatible(left, right) is False
    assert types_are_compatible(right, left) is False


def test_kernel_empty_and_untyped_are_not_compatible() -> None:
    from hunting.contracts.ontology import types_are_compatible

    assert types_are_compatible("", "host") is False
    assert types_are_compatible("host", "") is False
    assert types_are_compatible("any", "host") is True
    assert types_are_compatible("address", "ip") is False


def test_untyped_empty_kinds_operation_is_not_executable() -> None:
    graph = _graph("person", "device")
    leftover = ProviderOperation(
        id="untyped-sweep",
        provider_id="mock",
        scope_ids=("scope",),
        output_fields=("raw",),
        output_value_bindings={"object": ("raw",)},
        route_class="EXECUTABLE",
        expected_cost=1,
    )
    resolution = _resolve(graph, leftover)
    assert not any(route.executable for route in resolution.routes_by_goal.get("goal-1", ()))


def test_token_drop_cannot_kill_f0_typed_admit() -> None:
    graph = _graph("person", "device", include_answer=False, relation="associated_with")
    operation = _typed_operation(
        input_kinds=("person",),
        output_kinds=("host",),
        output_roles=("endpoint_identity",),
        output_fields=("host",),
        guaranteed_relations=("associated_with",),
        discovery_provenance=("F0_CERTIFIED",),
    )
    retrieval = SemanticCapabilityIndex((), operations=(operation,)).retrieve(
        build_capability_queries(graph)[0], k=4,
    )
    assert retrieval.operation_hits
    assert retrieval.operation_hits[0].frontier_stage == "F0_CERTIFIED"
    assert retrieval.operation_hits[0].relevant is True

    resolution = _resolve(graph, operation)
    assert _admitted_explore(resolution), "F0 typed hit must remain EXECUTABLE after admission"


def test_f0_typed_admit_does_not_require_c2() -> None:
    graph = _graph("person", "device", include_answer=False, relation="associated_with")
    operation = _typed_operation(
        input_kinds=("person",),
        output_kinds=("host",),
        output_roles=("endpoint_identity",),
        output_fields=("host",),
        guaranteed_relations=("associated_with",),
        discovery_provenance=("F0_CERTIFIED",),
    )
    resolution = _resolve(graph, operation)
    plan = SemanticGoalPlanner((operation,), "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal, legacy_relation_matching=False,
    )
    assessments = assess_semantic_readiness(
        graph, plan, (operation,), candidate_routes=resolution.routes_by_goal,
    )
    executable = {
        goal.id
        for goal in graph.relations
        if any(route.executable for route in resolution.routes_by_goal.get(goal.id, ()))
    }
    profiling = {
        item.goal_id
        for item in assessments
        if item.goal_id not in executable
        and item.readiness.value in {"CAPABILITY_GAP", "RETRIEVAL_CAPABLE"}
        and "blocked_on_dependency" not in item.capability_gaps
    }
    assert "goal-1" in executable
    assert "goal-1" not in profiling
    assert plan.steps
    intent_plan = query_plan_from_step(
        plan,
        plan.steps[0],
        scope=ProviderScope(provider_id="mock", native_partition={"source": "mock"}, scope_id="scope"),
        time_window="2026-01-01T00:00:00Z/P1D",
        operation=operation,
    )
    assert intent_plan.parameters["query_intent"]["mode"] == "EXPLORE"


def test_f1_source_only_still_allows_c2() -> None:
    graph = _graph("person", "file", answer_role="file_name", include_answer=True)
    profile = TelemetrySourceProfile(
        source_id="source-file",
        provider_id="mock",
        partition_id="scope",
        native_type="opaque",
        fields=(TelemetryFieldProfile("f-path", "file_path"),),
    )
    resolution = CapabilityRouteResolver().resolve(graph, (), "mock", profiles=(profile,))
    plan = SemanticGoalPlanner((), "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal, legacy_relation_matching=False,
    )
    assessments = assess_semantic_readiness(
        graph, plan, (), candidate_routes=resolution.routes_by_goal,
    )
    executable = {
        goal.id
        for goal in graph.relations
        if any(route.executable for route in resolution.routes_by_goal.get(goal.id, ()))
    }
    profiling = {
        item.goal_id
        for item in assessments
        if item.goal_id not in executable
        and item.readiness.value in {"CAPABILITY_GAP", "RETRIEVAL_CAPABLE"}
    }
    assert executable == set()
    assert "goal-1" in profiling


def test_and_goal_with_typed_route_is_blocked_not_capability_gap() -> None:
    graph = SemanticGoalGraph(
        id="graph-and",
        request_id="req-and",
        objective="observe two typed relations",
        variables=[
            SemanticVariable("subject", "person", "subject-1"),
            SemanticVariable("opaque", "opaque"),
            SemanticVariable("host", "host", "host-1"),
            SemanticVariable("artifact", "file"),
        ],
        relations=[
            SemanticRelationGoal("goal-1", "subject", "unregistered_identity", "opaque"),
            SemanticRelationGoal(
                "goal-2", "host", "modified", "artifact",
                dependencies=("goal-1",),
                dependency_operator="AND",
            ),
        ],
    )
    typed = _typed_operation(
        operation_id="op-host-file",
        input_kinds=("host",),
        output_kinds=("file",),
        output_roles=("file",),
        output_fields=("file_path",),
        guaranteed_relations=("modified",),
        discovery_provenance=("F0_CERTIFIED",),
    )
    resolution = CapabilityRouteResolver().resolve(graph, (typed,), "mock")
    plan = SemanticGoalPlanner((typed,), "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal, legacy_relation_matching=False,
    )
    assessments = {
        item.goal_id: item
        for item in assess_semantic_readiness(
            graph, plan, (typed,), candidate_routes=resolution.routes_by_goal,
        )
    }
    assert assessments["goal-1"].readiness == CapabilityReadiness.CAPABILITY_GAP
    assert "no_typed_reachable_route" in assessments["goal-1"].capability_gaps
    assert assessments["goal-2"].readiness != CapabilityReadiness.CAPABILITY_GAP
    assert assessments["goal-2"].status != SemanticRouteStatus.CAPABILITY_GAP
    assert "no_typed_reachable_route" not in assessments["goal-2"].capability_gaps
    assert "blocked_on_dependency" in assessments["goal-2"].capability_gaps
    assert getattr(plan, "unresolved_reasons", {}).get("goal-2") == "blocked_on_dependency"


def test_or_one_typed_branch_is_sufficient() -> None:
    graph = SemanticGoalGraph(
        id="graph-or",
        request_id="req-or",
        objective="observe one of two methods",
        variables=[
            SemanticVariable("host", "host", "host-1"),
            SemanticVariable("address", "ip"),
            SemanticVariable("name", "domain"),
            SemanticVariable("verdict", "entity"),
        ],
        relations=[
            SemanticRelationGoal("goal-ip", "host", "assigned_ip", "address"),
            SemanticRelationGoal("goal-dns", "host", "resolved_to", "name"),
            SemanticRelationGoal(
                "goal-target", "address", "communicated_with", "verdict",
                dependencies=("goal-ip", "goal-dns"),
                dependency_operator="OR",
            ),
        ],
    )
    ops = (
        _typed_operation(
            operation_id="op-ip",
            input_kinds=("host",),
            output_kinds=("ip",),
            output_fields=("destination_ip",),
            guaranteed_relations=("assigned_ip",),
        ),
        _typed_operation(
            operation_id="op-comm",
            input_kinds=("ip",),
            output_kinds=("entity",),
            output_fields=("value",),
            guaranteed_relations=("communicated_with",),
        ),
    )
    resolution = CapabilityRouteResolver().resolve(graph, ops, "mock")
    plan = SemanticGoalPlanner(ops, "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal, legacy_relation_matching=False,
    )
    assessments = {
        item.goal_id: item
        for item in assess_semantic_readiness(
            graph, plan, ops, candidate_routes=resolution.routes_by_goal,
        )
    }
    assert assessments["goal-ip"].readiness != CapabilityReadiness.CAPABILITY_GAP
    assert assessments["goal-dns"].readiness == CapabilityReadiness.CAPABILITY_GAP
    assert assessments["goal-target"].readiness != CapabilityReadiness.CAPABILITY_GAP
    assert "no_typed_reachable_route" not in assessments["goal-target"].capability_gaps
    assert any("goal-target" in step.advances_goal_ids for step in plan.steps)


def test_gate_blocked_is_not_unsupported() -> None:
    graph = SemanticGoalGraph(
        id="graph-gate",
        request_id="req-gate",
        objective="observe a gated relation",
        variables=[
            SemanticVariable("host", "host", "host-1"),
            SemanticVariable("account", "account"),
            SemanticVariable("artifact", "file"),
        ],
        relations=[
            SemanticRelationGoal("goal-1", "host", "unregistered_logon", "account"),
            SemanticRelationGoal(
                "goal-2", "host", "wrote", "artifact",
                dependencies=("goal-1",),
                dependency_operator="GATE",
                gate_condition="goal-1:verified",
            ),
        ],
    )
    typed = _typed_operation(
        operation_id="op-write",
        input_kinds=("host",),
        output_kinds=("file",),
        output_fields=("file_path",),
        guaranteed_relations=("wrote",),
    )
    resolution = CapabilityRouteResolver().resolve(graph, (typed,), "mock")
    plan = SemanticGoalPlanner((typed,), "mock").compose(
        graph, candidate_routes=resolution.routes_by_goal, legacy_relation_matching=False,
    )
    assessments = {
        item.goal_id: item
        for item in assess_semantic_readiness(
            graph, plan, (typed,), candidate_routes=resolution.routes_by_goal,
        )
    }
    assert assessments["goal-2"].status != SemanticRouteStatus.CAPABILITY_GAP
    assert assessments["goal-2"].terminal_cause is None or assessments["goal-2"].terminal_cause.value != "UNSUPPORTED"
    assert "blocked_on_dependency" in assessments["goal-2"].capability_gaps
    assert "no_typed_reachable_route" not in assessments["goal-2"].capability_gaps
