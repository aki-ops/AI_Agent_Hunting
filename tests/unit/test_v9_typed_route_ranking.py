"""Ranking and leftover-catalog counterexamples.  Separate from the type matrix."""
from __future__ import annotations

from hunting.capabilities.route_resolver import CapabilityRouteResolver
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import (
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner


def _graph() -> SemanticGoalGraph:
    return SemanticGoalGraph(
        id="graph-rank",
        request_id="req-rank",
        objective="observe a typed host attribute",
        variables=[
            SemanticVariable("subject", "person", "subject-1"),
            SemanticVariable("device", "device"),
        ],
        relations=[SemanticRelationGoal("goal-1", "subject", "associated_with", "device")],
    )


def test_typed_mapped_f0_outranks_discovery_and_untyped_sweep() -> None:
    typed = ProviderOperation(
        id="op-typed-mapped",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        output_roles=("endpoint_identity",),
        output_fields=("host",),
        native_field_bindings={"subject": ("user",)},
        output_value_bindings={"object": ("host",)},
        guaranteed_relations=("associated_with",),
        discovery_provenance=("F0_CERTIFIED",),
        route_class="EXECUTABLE",
        expected_cost=10,
        query_builder="mock.typed.v1",
    )
    discovery = ProviderOperation(
        id="op-sourcetype-discovery",
        provider_id="mock",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        guaranteed_relations=("associated_with",),
        route_class="DISCOVERY_ONLY",
        expected_cost=1,
    )
    leftover = ProviderOperation(
        id="untyped-sweep",
        provider_id="mock",
        scope_ids=("scope",),
        output_fields=("raw", "sourcetype"),
        output_value_bindings={"object": ("raw",)},
        guaranteed_relations=("associated_with",),
        route_class="EXECUTABLE",
        expected_cost=1,
    )
    graph = _graph()
    plan = SemanticGoalPlanner((leftover, discovery, typed), "mock").compose(graph)
    assert plan.steps
    assert plan.steps[0].operation_id == "op-typed-mapped"


def test_cdb_shaped_leftover_on_typed_catalog_does_not_win() -> None:
    leftover = ProviderOperation(
        id="legacy_scope_copy",
        provider_id="typed_provider",
        scope_ids=("scope",),
        params_schema={"window": "interval", "limit": "integer"},
        expected_cost=1,
    )
    typed = ProviderOperation(
        id="op-typed-identity",
        provider_id="typed_provider",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        native_field_bindings={"subject": ("user",)},
        output_value_bindings={"object": ("host",)},
        output_fields=("host",),
        guaranteed_relations=("associated_with",),
        discovery_provenance=("F0_CERTIFIED",),
        expected_cost=8,
        query_builder="typed.identity.v1",
    )
    graph = SemanticGoalGraph(
        id="graph-catalog",
        request_id="req-catalog",
        objective="identify an endpoint",
        variables=[
            SemanticVariable("subject", "person", "subject-1"),
            SemanticVariable("device", "device"),
        ],
        relations=[SemanticRelationGoal("goal-1", "subject", "associated_with", "device")],
    )
    resolution = CapabilityRouteResolver().resolve(
        graph, (leftover, typed), "typed_provider",
    )
    plan = SemanticGoalPlanner((leftover, typed), "typed_provider").compose(
        graph, candidate_routes=resolution.routes_by_goal, legacy_relation_matching=True,
    )
    assert plan.steps
    assert plan.steps[0].operation_id == "op-typed-identity"
    assert leftover.route_class == "DISCOVERY_ONLY" or leftover.legacy_alias is True
    assert not any(
        route.executable and route.operation_id == leftover.id
        for route in resolution.routes_by_goal.get("goal-1", ())
    )
