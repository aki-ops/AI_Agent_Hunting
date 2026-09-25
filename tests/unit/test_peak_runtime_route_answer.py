"""Explicitly bound runtime route: answer slot may come from payload downstream."""
from hunting.capabilities.route_resolver import CapabilityRouteResolver
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import SemanticGoalGraph, SemanticRelationGoal, SemanticVariable


def test_explicit_runtime_route_forgiven_answer_role():
    graph = SemanticGoalGraph(
        id="g",
        request_id="req",
        objective="mail",
        variables=[
            SemanticVariable(id="recipient", entity_type="person", value="Frothly"),
            SemanticVariable(id="target_message", entity_type="message"),
        ],
        relations=[SemanticRelationGoal(
            id="goal-1", subject="recipient", relation="received_message",
            object="target_message", goal_class="behavior",
        )],
    )
    op = ProviderOperation(
        id="runtime:splunk:schema-x:splunk:botsv2:stream:smtp:received_message",
        provider_id="splunk",
        scope_ids=("botsv2",),
        input_entity_kinds=("person",),
        output_entity_kinds=("message",),
        output_fields=("sender", "receiver_email"),
        native_field_bindings={"subject": ("sender",)},
        output_value_bindings={"object": ("receiver_email",)},
        route_goal_ids=("goal-1",),
        route_class="EXECUTABLE",
        query_builder="runtime.source_profile.v1",
        discovery_provenance=("F2_C2_PROBED_CAPABILITY",),
    )
    resolution = CapabilityRouteResolver().resolve(graph, (op,), "splunk")
    assert resolution.routes_by_goal["goal-1"], "explicitly bound runtime route must survive answer_role=file_name"
    assert resolution.routes_by_goal["goal-1"][0].executable is True
