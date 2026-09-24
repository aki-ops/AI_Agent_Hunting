"""Typed port projection: QueryResult cells fill a slot only via a typed port.

Generic counterexamples. No scenario names, no playbooks, no LLM field picking.
"""
from __future__ import annotations

from hunting.capabilities.route_resolver import CapabilityRouteResolver
from hunting.contracts.cells import ProviderScope
from hunting.contracts.ontology import native_field_compatible_with_kind
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult, is_untyped_leftover_contract
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.planner.semantic_executor import SemanticPlanExecutor
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner
from hunting.planner.semantic_query_compiler import query_plan_from_step
from hunting.validator.investigation_validator import SemanticGoalGraphValidator


class _RowAdapter:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows

    def execute_query(self, **kwargs):
        return QueryResult(
            kwargs["query_id"],
            QueryOutcome.ROWS,
            True,
            True,
            rows=list(self.rows),
        )


def _execute(
    operation: ProviderOperation,
    rows: list[dict],
    *,
    object_type: str,
    object_id: str = "object",
) -> object:
    adapter = _RowAdapter(rows)
    plan = LogicalPlan(
        "plan",
        "g",
        "p",
        [PlanStep("s1", operation.id, {"subject": "subject"}, {"object": object_id})],
    )
    return SemanticPlanExecutor(adapter, [operation]).execute(
        plan,
        ProviderScope("p", "scope", {}),
        "2017-08-01T00:00:00Z/P30D",
        {"subject": "subject-1"},
        variable_types={"subject": "person", object_id: object_type},
    )


def test_untyped_port_does_not_bind_first_nonempty_cell_as_file() -> None:
    operation = ProviderOperation(
        "scan",
        "p",
        ("scope",),
        input_entity_kinds=("ANY",),
        output_entity_kinds=("file", "ip"),
        output_value_bindings={"object": ("destination_ip", "file_path")},
    )
    result = _execute(
        operation,
        [{"destination_ip": "172.31.7.2", "file_path": ""}],
        object_type="file",
        object_id="artifact",
    )
    assert "artifact" not in result.variables
    assert "172.31.7.2" not in str(result.variables)


def test_untyped_port_does_not_bind_uri_as_host() -> None:
    operation = ProviderOperation(
        "scan",
        "p",
        ("scope",),
        input_entity_kinds=("ANY",),
        output_entity_kinds=("host", "domain"),
        output_value_bindings={"object": ("uri", "host")},
    )
    result = _execute(
        operation,
        [{"uri": "/shop/item", "host": "endpoint-1"}],
        object_type="host",
        object_id="device",
    )
    assert "device" not in result.variables
    assert result.variables.get("device") != ["/shop/item"]


def test_typed_file_port_binds_path_not_ip_on_same_row() -> None:
    operation = ProviderOperation(
        "find-file",
        "p",
        ("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
    )
    result = _execute(
        operation,
        [{"destination_ip": "10.0.0.9", "file_path": "/tmp/report.bin"}],
        object_type="file",
        object_id="artifact",
    )
    assert result.variables["artifact"] == ["/tmp/report.bin"]


def test_known_incompatible_field_on_file_port_is_not_bound() -> None:
    operation = ProviderOperation(
        "find-file",
        "p",
        ("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("destination_ip", "file_path")},
        output_binding_entity_kinds={"object": "file"},
    )
    result = _execute(
        operation,
        [{"destination_ip": "10.0.0.9", "file_path": ""}],
        object_type="file",
        object_id="artifact",
    )
    assert "artifact" not in result.variables


def test_typed_host_port_does_not_bind_when_only_uri_is_populated() -> None:
    operation = ProviderOperation(
        "find-host",
        "p",
        ("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        output_value_bindings={"object": ("host",)},
        output_binding_entity_kinds={"object": "host"},
    )
    result = _execute(
        operation,
        [{"uri": "/shop/item", "host": ""}],
        object_type="host",
        object_id="device",
    )
    assert "device" not in result.variables


def test_unknown_native_filename_field_stays_on_file_port() -> None:
    assert native_field_compatible_with_kind("TargetFilename", "file") is True
    assert native_field_compatible_with_kind("destination_ip", "file") is False
    assert native_field_compatible_with_kind("host_value", "host") is True


def test_query_intent_projects_typed_native_fields_not_logical_port_name() -> None:
    operation = ProviderOperation(
        "find-file",
        "p",
        ("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path", "destination_ip")},
        output_binding_entity_kinds={"object": "file"},
    )
    plan = LogicalPlan(
        "logical",
        "g",
        "p",
        [PlanStep("s1", "find-file", {"subject": "host"}, {"object": "artifact"}, ("g1",))],
    )
    query = query_plan_from_step(
        plan,
        plan.steps[0],
        ProviderScope("p", "scope", {}),
        "2017-08-01T00:00:00Z/P30D",
        operation=operation,
    )
    intent = query.parameters["query_intent"]
    assert "file_path" in intent["projection_roles"]
    assert "destination_ip" not in intent["projection_roles"]
    assert "object" not in intent["projection_roles"]


def test_soup_without_port_kind_is_discovery_leftover() -> None:
    leftover = ProviderOperation(
        "scope-scan",
        "p",
        ("scope",),
        input_entity_kinds=("ANY",),
        output_entity_kinds=("file", "ip", "process"),
        output_fields=("destination_ip", "file_path", "image", "uri"),
        output_value_bindings={"object": ("destination_ip", "file_path", "image", "uri")},
        route_class="EXECUTABLE",
    )
    assert is_untyped_leftover_contract(leftover) is True
    assert leftover.route_class == "DISCOVERY_ONLY"


def test_dump_operation_is_not_executable_file_route() -> None:
    dump = ProviderOperation(
        "sample_records",
        "p",
        ("scope",),
        input_entity_kinds=("ANY",),
        output_entity_kinds=("file", "ip"),
        output_fields=("destination_ip", "file_path"),
        output_value_bindings={"object": ("destination_ip", "file_path")},
        guaranteed_relations=("sent_message",),
        route_class="EXECUTABLE",
    )
    typed = ProviderOperation(
        "find-file",
        "p",
        ("scope",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
        guaranteed_relations=("modified",),
        query_builder="typed.file.v1",
        discovery_provenance=("F0_CERTIFIED",),
        route_class="EXECUTABLE",
    )
    graph = SemanticGoalGraph(
        id="graph-file",
        request_id="req-file",
        objective="name a file on a host",
        variables=[
            SemanticVariable("host", "host", "HOST-1"),
            SemanticVariable("artifact", "file"),
        ],
        relations=[SemanticRelationGoal("goal-1", "host", "modified", "artifact")],
    )
    resolution = CapabilityRouteResolver().resolve(graph, (dump, typed), "p")
    executable_ids = {
        route.operation_id
        for route in resolution.routes_by_goal.get("goal-1", ())
        if route.executable
    }
    assert "find-file" in executable_ids
    assert "sample_records" not in executable_ids
    plan = SemanticGoalPlanner((dump, typed), "p").compose(
        graph, candidate_routes=resolution.routes_by_goal, legacy_relation_matching=True,
    )
    assert plan.steps
    assert plan.steps[0].operation_id == "find-file"


def test_scope_catalog_ops_do_not_claim_file_or_ip_kinds() -> None:
    from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter

    adapter = SplunkLiveAdapter(index="botsv2", verify_ssl=False)
    sample = next(
        op for op in adapter.get_capability_descriptor().operations if op.id == "sample_records"
    )
    search = next(
        op for op in adapter.get_capability_descriptor().operations if op.id == "search_text"
    )
    for operation in (sample, search):
        kinds = {str(kind).casefold() for kind in operation.output_entity_kinds}
        assert "file" not in kinds
        assert "ip" not in kinds
        assert "process" not in kinds
        assert operation.route_class == "DISCOVERY_ONLY"
        assert not operation.output_binding_entity_kinds.get("object")


def test_sent_message_to_file_is_not_a_valid_graph() -> None:
    graph = SemanticGoalGraph(
        id="g-sig",
        request_id="req-sig",
        objective="name an attachment",
        variables=[
            SemanticVariable("actor", "person", "Actor", value_origin="request"),
            SemanticVariable("attachment", "file"),
        ],
        relations=[SemanticRelationGoal("goal-1", "actor", "sent_message", "attachment")],
    )
    result = SemanticGoalGraphValidator().validate_goal_graph(graph, "What attachment did Actor send?")
    assert result.valid is False
    assert any("sent_message" in item and "file" in item for item in result.rejections)


def test_executed_to_process_remains_valid() -> None:
    graph = SemanticGoalGraph(
        id="g-exec",
        request_id="req-exec",
        objective="name a process",
        variables=[
            SemanticVariable("device", "host", "HOST-1", value_origin="request"),
            SemanticVariable("proc", "process"),
        ],
        relations=[SemanticRelationGoal("goal-1", "device", "executed", "proc")],
    )
    result = SemanticGoalGraphValidator().validate_goal_graph(graph, "What process ran on HOST-1?")
    assert result.valid is True
    assert not result.rejections


def test_associated_with_ip_object_is_not_valid() -> None:
    graph = SemanticGoalGraph(
        id="g-assoc",
        request_id="req-assoc",
        objective="name an endpoint",
        variables=[
            SemanticVariable("user", "person", "Alice", value_origin="request"),
            SemanticVariable("addr", "ip"),
        ],
        relations=[SemanticRelationGoal("goal-1", "user", "associated_with", "addr")],
    )
    result = SemanticGoalGraphValidator().validate_goal_graph(graph, "Which host is associated with Alice?")
    assert result.valid is False
    assert any("associated_with" in item for item in result.rejections)
