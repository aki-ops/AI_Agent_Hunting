from hunting.contracts.cells import ProviderScope
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep
from hunting.planner.semantic_query_compiler import query_plan_from_step


def test_step_compiles_to_query_envelope_without_native_syntax() -> None:
    logical = LogicalPlan(
        id="logical-1",
        goal_graph_id="goal-1",
        provider_id="splunk",
        steps=[PlanStep("s1", "provider.operation", {"subject": "person"}, {"object": "host"}, ("g1",))],
    )
    query = query_plan_from_step(
        logical,
        logical.steps[0],
        ProviderScope("splunk", "scope", {"index": "hidden-from-core"}),
        "2026-01-01T00:00:00Z/P1D",
    )
    assert query.operation_id == "provider.operation"
    assert query.parameters["logical_plan_id"] == "logical-1"
    assert "index=" not in str(query.parameters)


def test_semantic_constraints_survive_plan_to_query_boundary() -> None:
    logical = LogicalPlan(
        id="logical-constraints",
        goal_graph_id="goal-constraints",
        provider_id="splunk",
        steps=[PlanStep(
            "s1",
            "provider.operation",
            {"subject": "person"},
            {"object": "file"},
            ("g1",),
            constraints=("date=August 18", "platform=MacBook", "kind=PowerPoint"),
        )],
    )
    query = query_plan_from_step(
        logical,
        logical.steps[0],
        ProviderScope("splunk", "scope", {}),
        "2026-08-18T00:00:00Z/P1D",
    )
    assert query.parameters["constraints"] == [
        "date=August 18", "platform=MacBook", "kind=PowerPoint"
    ]
