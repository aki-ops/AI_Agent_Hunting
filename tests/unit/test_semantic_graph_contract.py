import pytest

from hunting.compiler.compiler import parse_and_validate_semantic_goal_graph
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticAnswerGoal,
    SemanticConstraint,
    SemanticGoalGraph,
    SemanticQualifierGoal,
    SemanticRelationGoal,
    SemanticVariable,
)


def test_goal_graph_is_provider_neutral_and_serializable() -> None:
    graph = SemanticGoalGraph(
        id="goal-1",
        request_id="req-1",
        objective="Find the software version used by the subject",
        variables=[
            SemanticVariable("subject", "person", "Amber"),
            SemanticVariable("software", "software"),
            SemanticVariable("version", "version"),
        ],
        relations=[
            SemanticRelationGoal("installed", "subject", "installed", "software"),
            SemanticRelationGoal("has-version", "software", "has_version", "version"),
        ],
        qualifiers=[SemanticQualifierGoal("q1", "installed", "observed_in_telemetry")],
        answers=[SemanticAnswerGoal("version", "software_version")],
    )

    payload = graph.to_dict()
    assert payload["relations"][0]["relation"] == "installed"
    assert "index" not in str(payload).lower()
    assert "sourcetype" not in str(payload).lower()


def test_goal_graph_rejects_dangling_references() -> None:
    with pytest.raises(ValueError, match="unknown variable"):
        SemanticGoalGraph(
            id="goal-1",
            request_id="req-1",
            objective="x",
            variables=[SemanticVariable("subject", "person")],
            relations=[SemanticRelationGoal("r1", "subject", "observed", "missing")],
        )


def test_logical_plan_supports_composed_steps() -> None:
    plan = LogicalPlan(
        id="plan-1",
        goal_graph_id="goal-1",
        provider_id="splunk",
        steps=[
            PlanStep("s1", "operation-a", output_bindings={"account": "account-1"}),
            PlanStep(
                "s2",
                "operation-b",
                input_bindings={"account": "account-1"},
                advances_goal_ids=("r1",),
                depends_on=("s1",),
            ),
        ],
    )
    assert plan.to_dict()["steps"][1]["depends_on"] == ["s1"]


def test_plan_step_serializes_constraints() -> None:
    step = PlanStep("s1", "operation", constraints=("date=August 18", "kind=PowerPoint"))
    assert step.to_dict()["constraints"] == ["date=August 18", "kind=PowerPoint"]


def test_logical_plan_rejects_unknown_dependency() -> None:
    with pytest.raises(ValueError, match="unknown steps"):
        LogicalPlan(
            id="plan-1",
            goal_graph_id="goal-1",
            provider_id="provider",
            steps=[PlanStep("s1", "operation", depends_on=("missing",))],
        )


def test_compiler_accepts_generic_goal_graph_payload() -> None:
    graph = parse_and_validate_semantic_goal_graph({
        "id": "goal-1",
        "request_id": "req-1",
        "objective": "Find the observed domain",
        "variables": [
            {"id": "person", "entity_type": "person", "value": "Amber"},
            {"id": "domain", "entity_type": "domain"},
        ],
        "relations": [{"id": "r1", "subject": "person", "relation": "visited", "object": "domain"}],
        "qualifiers": [],
        "answers": [{"variable_id": "domain", "answer_type": "domain"}],
    }, "req-1")
    assert graph.answers[0].answer_type == "domain"


def test_object_constraints_are_typed_and_not_stringified() -> None:
    graph = parse_and_validate_semantic_goal_graph({
        "id": "goal-constraints",
        "request_id": "req-constraints",
        "objective": "Find the requested file",
        "variables": [
            {"id": "host", "entity_type": "host", "value": "MacBook", "constraints": [
                {"type": "device_type", "value": "MacBook"},
            ]},
            {"id": "file", "entity_type": "file", "constraints": [
                {"key": "state", "operator": "equals", "value": "encrypted"},
            ]},
        ],
        "relations": [{"id": "r1", "subject": "host", "relation": "modified", "object": "file"}],
        "qualifiers": [],
        "answers": [{"variable_id": "file", "answer_type": "file"}],
    }, "req-constraints")
    assert isinstance(graph.variables[0].constraints[0], SemanticConstraint)
    assert graph.variables[1].constraints[0].text() == "state=encrypted"
    assert "{'type'" not in str(graph.to_dict())
    assert graph.variables[0].value_origin == "llm_proposal"


def test_retrieval_terms_are_data_and_survive_planning_contract() -> None:
    graph = parse_and_validate_semantic_goal_graph({
        "id": "goal-retrieval-terms",
        "request_id": "req-retrieval-terms",
        "objective": "Find the requested artifact",
        "variables": [
            {"id": "subject", "entity_type": "person", "value": "Analyst"},
            {"id": "artifact", "entity_type": "artifact", "constraints": [{
                "key": "artifact_type",
                "value": "document",
                "retrieval_terms": ["*.docx", "briefing"],
            }]},
        ],
        "relations": [{"id": "r1", "subject": "subject", "relation": "modified", "object": "artifact"}],
        "qualifiers": [],
        "answers": [{"variable_id": "artifact", "answer_type": "file_name"}],
    }, "req-retrieval-terms")
    constraint = graph.variables[1].constraints[0]
    assert constraint.retrieval_terms == ("*.docx", "briefing")
    assert graph.to_dict()["variables"][1]["constraints"][0]["retrieval_terms"] == ["*.docx", "briefing"]


def test_retrieval_terms_reject_native_query_syntax() -> None:
    with pytest.raises(ValueError, match="Raw SPL syntax"):
        parse_and_validate_semantic_goal_graph({
            "id": "goal-injection",
            "request_id": "req-injection",
            "objective": "Find an artifact",
            "variables": [
                {"id": "subject", "entity_type": "person", "value": "Analyst"},
                {"id": "artifact", "entity_type": "artifact", "constraints": [{"key": "name", "value": "x", "retrieval_terms": ["index=botsv2 | head 1"]}]},
            ],
            "relations": [{"id": "r1", "subject": "subject", "relation": "modified", "object": "artifact"}],
            "qualifiers": [],
            "answers": [{"variable_id": "artifact", "answer_type": "file_name"}],
        }, "req-injection")


def test_wrong_qualifier_shape_is_rejected_instead_of_dropped() -> None:
    with pytest.raises(ValueError, match="target_goal_id/qualifier/expected_value"):
        parse_and_validate_semantic_goal_graph({
            "id": "goal-bad-qualifier",
            "request_id": "req-bad-qualifier",
            "objective": "Find a value",
            "variables": [{"id": "subject", "entity_type": "person", "value": "Amber"}, {"id": "value", "entity_type": "value"}],
            "relations": [{"id": "r1", "subject": "subject", "relation": "associated_with", "object": "value"}],
            "qualifiers": [{"relation_id": "r1", "type": "role", "value": "owner"}],
            "answers": [{"variable_id": "value", "answer_type": "value"}],
        }, "req-bad-qualifier")
