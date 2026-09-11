from hunting.contracts.queries import ProviderOperation
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner


def _graph() -> SemanticGoalGraph:
    return SemanticGoalGraph(
        id="goal-1",
        request_id="req-1",
        objective="Follow a subject to a domain",
        variables=[
            SemanticVariable("person", "person", "Amber"),
            SemanticVariable("host", "host"),
            SemanticVariable("domain", "domain"),
        ],
        relations=[
            SemanticRelationGoal("person-host", "person", "associated_with", "host"),
            SemanticRelationGoal("host-domain", "host", "communicated_with", "domain"),
        ],
        answers=[SemanticAnswerGoal("domain", "domain")],
    )


def test_composes_multiple_steps_without_operation_name_heuristics() -> None:
    operations = [
        ProviderOperation(
            id="op-a",
            provider_id="p",
            scope_ids=("scope",),
            input_entity_kinds=("person",),
            output_entity_kinds=("host",),
            guaranteed_relations=("associated_with",),
        ),
        ProviderOperation(
            id="op-b",
            provider_id="p",
            scope_ids=("scope",),
            input_entity_kinds=("host",),
            output_entity_kinds=("domain",),
            guaranteed_relations=("communicated_with",),
        ),
    ]
    plan = SemanticGoalPlanner(operations, "p").compose(_graph())
    assert [step.operation_id for step in plan.steps] == ["op-a", "op-b"]
    assert plan.unresolved_goal_ids == []
    assert plan.steps[1].depends_on == ("step-1",)
    selected_host_domain = next(method for method in plan.proof_methods if method.goal_id == "host-domain")
    assert selected_host_domain.prerequisite_goal_ids == ("person-host",)


def test_unavailable_relation_is_explicitly_unresolved() -> None:
    operation = ProviderOperation(
        id="op-a",
        provider_id="p",
        scope_ids=("scope",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        guaranteed_relations=("associated_with",),
    )
    plan = SemanticGoalPlanner((operation,), "p").compose(_graph())
    assert plan.unresolved_goal_ids == ["host-domain"]


def test_planner_inserts_typed_intermediate_capabilities() -> None:
    graph = SemanticGoalGraph(
        id="goal-2",
        request_id="req-2",
        objective="Find a domain visited by a person",
        variables=[
            SemanticVariable("person", "person", "Amber"),
            SemanticVariable("domain", "domain"),
        ],
        relations=[SemanticRelationGoal("visited", "person", "visited", "domain")],
    )
    operations = [
        ProviderOperation("person-account", "p", ("s",), input_entity_kinds=("person",), output_entity_kinds=("account",), guaranteed_relations=("associated_with",)),
        ProviderOperation("account-host", "p", ("s",), input_entity_kinds=("account",), output_entity_kinds=("host",), guaranteed_relations=("associated_with",)),
        ProviderOperation("host-domain", "p", ("s",), input_entity_kinds=("host",), output_entity_kinds=("domain",), guaranteed_relations=("visited",)),
    ]
    plan = SemanticGoalPlanner(operations, "p").compose(graph)
    assert [step.operation_id for step in plan.steps] == ["person-account", "account-host", "host-domain"]
    assert plan.unresolved_goal_ids == []


def test_typed_grounding_does_not_use_unrelated_relation_for_intermediate() -> None:
    graph = SemanticGoalGraph(
        id="goal-3",
        request_id="req-3",
        objective="Resolve a subject attribute",
        variables=[
            SemanticVariable("person", "person", "Amber"),
            SemanticVariable("attribute", "email_address"),
        ],
        relations=[SemanticRelationGoal("attribute", "person", "associated_with", "attribute")],
    )
    operations = [
        ProviderOperation(
            "unrelated-auth",
            "p",
            ("s",),
            input_entity_kinds=("person",),
            output_entity_kinds=("account",),
            guaranteed_relations=("authenticated",),
        ),
        ProviderOperation(
            "identity-person-account",
            "p",
            ("s",),
            input_entity_kinds=("person",),
            output_entity_kinds=("account",),
            guaranteed_relations=("associated_with",),
        ),
        ProviderOperation(
            "identity-account-attribute",
            "p",
            ("s",),
            input_entity_kinds=("account",),
            output_entity_kinds=("email_address",),
            guaranteed_relations=("associated_with",),
        ),
    ]
    plan = SemanticGoalPlanner(operations, "p").compose(graph)
    assert [step.operation_id for step in plan.steps] == [
        "identity-person-account",
        "identity-account-attribute",
    ]


def test_planner_prefers_narrow_capability_and_keeps_alternatives() -> None:
    graph = SemanticGoalGraph(
        id="goal-file",
        request_id="req-file",
        objective="Find a file changed on a host",
        variables=[SemanticVariable("host", "host", "venus"), SemanticVariable("file", "file")],
        relations=[SemanticRelationGoal("file-change", "host", "modified", "file")],
    )
    operations = [
        ProviderOperation("generic-file-scan", "p", ("s",), input_entity_kinds=("host", "account", "process", "file"), output_entity_kinds=("file",), guaranteed_relations=("modified",)),
        ProviderOperation("host-file-change", "p", ("s",), input_entity_kinds=("host", "file"), output_entity_kinds=("file",), guaranteed_relations=("modified",)),
    ]
    plan = SemanticGoalPlanner(operations, "p").compose(graph)
    assert plan.steps[0].operation_id == "host-file-change"
    assert plan.steps[0].alternative_operation_ids == ("generic-file-scan",)


def test_planner_keeps_unproven_operation_as_a_retrieval_alternative() -> None:
    graph = SemanticGoalGraph(
        id="goal-constraint",
        request_id="req-constraint",
        objective="Find an encrypted file",
        variables=[
            SemanticVariable("host", "host", "venus"),
            SemanticVariable("file", "file", constraints=("state=encrypted",)),
        ],
        relations=[SemanticRelationGoal("changed", "host", "modified", "file")],
    )
    unsupported = ProviderOperation(
        "generic-file", "p", ("s",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"},
    )
    supported = ProviderOperation(
        "encrypted-file", "p", ("s",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), output_value_bindings={"object": ("file_path",)},
        output_binding_entity_kinds={"object": "file"}, supported_constraints=("state",),
    )
    plan = SemanticGoalPlanner((unsupported, supported), "p").compose(graph)
    assert plan.steps[0].operation_id == "encrypted-file"
    assert plan.steps[0].alternative_operation_ids == ("generic-file",)


def test_planner_keeps_base_relation_when_restriction_has_no_proof_capability() -> None:
    graph = SemanticGoalGraph(
        id="goal-unsupported-constraint",
        request_id="req-unsupported-constraint",
        objective="Find an encrypted file",
        variables=[SemanticVariable("host", "host", "venus"), SemanticVariable("file", "file", constraints=("state=encrypted",))],
        relations=[SemanticRelationGoal("changed", "host", "modified", "file")],
    )
    operation = ProviderOperation(
        "generic-file", "p", ("s",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), output_value_bindings={"object": ("file_path",)},
    )
    plan = SemanticGoalPlanner((operation,), "p").compose(graph)
    assert plan.unresolved_goal_ids == []
    assert plan.steps[0].constraints == ("state=encrypted",)


def test_planner_accepts_searchable_but_not_proven_restriction() -> None:
    graph = SemanticGoalGraph(
        id="goal-searchable", request_id="req-searchable", objective="Find an encrypted file",
        variables=[
            SemanticVariable("host", "host", "venus"),
            SemanticVariable("file", "file", constraints=("state=encrypted",)),
        ],
        relations=[SemanticRelationGoal("changed", "host", "modified", "file")],
    )
    operation = ProviderOperation(
        "file-search", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
        guaranteed_relations=("modified",), searchable_constraints=("state",),
        output_value_bindings={"object": ("file_path",)}, output_binding_entity_kinds={"object": "file"},
    )
    plan = SemanticGoalPlanner((operation,), "p").compose(graph)
    assert plan.unresolved_goal_ids == []
    assert plan.steps[0].constraints == ("state=encrypted",)


def test_variable_restriction_stays_on_its_grounding_step() -> None:
    graph = SemanticGoalGraph(
        id="goal-scoped", request_id="req-scoped", objective="Find a file on the user's laptop",
        variables=[
            SemanticVariable("person", "person", "Amber"),
            SemanticVariable("host", "host", constraints=("device_type=MacBook",)),
            SemanticVariable("file", "file"),
        ],
        relations=[
            SemanticRelationGoal("person-host", "person", "associated_with", "host"),
            SemanticRelationGoal("host-file", "host", "modified", "file"),
        ],
    )
    operations = [
        ProviderOperation(
            "person-host", "p", ("scope",), input_entity_kinds=("person",), output_entity_kinds=("host",),
            guaranteed_relations=("associated_with",), searchable_constraints=("device_type",),
            output_value_bindings={"object": ("host",)}, output_binding_entity_kinds={"object": "host"},
        ),
        ProviderOperation(
            "host-file", "p", ("scope",), input_entity_kinds=("host",), output_entity_kinds=("file",),
            guaranteed_relations=("modified",), output_value_bindings={"object": ("file_path",)},
            output_binding_entity_kinds={"object": "file"},
        ),
    ]
    plan = SemanticGoalPlanner(operations, "p").compose(graph)
    assert plan.unresolved_goal_ids == []
    assert plan.steps[0].constraints == ("device_type=MacBook",)
    assert plan.steps[1].constraints == ()
