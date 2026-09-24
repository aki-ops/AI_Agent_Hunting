from types import SimpleNamespace

from hunting.contracts.capability_query import CapabilityQuery, build_capability_queries
from hunting.contracts.semantic_graph import SemanticConstraint


def _graph(relation: str):
    return SimpleNamespace(
        variables=(
            SimpleNamespace(id="subject", entity_type="person", constraints=()),
            SimpleNamespace(
                id="object",
                entity_type="file",
                constraints=(SemanticConstraint("format", "zip"),),
            ),
        ),
        relations=(SimpleNamespace(id="goal-1", subject="subject", relation=relation, object="object"),),
        qualifiers=(),
        answers=(SimpleNamespace(variable_id="object", answer_type="file_name"),),
    )


def test_relation_wording_is_not_the_structural_f1_key():
    first = build_capability_queries(_graph("sent_to"))[0]
    second = build_capability_queries(_graph("delivered_to"))[0]

    assert first.key == second.key
    assert first.relation_text != second.relation_text


def test_capability_query_keeps_unknown_relation_as_proposal():
    query = build_capability_queries(_graph("novel_relation"))[0]
    assert query.canonical_relation is None
    assert query.proposed_unregistered is True
    assert query.to_dict()["query_key"]


def test_capability_query_has_no_provider_or_scenario_route():
    query = CapabilityQuery("g", "person", "file", "file_name", relation_text="sent_to")
    assert not hasattr(query, "index")
    assert not hasattr(query, "sourcetype")


def test_identity_goal_without_answer_keeps_empty_answer_role():
    graph = SimpleNamespace(
        variables=(
            SimpleNamespace(id="subject", entity_type="person", constraints=()),
            SimpleNamespace(id="object", entity_type="device", constraints=()),
        ),
        relations=(SimpleNamespace(id="goal-identity", subject="subject", relation="associated_with", object="object"),),
        qualifiers=(),
        answers=(),
    )
    query = build_capability_queries(graph)[0]
    assert query.subject_type == "person"
    assert query.object_type == "device"
    assert query.answer_role == ""


def test_answer_role_is_only_taken_from_object_answer_goal():
    graph = SimpleNamespace(
        variables=(
            SimpleNamespace(id="subject", entity_type="person", constraints=()),
            SimpleNamespace(id="object", entity_type="file", constraints=()),
            SimpleNamespace(id="other", entity_type="device", constraints=()),
        ),
        relations=(SimpleNamespace(id="goal-1", subject="subject", relation="observed", object="object"),),
        qualifiers=(),
        answers=(
            SimpleNamespace(variable_id="other", answer_type="device"),
            SimpleNamespace(variable_id="object", answer_type="file_name"),
        ),
    )
    query = build_capability_queries(graph)[0]
    assert query.object_type == "file"
    assert query.answer_role == "file_name"
