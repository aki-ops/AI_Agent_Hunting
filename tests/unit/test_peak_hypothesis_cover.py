"""File identity answers are rewritten onto a file variable; C2 maps ports only."""
from hunting.capabilities.source_profiler import compact_fields_for_c2, mapping_ports
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticQualifierGoal,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile
from hunting.validator.investigation_validator import SemanticGoalGraphValidator


def _live_cover_graph() -> SemanticGoalGraph:
    return SemanticGoalGraph(
        id="g-live",
        request_id="req-live",
        objective="name the attachment",
        variables=[
            SemanticVariable("actor", "person"),
            SemanticVariable("recipient", "email_address"),
        ],
        relations=[SemanticRelationGoal("goal-1", "actor", "sent_message", "recipient")],
        qualifiers=[
            SemanticQualifierGoal("q1", "goal-1", "threat_actor_group", "Taedonggang"),
        ],
        answers=[SemanticAnswerGoal("recipient", "attachment_name")],
    )


def test_file_answer_on_email_is_moved_to_a_file_variable():
    result = SemanticGoalGraphValidator().validate_goal_graph(
        _live_cover_graph(),
        "What is the name of the attachment sent to Frothly?",
    )
    assert result.valid is True
    assert not result.rejections
    answer = result.validated_graph.answers[0]
    variable = next(item for item in result.validated_graph.variables if item.id == answer.variable_id)
    assert variable.entity_type == "file"
    assert answer.answer_type == "attachment_name"
    assert any(rel.relation == "sent_message" for rel in result.validated_graph.relations)
    assert {item.entity_type for item in result.validated_graph.variables} >= {"person", "email_address", "file"}
    assert any("moved" in item and "email_address" in item for item in result.diagnostics)


def test_file_answer_on_file_variable_is_accepted():
    graph = SemanticGoalGraph(
        id="g-ok",
        request_id="req-ok",
        objective="name the attachment",
        variables=[
            SemanticVariable("actor", "person"),
            SemanticVariable("recipient", "email_address"),
            SemanticVariable("attachment", "file"),
        ],
        relations=[SemanticRelationGoal("goal-1", "actor", "sent_message", "recipient")],
        answers=[SemanticAnswerGoal("attachment", "file_name")],
    )
    result = SemanticGoalGraphValidator().validate_goal_graph(
        graph,
        "What is the name of the attachment sent to Frothly?",
    )
    assert result.valid is True
    assert not result.rejections


def test_threat_actor_is_not_a_mapping_port():
    ports = mapping_ports({
        "subject_type": "person",
        "object_type": "email_address",
        "answer_role": "attachment_name",
        "constraint_keys": ["threat_actor_group", "organization"],
        "qualifier_hints": [{"key": "threat_actor_group", "value": "Taedonggang"}],
    })
    assert "attachment_name" in ports["mapping_keys"]
    assert "email_address" in ports["mapping_keys"]
    assert "threat_actor_group" in ports["unmapped_keys"]
    assert "organization" in ports["unmapped_keys"]


def test_c2_window_keeps_filename_ahead_of_noise():
    noise = tuple(TelemetryFieldProfile(f"n{i}", f"noise_{i}", "string") for i in range(12))
    profile = TelemetrySourceProfile(
        source_id="smtp",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="stream:smtp",
        fields=noise + (
            TelemetryFieldProfile("f_sender", "sender", "string"),
            TelemetryFieldProfile("f_file", "filename", "string"),
        ),
    )
    compact = compact_fields_for_c2(
        profile.fields,
        ("email_address", "attachment_name"),
        limit=6,
    )
    names = [field.name for field in compact]
    assert "filename" in names
    assert "sender" in names
