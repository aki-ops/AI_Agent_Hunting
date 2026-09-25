"""Goal class is assigned after validation, without another model call."""
from __future__ import annotations

import json

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.compiler.goal_class import annotate_goal_classes
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.contracts.semantic_graph import (
    SemanticAnswerGoal,
    SemanticGoalGraph,
    SemanticQualifierGoal,
    SemanticRelationGoal,
    SemanticVariable,
)

LOGON = "Tài khoản dịch vụ đang bị dùng để đăng nhập tương tác (RDP/console) vào Windows server."


def _graph(relation: str, qualifier: str | None, answer_type: str) -> SemanticGoalGraph:
    relations = [SemanticRelationGoal(id="goal-1", subject="subject", relation=relation, object="target")]
    qualifiers = []
    if qualifier:
        qualifiers.append(SemanticQualifierGoal(
            id="q1", target_goal_id="goal-1", qualifier=qualifier, expected_value="interactive",
        ))
    return SemanticGoalGraph(
        id="g",
        request_id="req",
        objective="objective",
        variables=[
            SemanticVariable(id="subject", entity_type="account"),
            SemanticVariable(id="target", entity_type="endpoint"),
        ],
        relations=relations,
        qualifiers=qualifiers,
        answers=[SemanticAnswerGoal(variable_id="target", answer_type=answer_type)],
    )


def test_logon_relation_is_behavior_and_keeps_channels():
    graph = annotate_goal_classes(_graph("logged_on_to", "logon_type", "hostname"), LOGON)
    assert graph.relations[0].goal_class == "behavior"
    assert graph.qualifiers[0].retrieval_terms == ("RDP", "console")


def test_filename_question_is_artifact():
    graph = annotate_goal_classes(
        _graph("stored_on", None, "file_name"),
        "What is the name of the attachment?",
    )
    assert graph.relations[0].goal_class == "artifact"


def test_compiler_assigns_class_after_a_validated_proposal():
    payload = {
        "id": "goal-graph-req",
        "request_id": "req-logon",
        "objective": LOGON,
        "variables": [
            {"id": "service_account", "entity_type": "account"},
            {"id": "windows_server", "entity_type": "endpoint"},
        ],
        "relations": [{
            "id": "goal-1",
            "subject": "service_account",
            "relation": "logged_on_to",
            "object": "windows_server",
            "required": True,
            "description": "service account logon",
        }],
        "qualifiers": [{
            "id": "qualifier-interactive-logon",
            "target_goal_id": "goal-1",
            "qualifier": "logon_type",
            "expected_value": "interactive",
            "required": True,
        }],
        "answers": [
            {"variable_id": "service_account", "answer_type": "account_name"},
            {"variable_id": "windows_server", "answer_type": "hostname"},
        ],
    }
    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _prompt: json.dumps(payload), require_semantic_goal_graph=True)
    objective, _hypotheses, _requirements = compiler.compile(HuntRequest(
        id="req-logon",
        kind=HuntRequestKind.HYPOTHESIS,
        content=LOGON,
    ))
    relation = objective.semantic_goal_graph.relations[0]
    qualifier = objective.semantic_goal_graph.qualifiers[0]
    assert relation.goal_class == "behavior"
    assert "RDP" in qualifier.retrieval_terms
    assert "console" in qualifier.retrieval_terms
    assert compiler.llm_calls_made == 1
