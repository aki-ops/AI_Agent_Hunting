import json

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import HuntRequest, HuntRequestKind


def test_unstructured_llm_can_compile_direct_goal_graph() -> None:
    payload = {
        "id": "goal-graph-1",
        "request_id": "req-1",
        "objective": "Find the domain visited by a host",
        "variables": [
            {"id": "host", "entity_type": "host", "value": "workstation-01"},
            {"id": "domain", "entity_type": "domain"},
        ],
        "relations": [{"id": "g1", "subject": "host", "relation": "visited", "object": "domain", "required": True}],
        "qualifiers": [],
        "answers": [{"variable_id": "domain", "answer_type": "domain"}],
    }
    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _: json.dumps(payload))
    objective, hypotheses, requirements = compiler.compile(HuntRequest("req-1", HuntRequestKind.NL_QUESTION, "Where did Amber go?"))
    assert objective.semantic_goal_graph is not None
    assert objective.claim_graph is None
    assert hypotheses[0].status.value == "LIVE"
    assert requirements[0].semantic_intent == "visited"


def test_alert_and_poc_compile_to_the_same_goal_graph_contract() -> None:
    payload = {
        "id": "goal-graph-alert",
        "request_id": "req-alert",
        "objective": "Investigate suspicious process on workstation-01",
        "variables": [
            {"id": "host", "entity_type": "host", "value": "workstation-01"},
            {"id": "process", "entity_type": "process"},
        ],
        "relations": [{"id": "g1", "subject": "host", "relation": "executed", "object": "process", "required": True}],
        "qualifiers": [],
        "answers": [{"variable_id": "process", "answer_type": "process"}],
    }
    kinds = (
        (HuntRequestKind.HYPOTHESIS, "A host executed a suspicious process"),
    )
    graphs = []
    for kind, content in kinds:
        compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _: json.dumps(payload))
        objective, hypotheses, _requirements = compiler.compile(HuntRequest(f"req-{kind.value}", kind, content))
        assert objective.semantic_goal_graph is not None
        assert objective.claim_graph is None
        assert hypotheses[0].status.value == "LIVE"
        graphs.append(type(objective.semantic_goal_graph).__name__)
    assert len(set(graphs)) == 1
