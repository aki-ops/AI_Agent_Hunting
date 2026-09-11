import json

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import HuntRequest, HuntRequestKind


def test_unstructured_llm_can_compile_direct_goal_graph() -> None:
    payload = {
        "id": "goal-graph-1",
        "request_id": "req-1",
        "objective": "Find the domain visited by Amber",
        "variables": [
            {"id": "person", "entity_type": "person", "value": "Amber"},
            {"id": "domain", "entity_type": "domain"},
        ],
        "relations": [{"id": "g1", "subject": "person", "relation": "visited", "object": "domain", "required": True}],
        "qualifiers": [],
        "answers": [{"variable_id": "domain", "answer_type": "domain"}],
    }
    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _: json.dumps(payload))
    objective, hypotheses, requirements = compiler.compile(HuntRequest("req-1", HuntRequestKind.NL_QUESTION, "Where did Amber go?"))
    assert objective.semantic_goal_graph is not None
    assert objective.claim_graph is None
    assert hypotheses[0].status.value == "LIVE"
    assert requirements[0].semantic_intent == "visited"
