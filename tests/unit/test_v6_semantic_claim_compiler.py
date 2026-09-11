"""Phase B regression tests for request-derived ClaimGraph compilation."""
from __future__ import annotations

import json

from hunting.compiler.compiler import KnowledgeBehaviorCompiler, parse_and_validate_claim_graph
from hunting.contracts.claim import ClaimGraph
from hunting.contracts.hunt import HuntRequest, HuntRequestKind


def _payload(request_id: str, objective: str, claims: list[dict], answer_type: str = "email_address") -> str:
    return json.dumps({
        "id": f"graph-{request_id}",
        "request_id": request_id,
        "objective": objective,
        "answer_contract": {
            "mode": "lookup",
            "answer_type": answer_type,
            "required_fields": [],
            "question": objective,
        },
        "claims": claims,
    })


def _claim(
    request_id: str,
    claim_id: str,
    predicate: str,
    value_type: str,
    *,
    subject: str = "person:Amber Turing",
    dependencies: list[str] | None = None,
) -> dict:
    return {
        "id": claim_id,
        "claim_type": "relation" if dependencies else "attribute",
        "subject": subject,
        "predicate": predicate,
        "object_or_value": None,
        "value_type": value_type,
        "provenance": "request",
        "source_request_id": request_id,
        "dependencies": dependencies or [],
        "observation_requirements": [{
            "id": f"req-{claim_id}",
            "fact_kind": predicate,
            "required_fields": [],
            "field_roles": [],
            "completeness_required": False,
        }],
        "acceptance_rule": {
            "min_observations": 1,
            "required_fields": [],
            "requires_query_complete": False,
            "value_must_match": None,
        },
        "reason": f"The request asks to test {predicate}",
    }


def test_question_kind_compiles_claim_graph_in_one_call() -> None:
    request_id = "req-email-lookup"
    response = _payload(
        request_id,
        "What is Amber Turing's email address?",
        [_claim(request_id, "claim-email", "has_email", "email_address")],
    )
    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda _: response)
    objective, hypotheses, requirements = compiler.compile(HuntRequest(
        id=request_id,
        kind=HuntRequestKind.QUESTION,
        content="What is Amber Turing's email address?",
    ))

    assert compiler.llm_calls_made == 1
    assert isinstance(objective.claim_graph, ClaimGraph)
    assert [claim.predicate for claim in objective.claim_graph.claims] == ["has_email"]
    assert list(objective.case.graph.edges) == ["edge-claim-email"]
    assert not any(node.type in ("message", "role") for node in objective.case.graph.nodes.values())
    assert [hypothesis.id for hypothesis in hypotheses] == ["claim-email"]
    assert [requirement.id for requirement in requirements] == ["req-claim-email"]


def test_live_api_compiler_rejects_legacy_claim_graph_output() -> None:
    request_id = "req-live-boundary"
    response = _payload(
        request_id,
        "What is the encrypted filename?",
        [_claim(request_id, "claim-file", "has_file", "filename")],
        answer_type="filename",
    )
    compiler = KnowledgeBehaviorCompiler(
        llm_caller=lambda _: response,
        require_semantic_goal_graph=True,
    )

    objective, hypotheses, requirements = compiler.compile(HuntRequest(
        id=request_id,
        kind=HuntRequestKind.QUESTION,
        content="What is the encrypted filename?",
    ))

    assert objective.semantic_goal_graph is None
    assert not objective.claim_graph
    assert requirements == []
    assert len(hypotheses) == 1
    assert hypotheses[0].status.value == "INSUFFICIENTLY_SPECIFIED"
    assert "legacy ClaimGraph output is rejected" in compiler.last_compile_trace["validation_error"]


def test_same_keyword_different_objective_produces_different_claims() -> None:
    lookup_id = "req-email-lookup"
    sent_id = "req-email-sent"
    responses = iter([
        _payload(lookup_id, "What is Amber's email?", [_claim(lookup_id, "claim-email", "has_email", "email_address")]),
        _payload(sent_id, "Who received Amber's email?", [
            _claim(sent_id, "claim-message", "sent_message", "message"),
            _claim(sent_id, "claim-recipient", "received_message", "email_address", subject="claim:claim-message", dependencies=["claim-message"]),
        ]),
    ])

    lookup = KnowledgeBehaviorCompiler(llm_caller=lambda _: next(responses)).compile(HuntRequest(
        id=lookup_id, kind=HuntRequestKind.QUESTION, content="What is Amber's email?",
    ))[0].claim_graph
    sent = KnowledgeBehaviorCompiler(llm_caller=lambda _: next(responses)).compile(HuntRequest(
        id=sent_id, kind=HuntRequestKind.QUESTION, content="Who received Amber's email?",
    ))[0].claim_graph

    assert [claim.predicate for claim in lookup.claims] == ["has_email"]
    assert [claim.predicate for claim in sent.claims] == ["sent_message", "received_message"]


def test_unseen_request_yields_valid_claim_graph() -> None:
    request_id = "req-unseen"
    response = _payload(
        request_id,
        "Which signing identity approved an unusual package?",
        [_claim(request_id, "claim-signer", "signed_by", "identity", subject="package:unknown")],
        answer_type="identity",
    )
    graph, answer_spec = parse_and_validate_claim_graph(response, request_id)

    assert isinstance(graph, ClaimGraph)
    assert graph.claims[0].predicate == "signed_by"
    assert answer_spec["answer_type"] == "identity"


def test_prompt_forbids_native_query_evidence_and_verdict() -> None:
    request_id = "req-boundary"
    response = _payload(request_id, "Test a claim", [_claim(request_id, "claim-1", "connected_to", "domain")])
    captured: list[str] = []

    def caller(prompt: str) -> str:
        captured.append(prompt)
        return response

    KnowledgeBehaviorCompiler(llm_caller=caller).compile(HuntRequest(
        id=request_id, kind=HuntRequestKind.QUESTION, content="Test a claim",
    ))

    prompt = captured[0]
    for forbidden in ("SPL", "KQL", "SQL", "event IDs", "evidence", "verdicts", "attack paths"):
        assert forbidden in prompt
