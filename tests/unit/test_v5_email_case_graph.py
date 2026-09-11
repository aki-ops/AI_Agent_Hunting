"""Unit tests for v5 Email Investigation Case Graph & Dynamic Semantic Capabilities."""
from __future__ import annotations

from hunting.capabilities.inventory import RuntimeSourceInventory, SourceSchema
from hunting.contracts.case_graph import (
    FieldRole,
    NodeStatus,
    NodeType,
    RelationType,
    build_investigation_case_from_intent,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.claim import AcceptanceRule, Claim, ClaimEvidenceRequirement, ClaimGraph
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.hunt import (
    AnswerStatus,
    ClaimVerdict,
    FinalHuntAccount,
    HuntObjective,
    HuntOutcome,
    Hypothesis,
    HypothesisOrigin,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.semantic_intent import (
    RequestedObject,
    SemanticCapabilityProposal,
    SemanticHuntIntent,
    SubjectEntity,
)
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.reporter.renderer import render_analyst_report, render_final_hunt_account

SCOPE = ProviderScope(provider_id="splunk", scope_id="botsv2_main", native_partition={"index": "botsv2"})


def test_runtime_source_inventory_matching():
    """Verify that RuntimeSourceInventory introspects sources and matches proposals."""
    inventory = RuntimeSourceInventory()
    inventory.register_source(
        SourceSchema(
            source_name="stream:smtp",
            available_fields={"sender", "sender_email", "receiver", "receiver_email", "msg_id", "subject", "src_ip", "dest_ip"},
            event_count=670760,
        )
    )

    proposal = SemanticCapabilityProposal(
        capability_name="outbound_message_metadata",
        description="Outbound email communication telemetry",
        required_roles=[FieldRole.SENDER_EMAIL.value, FieldRole.RECIPIENT_EMAIL.value, FieldRole.MESSAGE_ID.value],
    )

    status, matched_schema, field_bindings = inventory.match_capability_proposal(proposal)
    assert status == "BOUND"
    assert matched_schema is not None
    assert matched_schema.source_name == "stream:smtp"
    assert FieldRole.SENDER_EMAIL.value in field_bindings
    assert FieldRole.RECIPIENT_EMAIL.value in field_bindings


def _email_claim_graph(include_message: bool = True) -> ClaimGraph:
    claims = [
        Claim(
            id="claim-email",
            claim_type="attribute",
            subject="person:Amber Turing",
            predicate="has_email",
            value_type="email_address",
            provenance="request",
            source_request_id="req-email",
            observation_requirements=(
                ClaimEvidenceRequirement(
                    id="req-email",
                    fact_kind="identity_binding",
                    required_fields=("user", "mail"),
                    field_roles=("account_name", "sender_email"),
                ),
            ),
            acceptance_rule=AcceptanceRule(required_fields=("mail",)),
        )
    ]
    if include_message:
        claims.extend([
            Claim(
                id="claim-message",
                claim_type="relation",
                subject="claim:claim-email",
                predicate="sent_message",
                value_type="message",
                provenance="request",
                source_request_id="req-email",
                dependencies=("claim-email",),
                observation_requirements=(
                    ClaimEvidenceRequirement(id="req-message", fact_kind="outbound_message_metadata", required_fields=("sender_email", "msg_id")),
                ),
                acceptance_rule=AcceptanceRule(required_fields=("sender_email", "msg_id")),
            ),
            Claim(
                id="claim-recipient",
                claim_type="relation",
                subject="claim:claim-message",
                predicate="received_message",
                value_type="email_address",
                provenance="request",
                source_request_id="req-email",
                dependencies=("claim-message",),
                observation_requirements=(
                    ClaimEvidenceRequirement(id="req-recipient", fact_kind="recipient_identity", required_fields=("msg_id", "receiver_email")),
                ),
                acceptance_rule=AcceptanceRule(required_fields=("receiver_email",)),
            ),
        ])
    return ClaimGraph(
        id="graph-email",
        request_id="req-email",
        objective="Identify the email facts explicitly requested",
        claims=claims,
        metadata={"request_content": "Amber sent an email", "question": "Who received Amber's email?"},
    )


def test_email_case_graph_construction():
    graph = build_investigation_case_from_intent(_email_claim_graph()).graph

    assert len(graph.edges) == 3
    assert graph.get_edge("edge-claim-email").relation_type == RelationType.HAS_EMAIL
    assert graph.get_edge("edge-claim-message").relation_type == RelationType.SENT_MESSAGE
    assert graph.get_edge("edge-claim-recipient").relation_type == RelationType.RECEIVED_MESSAGE
    assert all(edge.metadata["claim_id"] for edge in graph.edges.values())


def test_email_lookup_does_not_spawn_message_recipient_or_role():
    graph = build_investigation_case_from_intent(_email_claim_graph(include_message=False)).graph

    assert list(graph.edges) == ["edge-claim-email"]
    assert not any(node.type in (NodeType.MESSAGE, NodeType.ROLE) for node in graph.nodes.values())


def test_email_relation_verification():
    """Verify deterministic verification of email causal chain edges."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    # 1. Account -> Email Address
    obs_ad = Observation(
        id="obs-ad-1",
        provider_scope=SCOPE,
        cell_id="cell-email",
        timestamp="2017-08-25T03:00:00Z",
        native_type="ActiveDirectory:LDAP",
        fields={"user": "aturing", "mail": "aturing@froth.ly", "display_name": "Amber Turing"},
        epistemic_type=EpistemicType.OBSERVED,
    )
    ledger.add_observation(obs_ad)

    case = build_investigation_case_from_intent(_email_claim_graph())
    graph = case.graph

    email_edge = graph.get_edge("edge-claim-email")
    acct_node = graph.get_node(email_edge.source_id)
    acct_node.value = "aturing"
    acct_node.status = NodeStatus.KNOWN
    email_node = graph.get_node(email_edge.target_id)
    email_edge.citations = [obs_ad.id]
    res_email = verifier.verify_candidate_edge(email_edge, acct_node, email_node, ledger, [obs_ad])
    assert res_email.verified is True
    assert res_email.target_value == "aturing@froth.ly"

    # Apply email resolution
    verifier.apply_verification_to_graph(res_email, email_edge, email_node, graph)
    assert email_node.status == NodeStatus.KNOWN
    assert email_node.value == "aturing@froth.ly"

    # 2. Email Address -> Message
    obs_smtp = Observation(
        id="obs-smtp-1",
        provider_scope=SCOPE,
        cell_id="cell-email",
        timestamp="2017-08-25T03:15:00Z",
        native_type="stream:smtp",
        fields={
            "sender_email": "aturing@froth.ly",
            "receiver_email": "val.smith@berkbeer.com",
            "msg_id": "<201708250315.msg001@froth.ly>",
            "subject": "Acquisition terms",
        },
        epistemic_type=EpistemicType.OBSERVED,
    )
    ledger.add_observation(obs_smtp)

    sent_edge = graph.get_edge("edge-claim-message")
    msg_node = graph.get_node(sent_edge.target_id)
    sent_edge.citations = [obs_smtp.id]
    res_sent = verifier.verify_candidate_edge(sent_edge, email_node, msg_node, ledger, [obs_smtp])
    assert res_sent.verified is True
    assert res_sent.target_value == "<201708250315.msg001@froth.ly>"

    verifier.apply_verification_to_graph(res_sent, sent_edge, msg_node, graph)
    assert msg_node.status == NodeStatus.KNOWN

    # 3. Message -> Recipient
    rcvd_edge = graph.get_edge("edge-claim-recipient")
    rcpt_node = graph.get_node(rcvd_edge.target_id)
    rcvd_edge.citations = [obs_smtp.id]
    res_rcvd = verifier.verify_candidate_edge(rcvd_edge, msg_node, rcpt_node, ledger, [obs_smtp])
    assert res_rcvd.verified is True
    assert res_rcvd.target_value == "val.smith@berkbeer.com"

    verifier.apply_verification_to_graph(res_rcvd, rcvd_edge, rcpt_node, graph)
    assert rcpt_node.status == NodeStatus.KNOWN



def test_email_report_rendering_with_claims_and_limitations():
    """Verify that reports correctly render PARTIALLY_ANSWERED, claims evaluation, and limitations."""
    intent = SemanticHuntIntent(
        original_request="Find recipient email and CEO role",
        question="What is recipient email and CEO role?",
        subject=SubjectEntity(type="person", value="Amber Turing"),
        requested_object=RequestedObject(type="email_address", role="recipient"),
        behavior="sent email to competitor CEO",
    )
    case = build_investigation_case_from_intent(_email_claim_graph())

    cov = CoverageBound(
        known_cells_wildcard=1,
        explored_cells_wildcard=0,
        known_cells_instance=4,
        explored_cells_instance=4,
        causal_path_total_edges=5,
        causal_path_verified_edges=4,
    )

    claims = [
        ClaimVerdict(
            claim_id="claim-email-sent",
            statement="Amber sent email from aturing@froth.ly",
            required_capability="outbound_message_metadata",
            status="SUPPORTED",
            cited_evidence_ids=["obs-smtp-1"],
        ),
        ClaimVerdict(
            claim_id="claim-recipient",
            statement="Recipient is val.smith@berkbeer.com",
            required_capability="recipient_identity",
            status="SUPPORTED",
            cited_evidence_ids=["obs-smtp-1"],
        ),
        ClaimVerdict(
            claim_id="claim-ceo",
            statement="The recipient holds the CEO role",
            required_capability="role_identity",
            status="UNKNOWN",
            limitations=["Chưa chứng minh được người nhận là CEO từ dữ liệu telemetry."],
        ),
    ]

    account = FinalHuntAccount(
        request_id="req-email-test-01",
        objective=HuntObjective(
            request_id="req-email-test-01",
            statement="Amber sent an email to competitor CEO. Who was the recipient?",
            semantic_intent=intent,
        ),
        hypotheses=[
            Hypothesis(
                id="hypo-email-outbound",
                statement="Amber Turing sent an email to the competitor CEO.",
                origin=HypothesisOrigin.HUMAN,
                status=HypothesisStatus.SUPPORTED,
                requirements=["req-email-sent", "req-recipient"],
            )
        ],
        evidence_cards=[],
        queries=[],
        supporting=["hypo-email-outbound"],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=["Chưa chứng minh được người nhận là CEO từ dữ liệu telemetry."],
        coverage_bound=cov,
        stopping_decision=StoppingDecision.STOP_RESOLVED,
        case=case,
        answer={
            "status": "ANSWERED",
            "answer_type": "recipient_email",
            "value": "val.smith@berkbeer.com",
            "explanation": "Amber Turing sent message <msg-1> to val.smith@berkbeer.com.",
        },
        answer_status=AnswerStatus.PARTIALLY_ANSWERED,
        claim_verdicts=claims,
        limitations=["Chưa chứng minh được người nhận là CEO từ dữ liệu telemetry."],
    )

    # 1. Outcome must be SUPPORTED_WITH_LIMITATIONS because answer is PARTIALLY_ANSWERED
    assert account.outcome == HuntOutcome.SUPPORTED_WITH_LIMITATIONS

    # 2. Analyst report rendering
    analyst_md = render_analyst_report(account)
    assert "SUPPORTED_WITH_LIMITATIONS" in analyst_md
    assert "PARTIALLY_ANSWERED" in analyst_md
    assert "val.smith@berkbeer.com" in analyst_md
    assert "### Claims Evaluation" in analyst_md
    assert "outbound_message_metadata" in analyst_md
    assert "role_identity" in analyst_md
    assert "### Limitations" in analyst_md
    assert "Chưa chứng minh được người nhận là CEO" in analyst_md

    # 3. Canonical report rendering
    final_md = render_final_hunt_account(account)
    assert "SUPPORTED_WITH_LIMITATIONS" in final_md
    assert "PARTIALLY_ANSWERED" in final_md
    assert "### Claims Evaluation" in final_md
    assert "### Epistemic Limitations" in final_md
