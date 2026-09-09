"""Regression tests freezing hardcoded shortcuts in RelationVerifier, SplunkLiveAdapter, and CapabilityBinder (Phase 0).

These tests ensure:
1. No guessing accounts without evidence (e.g. Amber Turing -> aturing).
2. No guessing emails without evidence (e.g. aturing -> aturing@froth.ly).
3. Arbitrary recipient resolution (e.g. carol@external.org, no hardcoded Martin Berk).
4. Role remains UNPROVEN without independent directory telemetry.
5. Generated queries contain no hardcoded scenario constants (amber, aturing, berkbeer, mberk, etc.).
"""
from __future__ import annotations

import json

from hunting.capabilities.binder import ActionCandidate, CapabilityBinder
from hunting.contracts.case_graph import (
    FieldRole,
    GraphEdge,
    GraphNode,
    NodeStatus,
    NodeType,
    RelationType,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m2_abduction.provider import StubSemanticCompiler
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter

SCOPE = ProviderScope(provider_id="splunk", scope_id="botsv2_main", native_partition={"index": "botsv2"})


def test_stub_fixture_requires_explicit_scenario_selection():
    """The offline fixture must not classify arbitrary text by matching 'amber'."""
    result = json.loads(
        StubSemanticCompiler(scenario="generic")(
            "Request content: Amber Turing sent an email to a competitor"
        )
    )
    assert result["objective"] == "Generic free-text threat inquiry"
    assert result["metadata"]["request_content"] == "Amber Turing sent an email to a competitor"
    assert len(result["claims"]) == 2
    assert all(claim["subject"] == "entity:unknown" for claim in result["claims"])
    assert not any("email" in str(claim).lower() for claim in result["claims"])

    # The fixture is now a ClaimGraph producer. Scenario selection remains
    # explicit on the fixture constructor, never inferred from request words.
    assert "normalized_claim" not in result
    assert "entities" not in result


def test_verifier_does_not_invent_account_for_unknown_user():
    """Verifier must return verified=False when no evidence links a person to an account, even for 'Amber Turing'."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    # Unrelated observation
    obs = Observation(
        id="obs-sec-1",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="WinEventLog:Security",
        fields={"TargetUserName": "system_service", "host": "srv01"},
    )
    ledger.add_observation(obs)

    node_person = GraphNode(id="np", type=NodeType.PERSON, value="Amber Turing", status=NodeStatus.KNOWN)
    node_acct = GraphNode(id="na", type=NodeType.ACCOUNT, value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-owns",
        source_id="np",
        source_entity_type=NodeType.PERSON,
        relation_type=RelationType.OWNS,
        target_id="na",
        target_entity_type=NodeType.ACCOUNT,
        required_field_roles={"source": FieldRole.PERSON_NAME, "target": FieldRole.ACCOUNT_NAME},
        citations=["obs-sec-1"],
    )

    result = verifier.verify_candidate_edge(edge, node_person, node_acct, ledger, [obs])
    assert result.verified is False, "Verifier must not verify edge when observation has no matching user."
    assert result.target_value != "aturing", "Verifier must never invent 'aturing' without supporting evidence."
    assert result.target_value is None


def test_verifier_does_not_invent_email_without_evidence():
    """Verifier must not invent email address (e.g. aturing@froth.ly) when observation has no email field."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    obs = Observation(
        id="obs-sec-2",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="WinEventLog:Security",
        fields={"TargetUserName": "aturing", "ComputerName": "wrk-aturing"},
    )
    ledger.add_observation(obs)

    node_acct = GraphNode(id="na", type=NodeType.ACCOUNT, value="aturing", status=NodeStatus.KNOWN)
    node_email = GraphNode(id="ne", type=NodeType.EMAIL_ADDRESS, value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-email",
        source_id="na",
        source_entity_type=NodeType.ACCOUNT,
        relation_type=RelationType.HAS_EMAIL,
        target_id="ne",
        target_entity_type=NodeType.EMAIL_ADDRESS,
        required_field_roles={"source": FieldRole.ACCOUNT_NAME, "target": FieldRole.SENDER_EMAIL},
        citations=["obs-sec-2"],
    )

    result = verifier.verify_candidate_edge(edge, node_acct, node_email, ledger, [obs])
    assert result.verified is False, "Verifier must not verify email when observation contains no email address."
    assert result.target_value != "aturing@froth.ly", "Verifier must never invent 'aturing@froth.ly' without email evidence."
    assert result.target_value is None


def test_verifier_arbitrary_recipient_binding():
    """Verifier must bind arbitrary recipient email and not invent 'Martin Berk' when not in evidence."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    # Case A: Arbitrary recipient Carol Danvers
    obs_carol = Observation(
        id="obs-smtp-carol",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="stream:smtp",
        fields={
            "msg_id": "msg-carol-101",
            "sender_email": "alice@acme.com",
            "receiver_email": "carol@external.org",
            "receiver": "Carol Danvers <carol@external.org>",
            "subject": "Confidential proposal",
        },
    )
    ledger.add_observation(obs_carol)

    node_msg = GraphNode(id="nm", type=NodeType.MESSAGE, value="msg-carol-101", status=NodeStatus.KNOWN)
    node_recip = GraphNode(id="nr", type=NodeType.EMAIL_ADDRESS, value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-recip",
        source_id="nm",
        source_entity_type=NodeType.MESSAGE,
        relation_type=RelationType.RECEIVED_MESSAGE,
        target_id="nr",
        target_entity_type=NodeType.EMAIL_ADDRESS,
        citations=["obs-smtp-carol"],
    )

    res_carol = verifier.verify_candidate_edge(edge, node_msg, node_recip, ledger, [obs_carol])
    assert res_carol.verified is True
    assert res_carol.target_value == "carol@external.org"
    assert res_carol.field_matches.get("recipient_email") == "carol@external.org"
    assert res_carol.field_matches.get("recipient_name") == "Carol Danvers"

    # Case B: Recipient mberk@berkbeer.com with NO display name in header
    obs_mberk_raw = Observation(
        id="obs-smtp-raw",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="stream:smtp",
        fields={
            "msg_id": "msg-mberk-202",
            "sender_email": "aturing@froth.ly",
            "receiver_email": "mberk@berkbeer.com",
            "receiver": "mberk@berkbeer.com",  # No display name present
            "subject": "Meeting",
        },
    )
    ledger.add_observation(obs_mberk_raw)

    node_msg2 = GraphNode(id="nm2", type=NodeType.MESSAGE, value="msg-mberk-202", status=NodeStatus.KNOWN)
    node_recip2 = GraphNode(id="nr2", type=NodeType.EMAIL_ADDRESS, value="?", status=NodeStatus.UNKNOWN)
    edge2 = GraphEdge(
        id="e-recip2",
        source_id="nm2",
        source_entity_type=NodeType.MESSAGE,
        relation_type=RelationType.RECEIVED_MESSAGE,
        target_id="nr2",
        target_entity_type=NodeType.EMAIL_ADDRESS,
        citations=["obs-smtp-raw"],
    )

    res_mberk = verifier.verify_candidate_edge(edge2, node_msg2, node_recip2, ledger, [obs_mberk_raw])
    assert res_mberk.verified is True
    assert res_mberk.target_value == "mberk@berkbeer.com"
    # Verifier must NOT magically inject "Martin Berk" when header only has "mberk@berkbeer.com"
    assert res_mberk.field_matches.get("recipient_name") != "Martin Berk"


def test_role_unproven_without_independent_directory():
    """Verifier must reject HOLDS_ROLE when telemetry does not contain authoritative title/role."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    obs_smtp = Observation(
        id="obs-smtp-norole",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="stream:smtp",
        fields={
            "sender_email": "aturing@froth.ly",
            "receiver_email": "mberk@berkbeer.com",
            "subject": "Secret proposal for CEO",
            # No directory fields like title, role, job_title
        },
    )
    ledger.add_observation(obs_smtp)

    node_recip = GraphNode(id="nr", type=NodeType.EMAIL_ADDRESS, value="mberk@berkbeer.com", status=NodeStatus.KNOWN)
    node_role = GraphNode(id="nrole", type=NodeType.ROLE, value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-role",
        source_id="nr",
        source_entity_type=NodeType.EMAIL_ADDRESS,
        relation_type=RelationType.HOLDS_ROLE,
        target_id="nrole",
        target_entity_type=NodeType.ROLE,
        citations=["obs-smtp-norole"],
    )

    res = verifier.verify_candidate_edge(edge, node_recip, node_role, ledger, [obs_smtp])
    assert res.verified is False, "Role must be unproven when no directory/LDAP/title evidence exists."
    assert res.target_value is None


def test_native_queries_contain_no_scenario_constants():
    """Generated queries must be parameterized purely by entity value, without hardcoded scenario constants."""
    binder = CapabilityBinder()
    adapter = SplunkLiveAdapter(splunk_url="https://127.0.0.1:8089", index="test_index")

    banned_substrings = [
        "amber",
        "aturing",
        "berkbeer",
        "mberk",
        "heinz",
        "froth.ly",
        "Amber from Froth.ly",
    ]

    # Test Binder queries for generic entities
    candidate_person = ActionCandidate(
        operation_name="resolve_person_to_account",
        target_edge_id="e1",
        bound_source_node_id="n1",
        bound_source_value="John Doe",
    )
    spl_binder_person = binder.compile_operation_query(candidate_person, provider_id="splunk", index="test_index")

    candidate_msg = ActionCandidate(
        operation_name="find_outbound_message_metadata",
        target_edge_id="e2",
        bound_source_node_id="n2",
        bound_source_value="jdoe@example.com",
    )
    spl_binder_msg = binder.compile_operation_query(candidate_msg, provider_id="splunk", index="test_index")

    candidate_recip = ActionCandidate(
        operation_name="resolve_recipient_identity",
        target_edge_id="e3",
        bound_source_node_id="n3",
        bound_source_value="msg-99999",
    )
    spl_binder_recip = binder.compile_operation_query(candidate_recip, provider_id="splunk", index="test_index")

    candidate_role = ActionCandidate(
        operation_name="resolve_role_identity",
        target_edge_id="e4",
        bound_source_node_id="n4",
        bound_source_value="recipient@domain.com",
    )
    spl_binder_role = binder.compile_operation_query(candidate_role, provider_id="splunk", index="test_index")

    # Test Adapter queries
    spl_adapter_person, _, _ = adapter._build_spl(
        operation_id="resolve_person_to_account",
        entity="John Doe",
        window="2026-09-01T00:00:00Z/2026-09-01T23:59:59Z",
        predicate=None,
        limit=100,
    )
    spl_adapter_msg, _, _ = adapter._build_spl(
        operation_id="find_outbound_message_metadata",
        entity="jdoe@example.com",
        window="2026-09-01T00:00:00Z/2026-09-01T23:59:59Z",
        predicate=None,
        limit=100,
    )
    spl_adapter_recip, _, _ = adapter._build_spl(
        operation_id="resolve_recipient_identity",
        entity="msg-99999",
        window="2026-09-01T00:00:00Z/2026-09-01T23:59:59Z",
        predicate=None,
        limit=100,
    )

    all_queries = [
        ("binder_person", spl_binder_person),
        ("binder_msg", spl_binder_msg),
        ("binder_recip", spl_binder_recip),
        ("binder_role", spl_binder_role),
        ("adapter_person", spl_adapter_person),
        ("adapter_msg", spl_adapter_msg),
        ("adapter_recip", spl_adapter_recip),
    ]

    for q_name, query in all_queries:
        for banned in banned_substrings:
            assert banned.lower() not in query.lower(), (
                f"Query '{q_name}' contains hardcoded constant '{banned}': {query}"
            )
