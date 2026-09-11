"""Unit tests for v5 CapabilityBinder."""
from __future__ import annotations

from hunting.capabilities.binder import CapabilityBinder
from hunting.contracts.case_graph import (
    GraphEdge,
    GraphNode,
    NodeType,
    RelationType,
)


def test_binder_identifies_correct_operations():
    """Verify CapabilityBinder maps entity types and relations to logical operations."""
    binder = CapabilityBinder()

    # 1. Person -> Account
    n_person = GraphNode(id="n1", type=NodeType.PERSON, value="Amber Turing")
    n_account = GraphNode(id="n2", type=NodeType.ACCOUNT, value="?")
    e_person_acct = GraphEdge(
        id="e1", source_id="n1", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.OWNS, target_id="n2", target_entity_type=NodeType.ACCOUNT
    )
    op = binder.identify_operation_for_edge(e_person_acct, n_person, n_account)
    assert op == "resolve_person_to_account"

    # 2. Account -> Endpoint
    n_endpoint = GraphNode(id="n3", type=NodeType.ENDPOINT, value="?")
    e_acct_endpoint = GraphEdge(
        id="e2", source_id="n2", source_entity_type=NodeType.ACCOUNT,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n3", target_entity_type=NodeType.ENDPOINT
    )
    op = binder.identify_operation_for_edge(e_acct_endpoint, n_account, n_endpoint)
    assert op == "resolve_account_to_endpoint"

    # 3. Endpoint -> IP
    n_ip = GraphNode(id="n4", type=NodeType.IP, value="?")
    e_endpoint_ip = GraphEdge(
        id="e3", source_id="n3", source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.ASSIGNED_IP, target_id="n4", target_entity_type=NodeType.IP
    )
    op = binder.identify_operation_for_edge(e_endpoint_ip, n_endpoint, n_ip)
    assert op == "resolve_endpoint_to_client_ip"

    # 4. IP -> Web Request (Domain)
    n_domain = GraphNode(id="n5", type=NodeType.DOMAIN, value="?")
    e_ip_domain = GraphEdge(
        id="e4", source_id="n4", source_entity_type=NodeType.IP,
        relation_type=RelationType.REQUESTED, target_id="n5", target_entity_type=NodeType.DOMAIN
    )
    op = binder.identify_operation_for_edge(e_ip_domain, n_ip, n_domain)
    assert op == "find_web_activity_from_client_ip"


def test_binder_creates_prioritized_candidates():
    """Verify entity resolution candidates have higher priority than traffic queries."""
    binder = CapabilityBinder()

    n_person = GraphNode(id="n1", type=NodeType.PERSON, value="Amber Turing")
    n_endpoint = GraphNode(id="n3", type=NodeType.ENDPOINT, value="?")
    e_logon = GraphEdge(
        id="e_logon", source_id="n1", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n3", target_entity_type=NodeType.ENDPOINT
    )
    candidate_id = binder.create_candidate(e_logon, n_person, n_endpoint)
    assert candidate_id is not None
    assert candidate_id.priority == 1  # highest

    n_ip = GraphNode(id="n4", type=NodeType.IP, value="10.0.1.25")
    n_domain = GraphNode(id="n5", type=NodeType.DOMAIN, value="?")
    e_web = GraphEdge(
        id="e_web", source_id="n4", source_entity_type=NodeType.IP,
        relation_type=RelationType.REQUESTED, target_id="n5", target_entity_type=NodeType.DOMAIN
    )
    candidate_web = binder.create_candidate(e_web, n_ip, n_domain)
    assert candidate_web is not None
    assert candidate_web.priority == 2


def test_binder_compiles_splunk_queries():
    """Verify compilation of logical candidates to parameterized SPL."""
    binder = CapabilityBinder()
    n_person = GraphNode(id="n1", type=NodeType.PERSON, value="Amber Turing")
    n_endpoint = GraphNode(id="n3", type=NodeType.ENDPOINT, value="?")
    e_logon = GraphEdge(
        id="e_logon", source_id="n1", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n3", target_entity_type=NodeType.ENDPOINT
    )
    candidate = binder.create_candidate(e_logon, n_person, n_endpoint)
    assert candidate.operation_name == "resolve_person_to_endpoint"
    spl = binder.compile_operation_query(candidate, provider_id="splunk", index="botsv2")
    assert 'index="botsv2"' in spl
    assert '"Amber Turing"' in spl
    assert 'sourcetype="' not in spl
    assert "EventCode=" not in spl
    assert "_host_candidate" in spl
    assert 'Amber' in spl
