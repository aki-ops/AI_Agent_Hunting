"""Unit tests for v5 InvestigationActionPlanner.

Verifies:
1. Dependency-driven edge selection: selects unproven edge whose source is KNOWN.
2. Enforces Amber invariant: strictly selects RESOLVE_ENTITY until identity prefix is proven.
3. Once client IP is proven, selects TEST for web/DNS activity.
4. When all mandatory relations are verified, terminates with STOP.
5. Respects budget exhaustion immediately.
"""
from __future__ import annotations

from hunting.contracts.case_graph import (
    GraphEdge,
    GraphNode,
    InvestigationCase,
    InvestigationGraph,
    NodeStatus,
    NodeType,
    RelationType,
)
from hunting.contracts.hunt import HuntState
from hunting.controller.action_planner import (
    InvestigationAction,
    InvestigationActionPlanner,
)


def test_planner_amber_dependency_chain():
    """Verify planner traverses Amber causal chain sequentially and blocks web query early."""
    planner = InvestigationActionPlanner()

    # Build Amber case graph
    graph = InvestigationGraph()
    n_person = GraphNode(id="n_person", type=NodeType.PERSON, value="Amber Turing", status=NodeStatus.KNOWN)
    n_account = GraphNode(id="n_account", type=NodeType.ACCOUNT, value="?", status=NodeStatus.UNKNOWN)
    n_endpoint = GraphNode(id="n_endpoint", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
    n_ip = GraphNode(id="n_ip", type=NodeType.IP, value="?", status=NodeStatus.UNKNOWN)
    n_domain = GraphNode(id="n_domain", type=NodeType.DOMAIN, value="?", status=NodeStatus.UNKNOWN)

    for n in (n_person, n_account, n_endpoint, n_ip, n_domain):
        graph.add_node(n)

    e_owns = GraphEdge(
        id="e_owns", source_id="n_person", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.OWNS, target_id="n_account", target_entity_type=NodeType.ACCOUNT
    )
    e_logon = GraphEdge(
        id="e_logon", source_id="n_account", source_entity_type=NodeType.ACCOUNT,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n_endpoint", target_entity_type=NodeType.ENDPOINT
    )
    e_ip = GraphEdge(
        id="e_ip", source_id="n_endpoint", source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.ASSIGNED_IP, target_id="n_ip", target_entity_type=NodeType.IP
    )
    e_web = GraphEdge(
        id="e_web", source_id="n_ip", source_entity_type=NodeType.IP,
        relation_type=RelationType.REQUESTED, target_id="n_domain", target_entity_type=NodeType.DOMAIN
    )

    for e in (e_owns, e_logon, e_ip, e_web):
        graph.add_edge(e)

    case = InvestigationCase(
        id="case-amber",
        request_content="Amber Turing visited competitor beer website",
        question="What website did Amber Turing visit?",
        graph=graph,
    )
    state = HuntState(case=case)

    # Step 1: Only n_person is KNOWN -> Planner MUST select RESOLVE_ENTITY for e_owns
    dec1 = planner.select_action(state=state, case=case)
    assert dec1.action == InvestigationAction.RESOLVE_ENTITY
    assert dec1.metadata.get("operation_name") == "resolve_person_to_account"
    assert dec1.metadata.get("edge_id") == "e_owns"

    # Simulate proof of e_owns
    graph.promote_edge_to_verified("e_owns", citations=["obs-1"], field_matches={"TargetUserName": "amber.turing"})
    n_account.value = "amber.turing"

    # Step 2: Now n_account is KNOWN -> Planner MUST select RESOLVE_ENTITY for e_logon
    dec2 = planner.select_action(state=state, case=case)
    assert dec2.action == InvestigationAction.RESOLVE_ENTITY
    assert dec2.metadata.get("operation_name") == "resolve_account_to_endpoint"
    assert dec2.metadata.get("edge_id") == "e_logon"

    # Simulate proof of e_logon
    graph.promote_edge_to_verified("e_logon", citations=["obs-2"], field_matches={"ComputerName": "wrk-amber"})
    n_endpoint.value = "wrk-amber"

    # Step 3: Now n_endpoint is KNOWN -> Planner MUST select RESOLVE_ENTITY for e_ip
    dec3 = planner.select_action(state=state, case=case)
    assert dec3.action == InvestigationAction.RESOLVE_ENTITY
    assert dec3.metadata.get("operation_name") == "resolve_endpoint_to_client_ip"
    assert dec3.metadata.get("edge_id") == "e_ip"

    # Simulate proof of e_ip
    graph.promote_edge_to_verified("e_ip", citations=["obs-3"], field_matches={"IpAddress": "10.0.1.25"})
    n_ip.value = "10.0.1.25"

    # Step 4: Now and ONLY now is e_web actionable -> Planner MUST select TEST
    dec4 = planner.select_action(state=state, case=case)
    assert dec4.action == InvestigationAction.TEST
    assert dec4.metadata.get("operation_name") == "find_web_activity_from_client_ip"
    assert dec4.metadata.get("edge_id") == "e_web"

    # Simulate proof of e_web
    graph.promote_edge_to_verified("e_web", citations=["obs-4"], field_matches={"site": "competitor-beer.com"})
    n_domain.value = "competitor-beer.com"

    # Step 5: All edges verified -> Planner MUST select STOP
    dec5 = planner.select_action(state=state, case=case)
    assert dec5.action == InvestigationAction.STOP
    assert "All mandatory causal relations in case graph verified" in dec5.reason


def test_planner_stops_on_budget_exhaustion():
    """Verify planner immediately stops when budget is exhausted."""
    planner = InvestigationActionPlanner()
    dec = planner.select_action(budget_exhausted=True)
    assert dec.action == InvestigationAction.STOP
    assert "exhausted" in dec.reason.lower()
