"""Unit tests for v5 Investigation Case Graph Contracts."""
from __future__ import annotations

from hunting.contracts.case_graph import (
    EvidenceGoal,
    FieldRole,
    GraphEdge,
    GraphNode,
    InvestigationCase,
    InvestigationGraph,
    InvestigationUnknown,
    NodeStatus,
    NodeType,
    RelationStatus,
    RelationType,
)
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntObjective,
    HuntOutcome,
    StoppingDecision,
)


def test_field_role_isolation():
    """Verify strict semantic role distinctions."""
    assert FieldRole.CLIENT_IP != FieldRole.SERVER_IP
    assert FieldRole.SOURCE_IP != FieldRole.DESTINATION_IP
    assert FieldRole.ENDPOINT_HOST != FieldRole.SERVER_HOST
    assert FieldRole.ENDPOINT_HOST != FieldRole.SENSOR_HOST
    assert FieldRole.ACCOUNT_NAME != FieldRole.PERSON_NAME


def test_case_graph_node_and_edge_creation():
    """Verify node and edge instantiation with explicit field roles and operations."""
    node_amber = GraphNode(
        id="node-amber",
        type=NodeType.PERSON,
        value="Amber Turing",
        status=NodeStatus.KNOWN,
        field_role=FieldRole.PERSON_NAME,
    )
    node_account = GraphNode(
        id="node-amber-acct",
        type=NodeType.ACCOUNT,
        value="aturing",
        status=NodeStatus.UNKNOWN,
        field_role=FieldRole.ACCOUNT_NAME,
    )
    edge = GraphEdge(
        id="edge-amber-owns-acct",
        source_id=node_amber.id,
        source_entity_type=node_amber.type,
        relation_type=RelationType.OWNS,
        target_id=node_account.id,
        target_entity_type=node_account.type,
        required_field_roles={"source": FieldRole.PERSON_NAME, "target": FieldRole.ACCOUNT_NAME},
        acceptable_operations=["resolve_person_to_account"],
        status=RelationStatus.UNPROVEN,
    )

    assert edge.source_id == "node-amber"
    assert edge.target_id == "node-amber-acct"
    assert edge.required_field_roles["source"] == FieldRole.PERSON_NAME
    assert "resolve_person_to_account" in edge.acceptable_operations
    assert edge.status == RelationStatus.UNPROVEN


def test_investigation_graph_dependency_traversal():
    """Verify querying unproven edges whose source node is proven."""
    graph = InvestigationGraph()
    node_person = GraphNode(id="n1", type=NodeType.PERSON, value="Amber Turing", status=NodeStatus.KNOWN)
    node_endpoint = GraphNode(id="n2", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
    node_ip = GraphNode(id="n3", type=NodeType.IP, value="?", status=NodeStatus.UNKNOWN)

    edge1 = GraphEdge(
        id="e1", source_id="n1", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n2", target_entity_type=NodeType.ENDPOINT,
        status=RelationStatus.UNPROVEN
    )
    edge2 = GraphEdge(
        id="e2", source_id="n2", source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.ASSIGNED_IP, target_id="n3", target_entity_type=NodeType.IP,
        status=RelationStatus.UNPROVEN
    )

    graph.add_node(node_person)
    graph.add_node(node_endpoint)
    graph.add_node(node_ip)
    graph.add_edge(edge1)
    graph.add_edge(edge2)

    # When only_known_source=True, only e1 should be returned because n1 is KNOWN but n2 is UNKNOWN
    actionable = graph.get_unproven_edges(only_known_source=True)
    assert len(actionable) == 1
    assert actionable[0].id == "e1"


def test_promote_edge_to_verified_and_extract_subgraph():
    """Verify promotion of edges with citations and extraction of EvidenceSubgraph."""
    graph = InvestigationGraph()
    node_endpoint = GraphNode(id="n2", type=NodeType.ENDPOINT, value="wrk-amber", status=NodeStatus.KNOWN)
    node_ip = GraphNode(id="n3", type=NodeType.IP, value="10.0.1.25", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e2", source_id="n2", source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.ASSIGNED_IP, target_id="n3", target_entity_type=NodeType.IP,
        status=RelationStatus.UNPROVEN
    )
    graph.add_node(node_endpoint)
    graph.add_node(node_ip)
    graph.add_edge(edge)

    proof = graph.promote_edge_to_verified(
        edge_id="e2",
        citations=["obs-dhcp-101", "obs-dhcp-102"],
        field_matches={"host": "wrk-amber", "client_ip": "10.0.1.25"}
    )

    assert edge.status == RelationStatus.VERIFIED
    assert node_ip.status == NodeStatus.KNOWN
    assert proof.id == "proof-e2"
    assert "obs-dhcp-101" in proof.citations

    subgraph = graph.extract_subgraph_for_claim("claim-web-compromise")
    assert len(subgraph.proofs) == 1
    assert "obs-dhcp-101" in subgraph.cited_observation_ids
    assert "wrk-amber -[assigned_ip]-> 10.0.1.25" in subgraph.render_provenance_path()


def test_investigation_case_serialization_roundtrip():
    """Verify InvestigationCase to_dict and from_dict preserve all properties."""
    case = InvestigationCase(
        id="case-100",
        request_content="Investigate Amber Turing workstation activity",
        question="What domain was visited?",
        claims=[{"claim_id": "c1", "text": "Amber visited competitor"}],
        unknowns=[
            InvestigationUnknown(
                id="unk-1",
                entity_type=NodeType.ENDPOINT,
                variable_name="endpoint_amber",
                description="Amber's workstation",
                mandatory=True
            )
        ],
        evidence_goals=[
            EvidenceGoal(
                id="goal-1",
                target_edge_id="edge-1",
                description="Verify Amber logon",
                necessity="CRITICAL"
            )
        ],
        acceptance_criteria=[{"criterion": "Domain resolved and verified"}],
        status="READY_FOR_DISCOVERY"
    )

    d = case.to_dict()
    assert d["id"] == "case-100"
    assert len(d["unknowns"]) == 1
    assert d["unknowns"][0]["variable_name"] == "endpoint_amber"

    restored = InvestigationCase.from_dict(d)
    assert restored.id == "case-100"
    assert restored.unknowns[0].variable_name == "endpoint_amber"
    assert restored.status == "READY_FOR_DISCOVERY"


def test_stopping_decision_v5_outcomes():
    """Verify mapping of new v5 stopping decisions to canonical HuntOutcome."""
    obj = HuntObjective(request_id="req-1")

    account_identity_unresolved = FinalHuntAccount(
        request_id="req-1",
        objective=obj,
        hypotheses=[],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED,
    )
    assert account_identity_unresolved.outcome == HuntOutcome.INCONCLUSIVE

    account_relation_unproven = FinalHuntAccount(
        request_id="req-1",
        objective=obj,
        hypotheses=[],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN,
    )
    assert account_relation_unproven.outcome == HuntOutcome.INCONCLUSIVE

    account_unsupported_cap = FinalHuntAccount(
        request_id="req-1",
        objective=obj,
        hypotheses=[],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_UNSUPPORTED_CAPABILITY,
    )
    assert account_unsupported_cap.outcome == HuntOutcome.UNSUPPORTED
