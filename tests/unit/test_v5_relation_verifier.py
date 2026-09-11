"""Unit tests for v5 RelationVerifier."""
from __future__ import annotations

from hunting.contracts.case_graph import (
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeStatus,
    NodeType,
    RelationStatus,
    RelationType,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger

SCOPE = ProviderScope(provider_id="splunk", scope_id="botsv2_main", native_partition={"index": "botsv2"})


def test_verifier_accepts_valid_logon_observation():
    """Verify RelationVerifier accepts genuine authentication events and mints RelationProof."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    obs = Observation(
        id="obs-logon-1",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="WinEventLog:Security",
        fields={
            "EventCode": "4624",
            "TargetUserName": "amber.turing",
            "ComputerName": "wrk-amber.froth.ly",
            "IpAddress": "10.0.1.25",
        }
    )
    ledger.add_observation(obs)

    node_person = GraphNode(id="n1", type=NodeType.PERSON, value="Amber Turing", status=NodeStatus.KNOWN)
    node_endpoint = GraphNode(id="n2", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e1", source_id="n1", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n2", target_entity_type=NodeType.ENDPOINT,
        citations=["obs-logon-1"]
    )

    result = verifier.verify_candidate_edge(edge, node_person, node_endpoint, ledger)
    assert result.verified is True
    assert result.proof is not None
    assert result.target_value == "wrk-amber.froth.ly"
    assert "obs-logon-1" in result.proof.citations

    graph = InvestigationGraph()
    graph.add_node(node_person)
    graph.add_node(node_endpoint)
    graph.add_edge(edge)
    verifier.apply_verification_to_graph(result, edge, node_endpoint, graph)

    assert edge.status == RelationStatus.VERIFIED
    assert node_endpoint.status == NodeStatus.KNOWN
    assert node_endpoint.value == "wrk-amber.froth.ly"


def test_verifier_rejects_web_server_as_user_endpoint():
    """Verify RelationVerifier strictly forbids web servers (e.g. jabbah) from becoming user endpoints."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    obs_iis = Observation(
        id="obs-iis-1",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="iis",
        fields={
            "host": "jabbah",
            "user": "amber.turing",
            "uri": "/login.aspx",
            "asset_role": "server",
        }
    )
    ledger.add_observation(obs_iis)

    node_person = GraphNode(id="n1", type=NodeType.PERSON, value="Amber Turing", status=NodeStatus.KNOWN)
    node_endpoint = GraphNode(id="n2", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e1", source_id="n1", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n2", target_entity_type=NodeType.ENDPOINT,
        citations=["obs-iis-1"]
    )

    result = verifier.verify_candidate_edge(edge, node_person, node_endpoint, ledger)
    assert result.verified is False
    assert any("server-like role" in v for v in result.violations)


def test_verifier_rejects_server_ip_as_client_ip():
    """Verify RelationVerifier forbids destination/server IP from satisfying a client IP requirement."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    # Observation that only has destination/server IP (like an inbound connection or server log)
    obs_net = Observation(
        id="obs-net-1",
        provider_scope=SCOPE,
        cell_id="cell-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="stream:http",
        fields={
            "dest_ip": "172.31.7.2",
            "server_ip": "172.31.7.2",
            "site": "store.froth.ly",
        }
    )
    ledger.add_observation(obs_net)

    node_endpoint = GraphNode(id="n1", type=NodeType.ENDPOINT, value="wrk-amber", status=NodeStatus.KNOWN)
    node_ip = GraphNode(id="n2", type=NodeType.IP, value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e1", source_id="n1", source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.ASSIGNED_IP, target_id="n2", target_entity_type=NodeType.IP,
        citations=["obs-net-1"]
    )

    result = verifier.verify_candidate_edge(edge, node_endpoint, node_ip, ledger)
    assert result.verified is False
    assert any("server/destination IP" in v for v in result.violations)
