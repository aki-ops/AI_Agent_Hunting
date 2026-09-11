"""Amber Turing Vertical Slice Acceptance Tests (v5.0).

Verifies the central v5 invariant:
Amber (Person) -> Account -> Endpoint -> Client IP -> Web Request -> Domain
- Strictly bars global web query before resolving identity.
- Never binds host=jabbah as Amber's endpoint.
- Never uses server/destination IP as client IP.
- Demands full path citations for any final answer.
- Yields truthful INCONCLUSIVE when identity is unobservable.
"""
from __future__ import annotations

from hunting.capabilities.binder import CapabilityBinder
from hunting.contracts.case_graph import (
    FieldRole,
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeStatus,
    NodeType,
    RelationType,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntObjective,
    HuntOutcome,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger

SCOPE = ProviderScope(provider_id="splunk", scope_id="botsv2_main", native_partition={"index": "botsv2"})


def test_amber_vertical_slice_causal_chain_resolution():
    """Verify end-to-end traversal and proof of Amber Turing causal investigation graph."""
    binder = CapabilityBinder()
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    graph = InvestigationGraph()

    # 1. Initialize Nodes
    n_person = GraphNode(id="n_person", type=NodeType.PERSON, value="Amber Turing", status=NodeStatus.KNOWN)
    n_account = GraphNode(id="n_account", type=NodeType.ACCOUNT, value="?", status=NodeStatus.UNKNOWN)
    n_endpoint = GraphNode(id="n_endpoint", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
    n_client_ip = GraphNode(id="n_client_ip", type=NodeType.IP, value="?", status=NodeStatus.UNKNOWN)
    n_domain = GraphNode(id="n_domain", type=NodeType.DOMAIN, value="?", status=NodeStatus.UNKNOWN)

    for n in (n_person, n_account, n_endpoint, n_client_ip, n_domain):
        graph.add_node(n)

    # 2. Initialize Directed Causal Edges
    e_owns = GraphEdge(
        id="e_owns", source_id="n_person", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.OWNS, target_id="n_account", target_entity_type=NodeType.ACCOUNT,
        required_field_roles={"source": FieldRole.PERSON_NAME, "target": FieldRole.ACCOUNT_NAME}
    )
    e_logon = GraphEdge(
        id="e_logon", source_id="n_account", source_entity_type=NodeType.ACCOUNT,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n_endpoint", target_entity_type=NodeType.ENDPOINT,
        required_field_roles={"source": FieldRole.ACCOUNT_NAME, "target": FieldRole.ENDPOINT_HOST}
    )
    e_ip = GraphEdge(
        id="e_ip", source_id="n_endpoint", source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.ASSIGNED_IP, target_id="n_client_ip", target_entity_type=NodeType.IP,
        required_field_roles={"source": FieldRole.ENDPOINT_HOST, "target": FieldRole.CLIENT_IP}
    )
    e_web = GraphEdge(
        id="e_web", source_id="n_client_ip", source_entity_type=NodeType.IP,
        relation_type=RelationType.REQUESTED, target_id="n_domain", target_entity_type=NodeType.DOMAIN,
        required_field_roles={"source": FieldRole.CLIENT_IP, "target": FieldRole.DOMAIN_NAME}
    )

    for e in (e_owns, e_logon, e_ip, e_web):
        graph.add_edge(e)

    # Invariant Check: Initially, only e_owns is actionable because only n_person is KNOWN
    actionable = graph.get_unproven_edges(only_known_source=True)
    assert len(actionable) == 1
    assert actionable[0].id == "e_owns"

    # Step 1: Resolve Person -> Account
    candidate_1 = binder.create_candidate(actionable[0], n_person, n_account)
    assert candidate_1.operation_name == "resolve_person_to_account"
    # Execute query, record observation
    obs_1 = Observation(
        id="obs-ad-1", provider_scope=SCOPE, cell_id="cell-1", timestamp="2026-09-01T08:00:00Z",
        epistemic_type=EpistemicType.OBSERVED, native_type="WinEventLog:Security",
        fields={"TargetUserName": "amber.turing", "user": "amber.turing"}
    )
    ledger.add_observation(obs_1)
    actionable[0].citations = [obs_1.id]
    res_1 = verifier.verify_candidate_edge(actionable[0], n_person, n_account, ledger, [obs_1])
    assert res_1.verified is True
    verifier.apply_verification_to_graph(res_1, actionable[0], n_account, graph)
    assert n_account.status == NodeStatus.KNOWN
    assert n_account.value == "amber.turing"

    # Step 2: Now e_logon is actionable
    actionable = graph.get_unproven_edges(only_known_source=True)
    assert len(actionable) == 1
    assert actionable[0].id == "e_logon"
    candidate_2 = binder.create_candidate(actionable[0], n_account, n_endpoint)
    assert candidate_2.operation_name == "resolve_account_to_endpoint"
    obs_2 = Observation(
        id="obs-logon-2", provider_scope=SCOPE, cell_id="cell-1", timestamp="2026-09-01T08:30:00Z",
        epistemic_type=EpistemicType.OBSERVED, native_type="WinEventLog:Security",
        fields={"TargetUserName": "amber.turing", "ComputerName": "wrk-amber.froth.ly"}
    )
    ledger.add_observation(obs_2)
    actionable[0].citations = [obs_2.id]
    res_2 = verifier.verify_candidate_edge(actionable[0], n_account, n_endpoint, ledger, [obs_2])
    assert res_2.verified is True
    verifier.apply_verification_to_graph(res_2, actionable[0], n_endpoint, graph)
    assert n_endpoint.status == NodeStatus.KNOWN
    assert n_endpoint.value == "wrk-amber.froth.ly"

    # Step 3: Now e_ip is actionable
    actionable = graph.get_unproven_edges(only_known_source=True)
    assert len(actionable) == 1
    assert actionable[0].id == "e_ip"
    candidate_3 = binder.create_candidate(actionable[0], n_endpoint, n_client_ip)
    assert candidate_3.operation_name == "resolve_endpoint_to_client_ip"
    obs_3 = Observation(
        id="obs-dhcp-3", provider_scope=SCOPE, cell_id="cell-1", timestamp="2026-09-01T08:35:00Z",
        epistemic_type=EpistemicType.OBSERVED, native_type="WinEventLog:Security",
        fields={"host": "wrk-amber.froth.ly", "IpAddress": "10.0.1.25"}
    )
    ledger.add_observation(obs_3)
    actionable[0].citations = [obs_3.id]
    res_3 = verifier.verify_candidate_edge(actionable[0], n_endpoint, n_client_ip, ledger, [obs_3])
    assert res_3.verified is True
    verifier.apply_verification_to_graph(res_3, actionable[0], n_client_ip, graph)
    assert n_client_ip.status == NodeStatus.KNOWN
    assert n_client_ip.value == "10.0.1.25"

    # Step 4: Now and ONLY now is e_web actionable
    actionable = graph.get_unproven_edges(only_known_source=True)
    assert len(actionable) == 1
    assert actionable[0].id == "e_web"
    candidate_4 = binder.create_candidate(actionable[0], n_client_ip, n_domain)
    assert candidate_4.operation_name == "find_web_activity_from_client_ip"
    assert candidate_4.bound_source_value == "10.0.1.25"
    spl = binder.compile_operation_query(candidate_4, provider_id="splunk", index="botsv2")
    assert 'src_ip="10.0.1.25"' in spl

    obs_4 = Observation(
        id="obs-http-4", provider_scope=SCOPE, cell_id="cell-1", timestamp="2026-09-01T09:15:00Z",
        epistemic_type=EpistemicType.OBSERVED, native_type="stream:http",
        fields={"src_ip": "10.0.1.25", "site": "competitor-beer.com", "uri": "/contact-execs"}
    )
    ledger.add_observation(obs_4)
    actionable[0].citations = [obs_4.id]
    res_4 = verifier.verify_candidate_edge(actionable[0], n_client_ip, n_domain, ledger, [obs_4])
    assert res_4.verified is True
    verifier.apply_verification_to_graph(res_4, actionable[0], n_domain, graph)
    assert n_domain.status == NodeStatus.KNOWN
    assert n_domain.value == "competitor-beer.com"

    # Step 5: Causal Provenance Extraction
    subgraph = graph.extract_subgraph_for_claim("amber_competitor_visit")
    assert len(subgraph.proofs) == 4
    provenance_text = subgraph.render_provenance_path()
    assert "Amber Turing" in provenance_text
    assert "amber.turing" in provenance_text
    assert "wrk-amber.froth.ly" in provenance_text
    assert "10.0.1.25" in provenance_text
    assert "competitor-beer.com" in provenance_text


def test_amber_unresolved_identity_halts_with_inconclusive():
    """Verify when Amber's identity cannot be resolved, hunt stops as INCONCLUSIVE_IDENTITY_UNRESOLVED, never NOT_FOUND."""
    graph = InvestigationGraph()
    n_person = GraphNode(id="n_person", type=NodeType.PERSON, value="Amber Turing", status=NodeStatus.KNOWN)
    n_endpoint = GraphNode(id="n_endpoint", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
    e_logon = GraphEdge(
        id="e_logon", source_id="n_person", source_entity_type=NodeType.PERSON,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n_endpoint", target_entity_type=NodeType.ENDPOINT
    )
    graph.add_node(n_person)
    graph.add_node(n_endpoint)
    graph.add_edge(e_logon)

    # Empty observations returned for logon
    ledger = ObservationLedger()
    verifier = RelationVerifier()
    res = verifier.verify_candidate_edge(e_logon, n_person, n_endpoint, ledger, [])
    assert res.verified is False

    # Simulate stopping decision
    account = FinalHuntAccount(
        request_id="req-amber-test",
        objective=HuntObjective(request_id="req-amber-test"),
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
    assert account.outcome == HuntOutcome.INCONCLUSIVE
    assert account.stopping_decision == StoppingDecision.STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED


def test_amber_rejects_jabbah_server_and_destination_ip():
    """Verify v5 relation verifier rejects binding jabbah or server IPs during Amber hunt."""
    verifier = RelationVerifier()
    ledger = ObservationLedger()

    n_account = GraphNode(id="n_account", type=NodeType.ACCOUNT, value="amber.turing", status=NodeStatus.KNOWN)
    n_endpoint = GraphNode(id="n_endpoint", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
    e_logon = GraphEdge(
        id="e_logon", source_id="n_account", source_entity_type=NodeType.ACCOUNT,
        relation_type=RelationType.LOGGED_ON_TO, target_id="n_endpoint", target_entity_type=NodeType.ENDPOINT
    )

    # 1. Telemetry from IIS on jabbah
    obs_jabbah = Observation(
        id="obs-jabbah-1", provider_scope=SCOPE, cell_id="cell-1", timestamp="2026-09-01T08:00:00Z",
        epistemic_type=EpistemicType.OBSERVED, native_type="iis",
        fields={"host": "jabbah", "user": "amber.turing", "dest_ip": "172.31.7.2", "asset_role": "server"}
    )
    ledger.add_observation(obs_jabbah)
    e_logon.citations = [obs_jabbah.id]
    res_jabbah = verifier.verify_candidate_edge(e_logon, n_account, n_endpoint, ledger, [obs_jabbah])
    assert res_jabbah.verified is False
    assert any("server-like role" in v for v in res_jabbah.violations)

    # 2. Reject dest_ip / server_ip as client IP
    n_client_ip = GraphNode(id="n_client_ip", type=NodeType.IP, value="?", status=NodeStatus.UNKNOWN)
    e_ip = GraphEdge(
        id="e_ip", source_id="n_endpoint", source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.ASSIGNED_IP, target_id="n_client_ip", target_entity_type=NodeType.IP,
        citations=[obs_jabbah.id],
    )
    res_ip = verifier.verify_candidate_edge(e_ip, n_endpoint, n_client_ip, ledger, [obs_jabbah])
    assert res_ip.verified is False
    assert any("server/destination IP" in v for v in res_ip.violations)
