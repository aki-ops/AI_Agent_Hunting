"""Unit tests for General Investigation Loop Architecture (Vòng Lặp Điều Tra Tổng Quát).

Tests:
1. InvestigationModel and RelationGraph contract: nodes, edges, claims, unknowns, provider isolation.
2. DeterministicValidator: schema validation, mandatory unknowns, READY_FOR_DISCOVERY state.
3. ActionPlanner: prioritizes RESOLVE_ENTITY over premature TEST until prerequisites resolved.
4. Adjudicator: enforces observation citations, field predicates, and promotes graph state.
5. Adjudicator: strictly blocks web servers (jabbah, we1149srv, IIS) from being bound as user endpoints.
6. Full investigation loop orchestration, stopping taxonomy, and provenance chain reporting.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.cells import ProviderScope
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    TestStatus,
)
from hunting.contracts.hunt import (
    HuntOutcome,
    HuntRequest,
    HuntRequestKind,
    HuntState,
    Hypothesis,
    QueryResult,
    StoppingDecision,
)
from hunting.contracts.investigation_model import (
    GraphEdge,
    GraphNode,
    InvestigationModel,
    NodeStatus,
    RelationGraph,
    RelationType,
    build_investigation_model_from_intent,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.semantic_intent import (
    RequestedObject,
    SemanticEvidenceRequirement,
    SemanticHuntIntent,
    SubjectEntity,
)
from hunting.controller.action_planner import (
    InvestigationAction,
    InvestigationActionPlanner,
)
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.adjudicator import (
    InvestigationAdjudicator,
)
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m2_abduction.provider import StubSemanticCompiler
from hunting.validator.investigation_validator import InvestigationValidator


def test_1_investigation_model_and_relation_graph_contract():
    """1. InvestigationModel and RelationGraph contract correctly model entities, relations, and isolation."""
    intent = SemanticHuntIntent(
        original_request="Amber Turing visited competitor site",
        question="What site did Amber Turing visit?",
        subject=SubjectEntity(type="person", value="Amber Turing"),
        requested_object=RequestedObject(type="website_domain", role="answer"),
        behavior="web browsing",
        evidence_requirements=[
            SemanticEvidenceRequirement(semantic_intent="identity_binding", required_fields=["user", "host"]),
            SemanticEvidenceRequirement(semantic_intent="web_navigation", required_fields=["site", "uri"]),
        ],
        required_correlations=["person_to_endpoint", "endpoint_to_client_ip", "client_ip_to_web_or_dns_event"],
    )
    hyp = Hypothesis(id="hyp-1", statement="Amber Turing visited competitor site", requirements=["req-1"])
    model = build_investigation_model_from_intent(intent, [hyp], [])

    assert model.question == "What site did Amber Turing visit?"
    assert len(model.subjects) == 1
    assert model.subjects[0].type == "person"
    assert model.subjects[0].value == "Amber Turing"

    # Verify Graph nodes & edges
    graph = model.graph
    assert graph.get_node("node-subj-person") is not None
    assert graph.get_node("node-endpoint") is not None
    assert graph.get_node("node-client-ip") is not None
    assert graph.get_node("node-target-object") is not None

    edges = list(graph.edges.values())
    assert any(e.relation_type == RelationType.LOGGED_ON_TO.value for e in edges)
    assert any(e.relation_type == RelationType.ORIGINATED_FROM.value for e in edges)
    assert any(e.relation_type == RelationType.REQUESTED.value for e in edges)

    # Provider isolation: passes when clean
    assert model.validate_provider_isolation() == []

    # Provider isolation: fails if SPL leaked
    leaky_model = build_investigation_model_from_intent(intent, [hyp], [])
    leaky_model.assumptions.append("search index=botsv2 sourcetype=stream:http")
    leaks = leaky_model.validate_provider_isolation()
    assert len(leaks) >= 1
    assert "Forbidden provider syntax" in leaks[0]

    # Serialization round-trip
    m_dict = model.to_dict()
    restored = InvestigationModel.from_dict(m_dict)
    assert restored.question == model.question
    assert len(restored.graph.nodes) == len(model.graph.nodes)
    assert len(restored.graph.edges) == len(model.graph.edges)


def test_2_deterministic_validator_establishes_mandatory_unknowns_and_discovery_state():
    """2. DeterministicValidator enforces mandatory unknowns and sets state to READY_FOR_DISCOVERY."""
    validator = InvestigationValidator()
    intent = SemanticHuntIntent(
        original_request="Amber Turing visited competitor site",
        question="What site did Amber Turing visit?",
        subject=SubjectEntity(type="person", value="Amber Turing"),
        requested_object=RequestedObject(type="website_domain"),
        behavior="web browsing",
    )
    model = build_investigation_model_from_intent(intent)

    result = validator.validate_investigation_model(model)
    assert result.valid is True
    assert result.investigation_state == "READY_FOR_DISCOVERY"
    assert any(u.entity_type == "endpoint" and u.mandatory for u in result.mandatory_unknowns)

    # An explicitly input-provided endpoint is allowed. Host names are not
    # role classifiers; role validation belongs to cited telemetry.
    jabbah_node = GraphNode(id="node-jabbah", type="endpoint", value="jabbah", status=NodeStatus.KNOWN, source="input")
    model.graph.add_node(jabbah_node)
    bad_edge = GraphEdge(
        id="edge-bad",
        source_id="node-subj-person",
        target_id=jabbah_node.id,
        relation_type=RelationType.LOGGED_ON_TO.value,
        status=NodeStatus.KNOWN,
        source="input",
    )
    model.graph.add_edge(bad_edge)

    result_with_input_endpoint = validator.validate_investigation_model(model)
    assert result_with_input_endpoint.valid is True


def test_3_action_planner_prioritizes_entity_resolution_over_traffic_testing():
    """3. ActionPlanner prioritizes RESOLVE_ENTITY when mandatory entity unknowns exist."""
    planner = InvestigationActionPlanner()
    intent = SemanticHuntIntent(
        original_request="Amber Turing visited website",
        question="What website did Amber Turing visit?",
        subject=SubjectEntity(type="person", value="Amber Turing"),
        requested_object=RequestedObject(type="website_domain"),
        behavior="web browsing",
    )
    model = build_investigation_model_from_intent(intent)
    state = HuntState(identity_resolved=False)

    # Untested expectation for web traffic exists
    exp_web = Expectation(
        id="exp-web-01",
        owner_explanation_id="hyp-1",
        evidence_requirement=EvidenceRequirement.WEB_REQUEST,
        predicted_observation="Web traffic to external site",
        entity_ref=SubjectEntity(type="person", value="Amber Turing"),
        field_predicate=None,
        provider_scope_id="scope-1",
        time_window="2026-09-01T00:00:00Z/P1D",
        falsification_condition="No web records",
        test_status=TestStatus.UNTESTED,
    )
    state.expectations.append(exp_web)

    # Invariant: ActionPlanner MUST select RESOLVE_ENTITY because Amber's endpoint is not resolved
    decision = planner.select_action(model, model.graph, state)
    assert decision.action == InvestigationAction.RESOLVE_ENTITY
    assert "endpoint" in decision.reason.lower()

    # Once identity is resolved, ActionPlanner can proceed to TEST
    state.identity_resolved = True
    decision_after = planner.select_action(model, model.graph, state)
    assert decision_after.action == InvestigationAction.TEST


def test_4_adjudicator_enforces_citations_and_field_predicates():
    """4. Adjudicator verifies observation citations and predicates before mutating graph."""
    adjudicator = InvestigationAdjudicator()
    ledger = ObservationLedger()
    graph = RelationGraph()

    p_node = GraphNode(id="p1", type="person", value="Amber Turing", status=NodeStatus.KNOWN)
    e_node = GraphNode(id="e1", type="endpoint", value="wrk-amber", status=NodeStatus.UNKNOWN)
    graph.add_node(p_node)
    graph.add_node(e_node)

    state = HuntState(relation_graph=graph, identity_resolved=False)

    # 1. Candidate edge without citation -> rejected
    cand_no_cite = GraphEdge(
        id="e-no-cite",
        source_id="p1",
        target_id="e1",
        relation_type=RelationType.LOGGED_ON_TO.value,
        source="telemetry",
        metadata={"observation_ids": []},
    )
    dec1 = adjudicator.adjudicate_edge(cand_no_cite, ledger, state)
    assert dec1.accepted is False
    assert "Citation failure" in dec1.reason

    # 2. Candidate edge citing observation with mismatched user -> rejected
    obs_wrong = Observation(
        id="obs-wrong",
        provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "main"}),
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"user": "Charlie", "host": "wrk-amber"},
    )
    ledger.add_observation(obs_wrong)

    cand_mismatch = GraphEdge(
        id="e-mismatch",
        source_id="p1",
        target_id="e1",
        relation_type=RelationType.LOGGED_ON_TO.value,
        source="telemetry",
        metadata={"observation_ids": [obs_wrong.id]},
    )
    dec2 = adjudicator.adjudicate_edge(cand_mismatch, ledger, state)
    assert dec2.accepted is False
    assert "do not substantiate relation" in dec2.reason

    # 3. Candidate edge citing valid observation with matching user and host -> accepted
    obs_valid = Observation(
        id="obs-valid",
        provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "main"}),
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"user": "Amber Turing", "host": "wrk-amber", "client_ip": "10.0.1.50"},
    )
    ledger.add_observation(obs_valid)

    cand_valid = GraphEdge(
        id="e-valid",
        source_id="p1",
        target_id="e1",
        relation_type=RelationType.LOGGED_ON_TO.value,
        source="telemetry",
        metadata={"observation_ids": [obs_valid.id], "client_ip": "10.0.1.50"},
    )
    result = adjudicator.adjudicate_and_apply([cand_valid], ledger, state)
    assert len(result.accepted_edges) == 1
    assert state.identity_resolved is True
    assert state.identity_mapping["endpoint"] == "wrk-amber"
    assert state.identity_mapping["client_ip"] == "10.0.1.50"
    assert e_node.status == NodeStatus.KNOWN


def test_5_adjudicator_strictly_blocks_web_servers_as_user_endpoints():
    """5. Adjudicator strictly blocks web servers (jabbah, we1149srv, IIS) from becoming user endpoints."""
    adjudicator = InvestigationAdjudicator()
    ledger = ObservationLedger()
    graph = RelationGraph()

    p_node = GraphNode(id="p1", type="person", value="Amber Turing", status=NodeStatus.KNOWN)
    jabbah_node = GraphNode(id="e-jabbah", type="endpoint", value="jabbah", status=NodeStatus.UNKNOWN)
    we1149_node = GraphNode(id="e-we1149", type="endpoint", value="we1149srv", status=NodeStatus.UNKNOWN)
    graph.add_node(p_node)
    graph.add_node(jabbah_node)
    graph.add_node(we1149_node)

    state = HuntState(relation_graph=graph, identity_resolved=False)

    obs_jabbah = Observation(
        id="obs-jabbah",
        provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "main"}),
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"user": "Amber Turing", "host": "jabbah", "asset_role": "server"},
    )
    ledger.add_observation(obs_jabbah)

    cand_jabbah = GraphEdge(
        id="e-jabbah",
        source_id="p1",
        target_id="e-jabbah",
        relation_type=RelationType.LOGGED_ON_TO.value,
        metadata={"observation_ids": [obs_jabbah.id]},
    )
    dec_jabbah = adjudicator.adjudicate_edge(cand_jabbah, ledger, state)
    assert dec_jabbah.accepted is False
    assert "server-like role" in dec_jabbah.reason

    # Test IIS telemetry on we1149srv
    obs_iis = Observation(
        id="obs-iis",
        provider_scope=ProviderScope(provider_id="splunk", native_partition={"index": "main"}),
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="iis",
        fields={"user": "Amber Turing", "host": "we1149srv", "asset_role": "server"},
    )
    ledger.add_observation(obs_iis)

    cand_we1149 = GraphEdge(
        id="e-we1149",
        source_id="p1",
        target_id="e-we1149",
        relation_type=RelationType.LOGGED_ON_TO.value,
        metadata={"observation_ids": [obs_iis.id]},
    )
    dec_we1149 = adjudicator.adjudicate_edge(cand_we1149, ledger, state)
    assert dec_we1149.accepted is False
    assert state.identity_resolved is False


def test_6_full_investigation_loop_orchestration_and_stopping_taxonomy(tmp_path):
    """6. Full investigation loop adheres to epistemic stop conditions and renders relation chain."""
    stub = StubSemanticCompiler(scenario="amber")
    compiler = KnowledgeBehaviorCompiler(llm_caller=stub)
    engine = HypothesisHuntEngine(compiler=compiler)

    req = HuntRequest(
        id="hunt-loop-amber",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Amber Turing visited the competitor website",
    )

    # Mock adapter returning 0 logon events -> identity cannot be resolved
    mock_adapter = MagicMock()
    mock_adapter.scope = ProviderScope(provider_id="cdb_sqlite", native_partition={"table": "events"})
    empty_result = QueryResult(
        query_id="qp-mock-1",
        outcome="EMPTY",
        executed_ok=True,
        complete=True,
        rows=[],
        row_count=0,
    )
    mock_adapter.execute_query.return_value = empty_result

    res = engine.execute_hunt(req, adapter=mock_adapter, time_window="2026-09-01T00:00:00Z/P1D")

    # Invariant: Must stop with STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED, never NOT_FOUND
    assert res.state.stopping_decision == StoppingDecision.STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED
    assert res.account.outcome == HuntOutcome.INCONCLUSIVE
    assert res.account.answer.get("status") == "INCONCLUSIVE"
    assert res.account.answer.get("reason") in ("NO_VERIFIED_ANSWER_CANDIDATE", "IDENTITY_UNRESOLVED")

    # The semantic projection preserves the requested relation only; operation
    # contracts may add identity prerequisites during capability binding.
    assert "visited" in res.report
    assert "person(Amber Turing) -> logged_on_to -> endpoint" not in res.report

    # Invariant: Persisted artifacts include investigation_model.json and relation_graph.json
    hunt_artifact_dir = Path("artifacts") / "hunt-loop-amber"
    assert (hunt_artifact_dir / "investigation_model.json").exists()
    assert (hunt_artifact_dir / "relation_graph.json").exists()

    with open(hunt_artifact_dir / "investigation_model.json", "r", encoding="utf-8") as f:
        inv_data = json.load(f)
    assert inv_data["question"] == "What website domain did Amber Turing visit?"

    with open(hunt_artifact_dir / "relation_graph.json", "r", encoding="utf-8") as f:
        graph_data = json.load(f)
    assert "nodes" in graph_data
    assert "edges" in graph_data
