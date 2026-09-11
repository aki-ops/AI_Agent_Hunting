"""Deterministic relation verifier: citation admission & generic state transition tests.

Verifies:
- Universal admission gate: explicit citations, ledger existence, supplied obs matching,
  epistemic OBSERVED requirement, and QueryResult completeness.
- Generic ProviderOperation-driven state transition:
  provider/scope isolation, timestamp ordering, temporal bounds, artifact identity matching,
  action/state role enforcement, and separation of ransomware causality.
"""
from __future__ import annotations

from hunting.contracts.case_graph import GraphEdge, GraphNode, NodeStatus, RelationType
from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import ProviderOperation, QueryOutcome, QueryResult
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger

SCOPE_A = ProviderScope(provider_id="splunk", scope_id="main_scope", native_partition={"index": "botsv2"})
SCOPE_B = ProviderScope(provider_id="splunk", scope_id="other_scope", native_partition={"index": "other"})
SCOPE_OTHER_PROVIDER = ProviderScope(provider_id="elastic", scope_id="elastic_scope", native_partition={"index": "logs"})


def _create_obs(
    obs_id: str,
    scope: ProviderScope = SCOPE_A,
    timestamp: str = "2017-08-18T21:50:00Z",
    fields: dict | None = None,
    epistemic_type: EpistemicType = EpistemicType.OBSERVED,
    query_id: str = "q-1",
) -> Observation:
    return Observation(
        id=obs_id,
        provider_scope=scope,
        cell_id="cell-1",
        timestamp=timestamp,
        epistemic_type=epistemic_type,
        native_type="sysmon:file_event",
        fields=fields or {"file_path": "C:\\Data\\doc.pptx", "action": "modified", "state": "created"},
        query_id=query_id,
    )


def test_admission_gate_requires_explicit_citations():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    source = GraphNode(id="n-src", type="file", value="doc.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="doc.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-transition",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        citations=[],
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger)
    assert res.verified is False
    assert "citations_required" in res.violations


def test_admission_gate_rejects_citation_not_in_ledger():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    source = GraphNode(id="n-src", type="file", value="doc.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="doc.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-transition",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        citations=["obs-missing-1"],
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger)
    assert res.verified is False
    assert "cited_observation_not_in_ledger" in res.violations


def test_admission_gate_rejects_supplied_observation_not_cited():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-1")
    obs2 = _create_obs("obs-2")
    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    source = GraphNode(id="n-src", type="file", value="doc.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="doc.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-transition",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        citations=["obs-1"],
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger, observations=[obs1, obs2])
    assert res.verified is False
    assert "supplied_observation_not_cited" in res.violations


def test_admission_gate_rejects_supplied_observation_not_in_ledger():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-1")

    source = GraphNode(id="n-src", type="file", value="doc.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="doc.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-transition",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        citations=["obs-1"],
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger, observations=[obs1])
    assert res.verified is False
    assert "cited_observation_not_in_ledger" in res.violations or "supplied_observation_not_in_ledger" in res.violations


def test_admission_gate_rejects_non_observed_epistemic_type():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-testimony", epistemic_type=EpistemicType.TESTIMONY)
    ledger.add_observation(obs1)

    source = GraphNode(id="n-src", type="file", value="doc.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="doc.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-transition",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        citations=["obs-testimony"],
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger)
    assert res.verified is False
    assert "evidence_not_observed" in res.violations


def test_admission_gate_rejects_incomplete_or_truncated_query_result():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-1", query_id="q-incomplete")
    ledger.add_observation(obs1)

    qr_incomplete = QueryResult(
        query_id="q-incomplete",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=False,
        rows=[],
    )
    ledger.record_query_result(qr_incomplete)

    source = GraphNode(id="n-src", type="file", value="doc.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="doc.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-transition",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        citations=["obs-1"],
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger)
    assert res.verified is False
    assert "incomplete_query_result" in res.violations

    ledger2 = ObservationLedger()
    obs2 = _create_obs("obs-2", query_id="q-truncated")
    ledger2.add_observation(obs2)
    qr_truncated = QueryResult(
        query_id="q-truncated",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        truncation_reason="provider_buffer_exhausted",
        rows=[],
    )
    ledger2.record_query_result(qr_truncated)
    edge2 = GraphEdge(
        id="e-2",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        citations=["obs-2"],
    )
    res2 = verifier.verify_candidate_edge(edge2, source, target, ledger2)
    assert res2.verified is False
    assert "query_result_truncated" in res2.violations


def test_transition_rejects_cross_provider_and_cross_scope():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-1", scope=SCOPE_A, timestamp="2017-08-18T21:50:00Z")
    obs2 = _create_obs("obs-2", scope=SCOPE_OTHER_PROVIDER, timestamp="2017-08-18T21:50:43Z")
    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    source = GraphNode(id="n-src", type="file", value="doc.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="doc.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-trans",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        metadata={"verification_mode": "state_transition"},
        citations=["obs-1", "obs-2"],
    )

    op = ProviderOperation(
        id="op_file_transition",
        provider_id="splunk",
        scope_ids=("main_scope",),
        artifact_identity_roles={"artifact": ("file_path",)},
        action_roles={"action": ("action",)},
        state_roles={"state": ("state",)},
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger, operation=op)
    assert res.verified is False
    assert "cross_provider_evidence" in res.violations


def test_transition_rejects_reversed_temporal_ordering_and_bound_exceeded():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-1", timestamp="2017-08-18T22:00:00Z", fields={"file_path": "report.pptx", "state": "clear"})
    obs2 = _create_obs("obs-2", timestamp="2017-08-18T21:00:00Z", fields={"file_path": "report.pptx", "state": "modified"})
    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    source = GraphNode(id="n-src", type="file", value="report.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="report.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-trans",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        metadata={"verification_mode": "state_transition"},
        citations=["obs-1", "obs-2"],
    )

    op = ProviderOperation(
        id="op_file_transition",
        provider_id="splunk",
        scope_ids=("main_scope",),
        artifact_identity_roles={"artifact": ("file_path",)},
        state_roles={"state": ("state",)},
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger, operation=op)
    assert res.verified is False
    assert "reversed_temporal_ordering" in res.violations

    ledger2 = ObservationLedger()
    obs_early = _create_obs("obs-e", timestamp="2017-08-18T10:00:00Z", fields={"file_path": "report.pptx", "state": "clear"})
    obs_late = _create_obs("obs-l", timestamp="2017-08-18T20:00:00Z", fields={"file_path": "report.pptx", "state": "modified"})
    ledger2.add_observation(obs_early)
    ledger2.add_observation(obs_late)

    edge2 = GraphEdge(
        id="e-trans-bound",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        acceptance_predicate={"max_time_delta_seconds": 3600},
        metadata={"verification_mode": "state_transition"},
        citations=["obs-e", "obs-l"],
    )

    res2 = verifier.verify_candidate_edge(edge2, source, target, ledger2, operation=op)
    assert res2.verified is False
    assert "temporal_bound_exceeded" in res2.violations


def test_transition_rejects_missing_or_mismatched_artifact_identity():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-1", timestamp="2017-08-18T21:50:00Z", fields={"file_path": "first.pptx", "state": "open"})
    obs2 = _create_obs("obs-2", timestamp="2017-08-18T21:50:43Z", fields={"file_path": "second.pptx", "state": "encrypted"})
    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    source = GraphNode(id="n-src", type="file", value="first.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="second.pptx", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-trans",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        metadata={"verification_mode": "state_transition"},
        citations=["obs-1", "obs-2"],
    )

    op = ProviderOperation(
        id="op_file_transition",
        provider_id="splunk",
        scope_ids=("main_scope",),
        artifact_identity_roles={"artifact": ("file_path",)},
        state_roles={"state": ("state",)},
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger, operation=op)
    assert res.verified is False
    assert "artifact_identity_mismatch" in res.violations


def test_transition_rejects_ransomware_qualifier_without_independent_evidence():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs("obs-1", timestamp="2017-08-18T21:50:00Z", fields={"file_path": "campaign.pptx", "state": "normal"})
    obs2 = _create_obs("obs-2", timestamp="2017-08-18T21:50:43Z", fields={"file_path": "campaign.pptx", "state": "renamed_crypt"})
    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    source = GraphNode(id="n-src", type="file", value="campaign.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="campaign.pptx.crypt", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-trans",
        source_id="n-src",
        source_entity_type="file",
        relation_type="ransomware_encrypted",
        target_id="n-tgt",
        target_entity_type="file",
        acceptance_predicate={"qualifier": "ransomware"},
        metadata={"verification_mode": "state_transition"},
        citations=["obs-1", "obs-2"],
    )

    op = ProviderOperation(
        id="op_file_transition",
        provider_id="splunk",
        scope_ids=("main_scope",),
        artifact_identity_roles={"artifact": ("file_path",)},
        state_roles={"state": ("state",)},
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger, operation=op)
    assert res.verified is False
    assert "ransomware_qualifier_unproven" in res.violations

    edge.acceptance_predicate["ransomware_indicators_verified"] = True
    res_verified = verifier.verify_candidate_edge(edge, source, target, ledger, operation=op)
    assert res_verified.verified is True
    assert res_verified.proof is not None
    assert res_verified.proof.verified_by == "StateTransitionVerifier"


def test_valid_generic_state_transition_proof():
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs1 = _create_obs(
        "obs-1",
        timestamp="2017-08-18T21:50:00Z",
        fields={"file_path": "marketing.pptx", "state": "normal", "action": "read"},
    )
    obs2 = _create_obs(
        "obs-2",
        timestamp="2017-08-18T21:50:43Z",
        fields={"file_path": "marketing.pptx", "state": "altered", "action": "write"},
    )
    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    source = GraphNode(id="n-src", type="file", value="marketing.pptx", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-tgt", type="file", value="marketing.pptx", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="e-trans",
        source_id="n-src",
        source_entity_type="file",
        relation_type=RelationType.MODIFIED,
        target_id="n-tgt",
        target_entity_type="file",
        acceptance_predicate={"max_time_delta_seconds": 120},
        metadata={"verification_mode": "state_transition"},
        citations=["obs-1", "obs-2"],
    )

    op = ProviderOperation(
        id="op_file_transition",
        provider_id="splunk",
        scope_ids=("main_scope",),
        artifact_identity_roles={"artifact": ("file_path",)},
        action_roles={"action": ("action",)},
        state_roles={"state": ("state",)},
    )

    res = verifier.verify_candidate_edge(edge, source, target, ledger, operation=op)
    assert res.verified is True
    assert res.proof is not None
    assert res.proof.verified_by == "StateTransitionVerifier"
    assert res.proof.citations == ["obs-1", "obs-2"]
    assert res.proof.field_matches.get("artifact_identity") == "marketing.pptx"
    assert res.proof.field_matches.get("delta_seconds") == "43.0"
