"""Regression tests for evidence-driven, non-hardcoded investigation paths."""
from __future__ import annotations

from hunting.capabilities.binder import CapabilityBinder
from hunting.contracts.case_graph import (
    GraphEdge,
    GraphNode,
    NodeStatus,
    NodeType,
    RelationType,
    build_investigation_case_from_intent,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import EvidenceRequirementV4
from hunting.contracts.investigation_model import build_investigation_model_from_intent
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.semantic_intent import RequestedObject, SemanticHuntIntent, SubjectEntity
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger

SCOPE = ProviderScope(provider_id="splunk", scope_id="test", native_partition={"index": "test"})


def _tor_intent() -> SemanticHuntIntent:
    return SemanticHuntIntent(
        original_request="Amber Turing da thuc hien cai dat TOR browser, phien ban cua TOR browser la gi",
        question="What is the version of Tor Browser installed or executed by Amber Turing?",
        subject=SubjectEntity(type="person", value="Amber Turing"),
        requested_object=RequestedObject(type="software_version"),
        behavior="installed or executed Tor Browser",
    )


def _requirements() -> list[EvidenceRequirementV4]:
    return [
        EvidenceRequirementV4(
            id="req-file",
            description="File system metadata from the Tor Browser directory or installer filename.",
            evidence_type="file_modification",
            necessity="CRITICAL",
        ),
        EvidenceRequirementV4(
            id="req-process",
            description="Process execution of the Tor Browser installer or main process.",
            evidence_type="process_ancestry",
            necessity="SUPPORTING",
        ),
        EvidenceRequirementV4(
            id="req-web",
            description="Outbound web request downloading the Tor Browser package.",
            evidence_type="web_request",
            necessity="SUPPORTING",
        ),
    ]


def test_artifact_question_does_not_get_forced_through_ip_or_web() -> None:
    case = build_investigation_case_from_intent(_tor_intent(), [], _requirements())
    edges = list(case.graph.edges.values())
    operations = [op for edge in edges for op in edge.acceptable_operations]

    assert "resolve_person_to_account" in operations
    assert "resolve_account_to_endpoint" in operations
    assert "find_file_change_from_endpoint" in operations
    assert "find_process_from_endpoint" in operations
    assert "find_web_activity_from_endpoint" in operations
    assert "resolve_endpoint_to_client_ip" not in operations
    assert "find_web_activity_from_client_ip" not in operations
    assert all(edge.metadata.get("requirement_id") for edge in edges if edge.id.startswith("edge-artifact-"))

    model = build_investigation_model_from_intent(_tor_intent(), [], _requirements())
    assert not any(edge.id == "edge-endpoint-ip" for edge in model.graph.edges.values())
    assert model.acceptance_criteria[0].required_path == ["person", "endpoint", "software_version"]


def test_file_endpoint_operation_is_provider_neutral_and_compilable() -> None:
    binder = CapabilityBinder()
    source = GraphNode(id="endpoint", type=NodeType.ENDPOINT, value="wrk-amber", status=NodeStatus.KNOWN)
    target = GraphNode(id="software", type="software_version", value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="artifact",
        source_id=source.id,
        source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.MODIFIED,
        target_id=target.id,
        target_entity_type="software_version",
        acceptable_operations=["find_file_change_from_endpoint"],
    )

    candidate = binder.create_candidate(edge, source, target)
    assert candidate is not None
    assert candidate.operation_name == "find_file_change_from_endpoint"
    query = binder.compile_operation_query(candidate, provider_id="splunk", index="main")
    assert 'EventCode=11' in query
    assert 'host="*wrk-amber*"' in query
    assert "ProductVersion" in query


def test_version_is_verified_only_from_matching_artifact_observation() -> None:
    verifier = RelationVerifier()
    ledger = ObservationLedger()
    obs = Observation(
        id="obs-tor-file",
        provider_scope=SCOPE,
        cell_id="cell",
        timestamp="2026-09-08T00:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="sysmon_file_create",
        fields={
            "host": "wrk-amber",
            "TargetFilename": r"C:\\Users\\amber\\Tor Browser\\Browser\\firefox.exe",
            "ProductVersion": "13.5.2",
        },
    )
    ledger.add_observation(obs)
    source = GraphNode(id="endpoint", type=NodeType.ENDPOINT, value="wrk-amber", status=NodeStatus.KNOWN)
    target = GraphNode(id="target", type="software_version", value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="artifact",
        source_id=source.id,
        source_entity_type=NodeType.ENDPOINT,
        relation_type=RelationType.MODIFIED,
        target_id=target.id,
        target_entity_type="software_version",
        acceptable_operations=["find_file_change_from_endpoint"],
        acceptance_predicate={"software_terms": ["tor"]},
        citations=[obs.id],
    )

    result = verifier.verify_candidate_edge(edge, source, target, ledger)
    assert result.verified is True
    assert result.target_value == "13.5.2"
    assert result.proof is not None and result.proof.citations == [obs.id]

    unrelated = Observation(
        id="obs-unrelated-file",
        provider_scope=SCOPE,
        cell_id="cell",
        timestamp="2026-09-08T00:00:01Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="sysmon_file_create",
        fields={"host": "wrk-amber", "TargetFilename": r"C:\\Apps\\Chrome\\chrome.exe", "ProductVersion": "99.1.0"},
    )
    ledger2 = ObservationLedger()
    ledger2.add_observation(unrelated)
    edge.citations = [unrelated.id]
    rejected = verifier.verify_candidate_edge(edge, source, target, ledger2)
    assert rejected.verified is False
