"""Regression tests for the provider-neutral ClaimGraph execution boundary."""
from __future__ import annotations

import json

from hunting.capabilities.binder import CapabilityBinder
from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.capabilities import CapabilityGraph
from hunting.contracts.case_graph import GraphEdge, GraphNode, NodeStatus
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import ProviderOperation
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m5_adapter.cdb_adapter import CdbAdapter


def _operation(operation_id: str, fact_kind: str) -> ProviderOperation:
    return ProviderOperation(
        id=operation_id,
        provider_id="test-provider",
        scope_ids=("scope-1",),
        input_entity_kinds=("package",),
        output_fields=("signer", "signature_id"),
        output_fact_kinds=(fact_kind,),
        completeness="cursor EOF proof",
        expected_cost=1,
    )


def test_binder_uses_declared_fact_contract_for_unseen_operation() -> None:
    """An unseen semantic fact binds without an operation-name/keyword route."""
    operation = _operation("lookup_signature_metadata", "signature_attribution")
    graph = CapabilityGraph(
        id="cap-1",
        census_version="test",
        operations=[operation],
    )
    binder = CapabilityBinder(graph, provider_id="test-provider")
    source = GraphNode(
        id="source",
        type="package",
        value="package-17",
        status=NodeStatus.KNOWN,
    )
    target = GraphNode(id="target", type="identity", value="?")
    edge = GraphEdge(
        id="edge-signature",
        source_id=source.id,
        source_entity_type=source.type,
        relation_type="signed_by",
        target_id=target.id,
        target_entity_type=target.type,
        acceptance_predicate={"fact_kinds": ["signature_attribution"]},
        metadata={"verification_mode": "claim_contract"},
    )

    candidate = binder.create_candidate(edge, source, target)

    assert candidate is not None
    assert candidate.operation_name == "lookup_signature_metadata"
    assert candidate.diagnostics["output_fact_kinds"] == ["signature_attribution"]
    assert candidate.completeness == "cursor EOF proof"


def test_claim_contract_verifier_cites_only_matching_observations() -> None:
    scope = ProviderScope(provider_id="test-provider", scope_id="scope-1", native_partition={"stream": "test"})
    ledger = ObservationLedger()
    observation = Observation(
        id="obs-signature-1",
        provider_scope=scope,
        cell_id="scope-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="custom:signature",
        fields={
            "package_id": "package-17",
            "signer": "build-service",
            "signature_id": "sig-42",
        },
    )
    ledger.add_observation(observation)

    source = GraphNode(id="source", type="package", value="package-17", status=NodeStatus.KNOWN)
    target = GraphNode(id="target", type="identity", value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="edge-signature",
        source_id=source.id,
        source_entity_type=source.type,
        relation_type="signed_by",
        target_id=target.id,
        target_entity_type=target.type,
        required_field_roles={"source": "package_id", "target": "signer"},
        acceptance_predicate={
            "fact_kinds": ["signature_attribution"],
            "required_fields": ["signer"],
            "min_observations": 1,
        },
        metadata={"verification_mode": "claim_contract"},
        citations=[observation.id],
    )

    result = RelationVerifier().verify_candidate_edge(edge, source, target, ledger)

    assert result.verified is True
    assert result.target_value == "build-service"
    assert result.cited_observation_ids == ["obs-signature-1"]
    assert result.proof is not None
    assert result.proof.verified_by == "ClaimContractVerifier"


def test_claim_contract_does_not_promote_schema_only_fields() -> None:
    scope = ProviderScope(provider_id="test-provider", scope_id="scope-1", native_partition={"stream": "test"})
    ledger = ObservationLedger()
    observation = Observation(
        id="obs-schema-only",
        provider_scope=scope,
        cell_id="scope-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="schema:field",
        fields={"available_field": "signer"},
    )
    ledger.add_observation(observation)

    source = GraphNode(id="source", type="package", value="package-17", status=NodeStatus.KNOWN)
    target = GraphNode(id="target", type="identity", value="?", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="edge-signature",
        source_id=source.id,
        source_entity_type=source.type,
        relation_type="signed_by",
        target_id=target.id,
        target_entity_type=target.type,
        acceptance_predicate={
            "fact_kinds": ["signature_attribution"],
            "required_fields": ["signer"],
        },
        metadata={"verification_mode": "claim_contract"},
        citations=[observation.id],
    )

    result = RelationVerifier().verify_candidate_edge(edge, source, target, ledger)

    assert result.verified is False
    assert result.proof is None


def test_compiler_does_not_receive_provider_capability_context() -> None:
    captured: list[str] = []
    response = '{"id":"g","request_id":"req-context","objective":"Find signer","answer_contract":{"mode":"lookup","answer_type":"identity","required_fields":[],"question":"Find signer"},"claims":[{"id":"c1","claim_type":"attribute","subject":"package:package-17","predicate":"signed_by","object_or_value":null,"value_type":"identity","provenance":"request","source_request_id":"req-context","dependencies":[],"evidence_requirements":[],"observation_requirements":[{"id":"r1","fact_kind":"signature_attribution","required_fields":["signer"],"field_roles":["signer"],"completeness_required":false}],"acceptance_rule":{"min_observations":1,"required_fields":["signer"],"requires_query_complete":false,"value_must_match":null},"refutation_rule":null,"optional":false,"is_prerequisite":false,"reason":"The request asks for the signer"}]}'

    compiler = KnowledgeBehaviorCompiler(llm_caller=lambda prompt: captured.append(prompt) or response)
    compiler.compile(
        HuntRequest(
            id="req-context",
            kind=HuntRequestKind.QUESTION,
            content="Find signer",
        ),
        capability_context={
            "providers": [{"provider_id": "test-provider", "status": "ONLINE"}],
            "operations": [{
                "id": "lookup_signature_metadata",
                "provider_id": "test-provider",
                "input_entity_kinds": ["package"],
                "output_fact_kinds": ["signature_attribution"],
                "output_fields": ["signer"],
            }],
        },
    )

    assert len(captured) == 1
    assert "lookup_signature_metadata" not in captured[0]
    assert "CAPABILITY SUMMARY" not in captured[0]
    assert "provider-neutral" in captured[0]


def test_claim_graph_vertical_slice_executes_only_declared_operation() -> None:
    request_id = "req-process-lookup"
    response = json.dumps({
        "id": "graph-process-lookup",
        "request_id": request_id,
        "objective": "Find the process observed on SRV-01",
        "answer_contract": {
            "mode": "lookup",
            "answer_type": "process",
            "required_fields": ["image"],
            "question": "Which process was observed on SRV-01?",
        },
        "claims": [{
            "id": "claim-process",
            "claim_type": "attribute",
            "subject": "host:SRV-01",
            "predicate": "observed_process",
            "object_or_value": None,
            "value_type": "process",
            "provenance": "request",
            "source_request_id": request_id,
            "dependencies": [],
            "evidence_requirements": [],
            "observation_requirements": [{
                "id": "req-process",
                "fact_kind": "process_ancestry",
                "required_fields": ["image"],
                "field_roles": ["endpoint_host", "process_name"],
                "completeness_required": True,
            }],
            "acceptance_rule": {
                "min_observations": 1,
                "required_fields": ["image"],
                "requires_query_complete": True,
                "value_must_match": None,
            },
            "refutation_rule": None,
            "optional": False,
            "is_prerequisite": False,
            "reason": "The request asks for the observed process",
        }],
    })
    cdb = CdbAdapter(":memory:")
    cdb.insert_events([{
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "process_creation",
        "host": "SRV-01",
        "image": "powershell.exe",
        "cmdline": "powershell.exe -NoProfile",
    }])

    engine = HypothesisHuntEngine(
        compiler=KnowledgeBehaviorCompiler(llm_caller=lambda _: response),
        cdb_adapter=cdb,
    )
    result = engine.execute_hunt(
        HuntRequest(
            id=request_id,
            kind=HuntRequestKind.QUESTION,
            content="Which process was observed on SRV-01?",
        ),
        adapter=cdb,
        time_window="2026-02-01T00:00:00Z/P1D",
    )

    claim = result.state.objective.claim_graph.get_claim("claim-process")
    assert claim.status.value == "SUPPORTED"
    assert claim._cited_observation_ids
    assert len(result.state.queries) == 1
    assert result.state.queries[0].operation_id == "cdb_process_search"
    assert result.state.stopping_decision.value == "STOP_RESOLVED"
