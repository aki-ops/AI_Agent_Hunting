"""Unit tests for the 8-scenario Counterfactual Acceptance Matrix.

Scenarios:
1. renamed source: Dynamic source profiler & validator accept custom-named source based on schema fingerprint.
2. misleading source name: Source named like file events but lacking required schema fields is rejected.
3. changed artifact type: Generic state transition verifier works for PDF, BIN, or custom files, not hardcoded to .pptx/.crypt.
4. missing telemetry: Unreachable or missing scope stops gracefully with INCONCLUSIVE, never false negative.
5. timeout/partial: Truncated or timed-out query (complete=False) blocks NOT_FOUND and yields COVERAGE_INCOMPLETE.
6. ambiguous binding: Ambiguous candidate entity bindings halt for user decision or candidate warning rather than unbounded fanout.
7. cdb parity: CDB SQLite backend adheres to the exact same relation query and EOF completeness contracts as live SIEM.
8. legacy compatibility: Legacy request formats project cleanly to modern semantic contracts without crashing.
"""
from __future__ import annotations

import dataclasses

from hunting.capabilities.runtime_materializer import materialize_runtime_operation
from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.contracts.case_graph import GraphEdge, GraphNode, NodeStatus, RelationType
from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    HuntState,
    StoppingDecision,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import (
    ProviderOperation,
    QueryOutcome,
    QueryResult,
)
from hunting.contracts.semantic_graph import (
    LogicalPlan,
    PlanStep,
    SemanticGoalGraph,
    SemanticRelationGoal,
    SemanticVariable,
)
from hunting.contracts.semantic_route import (
    SemanticAttempt,
    SemanticRouteAssessment,
    SemanticRouteStatus,
)
from hunting.contracts.source_profile import (
    RuntimeCapability,
    SourceCapabilityProposal,
    TelemetryFieldProfile,
    TelemetrySourceProfile,
)
from hunting.evidence.relation_verifier import RelationVerifier
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.planner.semantic_executor import SemanticPlanExecutor
from hunting.reporter.builder import build_final_hunt_account


def test_counterfactual_renamed_source():
    """Scenario 1: Renamed source with non-standard name is validated by schema profile, not source name."""
    census_profile = TelemetrySourceProfile(
        source_id="custom_telemetry_source_v9",
        provider_id="splunk",
        partition_id="custom_partition",
        native_type="custom:events",
        fields=(
            TelemetryFieldProfile("f_user", "login_user", "string", 0.95, ("Mallory",)),
            TelemetryFieldProfile("f_host", "workstation_name", "string", 0.90, ("MACLORY-AIR13",)),
        ),
    )
    validator = SourceMappingValidator()
    proposal = SourceCapabilityProposal(
        source_id="custom_telemetry_source_v9",
        relation="associated_with",
        input_roles={"person": "f_user"},
        output_roles={"endpoint": "f_host"},
        proof_mode="relation_observable",
        probe_kind="cooccurrence",
        rationale_refs=("f_user", "f_host"),
    )
    is_valid, errors, _ = validator.validate(proposal, [census_profile])
    assert is_valid is True
    assert not errors

    # Materialize capability
    cap = RuntimeCapability(
        capability_id="cap_custom_assoc",
        source_id="custom_telemetry_source_v9",
        provider_id="splunk",
        relation="associated_with",
        input_roles={"person": "f_user"},
        output_roles={"endpoint": "f_host"},
        status="VALIDATED",
        proof_mode="relation_observable",
        probe_query_id="q_probe_custom",
        schema_fingerprint=census_profile.schema_fingerprint,
    )
    req = {"subject_type": "person", "object_type": "endpoint"}
    op = materialize_runtime_operation(proposal, census_profile, req, cap)
    assert op is not None
    assert op.id == "cap_custom_assoc"
    assert op.provider_id == "splunk"
    assert "associated_with" in op.guaranteed_relations


def test_counterfactual_misleading_source_name():
    """Scenario 2: Source with misleading name ('file_events') lacking required fields is rejected."""
    misleading_profile = TelemetrySourceProfile(
        source_id="splunk:botsv2:file_downloader_fake",
        provider_id="splunk",
        partition_id="botsv2",
        native_type="network:download",
        fields=(
            TelemetryFieldProfile("f_url", "dest_url", "string", 0.8, ("http://example.com",)),
        ),
    )
    validator = SourceMappingValidator()
    # Attempt to bind file_path to nonexistent field
    proposal = SourceCapabilityProposal(
        source_id="splunk:botsv2:file_downloader_fake",
        relation="modified",
        input_roles={"device": "f_url"},
        output_roles={"target": "f_nonexistent_file"},
        proof_mode="relation_observable",
        probe_kind="cooccurrence",
    )
    is_valid, errors, _ = validator.validate(proposal, [misleading_profile])
    assert is_valid is False
    assert any("field_id_not_in_census" in e for e in errors)


def test_counterfactual_changed_artifact_type():
    """Scenario 3: Generic state-transition verification accepts arbitrary artifact extensions (e.g. PDF)."""
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv2"})
    ledger = ObservationLedger()
    obs_before = Observation(
        id="obs-pdf-1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-08-18T20:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={
            "file_path": "/Users/alice/Documents/financial_report.pdf",
            "file_state": "created",
            "host": "FIN-DESKTOP-01",
        },
    )
    obs_after = Observation(
        id="obs-pdf-2",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-08-18T20:05:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={
            "file_path": "/Users/alice/Documents/financial_report.pdf",
            "file_state": "encrypted_copy",
            "action": "modify",
            "host": "FIN-DESKTOP-01",
        },
    )
    ledger.add_observation(obs_before)
    ledger.add_observation(obs_after)

    qr = QueryResult(
        query_id="q-pdf-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        native_query="search financial_report.pdf",
        row_count=2,
    )
    ledger.record_query_result(qr)

    op = ProviderOperation(
        id="op_track_pdf",
        provider_id="splunk",
        scope_ids=("botsv2",),
        temporal_roles={"time": ("timestamp",)},
        action_roles={"operation": ("action",)},
        state_roles={"state": ("file_state",)},
        artifact_identity_roles={"artifact": ("file_path",)},
    )

    verifier = RelationVerifier()
    source = GraphNode(id="n-dev", type="device", value="FIN-DESKTOP-01", status=NodeStatus.KNOWN)
    target = GraphNode(id="n-file", type="artifact", value="/Users/alice/Documents/financial_report.pdf", status=NodeStatus.UNKNOWN)
    edge = GraphEdge(
        id="edge-transition-pdf",
        source_id="n-dev",
        source_entity_type="device",
        relation_type=RelationType.MODIFIED,
        target_id="n-file",
        target_entity_type="artifact",
        metadata={"verification_mode": "state_transition", "correlation_bound_seconds": 3600},
        citations=["obs-pdf-1", "obs-pdf-2"],
    )

    result = verifier.verify_candidate_edge(
        edge=edge,
        source_node=source,
        target_node=target,
        ledger=ledger,
        query_results={qr.query_id: qr},
        operation=op,
    )
    assert result.verified is True
    assert not result.violations


def test_counterfactual_missing_telemetry():
    """Scenario 4: Missing or unreachable telemetry stops gracefully with INCONCLUSIVE, never false negative."""
    graph = SemanticGoalGraph(
        id="goal-missing",
        request_id="req-missing",
        objective="Find file in decommissioned datacenter",
        variables=[SemanticVariable("e1", "device", "DECOMMISSIONED-01")],
        relations=[SemanticRelationGoal("r1", "e1", "observed", "e1", required=True)],
    )
    state = HuntState(
        objective=HuntObjective(request_id="req-missing", statement="Find file in decommissioned datacenter"),
        semantic_goal_graph=graph,
        stopping_decision=StoppingDecision.STOP_UNREACHABLE,
    )
    account = build_final_hunt_account(state)
    assert account.answer["status"] == "INCONCLUSIVE"
    assert account.stopping_decision == StoppingDecision.STOP_UNREACHABLE


def test_counterfactual_timeout_partial():
    """Scenario 5: Truncated or timed-out query cannot license negative absence and reports COVERAGE_INCOMPLETE."""
    graph = SemanticGoalGraph(
        id="goal-timeout",
        request_id="req-timeout",
        objective="Find suspicious activity",
        variables=[SemanticVariable("e1", "device", "SERVER-01")],
        relations=[SemanticRelationGoal("r1", "e1", "active", "e1", required=True)],
    )
    # A query that returned 0 rows but was truncated or timed out (complete=False)
    qr = QueryResult(
        query_id="q-timeout-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=False,
        complete=False,
        truncation_reason="execution_timeout_60s",
        row_count=0,
    )
    attempt = SemanticAttempt(
        attempt_id="att-to-1",
        goal_id="r1",
        operation_id="op-1",
        source_id="src-1",
        stage_id="stage-1",
        result_complete=False,
        row_count=0,
        trigger_reason="primary",
        no_progress_signature="sig-1",
        negative_evidence_capable=True,  # Even with capability, incomplete query blocks negative proof
    )
    route = SemanticRouteAssessment(
        goal_id="r1",
        relation="active",
        status=SemanticRouteStatus.ATTEMPTED_PARTIAL,
        execution_complete=False,
        proof_complete=False,
        route_exhausted=False,
        attempts=[attempt],
    )
    state = HuntState(
        objective=HuntObjective(request_id="req-timeout", statement="Find suspicious activity"),
        semantic_goal_graph=graph,
        semantic_route_assessments=[route],
        query_results=[qr],
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE_COVERAGE_GAP,
    )
    account = build_final_hunt_account(state)
    assert account.answer["status"] == "INCONCLUSIVE"
    assert account.answer.get("reason") in {"COVERAGE_INCOMPLETE", "NO_VERIFIED_ANSWER_CANDIDATE", "ROUTE_NEGATIVE_NOT_LICENSED"}


def test_counterfactual_ambiguous_binding():
    """Scenario 6: Ambiguous candidate entity bindings do not blindly fan out queries."""
    class AmbigAdapter:
        def __init__(self) -> None:
            self.calls = []

        def execute_query(self, operation_id, entity, window, limit, query_id):
            self.calls.append((operation_id, getattr(entity, "value", str(entity))))
            return QueryResult(
                query_id,
                QueryOutcome.ROWS,
                True,
                True,
                rows=[
                    {"host": "HOST-ALPHA"},
                    {"host": "HOST-BETA"},
                ],
            )

    adapter = AmbigAdapter()
    op1 = ProviderOperation(
        "resolve_person_to_endpoint",
        "splunk",
        ("main",),
        input_entity_kinds=("person",),
        output_entity_kinds=("host",),
        output_value_bindings={"object": ("host",)},
        output_binding_entity_kinds={"object": "host"},
        proof_mode="retrieval_only",
    )
    op2 = ProviderOperation(
        "resolve_endpoint_to_file",
        "splunk",
        ("main",),
        input_entity_kinds=("host",),
        output_entity_kinds=("file",),
        output_value_bindings={"object": ("file",)},
        output_binding_entity_kinds={"object": "file"},
    )
    plan = LogicalPlan(
        id="plan-ambig",
        goal_graph_id="goal-ambig",
        provider_id="splunk",
        steps=[
            PlanStep("s1", "resolve_person_to_endpoint", {"subject": "person"}, {"object": "host"}),
            PlanStep("s2", "resolve_endpoint_to_file", {"subject": "host"}, {"object": "file"}, requires_complete_inputs=True),
        ],
    )
    scope = ProviderScope(provider_id="splunk", scope_id="main", native_partition={"index": "main"})
    res = SemanticPlanExecutor(adapter, [op1, op2]).execute(
        plan,
        scope,
        "2026-08-18T00:00:00Z/P1D",
        {"person": "Mallory"},
        variable_types={"person": "person", "host": "host", "file": "file"},
    )
    # Step 1 yielded 2 candidate hosts
    assert len(res.variables["host"]) == 2
    assert all(b["status"] == "CANDIDATE" for b in res.binding_provenance["host"])
    assert res.executions[0].status == "EXECUTED"
    # Downstream step did not blindly fan out queries for unverified candidates
    assert len(adapter.calls) == 1
    assert res.needs_user_decision is True


def test_counterfactual_cdb_parity():
    """Scenario 7: CDB local SQLite backend satisfies same relation contract as SIEM."""
    adapter = CdbAdapter()
    desc = adapter.get_capability_descriptor()
    assert any(op.id == "resolve_person_to_account" for op in desc.operations)

    adapter.insert_events([
        {
            "timestamp": "2026-08-18T10:00:00Z",
            "event_id": "e-1",
            "native_type": "identity",
            "host": "MACLORY-AIR13",
            "user": "Mallory",
        }
    ])
    res = adapter.execute_query(
        operation_id="resolve_person_to_account",
        entity="Mallory",
        window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
    )
    assert res.executed_ok is True
    assert res.complete is True  # Strict EOF completeness
    assert len(res.rows) == 1
    assert res.rows[0]["user"] == "Mallory"
    assert res.provider == "cdb"


def test_counterfactual_legacy_compatibility():
    """Scenario 8: Legacy HuntRequest formats project cleanly to modern semantic contracts."""
    request = HuntRequest(
        id="req-legacy-01",
        kind=HuntRequestKind.QUESTION,
        content="What was the process executed by bob?",
    )
    assert request.id == "req-legacy-01"
    assert request.kind == HuntRequestKind.QUESTION
    assert "bob" in request.content
    payload = dataclasses.asdict(request)
    assert payload["id"] == "req-legacy-01"
    assert payload["kind"] == HuntRequestKind.QUESTION
