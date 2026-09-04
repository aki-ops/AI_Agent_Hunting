"""Phase 0 — Canonical v4 Contract and Invariant Tests.

Verifies the 10 Phase 0 checklist items from 04-IMPLEMENTATION-CHECKLIST.md:
1. HuntRequest accepts hypothesis/TTP/IOC/CVE/CTI/NL question without alert.
2. HuntObjective, Hypothesis, EvidenceRequirement, Expectation and QueryPlan are distinct.
3. Cell(provider_scope, entity|ANY, time_bucket) has no event_family.
4. ProviderScope preserves native partition, retention and gaps.
5. ProviderOperation declares schema, pagination and completeness.
6. Observation preserves native type and nullable semantic type.
7. QueryResult.complete is explicit; row count never implies EOF.
8. UNKNOWN, INCONCLUSIVE, UNREACHABLE and UNSUPPORTED are distinct.
9. CoverageBound separates scope, requirement and unknown boundaries.
10. Only the Action Controller changes HuntState (HuntState is data only).
"""
from __future__ import annotations

import pytest

from hunting.contracts import (
    ANY,
    Cell,
    CoverageBound,
    Diagnostic,
    EpistemicType,
    EvidenceRequirement,
    EvidenceRequirementV4,
    Expectation,
    FieldOp,
    FieldPredicate,
    Host,
    HuntObjective,
    HuntOutcome,
    HuntRequest,
    HuntRequestKind,
    HuntState,
    Hypothesis,
    HypothesisOrigin,
    HypothesisStatus,
    Observation,
    ProviderOperation,
    ProviderScope,
    QueryOutcome,
    QueryPlan,
    QueryResult,
    RequirementCoverage,
    RequirementStatus,
    SemanticType,
    StoppingDecision,
    TestStatus,
    TimePolicy,
)


def test_1_hunt_request_without_alert():
    """1. HuntRequest accepts hypothesis/TTP/IOC/CVE/CTI/NL question without alert."""
    kinds = [
        (HuntRequestKind.CVE, "CVE-2024-21887 command injection"),
        (HuntRequestKind.TTP, "T1059.001 PowerShell execution"),
        (HuntRequestKind.IOC, "evil-c2.example.com"),
        (HuntRequestKind.HYPOTHESIS, "Lateral movement via WMI across finance subnet"),
        (HuntRequestKind.CTI_REPORT, "APT29 campaign advisory 2026-03"),
        (HuntRequestKind.NL_QUESTION, "Are any web servers running unauthorized processes?"),
        (HuntRequestKind.SCHEDULED, "Weekly persistence sweep"),
    ]

    for kind, content in kinds:
        req = HuntRequest(
            id=f"req-{kind.value.lower()}",
            kind=kind,
            content=content,
            time_policy=TimePolicy(lookback_days=30),
            provider_hints=["edr", "proxy"],
        )
        assert req.id.startswith("req-")
        assert req.kind == kind
        assert req.content == content
        assert req.time_policy.lookback_days == 30

    # Validation: empty id or content must fail
    with pytest.raises(ValueError, match="HuntRequest.id must not be empty"):
        HuntRequest(id="", kind=HuntRequestKind.CVE, content="CVE-2024-1234")

    with pytest.raises(ValueError, match="HuntRequest.content must not be empty"):
        HuntRequest(id="req-empty", kind=HuntRequestKind.CVE, content="")


def test_2_distinct_contract_types():
    """2. HuntObjective, Hypothesis, EvidenceRequirement, Expectation, QueryPlan are distinct."""
    obj = HuntObjective(
        request_id="req-001",
        target_hypotheses=["hypo-01"],
        time_window="2026-09-01T00:00:00Z/2026-09-04T00:00:00Z",
        target_scopes=["edr_scope"],
    )

    hypo = Hypothesis(
        id="hypo-01",
        statement="Adversary maintains persistence via scheduled task",
        origin=HypothesisOrigin.RULE,
        status=HypothesisStatus.LIVE,
        source_refs=["CVE-2024-21887"],
        requirements=["req-pers-01"],
    )

    er = EvidenceRequirementV4(
        id="req-pers-01",
        description="Detection of scheduled task creation with cmdline payload",
        evidence_type="persistence_change",
        entity_scope="ANY",
        predicate=FieldPredicate(field="task_name", op=FieldOp.CONTAINS, value="update"),
        falsification_condition="no task creation logged under healthy telemetry",
        status=RequirementStatus.VALIDATED,
    )

    exp = Expectation(
        id="exp-01",
        owner_explanation_id="hypo-01",
        evidence_requirement=EvidenceRequirement.PERSISTENCE_CHANGE,
        predicted_observation="task created on web server",
        entity_ref=Host("WEB-SRV-01"),
        field_predicate=FieldPredicate(field="task_name", op=FieldOp.CONTAINS, value="update"),
        provider_scope_id="edr_scope",
        time_window="2026-09-01T00:00:00Z/2026-09-04T00:00:00Z",
        falsification_condition="no task logged",
        test_status=TestStatus.UNTESTED,
    )

    qp = QueryPlan(
        id="qp-01",
        requirement_id="req-pers-01",
        provider_id="edr",
        scope_id="edr_scope",
        operation_id="edr_scheduled_tasks",
        parameters={"window": "14d"},
        estimated_cost=2,
        completeness_contract="complete",
    )

    # All 5 contracts have distinct types and schemas
    assert isinstance(obj, HuntObjective)
    assert isinstance(hypo, Hypothesis)
    assert isinstance(er, EvidenceRequirementV4)
    assert isinstance(exp, Expectation)
    assert isinstance(qp, QueryPlan)
    assert type(obj) is not type(hypo)
    assert type(hypo) is not type(er)
    assert type(er) is not type(exp)
    assert type(exp) is not type(qp)


def test_3_cell_has_no_event_family():
    """3. Cell(provider_scope, entity|ANY, time_bucket) has no event_family."""
    scope = ProviderScope(provider_id="edr", native_partition={"table": "process_events"})
    cell = Cell(provider_scope=scope, entity=ANY, time_bucket="2026-09-01")

    # Invariant check: Cell has no event_family attribute
    assert not hasattr(cell, "event_family")
    assert cell.is_wildcard is True

    # Empty time bucket must fail
    with pytest.raises(ValueError, match="time_bucket must not be empty"):
        Cell(provider_scope=scope, entity=ANY, time_bucket="")


def test_4_provider_scope_native_partition_and_gaps():
    """4. ProviderScope preserves native partition, retention and gaps."""
    scope = ProviderScope(
        provider_id="splunk",
        scope_id="splunk_win_sysmon",
        native_partition={"index": "windows", "sourcetype": "xmlwineventlog"},
        coverage_start="2026-01-01T00:00:00Z",
        coverage_end=None,
        retention_days=90,
        known_gaps=({"start": "2026-06-01T00:00:00Z", "end": "2026-06-02T00:00:00Z", "reason": "indexer maintenance"},),
    )

    assert scope.provider_id == "splunk"
    assert scope.native_partition["index"] == "windows"
    assert scope.retention_days == 90
    assert len(scope.known_gaps) == 1
    assert scope.known_gaps[0]["reason"] == "indexer maintenance"

    with pytest.raises(ValueError, match="provider_id must not be empty"):
        ProviderScope(provider_id="", native_partition={"table": "events"})

    with pytest.raises(ValueError, match="native_partition must not be empty"):
        ProviderScope(provider_id="p1", native_partition={})


def test_5_provider_operation_schema_pagination_completeness():
    """5. ProviderOperation declares schema, pagination and completeness."""
    op = ProviderOperation(
        id="query_auth_events",
        provider_id="edr",
        scope_ids=("edr_scope_a", "edr_scope_b"),
        params_schema={"user": "string", "window": "interval"},
        pagination="cursor",
        limit_semantics="complete only when EOF is established",
    )

    assert op.id == "query_auth_events"
    assert op.pagination == "cursor"
    assert "EOF" in op.limit_semantics
    assert "user" in op.params_schema


def test_6_observation_preserves_native_and_nullable_semantic():
    """6. Observation preserves native type and nullable semantic type."""
    scope = ProviderScope(provider_id="suricata", native_partition={"stream": "eve.json"})

    # Case A: Unknown native event without semantic mapping
    obs_unmapped = Observation(
        id="obs-001",
        provider_scope=scope,
        cell_id="bucket-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="http_custom_header_anomaly",
        semantic_type=None,
        fields={"header_len": 4096},
    )

    assert obs_unmapped.native_type == "http_custom_header_anomaly"
    assert obs_unmapped.semantic_type is None
    assert obs_unmapped.is_unmapped is True

    # Case B: Observation with semantic mapping
    obs_mapped = Observation(
        id="obs-002",
        provider_scope=scope,
        cell_id="bucket-1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="dns_request",
        semantic_type=SemanticType(vocabulary="ocsf", value="dns_activity"),
        fields={"query": "test.corp"},
    )

    assert obs_mapped.is_unmapped is False
    assert obs_mapped.semantic_type.value == "dns_activity"


def test_7_query_result_explicit_completeness():
    """7. QueryResult.complete is explicit; row count never implies EOF."""
    res_truncated = QueryResult(
        query_id="q-001",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=False,  # Truncated query
        diagnostic=Diagnostic.PARTIAL_RESULT,
    )

    res_complete_empty = QueryResult(
        query_id="q-002",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,  # EOF reached
        rows=[],
    )

    assert res_truncated.complete is False
    assert res_complete_empty.complete is True
    # Zero rows on truncated query cannot be negative
    assert res_truncated.complete is not True


def test_8_distinct_epistemic_and_diagnostic_types():
    """8. UNKNOWN, INCONCLUSIVE, UNREACHABLE and UNSUPPORTED are distinct."""
    # Outcomes:
    assert HuntOutcome.UNKNOWN != HuntOutcome.INCONCLUSIVE
    assert HuntOutcome.INCONCLUSIVE != HuntOutcome.UNREACHABLE
    assert HuntOutcome.SUPPORTED != HuntOutcome.CONTRADICTED

    # Diagnostics:
    assert Diagnostic.UNSUPPORTED_REQUIREMENT != Diagnostic.UNQUERYABLE
    assert Diagnostic.UNQUERYABLE != Diagnostic.SOURCE_UNAVAILABLE
    assert Diagnostic.PARTIAL_RESULT != Diagnostic.QUERY_FAILED

    # Requirements:
    assert RequirementStatus.UNSUPPORTED != RequirementStatus.REJECTED
    assert RequirementStatus.VALIDATED != RequirementStatus.PROPOSED


def test_9_coverage_bound_separates_dimensions():
    """9. CoverageBound separates scope, requirement and unknown boundaries."""
    cb = CoverageBound(
        known_cells_wildcard=10,
        explored_cells_wildcard=8,
        partial_cells_wildcard=1,
        unexplored_cells_wildcard=1,
        unqueryable_cells_wildcard=2,
        unreachable_cells_wildcard=1,
        known_cells_instance=50,
        explored_cells_instance=40,
        partial_cells_instance=5,
        unexplored_cells_instance=5,
        scopes_never_queried=["cloudtrail"],
        unknown_sources=["unrecognized_syslog"],
        unmapped_observations=12,
        requirement_coverage=RequirementCoverage(
            attempted_requirements=["process_ancestry", "dns_activity"],
            satisfied_requirements=["process_ancestry"],
            partial_requirements=[],
            unsupported_requirements=["dns_activity"],
        ),
    )

    # Scopes vs instances are strictly separate
    assert cb.known_cells_wildcard == 10
    assert cb.known_cells_instance == 50
    # Requirements accounted separately
    assert cb.requirement_coverage.total_attempted == 2
    assert cb.requirement_coverage.total_satisfied == 1
    # Unknown source reported outside denominator
    assert "unrecognized_syslog" in cb.unknown_sources
    assert cb.unmapped_observations == 12


def test_10_hunt_state_is_data_only():
    """10. Only the Action Controller changes HuntState (HuntState is data only)."""
    obj = HuntObjective(request_id="req-hunt-01")
    state = HuntState(objective=obj)

    # Assert HuntState has data fields
    assert state.objective == obj
    assert state.hypotheses == []
    assert state.stopping_decision is None

    # Assert HuntState does NOT have action execution methods (Controller authority)
    assert not hasattr(state, "step")
    assert not hasattr(state, "execute_action")
    assert not hasattr(state, "stop")
    assert not hasattr(state, "decide_disposition")

    # Stopping decisions are distinct
    assert StoppingDecision.STOP_RESOLVED != StoppingDecision.STOP_BOUNDED
    assert StoppingDecision.STOP_BOUNDED != StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
