"""Comprehensive unit test suite for architectural overhaul invariants (Phases 0-9).

Verifies:
1. Empty query attempt (0 rows) is recorded in state, queries, and execution audit.
2. SourceCard conversion from real TelemetrySourceProfile with missing optional fields does not crash.
3. ProofContract strictly rejects cooccurrence, DNS + person, generic process -> ransomware, email -> role.
4. CandidateSet strictly prevents arbitrary candidate picking (anti-heuristics, 'air', candidates[0]).
5. StepTrace records full hunt lifecycle Steps A through J.
6. Partitioned LLM budgeting enforces component-level limits.
"""
from __future__ import annotations

import pytest

from hunting.capabilities.catalog_index import CatalogIndex
from hunting.capabilities.frontier import ProgressiveFrontier
from hunting.capabilities.source_card_store import SourceCard, SourceCardStore
from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.capabilities.source_profiler import SourceProfiler
from hunting.contracts.bindings import (
    BindingDirectness,
    CandidateBinding,
    CandidateSet,
    ConfidenceClass,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.proof_contract import ProofContract, ProofContractStatus
from hunting.contracts.queries import (
    ProviderOperation,
    QueryAttempt,
    QueryOutcome,
    QueryResult,
)
from hunting.contracts.semantic_graph import LogicalPlan, PlanStep
from hunting.contracts.semantic_route import SemanticRouteStatus
from hunting.contracts.source_profile import (
    SourceCapabilityProposal,
    TelemetryFieldProfile,
    TelemetrySourceProfile,
)
from hunting.contracts.step_trace import HuntStepName, StepTrace
from hunting.controller.cost import LLMUsageTracker
from hunting.evidence.relation_verifier import verify_relation_proof_contract
from hunting.human_loop.clarification import ClarificationController, DisambiguationAction
from hunting.planner.semantic_executor import SemanticPlanExecutor


class MockAdapter:
    """Mock provider adapter returning controlled query results."""

    def __init__(self, result: QueryResult) -> None:
        self._result = result
        self.executed_queries: list[dict] = []

    def execute_query(self, **kwargs) -> QueryResult:
        self.executed_queries.append(dict(kwargs))
        return self._result


def test_empty_query_attempt_recorded_in_executions_and_attempts():
    """Phase 0/1 invariant: Complete-empty query (0 rows) MUST produce QueryAttempt and StepExecution."""
    empty_result = QueryResult(
        query_id="query-empty-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[],
        row_count=0,
    )
    adapter = MockAdapter(empty_result)
    op = ProviderOperation(
        id="op-test",
        provider_id="splunk",
        scope_ids=("scope-default",),
        guaranteed_relations=("associated_with",),
        input_entity_kinds=("person",),
        output_binding_entity_kinds={"endpoint": "host"},
        output_value_bindings={"endpoint": ("host",)},
        proof_mode="retrieval_only",
        runtime_source_id="src-test",
    )
    plan = LogicalPlan(
        id="plan-1",
        goal_graph_id="gg-1",
        provider_id="splunk",
        steps=[
            PlanStep(
                id="step-1",
                operation_id="op-test",
                relation="associated_with",
                input_bindings={"person": "person_1"},
                output_bindings={"endpoint": "host_1"},
                advances_goal_ids=("goal-1",),
            ),
        ],
    )
    scope = ProviderScope("splunk", {"index": "default"}, scope_id="scope-default")
    executor = SemanticPlanExecutor(adapter, [op])

    result = executor.execute(
        plan,
        scope,
        time_window="2026-02-01T00:00:00Z/P1D",
        initial_variables={"person_1": "Alice"},
    )

    # Invariant: QueryAttempt must be recorded
    assert len(result.query_attempts) == 1
    attempt = result.query_attempts[0]
    assert isinstance(attempt, QueryAttempt)
    assert attempt.query_id == "query-empty-1"
    assert attempt.goal_id == "goal-1"
    assert attempt.step_id == "step-1"
    assert attempt.status == "COMPLETE_EMPTY"
    assert attempt.evidence_eligible is False
    assert attempt.proof_eligible is False

    # Invariant: StepExecution must also be retained in executions for audit recording
    assert len(result.executions) == 1
    exec_record = result.executions[0]
    assert exec_record.step_id == "step-1"
    assert exec_record.status == "COMPLETE_EMPTY"
    assert exec_record.outputs == {}
    assert exec_record.goal_id == "goal-1"


def test_source_card_derived_from_real_telemetry_source_profile():
    """Phase 2 invariant: SourceCard derivation from TelemetrySourceProfile handles real fields safely."""
    fields = (
        TelemetryFieldProfile(
            field_id="f1",
            name="host",
            primitive_type="string",
            coverage=0.95,
            sample_values=("SRV-01", "WS-10"),
        ),
        TelemetryFieldProfile(
            field_id="f2",
            name="user",
            primitive_type="string",
            coverage=0.88,
            sample_values=("Alice", "Bob"),
        ),
    )
    profile = TelemetrySourceProfile(
        source_id="src-wineventlog",
        provider_id="splunk",
        partition_id="index-main",
        native_type="XmlWinEventLog:Security",
        event_count=100000,
        fields=fields,
    )

    card = SourceCard.from_telemetry_source_profile(profile, provider_id="splunk", scope="enterprise")

    assert card.source_id == "src-wineventlog"
    assert card.provider_id == "splunk"
    assert card.scope == "enterprise"
    assert card.event_count == 100000
    assert len(card.fields) == 2
    assert card.parser_version == "v1"
    assert card.provenance == "census"
    assert bool(card.schema_fingerprint)

    sketch_host = next(f for f in card.fields if f.name == "host")
    assert sketch_host.field_type == "string"
    assert sketch_host.null_fraction == pytest.approx(0.05, abs=1e-4)
    assert "SRV-01" in sketch_host.sample_values


def test_proof_contract_rejects_cooccurrence_and_false_inferences():
    """Phase 3 invariant: Epistemic proof rejects cooccurrence, DNS+person, generic process->ransomware."""
    scope = ProviderScope("splunk", "default")
    dns_obs = Observation(
        id="obs-dns-1",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-02-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="stream:dns",
        fields={"query": "competitor.com", "user": "Alice", "host": "WS-01", "sourcetype": "stream:dns"},
        raw_event={},
        query_id="q1",
    )

    contract_visit = ProofContract(
        contract_id="proof-visit-v1",
        version="1.0.0",
        relation="visited_domain",
        required_entity_roles=("endpoint",),
        required_value_roles=("domain",),
        status=ProofContractStatus.APPROVED,
    )

    res_dns = verify_relation_proof_contract(contract_visit, [dns_obs])
    assert res_dns.verified is False
    assert res_dns.diagnostic == "dns_lookup_cannot_prove_web_visit"

    # Invariant 2: Generic file creation / process cannot prove ransomware encryption
    file_obs = Observation(
        id="obs-file-1",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-02-01T12:05:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="sysmon",
        fields={"EventCode": "11", "TargetFilename": "report.pptx", "action": "created"},
        raw_event={},
        query_id="q2",
    )
    contract_ransom = ProofContract(
        contract_id="proof-ransomware-v1",
        version="1.0.0",
        relation="ransomware_encrypted_file",
        required_entity_roles=("source_artifact",),
        required_value_roles=("target_artifact",),
        status=ProofContractStatus.APPROVED,
    )
    res_ransom = verify_relation_proof_contract(contract_ransom, [file_obs])
    assert res_ransom.verified is False
    assert res_ransom.diagnostic == "file_creation_does_not_prove_ransomware_encryption"

    # Invariant 3: Domain traffic does not prove domain ownership
    net_obs = Observation(
        id="obs-net-1",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-02-01T12:10:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="pan:traffic",
        fields={"site": "evil.com", "url": "evil.com/login", "user": "Mallory"},
        raw_event={},
        query_id="q3",
    )
    contract_owner = ProofContract(
        contract_id="proof-owner-v1",
        version="1.0.0",
        relation="owns_domain",
        required_entity_roles=("person",),
        required_value_roles=("domain",),
        status=ProofContractStatus.APPROVED,
    )
    res_owner = verify_relation_proof_contract(contract_owner, [net_obs])
    assert res_owner.verified is False
    assert res_owner.diagnostic == "domain_event_does_not_prove_ownership"

    # Invariant 4: Email address transaction does not prove person is CEO or holds title
    mail_obs = Observation(
        id="obs-mail-1",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-02-01T12:15:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="ms:o365",
        fields={"sender": "ceo@company.com", "recipient": "hr@company.com", "subject": "All Hands"},
        raw_event={},
        query_id="q4",
    )
    contract_title = ProofContract(
        contract_id="proof-title-v1",
        version="1.0.0",
        relation="is_ceo",
        required_entity_roles=("person",),
        required_value_roles=("role",),
        status=ProofContractStatus.APPROVED,
    )
    res_title = verify_relation_proof_contract(contract_title, [mail_obs])
    assert res_title.verified is False
    assert res_title.diagnostic == "email_does_not_prove_title"


def test_candidate_set_anti_heuristics_multiple_candidates_require_disambiguation():
    """Phase 4/5 invariant: Multi-candidate ambiguity must not auto-bind by substring (e.g. 'air') or position."""
    cset = CandidateSet(variable_id="host_var", entity_type="host")

    c1 = CandidateBinding(
        value="MACBOOK-AIR-13",
        entity_type="host",
        supporting_fact_ids=("fact-1",),
        relation_contract_id="proof-person-endpoint-v1",
        directness=BindingDirectness.DIRECT.value,
        contradictions=(),
        confidence_class=ConfidenceClass.HIGH.value,
    )
    c2 = CandidateBinding(
        value="DESKTOP-WIN-01",
        entity_type="host",
        supporting_fact_ids=("fact-2",),
        relation_contract_id="proof-person-endpoint-v1",
        directness=BindingDirectness.DIRECT.value,
        contradictions=(),
        confidence_class=ConfidenceClass.HIGH.value,
    )

    cset.add_candidate(c1)
    cset.add_candidate(c2)

    assert cset.is_ambiguous is True
    assert cset.can_autobind is False

    binding = cset.try_autobind()
    assert binding is None
    assert cset.resolution_status == "NEEDS_DISAMBIGUATION"

    # Clarification controller checks
    controller = ClarificationController(interactive=False)
    action, payload = controller.resolve_candidate_set(cset, request_id="req-101")
    # In non-interactive mode, must synthesize discriminator query or halt with checkpoint
    assert action in (DisambiguationAction.DISCRIMINATE, DisambiguationAction.NEEDS_DISAMBIGUATION)


def test_step_trace_chronological_records_steps_a_through_j():
    """Phase 7 invariant: StepTrace records full hunt lifecycle Steps A through J."""
    trace = StepTrace(request_id="req-lifecycle-01")

    trace.record_step(HuntStepName.STEP_A_FREEZE_REQUEST, inputs_summary={"req": "req-lifecycle-01"})
    trace.record_step(HuntStepName.STEP_B_COMPILE_GOAL_GRAPH, outputs_summary={"goals": 2})
    trace.record_step(HuntStepName.STEP_C_RESOLVE_FRONTIER, outputs_summary={"sources": 3})
    trace.record_step(HuntStepName.STEP_D_BIND_CANDIDATES, outputs_summary={"bindings": 1})
    trace.record_step(HuntStepName.STEP_E_COMPILE_QUERY_INTENT, outputs_summary={"intents": 1})
    trace.record_step(HuntStepName.STEP_F_EXECUTE_NATIVE_QUERY, duration_ms=45.2)
    trace.record_step(HuntStepName.STEP_G_RECORD_OBSERVATIONS, outputs_summary={"observations": 5})
    trace.record_step(HuntStepName.STEP_H_VERIFY_PROOF, outputs_summary={"proofs": 1})
    trace.record_step(HuntStepName.STEP_I_CHECK_STOPPING, outputs_summary={"decision": "STOP_RESOLVED"})
    trace.record_step(HuntStepName.STEP_J_REPORT_AND_ACCOUNT, outputs_summary={"account_exported": True})

    assert len(trace.steps) == 10
    step_names = [s.step_name for s in trace.steps]
    expected_names = [
        "STEP_A_FREEZE_REQUEST",
        "STEP_B_COMPILE_GOAL_GRAPH",
        "STEP_C_RESOLVE_FRONTIER",
        "STEP_D_BIND_CANDIDATES",
        "STEP_E_COMPILE_QUERY_INTENT",
        "STEP_F_EXECUTE_NATIVE_QUERY",
        "STEP_G_RECORD_OBSERVATIONS",
        "STEP_H_VERIFY_PROOF",
        "STEP_I_CHECK_STOPPING",
        "STEP_J_REPORT_AND_ACCOUNT",
    ]
    assert step_names == expected_names
    d = trace.to_dict()
    assert d["step_count"] == 10


def test_partitioned_llm_budget_enforces_component_limits():
    """Phase 8 invariant: Component-partitioned LLM budget limits calls per component."""
    tracker = LLMUsageTracker(
        max_calls=5,
        max_total_tokens=15000,
        component_limits={"compiler": 2, "source_profiler": 1},
    )

    # First compiler call succeeds preflight
    pf1 = tracker.preflight("Compile request 1", component="compiler")
    assert pf1["component"] == "compiler"
    tracker.record_call(
        component="compiler",
        prompt="Compile request 1",
        response="{}",
        actual_prompt_tokens=100,
        actual_completion_tokens=50,
        model="stub",
    )

    # Second compiler call (repair) succeeds preflight
    pf2 = tracker.preflight("Repair request 1", component="compiler")
    assert pf2["component"] == "compiler"
    tracker.record_call(
        component="compiler",
        prompt="Repair request 1",
        response="{}",
        actual_prompt_tokens=100,
        actual_completion_tokens=50,
        model="stub",
    )


    # Third compiler call MUST be rejected by component budget limit
    assert tracker.is_component_exhausted("compiler") is True
    with pytest.raises(RuntimeError, match="budget exhausted for component 'compiler'"):
        tracker.preflight("Third compile attempt", component="compiler")


def test_fake_mapping_cooccurrence_strictly_clamped_to_retrieval():
    """P0 invariant: Cooccurrence probe and semantic field mismatches NEVER elevate to PROOF_CAPABLE."""
    profile = TelemetrySourceProfile(
        source_id="src-fake-1",
        provider_id="splunk",
        partition_id="default",
        native_type="wineventlog",
        fields=(
            TelemetryFieldProfile(field_id="query", name="query", primitive_type="string"),
            TelemetryFieldProfile(field_id="host", name="host", primitive_type="string"),
        ),
        event_count=100,
        schema_fingerprint="fp1",
    )

    validator = SourceMappingValidator()

    # Fake mapping: query -> person, host -> endpoint
    proposal = SourceCapabilityProposal(
        source_id="src-fake-1",
        relation="associated_with",
        input_roles={"person": "query"},
        output_roles={"endpoint": "host"},
        proof_mode="relation_observable",
        probe_kind="cooccurrence",
    )

    # Invariant 1: ProofContract itself rejects query -> person as semantically incompatible
    contract = validator.registry.get("proof-person-endpoint-v1")
    assert contract is not None
    ok, reasons = contract.validate_capability_conformance(
        relation="associated_with",
        input_roles={"person": "query"},
        output_roles={"endpoint": "host"},
    )
    assert ok is False
    assert any("native_field_semantically_incompatible" in r for r in reasons)

    # Invariant 2: Materialization of cooccurrence probe strictly clamps to RETRIEVAL_CAPABLE
    cap = validator.materialize(
        proposal,
        profile,
        probe_query_id="probe-q1",
        probe_succeeded=True,
    )
    assert cap.capability_level == "RETRIEVAL_CAPABLE"
    assert cap.proof_mode == "retrieval_only"
    assert cap.proof_contract_id is None
    assert "cooccurrence_probe_cannot_grant_proof" in cap.diagnostics


def test_progressive_frontier_unexamined_has_no_overlap_with_rejected():
    """P1 invariant: Rejected sources from scoring are never simultaneously reported as unexamined."""
    card_store = SourceCardStore()

    # High-relevance card
    card_good = SourceCard(
        source_id="source-good",
        provider_id="splunk",
        scope="default",
        field_roles={"person": "user", "endpoint": "dest_host"},
    )
    card_store.register_card(card_good)

    # Low-relevance card with no relevant roles
    card_low = SourceCard(
        source_id="source-low",
        provider_id="splunk",
        scope="default",
        field_roles={"metric_count": "count"},
    )
    card_store.register_card(card_low)

    catalog_index = CatalogIndex(card_store)
    frontier = ProgressiveFrontier(card_store, catalog_index, max_batch_cards=1)

    selected_cards, manifest = frontier.expand(
        relation="associated_with",
        required_roles=("person", "endpoint"),
    )

    # Selected must contain good source
    assert any(c.source_id == "source-good" for c in selected_cards)

    # Invariant: unexamined_source_ids and rejected_source_ids must NEVER overlap
    overlap = set(manifest.unexamined_source_ids) & set(manifest.rejected_source_ids.keys())
    assert overlap == set(), f"Found overlapping sources between unexamined and rejected: {overlap}"


def test_route_assessment_uses_goal_id_as_primary_key():
    """P1 invariant: Route assessments index strictly by goal_id and executed empty query has empty capability_gaps."""
    empty_result = QueryResult(
        query_id="q-empty-1",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[],
        row_count=0,
    )
    adapter = MockAdapter(empty_result)
    op = ProviderOperation(
        id="op-1",
        provider_id="splunk",
        scope_ids=("scope-default",),
        guaranteed_relations=("associated_with",),
        input_entity_kinds=("person",),
        output_binding_entity_kinds={"endpoint": "host"},
        output_value_bindings={"endpoint": ("host",)},
        proof_mode="retrieval_only",
        runtime_source_id="src-test",
    )
    plan = LogicalPlan(
        id="plan-1",
        goal_graph_id="gg-1",
        provider_id="splunk",
        steps=[
            PlanStep(
                id="step-1",
                operation_id="op-1",
                relation="associated_with",
                input_bindings={"person": "person_1"},
                output_bindings={"endpoint": "host_1"},
                advances_goal_ids=("goal-1",),
            ),
        ],
    )
    scope = ProviderScope("splunk", {"index": "default"}, scope_id="scope-default")
    executor = SemanticPlanExecutor(adapter, [op])

    result = executor.execute(
        plan,
        scope,
        time_window="2026-02-01T00:00:00Z/P1D",
        initial_variables={"person_1": "Alice"},
    )

    # Invariant: Route assessment is keyed by goal-1, not step-1
    assessments_by_goal = {a.goal_id: a for a in result.route_assessments}
    assert "goal-1" in assessments_by_goal
    assert "step-1" not in assessments_by_goal

    goal_assessment = assessments_by_goal["goal-1"]
    assert goal_assessment.status == SemanticRouteStatus.ATTEMPTED_EMPTY
    assert "no_provider_attempt" not in goal_assessment.capability_gaps


def test_source_profiler_malformed_output_audit_status():
    """P1 invariant: Malformed LLM output is safely handled and recorded as MALFORMED_OUTPUT."""
    # LLM returning malformed string lacking proposals[]
    def bad_llm(prompt: str) -> str:
        return '{"result": "missing_proposals_field"}'

    profiler = SourceProfiler(bad_llm)

    profile = TelemetrySourceProfile(
        source_id="src-1",
        provider_id="splunk",
        partition_id="default",
        native_type="wineventlog",
        fields=(),
        event_count=10,
        schema_fingerprint="fp1",
    )
    req = {"relation": "associated_with", "subject_type": "person", "object_type": "endpoint"}

    proposals, audit = profiler.propose([profile], [req])
    assert proposals == []
    assert audit["status"] == "MALFORMED_OUTPUT"
    assert audit["repair_status"] == "REPAIR_NOT_ATTEMPTED"

