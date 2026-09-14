"""Unit tests for canonical OutcomeContract and GoalRuntimeState (Workstream B).

Acceptance Gate B requirements:
- all OutcomeContract variants serialize/deserialize;
- one goal cannot hold contradictory state axes;
- legacy stop aliases never appear in new run accounts;
- partial-empty classification test passes.
"""
import pytest

from hunting.contracts.hunt import StoppingDecision
from hunting.contracts.observation_class import (
    CoverageStatus,
    ExecutionStatus,
    ProofStatus,
    RouteStatus,
)
from hunting.contracts.outcome import (
    FactualAnswerContract,
    HypothesisVerdictContract,
    PopulationDiscoveryContract,
    outcome_contract_from_dict,
    outcome_contract_from_legacy_answer_contract,
)
from hunting.contracts.state import GoalRuntimeState


def test_outcome_contract_variants_serialize_and_deserialize():
    """All 3 OutcomeContract variants must serialize to dict and deserialize back identically."""
    # 1. FactualAnswerContract
    c1 = FactualAnswerContract(
        slots=("target_domain",),
        types={"target_domain": "domain"},
        cardinality={"target_domain": "singular"},
        qualifiers=("recent",),
        citations=("obs-1", "obs-2"),
    )
    d1 = c1.to_dict()
    assert d1["contract_kind"] == "FACTUAL_ANSWER"
    r1 = outcome_contract_from_dict(d1)
    assert isinstance(r1, FactualAnswerContract)
    assert r1.slots == ("target_domain",)
    assert r1.is_singular("target_domain")
    assert r1.citations == ("obs-1", "obs-2")

    # 2. HypothesisVerdictContract
    c2 = HypothesisVerdictContract(
        support_obligations=("lateral_movement_detected",),
        refutation_obligations=("authorized_admin_session",),
        falsification_conditions=("valid_ticket_granting_service",),
        scope="domain_controllers",
    )
    d2 = c2.to_dict()
    assert d2["contract_kind"] == "HYPOTHESIS_VERDICT"
    r2 = outcome_contract_from_dict(d2)
    assert isinstance(r2, HypothesisVerdictContract)
    assert r2.support_obligations == ("lateral_movement_detected",)
    assert r2.scope == "domain_controllers"

    # 3. PopulationDiscoveryContract
    c3 = PopulationDiscoveryContract(
        population_unit="endpoint_device",
        candidate_schema={"host": "string", "ip": "string"},
        prevalence_aggregation="count",
        coverage_requirement="EXHAUSTIVE",
    )
    d3 = c3.to_dict()
    assert d3["contract_kind"] == "POPULATION_DISCOVERY"
    r3 = outcome_contract_from_dict(d3)
    assert isinstance(r3, PopulationDiscoveryContract)
    assert r3.population_unit == "endpoint_device"
    assert r3.coverage_requirement == "EXHAUSTIVE"


def test_legacy_answer_contract_converter():
    """Compatibility converter turns legacy dicts/objects into FactualAnswerContract."""
    legacy_dict = {"variable_id": "resolved_ip", "answer_type": "ip"}
    contract = outcome_contract_from_legacy_answer_contract(legacy_dict)
    assert isinstance(contract, FactualAnswerContract)
    assert contract.slots == ("resolved_ip",)
    assert contract.types["resolved_ip"] == "ip"
    assert contract.is_singular("resolved_ip")


def test_goal_runtime_state_prohibits_contradictory_axes():
    """A goal cannot hold contradictory state axes (e.g. FAILED + PROVEN)."""
    # Valid state passes
    valid_state = GoalRuntimeState(
        goal_id="g1",
        execution_status=ExecutionStatus.EXECUTED,
        coverage_status=CoverageStatus.COMPLETE,
        proof_status=ProofStatus.VERIFIED,
        route_status=RouteStatus.ACTIVE,
    )
    assert valid_state.proof_status == ProofStatus.VERIFIED

    # FAILED execution cannot be PROVEN
    with pytest.raises(ValueError, match="cannot be PROVEN when execution FAILED"):
        GoalRuntimeState(
            goal_id="g2",
            execution_status=ExecutionStatus.FAILED,
            proof_status=ProofStatus.PROVEN,
        )

    # NOT_STARTED execution cannot be PROVEN
    with pytest.raises(ValueError, match="cannot be PROVEN when execution NOT_STARTED"):
        GoalRuntimeState(
            goal_id="g3",
            execution_status=ExecutionStatus.NOT_STARTED,
            proof_status=ProofStatus.PROVEN,
        )

    # PARTIAL coverage cannot license REJECTED proof (Decoupled TriStatus)
    with pytest.raises(ValueError, match="PARTIAL coverage cannot license REJECTED proof"):
        GoalRuntimeState(
            goal_id="g4",
            execution_status=ExecutionStatus.EXECUTED,
            coverage_status=CoverageStatus.PARTIAL,
            proof_status=ProofStatus.REJECTED,
        )


def test_stopping_decision_canonical_names_and_alias_mapping():
    """Legacy stop aliases map cleanly to canonical v9 enum values."""
    # Canonical v9 names
    assert StoppingDecision.STOP_ANSWERED.value == "STOP_ANSWERED"
    assert StoppingDecision.STOP_NOT_FOUND_BOUNDED.value == "STOP_NOT_FOUND_BOUNDED"
    assert StoppingDecision.STOP_NEEDS_CLARIFICATION.value == "STOP_NEEDS_CLARIFICATION"
    assert StoppingDecision.STOP_BUDGET.value == "STOP_BUDGET"

    # Legacy mapping during deserialization / migration
    assert StoppingDecision("STOP_RESOLVED").to_canonical_v9() == StoppingDecision.STOP_ANSWERED
    assert StoppingDecision("STOP_BOUNDED").to_canonical_v9() == StoppingDecision.STOP_NOT_FOUND_BOUNDED
    assert StoppingDecision("STOP_NEEDS_USER_DECISION").to_canonical_v9() == StoppingDecision.STOP_NEEDS_CLARIFICATION
    assert StoppingDecision("STOP_EXHAUSTED_BY_BUDGET").to_canonical_v9() == StoppingDecision.STOP_BUDGET
