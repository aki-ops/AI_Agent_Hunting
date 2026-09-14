"""Workstream G: Integrated Controller Agenda Loop Tests.

Acceptance gate G:
- code search finds one production agenda loop and one stop authority;
- all query attempts have an ObservationClass and next-action reason;
- repeated no-delta actions terminate deterministically;
- partial, ambiguity, proof gap, budget and backend failure reach distinct stops.
"""

from hunting.contracts.hunt import StoppingDecision
from hunting.contracts.observation_class import (
    ActionSignature,
    ControllerAttempt,
    CoverageStatus,
    ExecutionStatus,
    ObservationClass,
    ProofStatus,
    RouteStatus,
    TriStatus,
)
from hunting.contracts.outcome import (
    FactualAnswerContract,
    HypothesisVerdictContract,
)
from hunting.contracts.proof_contract import ProofResult
from hunting.contracts.queries import QueryOutcome, QueryResult
from hunting.contracts.search_envelope import BudgetEnvelope, SearchEnvelope
from hunting.controller.loop_guard import LoopGuard
from hunting.controller.models import HuntBudgetLedger
from hunting.controller.recovery_controller import RecoveryController
from hunting.evidence.outcome_verifier import OutcomeVerifier


def test_query_result_complete_false_rows_empty_is_partial() -> None:
    """Counterexample 6: QueryResult(complete=False, rows=[]) is PARTIAL.

    Under the decoupled TriStatus invariant:
    PARTIAL + 0 rows != BOUNDED_NOT_FOUND.
    When a query has complete=False and 0 rows (e.g. timeout or truncated scan),
    it MUST be classified as PARTIAL, never EMPTY.
    """
    controller = RecoveryController()

    incomplete_empty_result = QueryResult(
        query_id="q-timeout-1",
        outcome=QueryOutcome.UNKNOWN,
        executed_ok=True,
        complete=False,  # Truncated or incomplete!
        rows=[],  # 0 rows returned
        row_count=0,
    )

    obs_class = controller.classify(
        attempt=incomplete_empty_result,
        proof_contract=None,
    )
    assert obs_class == ObservationClass.PARTIAL, (
        f"Incomplete query with 0 rows must be PARTIAL, got {obs_class}"
    )

    from hunting.contracts.state import GoalRuntimeState

    goal_state = GoalRuntimeState(
        goal_id="goal-timeout-test",
        execution_status=ExecutionStatus.OK,
        coverage_status=CoverageStatus.PARTIAL,
        proof_status=ProofStatus.UNPROVEN,
        route_status=RouteStatus.PROGRESS,
    )
    assert goal_state.coverage_status == CoverageStatus.PARTIAL

    tristatus = TriStatus(
        execution_complete=False,
        proof_complete=False,
        route_exhausted=False,
    )
    assert not tristatus.is_bounded_not_found(negative_license_granted=True), (
        "0 rows with incomplete scan is NOT bounded not found"
    )


def test_stop_answered_impossible_before_outcome_verification() -> None:
    """Counterexample 7: STOP_ANSWERED is impossible before outcome verification.

    The controller must emit canonical v9 StoppingDecision.STOP_ANSWERED ONLY after
    outcome verification has verified all required slots.
    When outcome_verified is False, evaluate_stop must NOT return STOP_ANSWERED.
    """
    controller = RecoveryController()

    # 1. When outcome_verified is False, STOP_ANSWERED is impossible even if relations matched
    stop_decision_unverified = controller.evaluate_stop(
        obligations=["goal-1"],
        verified_obligations=["goal-1"],
        coverage=CoverageStatus.COMPLETE,
        contradictions=[],
        budgets=None,
        outcome_verified=False,
    )
    assert stop_decision_unverified != StoppingDecision.STOP_ANSWERED
    assert stop_decision_unverified == StoppingDecision.STOP_INCONCLUSIVE

    # 2. When outcome_verified is True, canonical STOP_ANSWERED is emitted
    stop_decision_verified = controller.evaluate_stop(
        obligations=["goal-1"],
        verified_obligations=["goal-1"],
        coverage=CoverageStatus.COMPLETE,
        contradictions=[],
        budgets=None,
        outcome_verified=True,
    )
    assert stop_decision_verified == StoppingDecision.STOP_ANSWERED


def test_canonical_attempt_adapter_unifies_fields() -> None:
    """G1: Canonical attempt adapter unifies QueryResult, candidate delta, and ProofResult."""
    qr = QueryResult(
        query_id="q-42",
        outcome=QueryOutcome.UNKNOWN,
        executed_ok=True,
        complete=True,
        rows=[{"user": "alice", "host": "workstation-1"}],
        row_count=1,
    )
    pr = ProofResult(
        verified=True,
        evaluator_id="eval.relation.v1",
        evaluator_version="1.0",
        citations=("obs-1",),
    )
    cands = [{"role": "user", "value": "alice"}]

    attempt = ControllerAttempt.from_result(
        query_result=qr,
        candidate_delta=cands,
        proof_result=pr,
        operation_id="find_user_login",
        source_id="edr_provider",
    )

    assert attempt.query_id == "q-42"
    assert attempt.executed_ok is True
    assert attempt.complete is True
    assert attempt.row_count == 1
    assert attempt.proof_conforming is True
    assert attempt.candidate_delta == cands

    controller = RecoveryController()
    obs_class = controller.classify(attempt)
    assert obs_class == ObservationClass.VERIFIED


def test_deterministic_triad_and_next_action_reasons() -> None:
    """G2: Every attempt passes through classify -> choose_next_action with typed reasons."""
    controller = RecoveryController()
    loop_guard = LoopGuard()
    envelope = SearchEnvelope(budgets=BudgetEnvelope(max_queries=10))

    # Test several classification rungs and ensure each has a typed next-action reason
    for qr, expected_class, expected_action in [
        (
            QueryResult(query_id="q-fail", outcome=QueryOutcome.UNKNOWN, executed_ok=False, complete=False),
            ObservationClass.QUERY_FAILURE,
            "REPAIR_QUERY",
        ),
        (
            QueryResult(query_id="q-part", outcome=QueryOutcome.UNKNOWN, executed_ok=True, complete=False, rows=[]),
            ObservationClass.PARTIAL,
            "PAGINATE",
        ),
        (
            QueryResult(query_id="q-empty", outcome=QueryOutcome.UNKNOWN, executed_ok=True, complete=True, rows=[], row_count=0),
            ObservationClass.EMPTY,
            "RELAX_HINT",
        ),
    ]:
        attempt = ControllerAttempt.from_result(query_result=qr)
        obs_class = controller.classify(attempt, envelope=envelope)
        assert obs_class == expected_class

        next_action = controller.choose_next_action(
            classification=obs_class,
            envelope=envelope,
            loop_guard=loop_guard,
        )
        assert next_action.action_type == expected_action
        assert len(next_action.reason) > 0, "Next action reason must not be empty"


def test_loop_guard_repeated_no_delta_terminates_deterministically() -> None:
    """G5: Repeated no-delta actions increment stalls and terminate deterministically."""
    loop_guard = LoopGuard(max_consecutive_stalls=2)
    sig = ActionSignature.from_params(
        goal_id="g-1",
        op_id="search_process",
        scope="edr_scope",
        source_id="edr",
        stage="TEST",
        bindings={"host": "host-a"},
        time_window="2026-01-01T00:00:00Z/P1D",
    )

    # Turn 1: First execution is considered initial material progress
    delta_1 = loop_guard.record_action(
        signature=sig,
        turn_index=1,
        rows_count=0,
        new_candidates_count=0,
        result_payload=[],
    )
    assert delta_1 is True
    assert not loop_guard.is_stalled(sig)

    # Turn 2: Repeated identical empty result -> no material progress (stall 1)
    delta_2 = loop_guard.record_action(
        signature=sig,
        turn_index=2,
        rows_count=0,
        new_candidates_count=0,
        result_payload=[],
    )
    assert delta_2 is False
    assert not loop_guard.is_stalled(sig)
    assert loop_guard.consecutive_stalls[sig.compute_hash()] == 1

    # Turn 3: Repeated identical empty result -> stall 2 (reaches max_consecutive_stalls)
    delta_3 = loop_guard.record_action(
        signature=sig,
        turn_index=3,
        rows_count=0,
        new_candidates_count=0,
        result_payload=[],
    )
    assert delta_3 is False
    assert loop_guard.is_stalled(sig)
    assert loop_guard.is_route_exhausted("edr", "search_process")


def test_distinct_stopping_decisions() -> None:
    """G2 & Gate G: Partial, ambiguity, proof gap, budget, and backend failure reach distinct stops."""
    controller = RecoveryController()

    # 1. Budget exhausted -> STOP_BUDGET
    ledger = HuntBudgetLedger(max_queries=5, query_count=5)
    stop_budget = controller.evaluate_stop(
        obligations=["g-1"],
        verified_obligations=[],
        coverage=CoverageStatus.PARTIAL,
        contradictions=[],
        budgets=ledger,
    )
    assert stop_budget == StoppingDecision.STOP_BUDGET

    # 2. Clarification / ambiguity -> STOP_NEEDS_CLARIFICATION
    stop_clarify = controller.evaluate_stop(
        obligations=["g-1"],
        verified_obligations=[],
        coverage=CoverageStatus.PARTIAL,
        contradictions=[],
        budgets=None,
        needs_clarification=True,
    )
    assert stop_clarify == StoppingDecision.STOP_NEEDS_CLARIFICATION

    # 3. Backend failure / unreachable -> STOP_UNREACHABLE
    stop_unreach = controller.evaluate_stop(
        obligations=["g-1"],
        verified_obligations=[],
        coverage=CoverageStatus.UNREACHABLE,
        contradictions=[],
        budgets=None,
        unreachable=True,
    )
    assert stop_unreach == StoppingDecision.STOP_UNREACHABLE

    # 4. Unsupported capability -> STOP_UNSUPPORTED
    stop_unsup = controller.evaluate_stop(
        obligations=["g-1"],
        verified_obligations=[],
        coverage=CoverageStatus.COMPLETE,
        contradictions=[],
        budgets=None,
        unsupported=True,
    )
    assert stop_unsup == StoppingDecision.STOP_UNSUPPORTED

    # 5. Bounded negative with license -> STOP_NOT_FOUND_BOUNDED
    stop_bounded_neg = controller.evaluate_stop(
        obligations=["g-1"],
        verified_obligations=[],
        coverage=CoverageStatus.COMPLETE,
        contradictions=[],
        budgets=None,
        routes_exhausted=True,
        negative_license_granted=True,
    )
    assert stop_bounded_neg == StoppingDecision.STOP_NOT_FOUND_BOUNDED

    # 6. Unproven / proof gap -> STOP_INCONCLUSIVE
    stop_inconclusive = controller.evaluate_stop(
        obligations=["g-1"],
        verified_obligations=[],
        coverage=CoverageStatus.COMPLETE,
        contradictions=[],
        budgets=None,
    )
    assert stop_inconclusive == StoppingDecision.STOP_INCONCLUSIVE


def test_outcome_verifier_factual_and_hypothesis() -> None:
    """G4: OutcomeVerifier strictly checks slots, cardinality, and hypothesis obligations."""
    # 1. FactualAnswerContract: Missing slot fails verification
    contract_factual = FactualAnswerContract(
        slots=("version", "host"),
        cardinality={"version": "singular", "host": "singular"},
    )
    res_missing = OutcomeVerifier.verify(
        contract=contract_factual,
        bound_variables={"host": "macbook-1"},  # version is missing!
        coverage_complete=True,
    )
    assert not res_missing.verified
    assert "version" in res_missing.missing_slots

    # 2. FactualAnswerContract: Singular slot with multiple candidates -> AMBIGUOUS
    res_ambiguous = OutcomeVerifier.verify(
        contract=contract_factual,
        bound_variables={"host": "macbook-1", "version": ["12.0.1", "12.0.2"]},
        coverage_complete=True,
    )
    assert not res_ambiguous.verified
    assert res_ambiguous.status == "AMBIGUOUS"

    # 3. FactualAnswerContract: Verified single slot with citation
    class MockObs:
        id = "obs-101"

    res_ok = OutcomeVerifier.verify(
        contract=contract_factual,
        bound_variables={"host": "macbook-1", "version": "12.0.1"},
        observations=[MockObs()],
        coverage_complete=True,
    )
    assert res_ok.verified
    assert res_ok.status == "ANSWERED"
    assert res_ok.slot_values["version"] == "12.0.1"
    assert "obs-101" in res_ok.citations

    # 4. HypothesisVerdictContract: Support obligations check
    contract_hyp = HypothesisVerdictContract(
        support_obligations=("goal-download", "goal-exec"),
        refutation_obligations=("goal-clean-baseline",),
    )
    res_hyp_unmet = OutcomeVerifier.verify(
        contract=contract_hyp,
        verified_goals=["goal-download"],  # goal-exec unverified
    )
    assert not res_hyp_unmet.verified
    assert res_hyp_unmet.status == "NOT_FOUND"

    res_hyp_ok = OutcomeVerifier.verify(
        contract=contract_hyp,
        verified_goals=["goal-download", "goal-exec"],
    )
    assert res_hyp_ok.verified
    assert res_hyp_ok.status == "SUPPORTED"

    res_hyp_refuted = OutcomeVerifier.verify(
        contract=contract_hyp,
        verified_goals=["goal-download", "goal-exec", "goal-clean-baseline"],
    )
    assert res_hyp_refuted.verified
    assert res_hyp_refuted.status == "REFUTED"
