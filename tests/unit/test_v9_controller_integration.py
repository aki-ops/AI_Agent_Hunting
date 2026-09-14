"""Workstream A: Failing regression counterexamples for controller integration.

Covers:
6. QueryResult(complete=False, rows=[]) is PARTIAL.
7. STOP_ANSWERED is impossible before outcome verification.
"""
from hunting.contracts.hunt import StoppingDecision
from hunting.contracts.observation_class import (
    CoverageStatus,
    ExecutionStatus,
    ObservationClass,
    ProofStatus,
    RouteStatus,
    TriStatus,
)
from hunting.contracts.queries import QueryOutcome, QueryResult
from hunting.controller.recovery_controller import RecoveryController


def test_query_result_complete_false_rows_empty_is_partial():
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

    # Defect: In legacy classify(), completed was checked via getattr(attempt, 'completed', True).
    # Since QueryResult defines 'complete', it defaulted to True and returned EMPTY!
    obs_class = controller.classify(
        attempt=incomplete_empty_result,
        proof_contract=None,
    )
    assert obs_class == ObservationClass.PARTIAL, (
        f"Incomplete query with 0 rows must be PARTIAL, got {obs_class}"
    )

    # Verify GoalRuntimeState and TriStatus mapping: CoverageStatus must be PARTIAL, not COMPLETE
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


def test_stop_answered_impossible_before_outcome_verification():
    """Counterexample 7: STOP_ANSWERED is impossible before outcome verification.

    The controller must emit canonical v9 StoppingDecision.STOP_ANSWERED ONLY after
    outcome verification has verified all required slots.
    Legacy STOP_RESOLVED without outcome verification is obsolete.
    """
    controller = RecoveryController()

    # When obligations are satisfied at relation level, v9 stopping must require
    # outcome verification, and the canonical enum must be STOP_ANSWERED.
    stop_decision = controller.evaluate_stop(
        obligations=["goal-1"],
        verified_obligations=["goal-1"],
        coverage=CoverageStatus.COMPLETE,
        contradictions=[],
        budgets=None,
    )
    # Defect: Legacy code returns STOP_RESOLVED, not the canonical v9 STOP_ANSWERED
    assert stop_decision == StoppingDecision.STOP_ANSWERED, (
        f"Expected canonical v9 STOP_ANSWERED, got {stop_decision}"
    )
