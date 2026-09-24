"""Unit tests for SearchEnvelope, ObservationClass, LoopGuard, and RecoveryController.

Verifies:
1. 8-rung ObservationClass classification ladder.
2. Invariant: PARTIAL + 0 rows != BOUNDED_NOT_FOUND.
3. SearchEnvelope immutability, monotonic narrowing, and versioned derivation.
4. Candidate fanout limit enforcement.
5. LoopGuard action deduplication and stall/NO_PROGRESS detection.
6. RecoveryController deterministic action choices.
7. Preflight budget reservation and truncated output rejection.
8. Decoupled orthogonal status axes (TriStatus).
"""

import pytest

from hunting.contracts.observation_class import (
    ActionSignature,
    ObservationClass,
    TriStatus,
)
from hunting.contracts.proof_contract import ProofContract, ProofContractStatus
from hunting.contracts.search_envelope import (
    BudgetEnvelope,
    ExpandableRetrievalHints,
    HardConstraints,
    SearchEnvelope,
)
from hunting.controller.cost import LLMUsageTracker
from hunting.controller.loop_guard import LoopGuard
from hunting.controller.recovery_controller import RecoveryController


class DummyAttempt:
    """Mock attempt for testing classification ladder."""

    def __init__(
        self,
        executed_ok: bool = True,
        completed: bool = True,
        row_count: int = 1,
        hit_limit: bool = False,
        truncated: bool = False,
        status: str = "SUCCESS",
        diagnostic_errors: list[str] | None = None,
        proof_conforming: bool = False,
    ):
        self.executed_ok = executed_ok
        self.completed = completed
        self.row_count = row_count
        self.hit_limit = hit_limit
        self.truncated = truncated
        self.status = status
        self.diagnostic_errors = diagnostic_errors or []
        self.proof_conforming = proof_conforming


def test_observation_classification_ladder():
    rc = RecoveryController()

    # 1. QUERY_INVALID on safety/AST violation
    att_invalid = DummyAttempt(diagnostic_errors=["AST validation error: unauthorized command"])
    assert rc.classify(att_invalid) == ObservationClass.QUERY_INVALID

    # 2. QUERY_FAILURE on crash or executed_ok=False
    att_fail = DummyAttempt(executed_ok=False, status="ERROR")
    assert rc.classify(att_fail) == ObservationClass.QUERY_FAILURE

    # 3. PARTIAL: complete=False with 0 rows
    # CRITICAL INVARIANT: 0 rows with partial execution is PARTIAL, NOT EMPTY
    att_partial_zero = DummyAttempt(completed=False, row_count=0)
    assert rc.classify(att_partial_zero) == ObservationClass.PARTIAL

    # 3b. PARTIAL: hit_limit or truncated
    att_limit = DummyAttempt(completed=True, hit_limit=True, row_count=100)
    assert rc.classify(att_limit) == ObservationClass.PARTIAL

    # 4. EMPTY: completed with 0 rows
    att_empty = DummyAttempt(completed=True, row_count=0)
    assert rc.classify(att_empty) == ObservationClass.EMPTY

    # 5. CONTRADICTORY: Conflict with hard constraints
    hc = HardConstraints(verified_bindings=(("user", "verified_user_1"),))
    env = SearchEnvelope(hard_constraints=hc)
    att_rows = DummyAttempt(completed=True, row_count=1)
    cands_conflict = [{"role": "user", "value": "other_user"}]
    assert rc.classify(att_rows, envelope=env, extracted_candidates=cands_conflict) == ObservationClass.CONTRADICTORY

    # 6. AMBIGUOUS: Multiple viable candidates with distinct values
    cands_ambiguous = [
        {"role": "target_host", "value": "host_a"},
        {"role": "target_host", "value": "host_b"},
    ]
    assert rc.classify(att_rows, extracted_candidates=cands_ambiguous) == ObservationClass.AMBIGUOUS

    # 7. PROOF_GAP: Candidates present, but ProofContract not approved or not conforming
    contract = ProofContract(
        contract_id="test-contract",
        version="v1",
        relation="executes_process",
        status=ProofContractStatus.APPROVED,
    )
    att_non_conforming = DummyAttempt(completed=True, row_count=1, proof_conforming=False)
    assert rc.classify(att_non_conforming, proof_contract=contract) == ObservationClass.PROOF_GAP

    # 8. VERIFIED: ProofContract approved and proof_conforming is True
    att_verified = DummyAttempt(completed=True, row_count=1, proof_conforming=True)
    assert rc.classify(att_verified, proof_contract=contract) == ObservationClass.VERIFIED


def test_search_envelope_immutability_and_derivation():
    # 1. Hard constraints immutability and monotonic narrowing
    hc0 = HardConstraints(
        pinned_entities=frozenset(["host-1"]),
        allowed_providers=frozenset(["splunk"]),
        time_window_start="2026-01-01T00:00:00Z",
        time_window_end="2026-01-02T00:00:00Z",
        verified_bindings=(("host", "host-1"),),
    )

    # Adding verified binding monotonically succeeds
    hc1 = hc0.with_verified_binding("user", "user-alpha")
    assert hc1.get_verified_binding("user") == "user-alpha"
    assert hc1.get_verified_binding("host") == "host-1"

    # Overriding verified binding fails
    with pytest.raises(ValueError, match="Cannot override verified binding"):
        hc1.with_verified_binding("user", "user-beta")

    # 2. SearchEnvelope derivation
    env0 = SearchEnvelope(
        hard_constraints=hc0,
        retrieval_hints=ExpandableRetrievalHints(current_expansion_level=0, max_expansion_level=2),
        budgets=BudgetEnvelope(max_queries=10),
    )

    env1 = env0.derive_next(
        new_hints=ExpandableRetrievalHints(current_expansion_level=0, max_expansion_level=2),
        reason="Relaxing hints to level 1",
    )
    assert env1.version == 1
    assert env1.parent_envelope_id == env0.envelope_id
    assert env1.retrieval_hints.current_expansion_level == 1
    assert env1.hard_constraints == hc0

    # Derive to max level 2
    env2 = env1.derive_next(
        new_hints=ExpandableRetrievalHints(current_expansion_level=1, max_expansion_level=2),
        reason="Relaxing hints to level 2",
    )
    assert env2.retrieval_hints.current_expansion_level == 2

    # Expanding beyond max level raises ValueError
    with pytest.raises(ValueError, match="Cannot expand beyond maximum retrieval expansion level"):
        env2.derive_next(
            new_hints=ExpandableRetrievalHints(current_expansion_level=2, max_expansion_level=2),
            reason="Exceeding limit",
        )

    # 3. Attempting to relax hard constraints raises ValueError
    hc_widened_pinned = HardConstraints(pinned_entities=frozenset())  # removed host-1
    with pytest.raises(ValueError, match="Cannot remove pinned entities"):
        env0.derive_next(new_hard_constraints=hc_widened_pinned)

    hc_widened_providers = HardConstraints(
        pinned_entities=hc0.pinned_entities,
        allowed_providers=frozenset(["splunk", "edr_unauthorized"]),
    )
    with pytest.raises(ValueError, match="Cannot expand allowed providers"):
        env0.derive_next(new_hard_constraints=hc_widened_providers)


def test_candidate_fanout_cap():
    env = SearchEnvelope(max_candidate_fanout=3)
    assert env.validate_candidate_fanout(2) is True
    assert env.validate_candidate_fanout(3) is True
    assert env.validate_candidate_fanout(4) is False


def test_loop_guard_deduplication_and_no_progress():
    guard = LoopGuard(max_consecutive_stalls=2)
    sig = ActionSignature.from_params(
        goal_id="g1",
        op_id="op_search",
        scope="s1",
        source_id="splunk",
        stage="TEST",
        bindings={"target": "val1"},
    )

    # First execution: treated as progress
    p1 = guard.record_action(sig, turn_index=1, rows_count=0, result_payload=[])
    assert p1 is True
    assert not guard.is_stalled(sig)

    # Second identical execution (0 rows, no delta): stall 1
    p2 = guard.record_action(sig, turn_index=2, rows_count=0, result_payload=[])
    assert p2 is False
    assert not guard.is_stalled(sig)

    # Third identical execution: stall 2 >= max_consecutive_stalls -> STALLED and NO_PROGRESS
    p3 = guard.record_action(sig, turn_index=3, rows_count=0, result_payload=[])
    assert p3 is False
    assert guard.is_stalled(sig)
    assert guard.is_route_exhausted("splunk", "op_search")


def test_recovery_controller_next_actions():
    rc = RecoveryController()
    guard = LoopGuard()
    hints = ExpandableRetrievalHints(current_expansion_level=0, max_expansion_level=2)
    env = SearchEnvelope(retrieval_hints=hints)

    # EMPTY with hints expandable -> RELAX_HINT
    act_relax = rc.choose_next_action(
        ObservationClass.EMPTY,
        envelope=env,
        loop_guard=guard,
        current_route=("splunk", "op1"),
    )
    assert act_relax.action_type == "RELAX_HINT"
    assert act_relax.new_envelope is not None
    assert act_relax.new_envelope.retrieval_hints.current_expansion_level == 1

    # EMPTY with hints exhausted, alternate route available -> SWITCH_ROUTE
    env_exhausted_hints = SearchEnvelope(
        retrieval_hints=ExpandableRetrievalHints(current_expansion_level=2, max_expansion_level=2)
    )
    act_switch = rc.choose_next_action(
        ObservationClass.EMPTY,
        envelope=env_exhausted_hints,
        loop_guard=guard,
        available_routes=[("splunk", "op1"), ("cdb", "op2")],
        current_route=("splunk", "op1"),
    )
    assert act_switch.action_type == "SWITCH_ROUTE"
    assert act_switch.target_source == "cdb"
    assert act_switch.target_op == "op2"

    # EMPTY with all routes exhausted + negative license -> STOP_BOUNDED_NOT_FOUND
    guard.mark_route_exhausted("cdb", "op2")
    act_not_found = rc.choose_next_action(
        ObservationClass.EMPTY,
        envelope=env_exhausted_hints,
        loop_guard=guard,
        available_routes=[("splunk", "op1"), ("cdb", "op2")],
        current_route=("splunk", "op1"),
        has_negative_license=True,
    )
    assert act_not_found.action_type == "STOP_BOUNDED_NOT_FOUND"

    # AMBIGUOUS with discriminator budget remaining -> DISCRIMINATE
    cands_many = [{"role": "host", "value": f"h{i}"} for i in range(10)]
    act_disc = rc.choose_next_action(
        ObservationClass.AMBIGUOUS,
        envelope=SearchEnvelope(max_candidate_fanout=5),
        loop_guard=guard,
        candidates=cands_many,
        declared_discriminator=True,
    )
    assert act_disc.action_type == "DISCRIMINATE"

    # AMBIGUOUS after discriminator budget is exhausted -> NEEDS_DISAMBIGUATION
    env_spent = SearchEnvelope(max_candidate_fanout=5)
    env_spent.budgets.consumed_discriminators = env_spent.budgets.max_discriminators
    act_disambig = rc.choose_next_action(
        ObservationClass.AMBIGUOUS,
        envelope=env_spent,
        loop_guard=guard,
        candidates=cands_many,
    )
    assert act_disambig.action_type == "NEEDS_DISAMBIGUATION"


def test_preflight_budget_enforcement_and_truncation():
    tracker = LLMUsageTracker(max_calls=5, max_total_tokens=15000, model_name="stub")

    # Preflight with acceptable prompt and completion fits
    res = tracker.preflight("Short prompt", expected_completion_tokens=200, component="compiler")
    assert res["component"] == "compiler"

    # Preflight exceeding component input ceiling (2500 tokens = ~10,001 chars for compiler)
    huge_prompt = "x" * 10500
    with pytest.raises(RuntimeError, match="exceeds ceiling"):
        tracker.preflight(huge_prompt, expected_completion_tokens=100, component="compiler")

    # Preflight exceeding component output ceiling (1200 tokens for compiler)
    with pytest.raises(RuntimeError, match="exceeds ceiling"):
        tracker.preflight("Normal prompt", expected_completion_tokens=1500, component="compiler")

    # Truncated output rejection
    valid, msg = tracker.validate_response("{\"valid\": true}", finish_reason="STOP")
    assert valid is True

    # Truncated by finish_reason
    valid_trunc, msg_trunc = tracker.validate_response("{\"valid\": true}", finish_reason="MAX_TOKENS")
    assert valid_trunc is False
    assert "truncated" in msg_trunc.lower()

    # Unclosed JSON rejected
    valid_unclosed, msg_unclosed = tracker.validate_response("{\"role\": \"host\", \"val\":")
    assert valid_unclosed is False
    assert "unclosed" in msg_unclosed.lower()


def test_orthogonal_status_axes_and_tristatus():
    # Invariant: execution_complete != proof_complete != route_exhausted
    tri = TriStatus(execution_complete=True, proof_complete=False, route_exhausted=False)
    # Even if execution complete and proof incomplete, not bounded not found because route is active
    assert tri.is_bounded_not_found(negative_license_granted=True) is False

    # When route is exhausted and negative license granted -> bounded not found
    tri_exhausted = TriStatus(execution_complete=True, proof_complete=False, route_exhausted=True)
    assert tri_exhausted.is_bounded_not_found(negative_license_granted=True) is True

    # Without negative license -> not bounded not found
    assert tri_exhausted.is_bounded_not_found(negative_license_granted=False) is False
