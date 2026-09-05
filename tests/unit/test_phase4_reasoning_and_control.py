"""Phase 4 — Reasoning and Control Layer Tests.

Verifies the 7 Phase 4 checklist items from 04-IMPLEMENTATION-CHECKLIST.md:
1. Exact predicates and temporal/entity correlations are deterministic.
2. Evidence may be compatible with multiple hypotheses.
3. Semantic LLM output is advisory and M3-validated.
4. Competing hypotheses remain until genuinely refuted.
5. Controller owns TEST/EXPAND/DISCOVER/PIVOT/REFINE/STOP.
6. Query, turn, runtime, scan and LLM budgets are enforced.
7. STOP_RESOLVED, STOP_BOUNDED and STOP_EXHAUSTED_BY_BUDGET are distinct.
"""
from __future__ import annotations

from hunting.contracts.entities import Host
from hunting.contracts.expectations import (
    EvidenceRequirement,
    Expectation,
    FieldOp,
    FieldPredicate,
    TestStatus,
)
from hunting.contracts.hunt import (
    EvidenceCard,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.controller import (
    CanonicalActionController,
    HuntAction,
    HuntBudgetLedger,
    HypothesisReasoningEngine,
    evaluate_field_predicate,
    evaluate_temporal_correlation,
)


def test_1_exact_predicates_and_correlations_deterministic():
    """1. Exact predicates and temporal/entity correlations are deterministic."""
    pred_eq = FieldPredicate(field="status", op=FieldOp.EQUALS, value="404")
    assert evaluate_field_predicate("404", pred_eq) is True
    assert evaluate_field_predicate("200", pred_eq) is False

    pred_contains = FieldPredicate(field="cmdline", op=FieldOp.CONTAINS, value="whoami")
    assert evaluate_field_predicate("cmd.exe /c whoami /all", pred_contains) is True
    assert evaluate_field_predicate("notepad.exe test.txt", pred_contains) is False

    pred_exists = FieldPredicate(field="parent", op=FieldOp.EXISTS)
    assert evaluate_field_predicate("w3wp.exe", pred_exists) is True
    assert evaluate_field_predicate(None, pred_exists) is False
    assert evaluate_field_predicate("", pred_exists) is False

    # Temporal correlation within 60s
    t1 = "2026-09-01T12:00:00Z"
    t2 = "2026-09-01T12:00:45Z"
    t3 = "2026-09-01T12:02:00Z"
    assert evaluate_temporal_correlation(t1, t2, max_delta_seconds=60.0) is True
    assert evaluate_temporal_correlation(t1, t3, max_delta_seconds=60.0) is False


def test_2_evidence_compatible_with_multiple_hypotheses():
    """2. Evidence may be compatible with multiple hypotheses."""
    engine = HypothesisReasoningEngine()

    h1 = Hypothesis(id="hypo-01", statement="Threat actor executing anomalous powershell commands")
    h2 = Hypothesis(id="hypo-02", statement="Investigate administrative process activity on host")

    card = EvidenceCard(
        id="card-proc-01",
        fingerprint="fp-proc-01",
        representative_observation_ids=["obs-01"],
        count=5,
        fact_type="process_execution",
    )

    expectations = [
        Expectation(
            id="exp-h1", owner_explanation_id=h1.id,
            evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
            predicted_observation="Process execution", entity_ref=Host(name="host-1"),
            field_predicate=None, provider_scope_id="p1", time_window="2026-09-01/2026-09-02",
            falsification_condition="No process telemetry",
        ),
        Expectation(
            id="exp-h2", owner_explanation_id=h2.id,
            evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
            predicted_observation="Process execution", entity_ref=Host(name="host-1"),
            field_predicate=None, provider_scope_id="p1", time_window="2026-09-01/2026-09-02",
            falsification_condition="No process telemetry",
        ),
    ]
    # Typed expectations, rather than statement keywords, make the card
    # compatible with both hypotheses.
    compat = engine.evaluate_compatibility(card, [h1, h2], expectations)
    assert compat[h1.id] is True
    assert compat[h2.id] is True

    # Without typed expectations, no hypothesis may be selected by guessing.
    assert engine.evaluate_compatibility(card, [h1, h2]) == {h1.id: False, h2.id: False}


def test_3_semantic_llm_output_is_advisory_and_m3_validated():
    """3. Semantic LLM output is advisory and M3-validated."""
    controller = CanonicalActionController()
    state = HuntState()

    advisory_proposal = {"suggested_hypothesis": "Adversary beaconing to port 443"}

    # Case A: When M3 validation fails, proposal must NOT be applied to state
    applied_fail = controller.apply_advisory_llm_proposal(state, advisory_proposal, m3_validator_passed=False)
    assert applied_fail is False

    # Case B: When M3 validation passes, proposal can be applied
    applied_ok = controller.apply_advisory_llm_proposal(state, advisory_proposal, m3_validator_passed=True)
    assert applied_ok is True


def test_4_competing_hypotheses_remain_until_genuinely_refuted():
    """4. Competing hypotheses remain until genuinely refuted."""
    engine = HypothesisReasoningEngine()

    h_attack = Hypothesis(id="hypo-attack", statement="Adversary compromise via web shell")
    h_benign = Hypothesis(id="hypo-benign", statement="Normal administrative web deployment")

    assert h_attack.status == HypothesisStatus.LIVE
    assert h_benign.status == HypothesisStatus.LIVE

    # Supporting evidence found for attack does NOT immediately delete benign hypothesis
    engine.update_hypothesis_status(h_attack, has_confirming_evidence=True, has_refuting_evidence=False)
    assert h_attack.status == HypothesisStatus.SUPPORTED
    assert h_benign.status == HypothesisStatus.LIVE  # Still live!

    # Contradiction weakens before total refutation
    engine.update_hypothesis_status(h_benign, has_confirming_evidence=True, has_refuting_evidence=True)
    assert h_benign.status == HypothesisStatus.WEAKENED

    # Genuine complete refutation sets REFUTED
    engine.update_hypothesis_status(h_benign, has_confirming_evidence=False, has_refuting_evidence=True)
    assert h_benign.status == HypothesisStatus.REFUTED


def test_5_controller_owns_action_order():
    """5. Controller owns TEST/EXPAND/DISCOVER/PIVOT/REFINE/STOP."""
    controller = CanonicalActionController()
    state = HuntState()

    # TEST takes highest precedence
    action_1 = controller.select_action(state, has_untested_expectations=True, has_expand_candidates=True)
    assert action_1 == HuntAction.TEST

    # CONTROL takes next precedence
    action_2 = controller.select_action(state, has_untested_expectations=False, has_pending_controls=True, has_expand_candidates=True)
    assert action_2 == HuntAction.CONTROL

    # EXPAND follows
    action_3 = controller.select_action(state, has_pending_controls=False, has_expand_candidates=True, has_discover_candidates=True)
    assert action_3 == HuntAction.EXPAND

    # DISCOVER follows
    action_4 = controller.select_action(state, has_expand_candidates=False, has_discover_candidates=True, has_pivot_candidates=True)
    assert action_4 == HuntAction.DISCOVER

    # PIVOT follows
    action_5 = controller.select_action(state, has_discover_candidates=False, has_pivot_candidates=True, has_ambiguous_evidence=True)
    assert action_5 == HuntAction.PIVOT

    # REFINE follows
    action_6 = controller.select_action(state, has_pivot_candidates=False, has_ambiguous_evidence=True)
    assert action_6 == HuntAction.REFINE

    # STOP when no active work remains
    action_7 = controller.select_action(state)
    assert action_7 == HuntAction.STOP


def test_6_budgets_enforced():
    """6. Query, turn, runtime, scan and LLM budgets are enforced."""
    budgets = HuntBudgetLedger(max_turns=3, max_queries=5, max_llm_calls=2, max_scan_cells=10, max_runtime_seconds=1.0)
    assert budgets.is_exhausted is False

    # Turns
    budgets.record_turn()
    budgets.record_turn()
    budgets.record_turn()
    assert budgets.is_turn_exhausted is True
    assert budgets.is_exhausted is True

    # Queries
    budgets_q = HuntBudgetLedger(max_queries=2)
    budgets_q.record_query(2)
    assert budgets_q.is_query_exhausted is True

    # LLM calls
    budgets_llm = HuntBudgetLedger(max_llm_calls=1)
    budgets_llm.record_llm_call()
    assert budgets_llm.is_llm_exhausted is True

    # Scan cells
    budgets_scan = HuntBudgetLedger(max_scan_cells=5)
    budgets_scan.record_scan_cell(5)
    assert budgets_scan.is_scan_exhausted is True


def test_7_stopping_states_distinct():
    """7. STOP_RESOLVED, STOP_BOUNDED and STOP_EXHAUSTED_BY_BUDGET are distinct."""
    # Distinct enums
    assert StoppingDecision.STOP_RESOLVED != StoppingDecision.STOP_BOUNDED
    assert StoppingDecision.STOP_BOUNDED != StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
    assert StoppingDecision.STOP_RESOLVED != StoppingDecision.STOP_EXHAUSTED_BY_BUDGET

    # Case A: Budget Exhaustion -> STOP_EXHAUSTED_BY_BUDGET
    exhausted_budgets = HuntBudgetLedger(max_turns=1)
    exhausted_budgets.record_turn()
    controller_exh = CanonicalActionController(budget_ledger=exhausted_budgets)

    state_a = HuntState()
    dec_a = controller_exh.evaluate_stopping(state_a)
    assert dec_a == StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
    assert state_a.stopping_decision == StoppingDecision.STOP_EXHAUSTED_BY_BUDGET

    # Case B: All hypotheses resolved, all expectations concluded -> STOP_RESOLVED
    controller_live = CanonicalActionController()
    h_resolved = Hypothesis(id="h1", statement="Exploit detected", status=HypothesisStatus.SUPPORTED)
    exp_concluded = Expectation(
        id="exp-1",
        owner_explanation_id="h1",
        evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
        predicted_observation="cmd execution",
        entity_ref=Host(name="WEB-01"),
        field_predicate=None,
        provider_scope_id="scope-1",
        time_window="NOW-1d/NOW",
        falsification_condition="clean",
        test_status=TestStatus.CONFIRMED,
    )
    state_resolved = HuntState(hypotheses=[h_resolved], expectations=[exp_concluded])
    dec_resolved = controller_live.evaluate_stopping(state_resolved)
    assert dec_resolved == StoppingDecision.STOP_RESOLVED

    # Case C: Active live hypothesis remains or incomplete expectations -> STOP_BOUNDED
    h_live = Hypothesis(id="h2", statement="Alternative attack", status=HypothesisStatus.LIVE)
    state_bounded = HuntState(hypotheses=[h_resolved, h_live], expectations=[exp_concluded])
    dec_bounded = controller_live.evaluate_stopping(state_bounded)
    assert dec_bounded == StoppingDecision.STOP_BOUNDED
