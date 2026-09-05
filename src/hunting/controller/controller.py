"""Canonical Action Controller.

Component 5 of v4 architecture:
- Sole state-transition authority over HuntState.
- Implements strict action sequence:
    TEST -> CONTROL -> EXPAND -> DISCOVER -> PIVOT -> REFINE -> STOP
- Enforces budgets and terminal stopping decisions:
    STOP_RESOLVED, STOP_BOUNDED, STOP_EXHAUSTED_BY_BUDGET.
- Ensures semantic LLM output is advisory and M3-validated.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from hunting.contracts.cells import Cell, CellState
from hunting.contracts.expectations import Expectation, TestStatus
from hunting.contracts.hunt import (
    EvidenceAssessment,
    EvidenceCard,
    EvidenceRequirementV4,
    HuntState,
    Hypothesis,
    HypothesisStatus,
    LogicalQueryPlan,
    NativeQueryPlan,
    QueryPlan,
    QueryResult,
    RequirementStatus,
    StoppingDecision,
)
from hunting.contracts.observations import Observation
from hunting.controller.models import HuntAction, HuntBudgetLedger
from hunting.controller.reasoning import (
    HypothesisReasoningEngine,
    verify_attack_chain_correlation,
)


class CanonicalActionController:
    """The central deterministic action controller."""

    def __init__(self, budget_ledger: HuntBudgetLedger | None = None) -> None:
        self.budgets = budget_ledger if budget_ledger is not None else HuntBudgetLedger()
        self.reasoning = HypothesisReasoningEngine()

    def transition_cell_state(self, state: HuntState, cell: Cell, new_state: CellState) -> None:
        """Authority method to transition a cell's exploration state."""
        cell.state = new_state

    def add_cell(self, state: HuntState, cell: Cell) -> None:
        """Authority method to add an entity cell to hunt state."""
        if not any(
            c == cell
            or (not c.is_wildcard and not cell.is_wildcard and c.entity == cell.entity and c.time_bucket == cell.time_bucket)
            for c in state.cells
        ):
            state.cells.append(cell)

    def add_expectation(self, state: HuntState, expectation: Expectation) -> None:
        """Authority method to add an expectation to hunt state."""
        if not any(e.id == expectation.id for e in state.expectations):
            state.expectations.append(expectation)

    def add_observation(self, state: HuntState, observation: Observation) -> None:
        """Authority method to add an observation to hunt state."""
        state.observations.append(observation)

    def set_evidence_cards(self, state: HuntState, cards: list[EvidenceCard]) -> None:
        """Authority method to update evidence cards in hunt state."""
        state.evidence_cards = list(cards)

    def add_logical_query_plan(self, state: HuntState, plan: LogicalQueryPlan) -> None:
        """Authority method to record a logical query plan."""
        state.logical_query_plans.append(plan)

    def add_native_query_plan(self, state: HuntState, plan: NativeQueryPlan) -> None:
        """Authority method to record a native query plan."""
        state.native_query_plans.append(plan)

    def add_evidence_assessment(self, state: HuntState, assessment: EvidenceAssessment) -> None:
        """Authority method to record an advisory evidence assessment."""
        if not any(a.card_id == assessment.card_id for a in state.evidence_assessments):
            state.evidence_assessments.append(assessment)

    def advance_turn(self, state: HuntState) -> int:
        """Authority method to advance the hunt turn counter."""
        state.turn += 1
        return state.turn

    def record_query_execution(self, state: HuntState, query: QueryPlan, result: QueryResult) -> None:
        """Authority method to record query plan execution and result."""
        state.queries.append(query)
        state.query_results.append(result)
        state.query_count += 1
        self.budgets.record_query()

    def update_expectation_status(self, state: HuntState, expectation: Expectation, status: TestStatus) -> None:
        """Authority method to update an expectation's epistemic status."""
        expectation.test_status = status

    def update_requirement_status(self, state: HuntState, requirement: EvidenceRequirementV4, status: RequirementStatus) -> None:
        """Authority method to update an evidence requirement's lifecycle status."""
        requirement.status = status

    def update_hypothesis_status(self, state: HuntState, hypothesis: Hypothesis, status: HypothesisStatus) -> None:
        """Authority method to update a hypothesis lifecycle status."""
        hypothesis.status = status

    def set_stopping_decision(self, state: HuntState, decision: StoppingDecision) -> None:
        """Authority method to set the terminal stopping decision."""
        state.stopping_decision = decision

    def select_action(
        self,
        state: HuntState,
        has_untested_expectations: bool = False,
        has_pending_controls: bool = False,
        has_expand_candidates: bool = False,
        has_discover_candidates: bool = False,
        has_pivot_candidates: bool = False,
        has_ambiguous_evidence: bool = False,
    ) -> HuntAction:
        """Select next action following strict lexicographical action order.

        Sequence: TEST -> CONTROL -> EXPAND -> DISCOVER -> PIVOT -> REFINE -> STOP
        """
        # 1. Check budget exhaustion first
        if self.budgets.is_exhausted:
            return HuntAction.STOP

        # 2. Sequential action precedence
        if has_untested_expectations:
            return HuntAction.TEST
        if has_pending_controls:
            return HuntAction.CONTROL
        if has_expand_candidates:
            return HuntAction.EXPAND
        if has_discover_candidates:
            return HuntAction.DISCOVER
        if has_pivot_candidates:
            return HuntAction.PIVOT
        if has_ambiguous_evidence and not self.budgets.is_llm_exhausted:
            return HuntAction.REFINE

        return HuntAction.STOP

    def evaluate_stopping(self, state: HuntState) -> StoppingDecision:
        """Evaluate terminal stopping decision for the hunt."""
        # 0. Check explicit hypothesis state boundaries
        if any(h.status == HypothesisStatus.INSUFFICIENTLY_SPECIFIED for h in state.hypotheses):
            decision = StoppingDecision.STOP_INSUFFICIENT
            self.set_stopping_decision(state, decision)
            return decision

        if any(h.status == HypothesisStatus.UNSUPPORTED for h in state.hypotheses):
            decision = StoppingDecision.STOP_UNSUPPORTED
            self.set_stopping_decision(state, decision)
            return decision

        if any(h.status == HypothesisStatus.UNREACHABLE for h in state.hypotheses):
            decision = StoppingDecision.STOP_UNREACHABLE
            self.set_stopping_decision(state, decision)
            return decision

        # 1. Budget exhaustion
        if self.budgets.is_exhausted:
            decision = StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
            self.set_stopping_decision(state, decision)
            return decision

        # Web compromise guard: Process creation alone cannot conclude full web compromise.
        # Evidence must correlate to the same target host / infrastructure chain!
        for h in state.hypotheses:
            has_web_req = any(
                r.evidence_type in ("web_request", "web_activity")
                for r in state.requirements
                if r.id in h.requirements
            )
            if has_web_req:
                fact_types = {c.fact_type for c in state.evidence_cards}
                has_web = "web_request" in fact_types or "web_activity" in fact_types
                has_proc = "process_execution" in fact_types
                has_file = "file_modification" in fact_types

                if not (has_web and has_proc and has_file):
                    if h.status == HypothesisStatus.SUPPORTED:
                        self.update_hypothesis_status(state, h, HypothesisStatus.WEAKENED)
                else:
                    # Entity co-location & temporal correlation check:
                    host_aliases: dict[str, set[str]] = defaultdict(set)
                    for obs in state.observations:
                        obs_h = str(obs.fields.get("host", "")).lower()
                        if obs_h:
                            for k in ("ip", "source_ip", "src_ip", "dest_ip", "destination_ip", "client_ip", "server_ip", "c_ip", "s_ip"):
                                v = obs.fields.get(k)
                                if v:
                                    host_aliases[obs_h].add(str(v).lower())

                    correlated = verify_attack_chain_correlation(
                        state.evidence_cards,
                        max_delta_seconds=86400.0,
                        host_aliases=host_aliases,
                    )

                    if not correlated and h.status == HypothesisStatus.SUPPORTED:
                        self.update_hypothesis_status(state, h, HypothesisStatus.WEAKENED)

        # 2. Check hypothesis resolution
        live_hypotheses = [h for h in state.hypotheses if h.status in (HypothesisStatus.LIVE, HypothesisStatus.WEAKENED)]
        resolved_hypotheses = [h for h in state.hypotheses if h.status in (HypothesisStatus.SUPPORTED, HypothesisStatus.REFUTED)]

        # Check if all expectations are concluded
        all_expectations_concluded = state.expectations and all(
            e.test_status in (TestStatus.CONFIRMED, TestStatus.REFUTED, TestStatus.UNTESTABLE)
            for e in state.expectations
        )

        # Invariant: A hunt CANNOT be STOP_RESOLVED if any targeted instance cell remains UNEXPLORED
        unexplored_instance_cells = [
            c for c in state.cells if not c.is_wildcard and c.state == CellState.UNEXPLORED
        ]

        if (
            resolved_hypotheses
            and not live_hypotheses
            and all_expectations_concluded
            and not unexplored_instance_cells
        ):
            decision = StoppingDecision.STOP_RESOLVED
        else:
            decision = StoppingDecision.STOP_BOUNDED

        self.set_stopping_decision(state, decision)
        return decision

    def apply_advisory_llm_proposal(
        self,
        state: HuntState,
        proposal: dict[str, Any],
        m3_validator_passed: bool,
    ) -> bool:
        """Apply advisory LLM proposal to HuntState only if M3 validator approves.

        Invariant: LLM cannot mutate state directly; M3 validation is mandatory.
        """
        if not m3_validator_passed:
            return False

        # Apply validated proposal (e.g. record advisory metadata)
        return True


__all__ = ["CanonicalActionController"]
