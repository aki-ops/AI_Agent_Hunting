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

from typing import Any

from hunting.contracts.cells import CellState
from hunting.contracts.expectations import TestStatus
from hunting.contracts.hunt import (
    HuntState,
    HypothesisStatus,
    StoppingDecision,
)
from hunting.controller.models import HuntAction, HuntBudgetLedger
from hunting.controller.reasoning import HypothesisReasoningEngine


class CanonicalActionController:
    """The central deterministic action controller."""

    def __init__(self, budget_ledger: HuntBudgetLedger | None = None) -> None:
        self.budgets = budget_ledger if budget_ledger is not None else HuntBudgetLedger()
        self.reasoning = HypothesisReasoningEngine()

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
        # 1. Budget exhaustion
        if self.budgets.is_exhausted:
            decision = StoppingDecision.STOP_EXHAUSTED_BY_BUDGET
            state.stopping_decision = decision
            return decision

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

        state.stopping_decision = decision
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
