"""M4 Controller — budget tracking, fixed action order, stopping rules, and disposition.

Responsibilities:
  - Fixed action order and lexicographic selection: TEST -> EXPAND -> SAMPLE.
  - Enforces budgets: T_max=15, Q_max=60, N_taint=20/turn (counts deferred entities).
  - Evaluates terminal states: STOP_RESOLVED vs STOP_BOUNDED.
  - STOP_RESOLVED requires a surviving explanation and no blocking uncertainty.
  - STOP_BOUNDED records residuals and emits CoverageBound.
  - Computes final disposition: MALICIOUS, BENIGN, UNKNOWN, INSUFFICIENT_EVIDENCE, CONFLICTED.
  - Enforces mandatory analyst confirmation for MALICIOUS, CONFLICTED, and all STOP_BOUNDED paths.
"""
from __future__ import annotations

from typing import Sequence

from hunting.contracts.coverage import CoverageBound
from hunting.contracts.entities import EntityRef
from hunting.contracts.explanations import ExplanationClass, ExplanationStatus
from hunting.contracts.state import (
    Disposition,
    FinalAccount,
    InvestigationState,
    TerminalState,
)

T_MAX = 15
Q_MAX = 60
N_TAINT_PER_TURN = 20


class BudgetLedger:
    """Tracks turn, query, and tainted entity budgets."""

    def __init__(self, t_max: int = T_MAX, q_max: int = Q_MAX, n_taint: int = N_TAINT_PER_TURN) -> None:
        self.t_max = t_max
        self.q_max = q_max
        self.n_taint = n_taint
        self.current_turn = 0
        self.query_count = 0
        self.deferred_taint_entities = 0

    @property
    def is_turn_budget_exhausted(self) -> bool:
        return self.current_turn >= self.t_max

    @property
    def is_query_budget_exhausted(self) -> bool:
        return self.query_count >= self.q_max

    @property
    def is_budget_exhausted(self) -> bool:
        return self.is_turn_budget_exhausted or self.is_query_budget_exhausted

    def filter_tainted_entities(self, tainted_entities: Sequence[EntityRef]) -> list[EntityRef]:
        """Limit tainted entities per turn to n_taint; count deferred entities."""
        if len(tainted_entities) <= self.n_taint:
            return list(tainted_entities)

        allowed = list(tainted_entities[: self.n_taint])
        deferred_count = len(tainted_entities) - self.n_taint
        self.deferred_taint_entities += deferred_count
        return allowed


def select_next_action(
    has_untested_expectations: bool,
    has_expand_candidates: bool,
    has_sample_candidates: bool,
) -> str | None:
    """Fixed action order: TEST -> EXPAND -> SAMPLE."""
    if has_untested_expectations:
        return "TEST"
    if has_expand_candidates:
        return "EXPAND"
    if has_sample_candidates:
        return "SAMPLE"
    return None


def evaluate_stopping(state: InvestigationState, budgets: BudgetLedger) -> tuple[TerminalState, Disposition, list[str]]:
    """Determine whether the investigation terminates as STOP_RESOLVED or STOP_BOUNDED.

    Computes unambiguous mutually-exclusive disposition.
    """
    surviving_explanations = [
        e for e in state.explanations
        if e.status in {ExplanationStatus.LIVE, ExplanationStatus.WEAKENED}
    ]

    blockers: list[str] = []

    # Check 1: Critical dark sources
    for ds in state.dark_sources:
        if ds.critical:
            blockers.append(f"Critical dark source: {ds.source} unavailable for window {ds.window}")

    # Check 2: Unresolved evidence conflicts
    unresolved_conflicts = [c for c in state.conflicts if not c.resolved]
    if unresolved_conflicts:
        blockers.append(f"Unresolved evidence conflicts: {len(unresolved_conflicts)}")

    # Check 3: Untestable surviving explanations
    untestable = [e for e in surviving_explanations if e.untestable]
    if untestable:
        blockers.append(f"Untestable surviving explanations: {[e.id for e in untestable]}")

    # Check 4: Demanding observations un-attributed
    unattributed_demanding = [o for o in state.observations if o.demanding and o.is_unexplained]
    if unattributed_demanding:
        blockers.append(f"Unattributed demanding observations: {len(unattributed_demanding)}")

    # Check 5: Cross-class tie among surviving explanations
    if surviving_explanations:
        classes = {e.class_ for e in surviving_explanations if e.status == ExplanationStatus.LIVE}
        if len(classes) > 1:
            # Check if tied on support count
            max_sup = max(e.supported_count for e in surviving_explanations)
            top_classes = {e.class_ for e in surviving_explanations if e.supported_count == max_sup}
            if len(top_classes) > 1:
                blockers.append("Cross-class tie between equally-supported surviving explanations")

    # If no surviving explanations exist at all
    if not surviving_explanations:
        blockers.append("No surviving explanations (all hypotheses refuted)")

    # If budget exhausted
    if budgets.is_budget_exhausted:
        blockers.append(
            f"Budget exhausted (turn {budgets.current_turn}/{budgets.t_max}, queries {budgets.query_count}/{budgets.q_max})"
        )

    # -----------------------------------------------------------------------
    # Decision: STOP_RESOLVED vs STOP_BOUNDED
    # -----------------------------------------------------------------------
    if not blockers and surviving_explanations:
        # STOP_RESOLVED requires surviving explanation and zero blocking uncertainty
        leading = max(surviving_explanations, key=lambda e: (e.supported_count, -e.refuted_count))
        if leading.class_ == ExplanationClass.MALICIOUS:
            disp = Disposition.MALICIOUS
        elif leading.class_ == ExplanationClass.BENIGN:
            disp = Disposition.BENIGN
        else:
            disp = Disposition.UNKNOWN
        return TerminalState.STOP_RESOLVED, disp, []

    # STOP_BOUNDED path
    if unresolved_conflicts:
        disp = Disposition.CONFLICTED
    elif surviving_explanations and any(e.class_ == ExplanationClass.UNKNOWN for e in surviving_explanations):
        disp = Disposition.UNKNOWN
    else:
        disp = Disposition.INSUFFICIENT_EVIDENCE

    return TerminalState.STOP_BOUNDED, disp, blockers


def is_confirmation_mandatory(disposition: Disposition, terminal_state: TerminalState) -> bool:
    """Analyst confirmation is mandatory for MALICIOUS, CONFLICTED, and all STOP_BOUNDED states."""
    if disposition in {Disposition.MALICIOUS, Disposition.CONFLICTED}:
        return True
    if terminal_state == TerminalState.STOP_BOUNDED:
        return True
    return False


def emit_final_account(
    disposition: Disposition,
    terminal_state: TerminalState,
    coverage_bound: CoverageBound,
    residuals: list[str],
    human_confirmed: bool = False,
) -> FinalAccount:
    """Build the final account document.

    Enforces mandatory human confirmation for MALICIOUS, CONFLICTED, and all STOP_BOUNDED.
    Raises PermissionError if confirmation is required but human_confirmed is False.
    """
    if is_confirmation_mandatory(disposition, terminal_state) and not human_confirmed:
        raise PermissionError(
            f"Mandatory analyst confirmation required for {disposition.value} / {terminal_state.value} before final account emission"
        )

    residual_text = "; ".join(residuals) if residuals else ""
    return FinalAccount(
        disposition=disposition,
        terminal_state=terminal_state,
        coverage_bound=coverage_bound,
        residual=residual_text,
        human_confirmed=human_confirmed,
    )



__all__ = [
    "T_MAX",
    "Q_MAX",
    "N_TAINT_PER_TURN",
    "BudgetLedger",
    "select_next_action",
    "evaluate_stopping",
    "emit_final_account",
]
