"""M3 Constraints — schema integrity, contradiction handling, and diagnostic partitioning.

Responsibilities:
  - Validates schema and cited-observation integrity against the ledger.
  - Handles contradictions: weakens or rejects explanations while preserving rejection reasons.
  - Partitions retryable vs permanent diagnostics; bounds retry attempts on cells.
  - Guards against M2 mutating statuses or attribution directly.
"""
from __future__ import annotations

from typing import Iterable

from hunting.contracts.cells import Cell, CellState
from hunting.contracts.expectations import Expectation, TestStatus
from hunting.contracts.explanations import Explanation, ExplanationStatus
from hunting.contracts.queries import Diagnostic, DiagnosticClass
from hunting.contracts.validators import assert_m2_cannot_mutate_attribution
from hunting.m1_ledger.ledger import ObservationLedger


def validate_citation_integrity(
    explanation: Explanation,
    ledger: ObservationLedger,
    actor: str = "controller",
) -> None:
    """Validate that all cited observations exist in the ledger and actor has write permission."""
    assert_m2_cannot_mutate_attribution(actor)

    ledger_obs_ids = {obs.id for obs in ledger.observations}
    for attr in explanation.attributions:
        if attr.observation_id not in ledger_obs_ids:
            raise KeyError(
                f"Integrity violation: Explanation '{explanation.id}' cites non-existent observation '{attr.observation_id}'"
            )


def update_explanation_contradictions(
    explanations: list[Explanation],
    expectations: Iterable[Expectation],
) -> None:
    """Evaluate test outcomes against owning explanations.

    Contract rules:
      - CONFIRMED expectation increases supported_count.
      - REFUTED expectation increases refuted_count and weakens the explanation.
      - If all expectations of an explanation are refuted, status transitions to REJECTED.
      - Rejection reasons are preserved in the record; rejected explanations are never deleted.
    """
    # Group expectations by owner explanation ID
    expectations_by_owner: dict[str, list[Expectation]] = {}
    for exp in expectations:
        expectations_by_owner.setdefault(exp.owner_explanation_id, []).append(exp)

    for expl in explanations:
        if expl.status == ExplanationStatus.REJECTED:
            # Already rejected; retain rejection reason
            continue

        owner_exps = expectations_by_owner.get(expl.id, [])
        if not owner_exps:
            continue

        confirmed = sum(1 for e in owner_exps if e.test_status == TestStatus.CONFIRMED)
        refuted = sum(1 for e in owner_exps if e.test_status == TestStatus.REFUTED)

        expl.supported_count = confirmed
        expl.refuted_count = refuted

        total_tested = confirmed + refuted
        if refuted > 0:
            if total_tested == len(owner_exps) and confirmed == 0:
                # All expectations refuted -> REJECTED
                expl.status = ExplanationStatus.REJECTED
                expl.rejection_reason = f"All {refuted} testable expectations were refuted by observable telemetry"
            else:
                # Partial contradiction -> WEAKENED
                expl.status = ExplanationStatus.WEAKENED
        elif confirmed > 0:
            expl.status = ExplanationStatus.LIVE


def is_diagnostic_retryable(diagnostic: Diagnostic) -> bool:
    """Partition diagnostics into RETRYABLE vs PERMANENT."""
    return diagnostic.diagnostic_class == DiagnosticClass.RETRYABLE


def evaluate_cell_retry(
    cell: Cell,
    diagnostic: Diagnostic,
    retry_count: int,
    max_retries: int = 2,
) -> CellState:
    """Determine cell state after a query failure based on diagnostic class and retry count."""
    if not is_diagnostic_retryable(diagnostic):
        # Permanent failure -> cell transitions immediately to UNREACHABLE
        cell.state = CellState.UNREACHABLE
        return CellState.UNREACHABLE

    if retry_count < max_retries:
        # Retryable: keep cell UNEXPLORED so it can be re-queried
        cell.state = CellState.UNEXPLORED
        return CellState.UNEXPLORED

    # Exceeded max retries -> permanent UNREACHABLE
    cell.state = CellState.UNREACHABLE
    return CellState.UNREACHABLE


__all__ = [
    "validate_citation_integrity",
    "update_explanation_contradictions",
    "is_diagnostic_retryable",
    "evaluate_cell_retry",
]
