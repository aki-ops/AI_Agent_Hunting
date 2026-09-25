"""Count-only sizing. These records are not evidence."""
from __future__ import annotations

from dataclasses import dataclass

from hunting.contracts.observation_class import ObservationClass


@dataclass(frozen=True)
class SizingObservation:
    kind: str
    coverage_ratio: float
    match_count: int
    distinct_entities: int
    strategy: str

    def __post_init__(self) -> None:
        if self.kind != ObservationClass.SIZING.value:
            raise ValueError("sizing observation kind must be SIZING")
        if self.strategy not in {"enumerate", "require_comparator"}:
            raise ValueError("sizing strategy must enumerate or require_comparator")


def measure_sizing(
    *,
    match_count: int,
    distinct_entities: int,
    scope_size: int,
    expected_magnitude: str = "population",
) -> SizingObservation:
    ratio = 0.0 if scope_size <= 0 else distinct_entities / scope_size
    ceiling = 5 if expected_magnitude == "small" else 50
    strategy = "enumerate" if distinct_entities <= ceiling else "require_comparator"
    return SizingObservation(
        kind=ObservationClass.SIZING.value,
        coverage_ratio=ratio,
        match_count=match_count,
        distinct_entities=distinct_entities,
        strategy=strategy,
    )


def refute_allowed(
    *,
    executed_ok: bool,
    complete: bool,
    coverage_ratio: float | None,
    min_coverage: float,
    index_mismatch: bool = False,
) -> bool:
    """REFUTED requires a finished query and coverage at the Prepare threshold."""
    if index_mismatch or not executed_ok or not complete:
        return False
    if coverage_ratio is None:
        return False
    return coverage_ratio >= min_coverage


def escalation_for(sizing: SizingObservation, expected_magnitude: str) -> str | None:
    """A serious excess is recorded during Execute, before the hunt ends."""
    if expected_magnitude == "small" and sizing.distinct_entities > 5:
        return (
            f"escalate: {sizing.distinct_entities} distinct entities "
            f"exceed expected magnitude {expected_magnitude}"
        )
    return None
