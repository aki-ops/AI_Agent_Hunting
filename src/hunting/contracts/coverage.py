"""CoverageBound — what the agent could and could not see.

Emitted by EVERY terminal state (STOP_RESOLVED and STOP_BOUNDED).
This is honesty, not a solution: the agent reports blind spots rather than
claiming complete visibility.

All integer fields must be reported with denominators — never as bare fractions.
Wildcard and instance cells are always counted separately.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class SamplingStats:
    """Per-source-stratum sampling statistics for the rule-of-three bound.

    rule_of_three_upper_bound: after sampling n cells from a stratum and finding
    no relevant result, this is the 95%-confidence upper bound on attack-bearing
    CELL prevalence in that stratum's sampled frame. Unit = CELL, not event.
    """
    sampled_cells_by_stratum: dict[str, int] = field(default_factory=dict)
    rule_of_three_upper_bound: dict[str, float] = field(default_factory=dict)


@dataclass
class CoverageBound:
    """Accounting of what the agent searched and what it could not reach.

    Wildcard cells: entity = ANY (BroadSweep cells)
    Instance cells: entity = a concrete entity discovered during investigation

    Split parents are counted in partial_cells_* but excluded from active denominators.
    KNOWN_inst grows as entities are discovered — fractions may decrease (non-monotonic).
    """
    # --- Wildcard cells ---
    known_cells_wildcard: int = 0
    explored_cells_wildcard: int = 0
    partial_cells_wildcard: int = 0
    frontier_cells_wildcard: int = 0
    unexplored_cells_wildcard: int = 0
    unreachable_cells_wildcard: int = 0

    # --- Instance cells ---
    known_cells_instance: int = 0
    explored_cells_instance: int = 0
    partial_cells_instance: int = 0
    frontier_cells_instance: int = 0
    unexplored_cells_instance: int = 0
    unreachable_cells_instance: int = 0

    # --- Additional context ---
    sources_never_queried: list[str] = field(default_factory=list)
    windows_never_covered: list[str] = field(default_factory=list)
    deferred_taint_entities: int = 0   # entities capped by N_taint, deferred not discarded
    truncated_queries: int = 0
    wildcard_window: str = ""          # the wildcard_window parameter used this investigation

    sampling: SamplingStats = field(default_factory=SamplingStats)
