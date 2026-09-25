"""Behavior goals need a comparator. A known-benign hit is a citation, not a verdict."""
from __future__ import annotations

from typing import Any


def goal_class_for(goal: Any, goal_graph: Any = None) -> str:
    explicit = str(getattr(goal, "goal_class", "") or "")
    if explicit in {"artifact", "behavior"}:
        return explicit
    goal_id = str(getattr(goal, "id", "") or getattr(goal, "goal_id", "") or "")
    for item in getattr(goal_graph, "relations", ()) or ():
        if goal_id and getattr(item, "id", "") == goal_id:
            return str(getattr(item, "goal_class", "artifact") or "artifact")
    return "artifact"


def comparator_satisfied(comparator: dict | None) -> bool:
    if not comparator:
        return False
    return bool(
        comparator.get("first_seen")
        or comparator.get("rare")
        or comparator.get("baseline_deviation")
    )


def derive_comparator(
    rows: list[dict],
    history_rows: list[dict],
    baseline_values: tuple[str, ...] | list[str],
    *,
    window_start: str,
    window_end: str,
    value: str,
) -> dict[str, bool]:
    """Compute first-seen, rarity, and baseline deviation from rows. No caller flag is required."""
    stamps = [
        str(row.get("timestamp") or row.get("first_seen") or "")
        for row in [*history_rows, *rows]
        if str(row.get("account") or row.get("user") or row.get("username") or "") == value
    ]
    stamps = [item for item in stamps if item]
    in_window = [item for item in stamps if (not window_start or item >= window_start) and (not window_end or item <= window_end)]
    before = [item for item in stamps if window_start and item < window_start]
    population = {
        str(row.get("account") or row.get("user") or row.get("username") or "")
        for row in history_rows
    }
    population.discard("")
    return {
        "first_seen": bool(in_window) and not before,
        "rare": len(in_window) == 1 and len(population) > 20,
        "baseline_deviation": bool(baseline_values) and value not in set(baseline_values),
    }


def proof_allowed(goal: Any, goal_graph: Any = None, comparator: dict | None = None) -> bool:
    if goal_class_for(goal, goal_graph) != "behavior":
        return True
    return comparator_satisfied(comparator)


def benign_citation(value: str, baseline_values: tuple[str, ...] | list[str]) -> str | None:
    if str(value) in set(baseline_values):
        return f"known-benign:{value}"
    return None
