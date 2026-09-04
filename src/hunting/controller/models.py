"""Action Controller models and budget ledger.

Fulfills Phase 4 requirements:
- Defines canonical HuntActions.
- Enforces strict budgets across turns, queries, LLM calls, scan cells, and runtime.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class HuntAction(str, Enum):
    """Canonical action taxonomy in strict execution order."""
    TEST = "TEST"
    CONTROL = "CONTROL"
    EXPAND = "EXPAND"
    DISCOVER = "DISCOVER"
    PIVOT = "PIVOT"
    REFINE = "REFINE"
    STOP = "STOP"


@dataclass
class HuntBudgetLedger:
    """Tracks and enforces execution resource budgets."""
    max_turns: int = 15
    max_queries: int = 60
    max_llm_calls: int = 3
    max_scan_cells: int = 100
    max_runtime_seconds: float = 300.0

    current_turn: int = 0
    query_count: int = 0
    llm_calls: int = 0
    scan_cells: int = 0
    start_time: float = field(default_factory=time.time)

    def record_turn(self) -> None:
        """Increment turn count."""
        self.current_turn += 1

    def record_query(self, count: int = 1) -> None:
        """Increment query count."""
        self.query_count += count

    def record_llm_call(self) -> None:
        """Increment LLM call count."""
        self.llm_calls += 1

    def record_scan_cell(self, count: int = 1) -> None:
        """Increment scanned cell count."""
        self.scan_cells += count

    @property
    def elapsed_seconds(self) -> float:
        """Elapsed execution runtime in seconds."""
        return time.time() - self.start_time

    @property
    def is_turn_exhausted(self) -> bool:
        return self.current_turn >= self.max_turns

    @property
    def is_query_exhausted(self) -> bool:
        return self.query_count >= self.max_queries

    @property
    def is_llm_exhausted(self) -> bool:
        return self.llm_calls >= self.max_llm_calls

    @property
    def is_scan_exhausted(self) -> bool:
        return self.scan_cells >= self.max_scan_cells

    @property
    def is_runtime_exhausted(self) -> bool:
        return self.elapsed_seconds >= self.max_runtime_seconds

    @property
    def is_exhausted(self) -> bool:
        """True if any budget dimension is exhausted."""
        return (
            self.is_turn_exhausted
            or self.is_query_exhausted
            or self.is_llm_exhausted
            or self.is_scan_exhausted
            or self.is_runtime_exhausted
        )


__all__ = ["HuntAction", "HuntBudgetLedger"]
