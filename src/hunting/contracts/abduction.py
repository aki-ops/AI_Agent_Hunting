"""Abduction runtime state and tracking."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AbductionRuntime:
    """Mutable runtime tracking for M2 Abduction lifecycle.

    Load-bearing distinction:
      unattributed != pending_for_abduction
    An observation may remain unattributed in the M1 ledger, but does not
    trigger immediate M2 re-invocation once processed in an epoch.
    """
    epoch: int = 0
    pending_observation_ids: set[str] = field(default_factory=set)
    processed_observation_ids: set[str] = field(default_factory=set)
    last_context_hash: str | None = None
    calls: int = 0
    failures: int = 0
    last_call_turn: int | None = None


__all__ = ["AbductionRuntime"]
