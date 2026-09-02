"""Conflicts and human input — irreconcilable disagreements and analyst interaction."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class HumanInputType(str, Enum):
    CONTEXT = "context"
    HYPOTHESIS = "hypothesis"
    CHALLENGE = "challenge"
    RESOLUTION = "resolution"
    CONFIRMATION = "confirmation"


@dataclass
class Conflict:
    """An irreconcilable disagreement between two OBSERVED sources.

    When created:
      - Neither explanation is weakened — both stay LIVE
      - T3 escalation trigger fires IMMEDIATELY
      - Source reliability is an ordinal preference for ordering tests,
        never for adjudicating which source wins

    Resolution requires human analyst input; cannot be bypassed.
    """
    id: str
    observation_ids: list[str] = field(default_factory=list)
    explanation_ids: list[str] = field(default_factory=list)
    resolved: bool = False
    resolved_by: str | None = None  # HumanInput.id that resolved this


@dataclass(frozen=True)
class HumanInput:
    """Input from an analyst — always TESTIMONY, never elevated to OBSERVED.

    Rules:
      - Passes identical constraints as machine proposals
      - Disagreement creates a Conflict, never overwrites existing evidence
      - Analyst may force continuation, bounded termination, or conflict resolution
      - Analyst may NEVER force STOP_RESOLVED while a blocker remains
      - Confirmation is mandatory for: MALICIOUS disposition, STOP_BOUNDED, CONFLICTED
    """
    id: str
    content: str
    type: HumanInputType
    analyst: str    # analyst identifier
    timestamp: str  # ISO 8601
