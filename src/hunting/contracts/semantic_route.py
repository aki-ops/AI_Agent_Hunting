"""Serializable proof-aware readiness and semantic route state."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SemanticRouteStatus(str, Enum):
    UNPLANNED = "UNPLANNED"
    PLANNED = "PLANNED"
    ATTEMPTED_EMPTY = "ATTEMPTED_EMPTY"
    ATTEMPTED_PARTIAL = "ATTEMPTED_PARTIAL"
    CANDIDATE_OBSERVED = "CANDIDATE_OBSERVED"
    PROOF_GAP = "PROOF_GAP"
    CAPABILITY_GAP = "CAPABILITY_GAP"
    VERIFIED = "VERIFIED"
    ROUTE_EXHAUSTED = "ROUTE_EXHAUSTED"


class SemanticTerminalCause(str, Enum):
    USER_DECISION = "USER_DECISION"
    UNSUPPORTED = "UNSUPPORTED"
    UNREACHABLE = "UNREACHABLE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class CapabilityReadiness(str, Enum):
    CAPABILITY_GAP = "CAPABILITY_GAP"
    RETRIEVAL_CAPABLE = "RETRIEVAL_CAPABLE"
    PROOF_CAPABLE = "PROOF_CAPABLE"
    ROUTE_EXHAUSTED = "ROUTE_EXHAUSTED"


@dataclass(frozen=True)
class SemanticAttempt:
    """One immutable bounded provider attempt for a semantic relation."""

    attempt_id: str
    goal_id: str
    operation_id: str
    source_id: str
    stage_id: str
    result_complete: bool
    row_count: int
    trigger_reason: str
    no_progress_signature: str
    query_id: str | None = None
    schema_fingerprint: str = ""
    alternatives_considered: tuple[str, ...] = ()
    negative_evidence_capable: bool = False

    def __post_init__(self) -> None:
        for name in (
            "attempt_id", "goal_id", "operation_id", "source_id", "stage_id",
            "trigger_reason", "no_progress_signature",
        ):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must not be empty")
        if self.row_count < 0:
            raise ValueError("row_count must not be negative")
        object.__setattr__(self, "alternatives_considered", tuple(self.alternatives_considered))

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "goal_id": self.goal_id,
            "operation_id": self.operation_id,
            "source_id": self.source_id,
            "schema_fingerprint": self.schema_fingerprint,
            "stage_id": self.stage_id,
            "query_id": self.query_id,
            "result_complete": self.result_complete,
            "row_count": self.row_count,
            "trigger_reason": self.trigger_reason,
            "no_progress_signature": self.no_progress_signature,
            "alternatives_considered": list(self.alternatives_considered),
            "negative_evidence_capable": self.negative_evidence_capable,
        }


@dataclass
class SemanticRouteAssessment:
    """Independent execution, proof, and route-exhaustion state for one goal."""

    goal_id: str
    relation: str
    status: SemanticRouteStatus = SemanticRouteStatus.UNPLANNED
    execution_complete: bool = False
    proof_complete: bool = False
    route_exhausted: bool = False
    readiness: CapabilityReadiness = CapabilityReadiness.CAPABILITY_GAP
    attempts: list[SemanticAttempt] = field(default_factory=list)
    proof_gaps: list[str] = field(default_factory=list)
    capability_gaps: list[str] = field(default_factory=list)
    terminal_cause: SemanticTerminalCause | None = None

    def __post_init__(self) -> None:
        if not str(self.goal_id).strip() or not str(self.relation).strip():
            raise ValueError("goal_id and relation must not be empty")
        if self.proof_complete and not self.execution_complete:
            raise ValueError("proof_complete requires execution_complete")
        if self.status == SemanticRouteStatus.VERIFIED and not self.proof_complete:
            raise ValueError("VERIFIED requires proof_complete")
        if self.status == SemanticRouteStatus.ROUTE_EXHAUSTED and not self.route_exhausted:
            raise ValueError("ROUTE_EXHAUSTED requires route_exhausted")

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "relation": self.relation,
            "status": self.status.value,
            "execution_complete": self.execution_complete,
            "proof_complete": self.proof_complete,
            "route_exhausted": self.route_exhausted,
            "readiness": self.readiness.value,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "proof_gaps": list(self.proof_gaps),
            "capability_gaps": list(self.capability_gaps),
            "terminal_cause": self.terminal_cause.value if self.terminal_cause else None,
        }


__all__ = [
    "CapabilityReadiness",
    "SemanticAttempt",
    "SemanticRouteAssessment",
    "SemanticRouteStatus",
    "SemanticTerminalCause",
]
