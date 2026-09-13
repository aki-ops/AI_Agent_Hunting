"""ObservationClass and Orthogonal Status Axes Contracts.

Defines:
- ObservationClass: The 8-rung ladder of query outcomes.
- 4 Orthogonal Status Axes: ExecutionStatus, CoverageStatus, ProofStatus, RouteStatus.
- TriStatus: Explicit decoupling of (execution_complete, proof_complete, route_exhausted).
- ActionSignature: Deterministic execution signature for loop detection and progress tracking.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ObservationClass(str, Enum):
    """Deterministic classification ladder for query results."""

    QUERY_INVALID = "QUERY_INVALID"
    """AST validation failure, safety policy violation, or unauthorized role."""

    QUERY_FAILURE = "QUERY_FAILURE"
    """Execution error, adapter/provider crash, syntax rejection."""

    PARTIAL = "PARTIAL"
    """Incomplete execution: truncation, timeout, limit hit, or provider partition."""

    EMPTY = "EMPTY"
    """Execution complete with zero rows matching the query envelope."""

    CONTRADICTORY = "CONTRADICTORY"
    """Returned observations conflict with verified bindings, temporal causality, or ground truth."""

    AMBIGUOUS = "AMBIGUOUS"
    """Multiple candidate bindings found with no clear winner; requires semantic discrimination."""

    PROOF_GAP = "PROOF_GAP"
    """Candidates/rows found, but ProofContract semantics (event type, field mapping, temporal binding)
    are missing or unverified."""

    VERIFIED = "VERIFIED"
    """ProofContract fully satisfied by native event semantics and directional bindings."""

    CANDIDATES = "CANDIDATES"
    """Extracted plausible candidate bindings awaiting proof verification."""


class ExecutionStatus(str, Enum):
    """Orthogonal axis: Low-level query execution state."""

    NOT_STARTED = "NOT_STARTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CoverageStatus(str, Enum):
    """Orthogonal axis: Search space coverage within the declared envelope."""

    UNKNOWN = "UNKNOWN"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"
    UNREACHABLE = "UNREACHABLE"


class ProofStatus(str, Enum):
    """Orthogonal axis: Epistemic proof state."""

    NOT_ASSESSED = "NOT_ASSESSED"
    RETRIEVAL_ONLY = "RETRIEVAL_ONLY"
    PROOF_GAP = "PROOF_GAP"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"


class RouteStatus(str, Enum):
    """Orthogonal axis: Telemetry route operational state."""

    UNPLANNED = "UNPLANNED"
    ACTIVE = "ACTIVE"
    EXHAUSTED = "EXHAUSTED"
    NO_PROGRESS = "NO_PROGRESS"


@dataclass
class TriStatus:
    """Explicit container for the 3 independent boolean axes.

    Invariant:
    execution_complete != proof_complete != route_exhausted.
    PARTIAL + 0 rows != BOUNDED_NOT_FOUND.
    """

    execution_complete: bool = False
    proof_complete: bool = False
    route_exhausted: bool = False

    def is_bounded_not_found(self, negative_license_granted: bool) -> bool:
        """Only true when all routes are exhausted, execution complete, and negative license granted."""
        return (
            self.execution_complete
            and self.route_exhausted
            and not self.proof_complete
            and negative_license_granted
        )


@dataclass(frozen=True)
class ActionSignature:
    """Deterministic signature of an investigation action for cycle and progress tracking."""

    goal_id: str
    op_id: str
    scope: str
    source_id: str
    stage: str
    binding_hash: str
    time_window: str
    hints_hash: str
    cursor: str | None = None
    mode: str = "retrieval"

    def compute_hash(self) -> str:
        """Compute SHA256 fingerprint of the canonical tuple."""
        canonical_str = (
            f"{self.goal_id}|{self.op_id}|{self.scope}|{self.source_id}|{self.stage}|"
            f"{self.binding_hash}|{self.time_window}|{self.hints_hash}|{self.cursor}|{self.mode}"
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @classmethod
    def from_params(
        cls,
        goal_id: str,
        op_id: str,
        scope: str,
        source_id: str,
        stage: str,
        bindings: dict[str, Any] | None = None,
        time_window: str = "",
        hints: list[str] | None = None,
        cursor: str | None = None,
        mode: str = "retrieval",
    ) -> ActionSignature:
        """Construct from raw parameters with canonicalized hashes."""
        b_str = json.dumps(bindings or {}, sort_keys=True, default=str)
        b_hash = hashlib.sha256(b_str.encode("utf-8")).hexdigest()[:12]
        h_str = json.dumps(hints or [], sort_keys=True, default=str)
        h_hash = hashlib.sha256(h_str.encode("utf-8")).hexdigest()[:12]
        return cls(
            goal_id=goal_id,
            op_id=op_id,
            scope=scope,
            source_id=source_id,
            stage=stage,
            binding_hash=b_hash,
            time_window=time_window,
            hints_hash=h_hash,
            cursor=cursor,
            mode=mode,
        )
