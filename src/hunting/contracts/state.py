"""Top-level state types: Alert, Seed, InvestigationState, FinalAccount.

InvestigationState is the single mutable object passed through the entire loop.
FinalAccount is the immutable output emitted at every terminal state.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.entities import EntityRef
from hunting.contracts.observations import Observation
from hunting.contracts.explanations import Explanation
from hunting.contracts.expectations import Expectation
from hunting.contracts.queries import Query, QueryResult, ControlResult
from hunting.contracts.conflicts import Conflict, HumanInput
from hunting.contracts.coverage import CoverageBound


@dataclass
class Alert:
    """Incoming security alert — the starting point of every investigation.

    raw is retained in protected storage and NEVER forwarded to the LLM.
    """
    id: str
    raw: str           # raw alert text — injection boundary, never to LLM
    source: str
    received_at: str   # ISO 8601
    fields: dict[str, Any] = field(default_factory=dict)
    free_text: str | None = None


@dataclass(frozen=True)
class TimeWindow:
    """A time interval."""
    start: str  # ISO 8601
    end: str    # ISO 8601

    def __str__(self) -> str:
        return f"{self.start}/{self.end}"


@dataclass
class Seed:
    """Starting scope extracted deterministically from the alert.

    entities MAY be empty — this is legal and triggers the entity-free path,
    which bootstraps via wildcard cells (BroadSweep).
    """
    entities: list[EntityRef] = field(default_factory=list)  # may be empty
    window: TimeWindow | None = None
    source: str = ""
    raw_ref: str = ""  # alert ID back-reference


@dataclass
class DarkSource:
    """A required source that was unavailable for a critical window."""
    source: str
    window: str
    demanded_by: list[str] = field(default_factory=list)  # expectation IDs that need this

    @property
    def critical(self) -> bool:
        """True if at least one expectation needs this source."""
        return len(self.demanded_by) > 0


class Disposition(str, Enum):
    """The final verdict — computed ONCE by M4's disposition(), rendered by M5.

    UNKNOWN vs INSUFFICIENT_EVIDENCE (load-bearing distinction):
      UNKNOWN               — a surviving explanation leads AND its class IS UNKNOWN
                              → statement about the attack (novel, evidence-supported)
      INSUFFICIENT_EVIDENCE — nothing can be chosen (no survivors, dark source, etc.)
                              → statement about the investigation
    """
    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"                          # surviving UNKNOWN-class explanation
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # investigation limitation
    CONFLICTED = "conflicted"                    # unresolved conflict or cross-class tie


class TerminalState(str, Enum):
    STOP_RESOLVED = "stop_resolved"  # no blockers + no disposition-changing action available
    STOP_BOUNDED = "stop_bounded"    # blockers remain, no action can resolve them


@dataclass(frozen=True)
class ChainLink:
    """One claim in the final account, linked to the observations that support it."""
    claim: str
    observation_ids: tuple[str, ...]  # tuple so ChainLink stays hashable


@dataclass
class FinalAccount:
    """The output of a completed investigation.

    Mandatory on every terminal path: disposition, terminal_state, coverage_bound.
    Confirmation required for: MALICIOUS, CONFLICTED, every STOP_BOUNDED.
    """
    disposition: Disposition
    terminal_state: TerminalState
    chain: list[ChainLink] = field(default_factory=list)
    coverage_bound: CoverageBound = field(default_factory=CoverageBound)
    residual: str = ""           # what remains unresolved
    human_confirmed: bool = False


@dataclass
class InvestigationState:
    """Complete mutable state of one investigation — passed through the entire loop."""
    registry: Any                                         # Registry (imported lazily to avoid circular)
    seed: Seed = field(default_factory=Seed)
    observations: list[Observation] = field(default_factory=list)
    explanations: list[Explanation] = field(default_factory=list)
    expectations: list[Expectation] = field(default_factory=list)
    queries: list[Query] = field(default_factory=list)
    query_results: list[QueryResult] = field(default_factory=list)
    control_results: list[ControlResult] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    dark_sources: list[DarkSource] = field(default_factory=list)
    unattributed: list[str] = field(default_factory=list)   # observation IDs not yet attributed
    abduced_over: list[str] = field(default_factory=list)   # observation IDs already abduced over
    human_inputs: list[HumanInput] = field(default_factory=list)
    # Runtime health — mutable, NOT in registry
    source_health: dict[str, bool] = field(default_factory=dict)
    family_collection: dict[str, bool] = field(default_factory=dict)
    field_presence: dict[str, dict[str, bool]] = field(default_factory=dict)
    degraded_families: list[tuple[str, str, float]] = field(default_factory=list)
    coverage_bound: CoverageBound = field(default_factory=CoverageBound)
    stop: TerminalState | None = None
    turn: int = 0
    query_count: int = 0
