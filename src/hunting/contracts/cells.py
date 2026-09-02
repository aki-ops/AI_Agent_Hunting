"""Cells — the unit of the queryable universe.

A Cell represents one (source, event_family, entity, time_bucket) tuple.
The agent tracks which cells have been explored, partially explored,
or remain unexplored to build the CoverageBound.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

from hunting.contracts.entities import EntityRef, AnyEntity


class EventFamily(str, Enum):
    """Closed enum of log event families the system can query.

    Comes from the capability registry — not all sources support all families.
    The LLM MUST pick from this enum when generating expectations; it cannot
    invent new family names (injection / hallucination risk).
    Adding new telemetry types requires updating both this enum AND registry.yaml.
    """
    PROCESS_CREATION = "process_creation"
    LOGON = "logon"
    NETWORK_BIND = "network_bind"
    FILE_WRITE = "file_write"
    REGISTRY = "registry"
    DNS = "dns"
    SCHEDULED_TASK = "scheduled_task"


class CellState(str, Enum):
    """Exploration state of a cell.

    Three active states, one terminal:
      UNEXPLORED  — not yet queried, or last query had a retryable failure
      EXPLORED    — queried with complete=True result (ROWS or VALID_NEGATIVE)
      PARTIAL     — queried, got rows, but result was truncated (hit sweep_limit)
                    Re-query = bucket split, NEVER a re-issue of the same query
      UNREACHABLE — excluded by capability / coverage / retention / permanent failure
    """
    UNEXPLORED = "unexplored"
    EXPLORED = "explored"
    PARTIAL = "partial"
    UNREACHABLE = "unreachable"


@dataclass
class Cell:
    """A searchable unit: (source, event_family, entity, time_bucket).

    Identity fields (treat as immutable):
        source, event_family, entity, time_bucket

    Mutable state fields (change as investigation progresses):
        state, split_parent

    NOT frozen=True because state must change during an investigation.
    """
    source: str            # e.g. "winsec"
    event_family: EventFamily
    entity: EntityRef      # concrete entity OR AnyEntity for wildcard cells
    time_bucket: str       # ISO 8601 interval "start/end"
    state: CellState = CellState.UNEXPLORED
    split_parent: bool = False  # True when this cell has been split into two child cells

    @property
    def is_wildcard(self) -> bool:
        """True if this is a wildcard cell (entity = ANY)."""
        return isinstance(self.entity, AnyEntity)
