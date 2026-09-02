"""Queries — the 7 investigation intents + 2 control operations, and their results.

Investigation intents  → mint Observations (evidence)
Control operations     → NEVER mint Observations (used to license VALID_NEGATIVE)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.entities import EntityRef
from hunting.contracts.cells import EventFamily


class QueryOutcome(str, Enum):
    ROWS = "rows"                      # matching events found
    VALID_NEGATIVE = "valid_negative"  # confirmed absence — requires 3-stage control
    UNKNOWN = "unknown"                # cannot determine (source dead, truncated, etc.)


class DiagnosticClass(str, Enum):
    RETRYABLE = "retryable"   # cell stays UNEXPLORED, retry up to 2 times
    PERMANENT = "permanent"   # cell → UNREACHABLE


class Diagnostic(str, Enum):
    # Retryable diagnostics
    QUERY_FAILED = "query_failed"
    SOURCE_UNHEALTHY = "source_unhealthy"
    PARTIAL_RESULT = "partial_result"
    # Permanent diagnostics
    RETENTION_EXPIRED = "retention_expired"
    OUT_OF_WINDOW = "out_of_window"
    SOURCE_UNAVAILABLE = "source_unavailable"
    PARSE_FAILED = "parse_failed"

    @property
    def diagnostic_class(self) -> DiagnosticClass:
        _retryable = {
            Diagnostic.QUERY_FAILED,
            Diagnostic.SOURCE_UNHEALTHY,
            Diagnostic.PARTIAL_RESULT,
        }
        return DiagnosticClass.RETRYABLE if self in _retryable else DiagnosticClass.PERMANENT


class QueryIntent(str, Enum):
    """The 9 query operations: 7 investigation intents + 2 control operations.

    Investigation intents mint Observations.
    Control operations NEVER mint Observations — they only return metadata
    (counts, field presence) to license VALID_NEGATIVE outcomes.
    """
    # --- Investigation intents (mint Observations) ---
    PROCESS_LINEAGE = "ProcessLineage"
    LOGON_HISTORY = "LogonHistory"
    NETWORK_CONNECTIONS = "NetworkConnections"
    PERSISTENCE_ARTIFACTS = "PersistenceArtifacts"
    FILE_WRITES = "FileWrites"
    DNS_QUERIES = "DNSQueries"
    BROAD_SWEEP = "BroadSweep"          # wildcard sweep; only intent that allows ANY entity

    # --- Control operations (never mint Observations) ---
    ANY_EVENT_CONTROL = "AnyEventControl"       # is source alive for host+window?
    ANY_EVENT_OF_FAMILY = "AnyEventOfFamily"    # is family collected? is field present?


CONTROL_INTENTS = {QueryIntent.ANY_EVENT_CONTROL, QueryIntent.ANY_EVENT_OF_FAMILY}
INVESTIGATION_INTENTS = set(QueryIntent) - CONTROL_INTENTS


class QueryGenerator(str, Enum):
    TEMPLATE = "template"  # cost = 1
    LLM = "llm"            # cost = 2 — fallback for novel intents only (<30% target)


@dataclass(frozen=True)
class Query:
    """A single query issued to a backend source."""
    id: str
    intent: QueryIntent
    entity: EntityRef        # ANY allowed ONLY for BroadSweep
    source: str
    event_family: EventFamily
    window: str              # ISO 8601 interval "start/end"
    backend: str
    generated_by: QueryGenerator
    cost: int                # 1 = template, 2 = LLM fallback
    limit: int | None = None


@dataclass
class QueryResult:
    """Result of an investigation query.

    CRITICAL: complete=True ONLY when EOF is established
    (via limit+1 trick, or backend has_more=False).
    complete=False (PARTIAL) means:
      - MAY yield CONFIRMED if a match is found
      - NEVER yields REFUTED or VALID_NEGATIVE
      - cell transitions to PARTIAL state, then bucket split
    """
    query_id: str
    outcome: QueryOutcome
    executed_ok: bool
    complete: bool                             # True ONLY when EOF established
    diagnostic: Diagnostic | None = None
    diagnostic_class: DiagnosticClass | None = None
    control_query_ids: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] | None = None  # raw rows — NEVER forwarded to LLM
    truncation_reason: str | None = None


@dataclass
class ControlResult:
    """Result of a control operation (AnyEventControl or AnyEventOfFamily).

    Controls return metadata only — no evidence rows, no Observations minted.
    If controls minted observations they would pollute unattributed and inflate T1.
    """
    query_id: str
    operation: QueryIntent   # must be ANY_EVENT_CONTROL or ANY_EVENT_OF_FAMILY
    executed_ok: bool
    count: int               # event count; 0 = source dead or family not collected
    field_present: dict[str, bool] | None = None  # only for AnyEventOfFamily
    diagnostic: Diagnostic | None = None
