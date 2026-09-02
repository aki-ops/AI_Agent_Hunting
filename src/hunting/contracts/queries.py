"""Provider-neutral query and result contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.entities import EntityRef
from hunting.contracts.expectations import EvidenceRequirement


class QueryOutcome(str, Enum):
    ROWS = "rows"
    VALID_NEGATIVE = "valid_negative"
    UNKNOWN = "unknown"


class DiagnosticClass(str, Enum):
    RETRYABLE = "retryable"
    PERMANENT = "permanent"


class Diagnostic(str, Enum):
    QUERY_FAILED = "query_failed"
    SOURCE_UNHEALTHY = "source_unhealthy"
    PARTIAL_RESULT = "partial_result"
    RETENTION_EXPIRED = "retention_expired"
    OUT_OF_WINDOW = "out_of_window"
    SOURCE_UNAVAILABLE = "source_unavailable"
    UNQUERYABLE = "unqueryable"
    UNSUPPORTED_REQUIREMENT = "unsupported_requirement"
    PARSE_FAILED = "parse_failed"

    @property
    def diagnostic_class(self) -> DiagnosticClass:
        retryable = {
            Diagnostic.QUERY_FAILED,
            Diagnostic.SOURCE_UNHEALTHY,
            Diagnostic.PARTIAL_RESULT,
        }
        return DiagnosticClass.RETRYABLE if self in retryable else DiagnosticClass.PERMANENT


class QueryIntent(str, Enum):
    PROCESS_LINEAGE = "ProcessLineage"
    LOGON_HISTORY = "LogonHistory"
    NETWORK_CONNECTIONS = "NetworkConnections"
    PERSISTENCE_ARTIFACTS = "PersistenceArtifacts"
    FILE_WRITES = "FileWrites"
    DNS_QUERIES = "DNSQueries"
    BROAD_SWEEP = "BroadSweep"
    SCOPE_HEALTH_CONTROL = "ScopeHealthControl"
    ANY_RECORD_IN_SCOPE = "AnyRecordInScope"
    PREDICATE_OBSERVABILITY_CONTROL = "PredicateObservabilityControl"


CONTROL_INTENTS = {
    QueryIntent.SCOPE_HEALTH_CONTROL,
    QueryIntent.ANY_RECORD_IN_SCOPE,
    QueryIntent.PREDICATE_OBSERVABILITY_CONTROL,
}
INVESTIGATION_INTENTS = set(QueryIntent) - CONTROL_INTENTS


class QueryGenerator(str, Enum):
    TEMPLATE = "template"
    LLM = "llm"


@dataclass(frozen=True)
class ProviderOperation:
    id: str
    provider_id: str
    scope_ids: tuple[str, ...]
    params_schema: dict[str, Any] = field(default_factory=dict)
    pagination: str = "none"
    limit_semantics: str = "provider-defined"
    rate_limit: dict[str, Any] | None = None


@dataclass(frozen=True)
class CapabilityBinding:
    evidence_requirement: EvidenceRequirement
    provider_id: str
    operation_id: str
    parameter_mapping: dict[str, str] = field(default_factory=dict)
    confidence: str = "EXACT"


@dataclass(frozen=True)
class Query:
    id: str
    intent: QueryIntent
    entity: EntityRef
    provider_scope_id: str
    operation_id: str
    evidence_requirement: EvidenceRequirement | None
    window: str
    backend: str
    generated_by: QueryGenerator
    cost: int
    limit: int | None = None


@dataclass
class QueryResult:
    query_id: str
    outcome: QueryOutcome
    executed_ok: bool
    complete: bool
    diagnostic: Diagnostic | None = None
    diagnostic_class: DiagnosticClass | None = None
    control_query_ids: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] | None = None
    observed_fields: list[str] = field(default_factory=list)
    native_types: list[str] = field(default_factory=list)
    cursor: str | None = None
    truncation_reason: str | None = None


@dataclass
class ControlResult:
    query_id: str
    operation: QueryIntent
    executed_ok: bool
    count: int | None = None
    field_present: dict[str, bool] | None = None
    predicate_observable: bool | None = None
    diagnostic: Diagnostic | None = None
