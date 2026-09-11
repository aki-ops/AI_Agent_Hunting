"""Provider-neutral query and result contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.entities import EntityRef
from hunting.contracts.expectations import EvidenceRequirement


@dataclass(frozen=True)
class RetrievalStage:
    """One bounded retrieval stage; only declared hint keys may be removed."""

    stage_id: str
    remove_constraint_keys: tuple[str, ...] = ()
    proof_mode: str = "retrieval_only"
    audit_reason: str = ""

    def __post_init__(self) -> None:
        if not str(self.stage_id).strip():
            raise ValueError("stage_id must not be empty")
        if self.proof_mode not in {"retrieval_only", "proof_capable"}:
            raise ValueError("proof_mode must be retrieval_only or proof_capable")
        keys = tuple(dict.fromkeys(str(key).strip().casefold() for key in self.remove_constraint_keys if str(key).strip()))
        object.__setattr__(self, "remove_constraint_keys", keys)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "remove_constraint_keys": list(self.remove_constraint_keys),
            "proof_mode": self.proof_mode,
            "audit_reason": self.audit_reason,
        }


@dataclass(frozen=True)
class RetrievalPolicy:
    """Ordered, finite recovery policy for one provider operation."""

    stages: tuple[RetrievalStage, ...] = ()
    max_attempts: int = 1
    preserve_bindings: bool = True
    preserve_scope: bool = True
    preserve_time_window: bool = True
    preserve_projection: bool = True
    no_progress_fields: tuple[str, ...] = ("operation", "source", "binding", "time", "stage")

    def __post_init__(self) -> None:
        stages = tuple(self.stages)
        ids = [stage.stage_id for stage in stages]
        if len(ids) != len(set(ids)):
            raise ValueError("retrieval stage IDs must be unique")
        if self.max_attempts <= 0 or self.max_attempts > 32:
            raise ValueError("max_attempts must be between 1 and 32")
        if not (self.preserve_bindings and self.preserve_scope and self.preserve_time_window and self.preserve_projection):
            raise ValueError("retrieval policy must preserve bindings, scope, time and projection")
        object.__setattr__(self, "stages", stages)
        object.__setattr__(self, "no_progress_fields", tuple(dict.fromkeys(str(item).strip() for item in self.no_progress_fields if str(item).strip())))

    def to_dict(self) -> dict[str, Any]:
        return {
            "stages": [stage.to_dict() for stage in self.stages],
            "max_attempts": self.max_attempts,
            "preserve_bindings": self.preserve_bindings,
            "preserve_scope": self.preserve_scope,
            "preserve_time_window": self.preserve_time_window,
            "preserve_projection": self.preserve_projection,
            "no_progress_fields": list(self.no_progress_fields),
        }




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
    ABDUCTION_TIMEOUT = "abduction_timeout"
    ABDUCTION_FAILED = "abduction_failed"
    UNREACHABLE = "unreachable"

    @property
    def diagnostic_class(self) -> DiagnosticClass:
        retryable = {
            Diagnostic.QUERY_FAILED,
            Diagnostic.SOURCE_UNHEALTHY,
            Diagnostic.PARTIAL_RESULT,
            Diagnostic.ABDUCTION_TIMEOUT,
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
    semantic_intents: tuple[str, ...] = ()
    input_entity_kinds: tuple[str, ...] = ()
    output_entity_kinds: tuple[str, ...] = ()
    output_fields: tuple[str, ...] = ()
    output_fact_kinds: tuple[str, ...] = ()
    # Canonical relations guaranteed by this operation.  These are semantic
    # contracts, not native field names and not operation-name heuristics.
    guaranteed_relations: tuple[str, ...] = ()
    # Provider-neutral semantic roles produced by this operation.  These are
    # deliberately separate from output_fields: the latter are native schema
    # names, while roles are the contract consumed by the planner.
    input_roles: tuple[str, ...] = ()
    output_roles: tuple[str, ...] = ()
    native_field_bindings: dict[str, tuple[str, ...]] = field(default_factory=dict)
    output_value_bindings: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # Entity type for each logical output port.  ``output_value_bindings``
    # contains provider field aliases; this map says what those aliases mean
    # semantically.  Keeping the two separate prevents a row containing both
    # ``user`` and ``host`` from being bound to the wrong next step.
    output_binding_entity_kinds: dict[str, str] = field(default_factory=dict)
    # Canonical keys of semantic restrictions that this operation can
    # translate and verify.  An operation that does not advertise a key must
    # not be selected for a goal carrying that restriction.
    supported_constraints: tuple[str, ...] = ()
    # Restrictions that can safely narrow a query but are not, by themselves,
    # proof of the restriction.  The report must keep these epistemically
    # separate from ``supported_constraints``.
    searchable_constraints: tuple[str, ...] = ()
    query_builder: str = ""
    completeness: str = ""
    expected_cost: int | None = None
    # Compatibility aliases may remain executable for old callers, but the
    # semantic planner must prefer a canonical operation whenever one exists.
    # This is declared metadata, not an operation-name heuristic in the
    # planner.
    legacy_alias: bool = False
    # Declarative finite recovery contract.  New semantic execution consumes
    # this policy; the boolean below remains only as a migration input for old
    # descriptors and never authorizes an unbounded query.
    retrieval_policy: RetrievalPolicy | None = None
    allow_constraint_relaxation: bool = True
    # Whether cited observations can prove the declared relation rather than
    # serving only as candidate retrieval.  Constraint proof remains governed
    # separately by ``supported_constraints``.
    proof_mode: str = "relation_observable"
    schema_fingerprint: str = ""
    temporal_roles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    action_roles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    state_roles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    artifact_identity_roles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    correlation_roles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # A complete-empty result may support a semantic negative only when this
    # provider contract explicitly licenses that inference. Route exhaustion is
    # checked separately by the controller/reporter.
    negative_evidence_capable: bool = False
    # Explicit source reference for a probed runtime mapping. This is kept
    # separate from the opaque operation ID and is never parsed heuristically.
    runtime_source_id: str = ""

    def __post_init__(self) -> None:
        if self.proof_mode not in {"retrieval_only", "relation_observable"}:
            raise ValueError("proof_mode must be retrieval_only or relation_observable")
        for name in (
            "native_field_bindings", "output_value_bindings", "temporal_roles",
            "action_roles", "state_roles", "artifact_identity_roles", "correlation_roles",
        ):
            value = {
                str(role): tuple(str(field_name) for field_name in fields)
                for role, fields in dict(getattr(self, name)).items()
            }
            object.__setattr__(self, name, value)
        policy = self.retrieval_policy
        if policy is None and self.allow_constraint_relaxation and self.searchable_constraints:
            policy = RetrievalPolicy(
                stages=(
                    RetrievalStage("narrow", (), "retrieval_only", "apply declared searchable predicates"),
                    RetrievalStage(
                        "base_relation",
                        tuple(self.searchable_constraints),
                        "retrieval_only",
                        "remove declared retrieval-only predicates after complete-empty",
                    ),
                ),
                max_attempts=2,
            )
        object.__setattr__(self, "retrieval_policy", policy)


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
    logical_plan_id: str | None = None
    native_query: str | None = None
    provider: str | None = None
    index: str | None = None
    sourcetype: str | None = None
    execution_time_ms: float = 0.0
    row_count: int = 0
    raw_count: int | None = None
    coverage: dict[str, Any] | None = None
    sid: str | None = None
    scan_count: int | None = None


@dataclass
class ControlResult:
    query_id: str
    operation: QueryIntent
    executed_ok: bool
    count: int | None = None
    field_present: dict[str, bool] | None = None
    predicate_observable: bool | None = None
    diagnostic: Diagnostic | None = None
