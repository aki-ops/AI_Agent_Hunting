"""Provider-neutral telemetry census and dynamic capability contracts.

These objects deliberately describe what a provider exposes, not what a
source name is assumed to mean.  Semantic labels are proposals until a
provider-side bounded probe validates them.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} must not be empty")
    return text


class FieldRoleStatus(str, Enum):
    """Lifecycle status of a telemetry field's semantic role assignment."""
    UNASSIGNED = "UNASSIGNED"
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    CERTIFIED = "CERTIFIED"


@dataclass(frozen=True)
class TelemetryFieldProfile:

    """Bounded metadata for one native field; values are never raw evidence."""

    field_id: str
    name: str
    primitive_type: str = "unknown"
    coverage: float | None = None
    sample_values: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "field_id", _required(self.field_id, "field_id"))
        object.__setattr__(self, "name", _required(self.name, "name"))
        if self.coverage is not None and not 0 <= float(self.coverage) <= 1:
            raise ValueError("coverage must be between 0 and 1")
        values = tuple(str(v)[:256] for v in self.sample_values[:5])
        object.__setattr__(self, "sample_values", values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_id": self.field_id,
            "name": self.name,
            "primitive_type": self.primitive_type,
            "coverage": self.coverage,
            "sample_values": list(self.sample_values),
        }


@dataclass(frozen=True)
class TelemetrySourceProfile:
    """Observed source/schema metadata used by the source profiler."""

    source_id: str
    provider_id: str
    partition_id: str
    native_type: str
    event_count: int | None = None
    fields: tuple[TelemetryFieldProfile, ...] = ()
    time_start: str | None = None
    time_end: str | None = None
    retention_days: int | None = None
    permissions: tuple[str, ...] = ()
    query_primitives: tuple[str, ...] = ()
    schema_fingerprint: str = ""

    def __post_init__(self) -> None:
        for name in ("source_id", "provider_id", "partition_id", "native_type"):
            object.__setattr__(self, name, _required(getattr(self, name), name))
        if self.event_count is not None and int(self.event_count) < 0:
            raise ValueError("event_count must not be negative")
        fields = tuple(self.fields)
        ids = [item.field_id for item in fields]
        if len(ids) != len(set(ids)):
            raise ValueError("source profile field IDs must be unique")
        object.__setattr__(self, "fields", fields)
        if not self.schema_fingerprint:
            basis = {
                "provider_id": self.provider_id,
                "partition_id": self.partition_id,
                "native_type": self.native_type,
                "fields": [item.to_dict() for item in fields],
            }
            digest = hashlib.sha256(
                json.dumps(basis, sort_keys=True, ensure_ascii=True).encode("utf-8")
            ).hexdigest()[:20]
            object.__setattr__(self, "schema_fingerprint", f"schema-{digest}")

    def field(self, field_id: str) -> TelemetryFieldProfile | None:
        return next((item for item in self.fields if item.field_id == field_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "provider_id": self.provider_id,
            "partition_id": self.partition_id,
            "native_type": self.native_type,
            "event_count": self.event_count,
            "fields": [item.to_dict() for item in self.fields],
            "time_start": self.time_start,
            "time_end": self.time_end,
            "retention_days": self.retention_days,
            "permissions": list(self.permissions),
            "query_primitives": list(self.query_primitives),
            "schema_fingerprint": self.schema_fingerprint,
        }


@dataclass(frozen=True)
class SourceCapabilityProposal:
    """Untrusted LLM proposal; it becomes executable only after a probe."""

    source_id: str
    relation: str
    input_roles: dict[str, str] = field(default_factory=dict)
    output_roles: dict[str, str] = field(default_factory=dict)
    proof_mode: str = "retrieval_only"
    capability_level: str = "RETRIEVAL_CAPABLE"
    probe_kind: str = "cooccurrence"
    projection_roles: tuple[str, ...] = ()
    supported_constraints: tuple[str, ...] = ()
    searchable_constraints: tuple[str, ...] = ()
    temporal_roles: dict[str, str] = field(default_factory=dict)
    action_roles: dict[str, str] = field(default_factory=dict)
    state_roles: dict[str, str] = field(default_factory=dict)
    artifact_identity_roles: dict[str, str] = field(default_factory=dict)
    correlation_roles: dict[str, str] = field(default_factory=dict)
    relaxable_constraint_keys: tuple[str, ...] = ()
    rationale_refs: tuple[str, ...] = ()
    confidence: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _required(self.source_id, "source_id"))
        object.__setattr__(self, "relation", _required(self.relation, "relation").casefold())
        if self.proof_mode not in {"retrieval_only", "relation_observable", "proof_capable", "structurally_valid"}:
            raise ValueError("proof_mode must be retrieval_only, proof_capable, or relation_observable")
        if self.confidence is not None and not 0 <= float(self.confidence) <= 1:
            raise ValueError("confidence must be between 0 and 1")
        object.__setattr__(self, "input_roles", dict(self.input_roles))
        object.__setattr__(self, "output_roles", dict(self.output_roles))

        for name in (
            "temporal_roles", "action_roles", "state_roles",
            "artifact_identity_roles", "correlation_roles",
        ):
            object.__setattr__(self, name, dict(getattr(self, name)))
        supported = tuple(dict.fromkeys(str(key).strip().casefold() for key in self.supported_constraints if str(key).strip()))
        searchable = tuple(dict.fromkeys(str(key).strip().casefold() for key in self.searchable_constraints if str(key).strip()))
        relaxable = tuple(dict.fromkeys(str(key).strip().casefold() for key in self.relaxable_constraint_keys if str(key).strip()))
        if set(relaxable) - set(searchable):
            raise ValueError("relaxable constraints must be declared searchable")
        object.__setattr__(self, "supported_constraints", supported)
        object.__setattr__(self, "searchable_constraints", searchable)
        object.__setattr__(self, "relaxable_constraint_keys", relaxable)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "relation": self.relation,
            "input_roles": dict(self.input_roles),
            "output_roles": dict(self.output_roles),
            "proof_mode": self.proof_mode,
            "probe_kind": self.probe_kind,
            "projection_roles": list(self.projection_roles),
            "supported_constraints": list(self.supported_constraints),
            "searchable_constraints": list(self.searchable_constraints),
            "temporal_roles": dict(self.temporal_roles),
            "action_roles": dict(self.action_roles),
            "state_roles": dict(self.state_roles),
            "artifact_identity_roles": dict(self.artifact_identity_roles),
            "correlation_roles": dict(self.correlation_roles),
            "relaxable_constraint_keys": list(self.relaxable_constraint_keys),
            "rationale_refs": list(self.rationale_refs),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ProbeSpec:
    """Provider-neutral bounded capability probe."""

    source_id: str
    kind: str
    field_ids: tuple[str, ...] = ()
    time_window: str | None = None
    max_rows: int = 20
    timeout_seconds: int = 10

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _required(self.source_id, "source_id"))
        object.__setattr__(self, "kind", _required(self.kind, "kind").casefold())
        if self.max_rows <= 0 or self.max_rows > 1000:
            raise ValueError("max_rows must be between 1 and 1000")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
            raise ValueError("timeout_seconds must be between 1 and 120")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "kind": self.kind,
            "field_ids": list(self.field_ids),
            "time_window": self.time_window,
            "max_rows": self.max_rows,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class RuntimeCapability:
    """Audited capability materialized after proposal validation/probing."""

    capability_id: str
    source_id: str
    provider_id: str
    relation: str
    input_roles: dict[str, str]
    output_roles: dict[str, str]
    status: str
    proof_mode: str
    schema_fingerprint: str
    supported_constraints: tuple[str, ...] = ()
    searchable_constraints: tuple[str, ...] = ()
    temporal_roles: dict[str, str] = field(default_factory=dict)
    action_roles: dict[str, str] = field(default_factory=dict)
    state_roles: dict[str, str] = field(default_factory=dict)
    artifact_identity_roles: dict[str, str] = field(default_factory=dict)
    correlation_roles: dict[str, str] = field(default_factory=dict)
    relaxable_constraint_keys: tuple[str, ...] = ()
    probe_query_id: str | None = None
    diagnostics: tuple[str, ...] = ()
    proof_contract_id: str | None = None
    capability_level: str = "RETRIEVAL_CAPABLE"

    def __post_init__(self) -> None:
        for name in ("capability_id", "source_id", "provider_id", "relation", "status", "proof_mode", "schema_fingerprint"):
            object.__setattr__(self, name, _required(getattr(self, name), name))
        if self.status not in {"VALIDATED", "CANDIDATE", "REJECTED", "UNSUPPORTED", "UNREACHABLE"}:
            raise ValueError("invalid runtime capability status")
        if self.proof_mode not in {"retrieval_only", "relation_observable", "proof_capable", "structurally_valid"}:
            raise ValueError("invalid runtime capability proof_mode")
        object.__setattr__(self, "input_roles", dict(self.input_roles))
        object.__setattr__(self, "output_roles", dict(self.output_roles))
        for name in (
            "temporal_roles", "action_roles", "state_roles",
            "artifact_identity_roles", "correlation_roles",
        ):
            object.__setattr__(self, name, dict(getattr(self, name)))
        object.__setattr__(self, "supported_constraints", tuple(self.supported_constraints))
        object.__setattr__(self, "searchable_constraints", tuple(self.searchable_constraints))
        object.__setattr__(self, "relaxable_constraint_keys", tuple(self.relaxable_constraint_keys))

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "source_id": self.source_id,
            "provider_id": self.provider_id,
            "relation": self.relation,
            "input_roles": dict(self.input_roles),
            "output_roles": dict(self.output_roles),
            "status": self.status,
            "proof_mode": self.proof_mode,
            "schema_fingerprint": self.schema_fingerprint,
            "supported_constraints": list(self.supported_constraints),
            "searchable_constraints": list(self.searchable_constraints),
            "temporal_roles": dict(self.temporal_roles),
            "action_roles": dict(self.action_roles),
            "state_roles": dict(self.state_roles),
            "artifact_identity_roles": dict(self.artifact_identity_roles),
            "correlation_roles": dict(self.correlation_roles),
            "relaxable_constraint_keys": list(self.relaxable_constraint_keys),
            "probe_query_id": self.probe_query_id,
            "diagnostics": list(self.diagnostics),
            "proof_contract_id": self.proof_contract_id,
            "capability_level": self.capability_level,
        }



__all__ = [
    "TelemetryFieldProfile",
    "TelemetrySourceProfile",
    "SourceCapabilityProposal",
    "ProbeSpec",
    "RuntimeCapability",
]
