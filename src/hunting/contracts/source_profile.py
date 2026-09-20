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
    # ``origin`` distinguishes provider-declared flat fields from keys found
    # inside a bounded payload sample.  Nested keys are candidates only; they
    # are never proof merely because they were observed in a payload.
    origin: str = "flat"
    evidence_query_id: str | None = None
    parent_field: str = ""
    nested_key: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "field_id", _required(self.field_id, "field_id"))
        object.__setattr__(self, "name", _required(self.name, "name"))
        if self.coverage is not None and not 0 <= float(self.coverage) <= 1:
            raise ValueError("coverage must be between 0 and 1")
        values = tuple(str(v)[:256] for v in self.sample_values[:5])
        object.__setattr__(self, "sample_values", values)
        origin = str(self.origin or "flat").strip().casefold()
        if origin not in {"flat", "nested_payload"}:
            raise ValueError("origin must be flat or nested_payload")
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "evidence_query_id", str(self.evidence_query_id).strip() if self.evidence_query_id else None)
        object.__setattr__(self, "parent_field", str(self.parent_field or "").strip())
        object.__setattr__(self, "nested_key", str(self.nested_key or "").strip())
        if origin == "nested_payload" and not self.nested_key:
            raise ValueError("nested_payload fields require nested_key")

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_id": self.field_id,
            "name": self.name,
            "primitive_type": self.primitive_type,
            "coverage": self.coverage,
            "sample_values": list(self.sample_values),
            "origin": self.origin,
            "evidence_query_id": self.evidence_query_id,
            "parent_field": self.parent_field,
            "nested_key": self.nested_key,
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
class ConstraintMapping:
    """Explicit mapping from semantic constraint to native telemetry field and transform."""

    semantic_constraint: str
    native_field: str
    operator: str = "equals"
    transform: str = ""
    proof_method: str = "field_match"
    # When the mapped field was discovered inside an opaque payload, retain
    # the provider-native parent and census-backed path separately.  This
    # keeps nested extraction declarative instead of making adapters infer it
    # from field IDs or relation names.
    nested_path: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "semantic_constraint", _required(self.semantic_constraint, "semantic_constraint").casefold())
        object.__setattr__(self, "native_field", _required(self.native_field, "native_field"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_constraint": self.semantic_constraint,
            "native_field": self.native_field,
            "operator": self.operator,
            "transform": self.transform,
            "proof_method": self.proof_method,
            "nested_path": self.nested_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConstraintMapping":
        return cls(
            semantic_constraint=str(data.get("semantic_constraint", data.get("key", ""))),
            native_field=str(data.get("native_field", data.get("field", ""))),
            operator=str(data.get("operator", "equals")),
            transform=str(data.get("transform", "")),
            proof_method=str(data.get("proof_method", "field_match")),
            nested_path=str(data.get("nested_path", "")),
        )


@dataclass(frozen=True)
class SourceCapabilityProposal:
    """Untrusted LLM proposal; it becomes executable only after a probe."""

    source_id: str
    relation: str
    # Semantic goal identity is optional at the compatibility boundary but is
    # required for new C2/runtime routes.  Relation text is not unique.
    goal_id: str = ""
    input_roles: dict[str, str] = field(default_factory=dict)
    output_roles: dict[str, str] = field(default_factory=dict)
    proof_mode: str = "retrieval_only"
    capability_level: str = "RETRIEVAL_CAPABLE"
    probe_kind: str = "cooccurrence"
    projection_roles: tuple[str, ...] = ()
    supported_constraints: tuple[str, ...] = ()
    searchable_constraints: tuple[str, ...] = ()
    constraint_mappings: tuple[ConstraintMapping, ...] = ()
    temporal_roles: dict[str, str] = field(default_factory=dict)
    action_roles: dict[str, str] = field(default_factory=dict)
    state_roles: dict[str, str] = field(default_factory=dict)
    artifact_identity_roles: dict[str, str] = field(default_factory=dict)
    correlation_roles: dict[str, str] = field(default_factory=dict)
    relaxable_constraint_keys: tuple[str, ...] = ()
    rationale_refs: tuple[str, ...] = ()
    confidence: float | None = None
    # Field-level transforms are separate from semantic constraint mappings.
    # They let an untrusted proposal state that a census-backed nested field
    # must be extracted from its parent payload before use.
    field_transforms: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_id", _required(self.source_id, "source_id"))
        object.__setattr__(self, "relation", _required(self.relation, "relation").casefold())
        object.__setattr__(self, "goal_id", str(self.goal_id or "").strip())
        if self.proof_mode not in {"retrieval_only", "relation_observable", "proof_capable", "structurally_valid"}:
            raise ValueError("proof_mode must be retrieval_only, proof_capable, or relation_observable")
        if self.confidence is not None and not 0 <= float(self.confidence) <= 1:
            raise ValueError("confidence must be between 0 and 1")
        object.__setattr__(self, "input_roles", dict(self.input_roles))
        object.__setattr__(self, "output_roles", dict(self.output_roles))
        object.__setattr__(
            self,
            "field_transforms",
            {str(k): str(v).strip().casefold() for k, v in dict(self.field_transforms).items() if str(k).strip() and str(v).strip()},
        )

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
        mappings = []
        for cm in self.constraint_mappings:
            if isinstance(cm, dict):
                mappings.append(ConstraintMapping.from_dict(cm))
            elif isinstance(cm, ConstraintMapping):
                mappings.append(cm)
        object.__setattr__(self, "constraint_mappings", tuple(mappings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "relation": self.relation,
            "goal_id": self.goal_id,
            "input_roles": dict(self.input_roles),
            "output_roles": dict(self.output_roles),
            "proof_mode": self.proof_mode,
            "probe_kind": self.probe_kind,
            "projection_roles": list(self.projection_roles),
            "supported_constraints": list(self.supported_constraints),
            "searchable_constraints": list(self.searchable_constraints),
            "constraint_mappings": [m.to_dict() for m in self.constraint_mappings],
            "temporal_roles": dict(self.temporal_roles),
            "action_roles": dict(self.action_roles),
            "state_roles": dict(self.state_roles),
            "artifact_identity_roles": dict(self.artifact_identity_roles),
            "correlation_roles": dict(self.correlation_roles),
            "relaxable_constraint_keys": list(self.relaxable_constraint_keys),
            "rationale_refs": list(self.rationale_refs),
            "confidence": self.confidence,
            "field_transforms": dict(self.field_transforms),
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
    goal_id: str = ""
    supported_constraints: tuple[str, ...] = ()
    searchable_constraints: tuple[str, ...] = ()
    constraint_mappings: tuple[ConstraintMapping, ...] = ()
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
    nested_field_bindings: dict[str, dict[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("capability_id", "source_id", "provider_id", "relation", "status", "proof_mode", "schema_fingerprint"):
            object.__setattr__(self, name, _required(getattr(self, name), name))
        object.__setattr__(self, "goal_id", str(self.goal_id or "").strip())
        if self.status not in {"VALIDATED", "CANDIDATE", "REJECTED", "UNSUPPORTED", "UNREACHABLE"}:
            raise ValueError("invalid runtime capability status")
        if self.proof_mode not in {"retrieval_only", "relation_observable", "proof_capable", "structurally_valid"}:
            raise ValueError("invalid runtime capability proof_mode")
        object.__setattr__(self, "input_roles", dict(self.input_roles))
        object.__setattr__(self, "output_roles", dict(self.output_roles))
        object.__setattr__(self, "nested_field_bindings", {
            str(role): {str(k): str(v) for k, v in dict(binding).items()}
            for role, binding in dict(self.nested_field_bindings).items()
        })
        for name in (
            "temporal_roles", "action_roles", "state_roles",
            "artifact_identity_roles", "correlation_roles",
        ):
            object.__setattr__(self, name, dict(getattr(self, name)))
        object.__setattr__(self, "supported_constraints", tuple(self.supported_constraints))
        object.__setattr__(self, "searchable_constraints", tuple(self.searchable_constraints))
        object.__setattr__(self, "relaxable_constraint_keys", tuple(self.relaxable_constraint_keys))
        mappings = []
        for cm in self.constraint_mappings:
            if isinstance(cm, dict):
                mappings.append(ConstraintMapping.from_dict(cm))
            elif isinstance(cm, ConstraintMapping):
                mappings.append(cm)
        object.__setattr__(self, "constraint_mappings", tuple(mappings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "source_id": self.source_id,
            "provider_id": self.provider_id,
            "relation": self.relation,
            "goal_id": self.goal_id,
            "input_roles": dict(self.input_roles),
            "output_roles": dict(self.output_roles),
            "status": self.status,
            "proof_mode": self.proof_mode,
            "schema_fingerprint": self.schema_fingerprint,
            "supported_constraints": list(self.supported_constraints),
            "searchable_constraints": list(self.searchable_constraints),
            "constraint_mappings": [m.to_dict() for m in self.constraint_mappings],
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
            "nested_field_bindings": {
                role: dict(binding) for role, binding in self.nested_field_bindings.items()
            },
        }


__all__ = [
    "ConstraintMapping",
    "TelemetryFieldProfile",
    "TelemetrySourceProfile",
    "SourceCapabilityProposal",
    "ProbeSpec",
    "RuntimeCapability",
]
