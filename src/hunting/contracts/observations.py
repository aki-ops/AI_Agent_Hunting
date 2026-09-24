"""Observation ledger contracts.

Native provider records are preserved even when semantic mapping is absent.
Raw content remains in protected storage and is never sent to an LLM.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import AnyEntity, EntityRef


class EpistemicType(str, Enum):
    OBSERVED = "observed"
    TESTIMONY = "testimony"


class TaintLabel(str, Enum):
    ATTACKER_INFLUENCED = "attacker_influenced"
    STRUCTURAL = "structural"


@dataclass(frozen=True)
class Provenance:
    query_id: str
    collector: str
    ingest_time: str
    native_partition: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SemanticType:
    """Optional post-hoc semantic label.

    An observation without a semantic label (semantic_type=None or mapped_by='unmapped')
    is still a valid, complete observation in the ledger.
    """
    vocabulary: str          # e.g. "ocsf", "attack_data_component", "local", "native"
    value: str               # e.g. "process_creation", "dns_query"
    confidence_basis: str = "exact"
    mapped_by: str = "adapter"  # "deterministic_rule" | "adapter" | "unmapped"


@dataclass
class Observation:
    id: str
    provider_scope: ProviderScope
    cell_id: str
    timestamp: str
    epistemic_type: EpistemicType
    native_type: str | None = None
    semantic_type: SemanticType | str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    native_fields: dict[str, Any] = field(default_factory=dict)
    canonical_fields: dict[str, Any] = field(default_factory=dict)
    taint: dict[str, TaintLabel] = field(default_factory=dict)
    entities: list[EntityRef] = field(default_factory=list)
    provenance: Provenance | None = None
    raw_ref: str | None = None
    attributed_by: list[str] = field(default_factory=list)
    demanding: bool = False
    raw_event: dict[str, Any] = field(default_factory=dict)
    query_id: str | None = None

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Observation.id must not be empty")
        if not self.timestamp.strip():
            raise ValueError("Observation.timestamp must not be empty")
        if any(isinstance(entity, AnyEntity) for entity in self.entities):
            raise ValueError("Observation.entities cannot contain ANY")
        if not self.native_fields and self.fields:
            self.native_fields = dict(self.fields)
        if not self.canonical_fields and self.fields:
            from hunting.evidence.normalizer import normalize_telemetry_fields
            _, self.canonical_fields = normalize_telemetry_fields(self.fields)
            # Merge canonical keys into fields if not already present, ensuring seamless legacy access
            for c_k, c_v in self.canonical_fields.items():
                if c_k not in self.fields:
                    self.fields[c_k] = c_v

    @property
    def is_unmapped(self) -> bool:
        """True if this observation has no semantic mapping."""
        if self.semantic_type is None:
            return True
        if isinstance(self.semantic_type, SemanticType):
            return self.semantic_type.mapped_by == "unmapped"
        return False

    @property
    def is_unexplained(self) -> bool:
        """True if no explanation currently accounts for this observation."""
        return len(self.attributed_by) == 0

    def elevate_epistemic_type(self, new_type: EpistemicType) -> None:
        """Inviolable rule: TESTIMONY may NEVER become OBSERVED."""
        if self.epistemic_type == EpistemicType.TESTIMONY and new_type == EpistemicType.OBSERVED:
            raise ValueError("Inviolable constraint: TESTIMONY cannot become OBSERVED")
        self.epistemic_type = new_type

    def to_dict(self) -> dict[str, Any]:
        """Serialize native observation fields for an immutable run account."""
        scope = self.provider_scope
        return {
            "id": self.id,
            "provider_scope": {
                "provider_id": getattr(scope, "provider_id", ""),
                "native_partition": dict(getattr(scope, "native_partition", {}) or {}),
                "scope_id": getattr(scope, "scope_id", ""),
                "retention_days": getattr(scope, "retention_days", None),
            },
            "cell_id": self.cell_id,
            "timestamp": self.timestamp,
            "epistemic_type": self.epistemic_type.value if hasattr(self.epistemic_type, "value") else str(self.epistemic_type),
            "native_type": self.native_type,
            "fields": dict(self.fields),
            "native_fields": dict(self.native_fields or self.fields),
            "query_id": self.query_id,
            "raw_ref": self.raw_ref,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Observation":
        """Rehydrate one observation without inventing missing native fields."""
        if not isinstance(raw, dict):
            raise ValueError("observation must be an object")
        scope_raw = raw.get("provider_scope") if isinstance(raw.get("provider_scope"), dict) else {}
        partition = dict(scope_raw.get("native_partition") or {})
        if not partition:
            partition = {"dataset": str(raw.get("scope_id") or scope_raw.get("scope_id") or "unknown")}
        scope = ProviderScope(
            provider_id=str(scope_raw.get("provider_id") or raw.get("provider_id") or "unknown"),
            native_partition=partition,
            scope_id=str(scope_raw.get("scope_id") or raw.get("scope_id") or ""),
            retention_days=scope_raw.get("retention_days"),
        )
        epistemic = raw.get("epistemic_type", EpistemicType.OBSERVED)
        if not isinstance(epistemic, EpistemicType):
            epistemic = EpistemicType(str(epistemic or EpistemicType.OBSERVED.value))
        return cls(
            id=str(raw.get("id") or raw.get("observation_id") or ""),
            provider_scope=scope,
            cell_id=str(raw.get("cell_id") or ""),
            timestamp=str(raw.get("timestamp") or ""),
            epistemic_type=epistemic,
            native_type=raw.get("native_type"),
            fields=dict(raw.get("fields") or {}),
            native_fields=dict(raw.get("native_fields") or raw.get("fields") or {}),
            query_id=raw.get("query_id"),
            raw_ref=raw.get("raw_ref"),
        )


__all__ = [
    "EpistemicType",
    "TaintLabel",
    "Provenance",
    "SemanticType",
    "Observation",
]
