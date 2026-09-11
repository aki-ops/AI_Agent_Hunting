"""Incremental, compact, and auditable SourceCard storage.

Component of Phase 3 (Progressive Frontier):
- Provides compact SourceCard structures (fields, sketches, time span, cardinality, provenance).
- Replaces raw schema dump with bounded, auditable summaries.
- Supports serialization, lookup, and conversion from TelemetrySourceProfile.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable

from hunting.contracts.source_profile import TelemetrySourceProfile


@dataclass(frozen=True)
class FieldSketch:
    """Bounded, safe sketch of a single telemetry field."""
    name: str
    field_type: str = "string"  # "string" | "number" | "timestamp" | "ip" | "boolean"
    cardinality: int = 0
    sample_values: tuple[str, ...] = ()
    null_fraction: float = 0.0
    field_roles: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "field_type": self.field_type,
            "cardinality": self.cardinality,
            "sample_values": list(self.sample_values),
            "null_fraction": round(self.null_fraction, 4),
            "field_roles": list(self.field_roles),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FieldSketch:
        return cls(
            name=str(data.get("name", "")),
            field_type=str(data.get("field_type", "string")),
            cardinality=int(data.get("cardinality", 0)),
            sample_values=tuple(str(v) for v in data.get("sample_values", ())),
            null_fraction=float(data.get("null_fraction", 0.0)),
            field_roles=tuple(str(r) for r in data.get("field_roles", ())),
        )


@dataclass(frozen=True)
class SourceCard:
    """Incremental, compact, and auditable representation of a telemetry source."""
    source_id: str
    provider_id: str
    scope: str
    event_count: int = 0
    earliest_time: str | None = None
    latest_time: str | None = None
    fields: tuple[FieldSketch, ...] = ()
    parser_version: str = "v1"
    provenance: str = "census"
    schema_fingerprint: str = ""
    field_roles: dict[str, str] = field(default_factory=dict)
    partition_keys: tuple[str, ...] = ()
    adjacent_source_ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.schema_fingerprint:
            # Generate deterministic fingerprint from sorted field names and types
            sorted_fields = sorted((f.name.lower(), f.field_type.lower()) for f in self.fields)
            raw = f"{self.provider_id}:{self.source_id}:{sorted_fields}"
            fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            object.__setattr__(self, "schema_fingerprint", fp)

    @property
    def field_names(self) -> set[str]:
        return {f.name for f in self.fields}

    def compact_summary(self, max_fields: int = 32) -> dict[str, Any]:
        """Compact summary suitable for inclusion in bounded LLM prompts."""
        selected_fields = list(self.fields)[:max_fields]
        return {
            "source_id": self.source_id,
            "provider_id": self.provider_id,
            "scope": self.scope,
            "event_count": self.event_count,
            "total_fields": len(self.fields),
            "fields": [
                {
                    "name": f.name,
                    "type": f.field_type,
                    "roles": list(f.field_roles),
                    "samples": list(f.sample_values)[:3],
                }
                for f in selected_fields
            ],
            "schema_fingerprint": self.schema_fingerprint,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "provider_id": self.provider_id,
            "scope": self.scope,
            "event_count": self.event_count,
            "earliest_time": self.earliest_time,
            "latest_time": self.latest_time,
            "fields": [f.to_dict() for f in self.fields],
            "parser_version": self.parser_version,
            "provenance": self.provenance,
            "schema_fingerprint": self.schema_fingerprint,
            "field_roles": dict(self.field_roles),
            "partition_keys": list(self.partition_keys),
            "adjacent_source_ids": list(self.adjacent_source_ids),
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceCard:
        fields = tuple(FieldSketch.from_dict(f) for f in data.get("fields", []))
        return cls(
            source_id=str(data.get("source_id", "")),
            provider_id=str(data.get("provider_id", "")),
            scope=str(data.get("scope", "")),
            event_count=int(data.get("event_count", 0)),
            earliest_time=data.get("earliest_time"),
            latest_time=data.get("latest_time"),
            fields=fields,
            parser_version=str(data.get("parser_version", "v1")),
            provenance=str(data.get("provenance", "census")),
            schema_fingerprint=str(data.get("schema_fingerprint", "")),
            field_roles=dict(data.get("field_roles", {})),
            partition_keys=tuple(str(k) for k in data.get("partition_keys", ())),
            adjacent_source_ids=tuple(str(a) for a in data.get("adjacent_source_ids", ())),
            tags=tuple(str(t) for t in data.get("tags", ())),
        )

    @classmethod
    def from_telemetry_source_profile(
        cls,
        profile: TelemetrySourceProfile,
        *,
        provider_id: str = "splunk",
        scope: str = "default",
        adjacent_source_ids: Iterable[str] = (),
    ) -> SourceCard:
        field_sketches: list[FieldSketch] = []
        field_roles: dict[str, str] = {}
        for f in profile.fields:
            roles: list[str] = []
            suggested_role = getattr(f, "suggested_role", None)
            if suggested_role:
                roles.append(suggested_role)
                field_roles[f.name] = suggested_role
            field_type = getattr(f, "primitive_type", None) or getattr(f, "field_type", "string")
            coverage = getattr(f, "coverage", None)
            null_fraction = getattr(f, "null_fraction", None)
            if null_fraction is None and coverage is not None:
                null_fraction = max(0.0, 1.0 - float(coverage))
            cardinality = getattr(f, "cardinality", 0) or 0
            sample_values = tuple(getattr(f, "sample_values", ())[:5])
            field_sketches.append(
                FieldSketch(
                    name=f.name,
                    field_type=field_type,
                    cardinality=cardinality,
                    sample_values=sample_values,
                    null_fraction=null_fraction or 0.0,
                    field_roles=tuple(roles),
                )
            )

        parser_ver = getattr(profile, "parser_version", "v1") or "v1"
        return cls(
            source_id=profile.source_id,
            provider_id=provider_id,
            scope=scope,
            event_count=profile.event_count or 0,
            fields=tuple(field_sketches),
            parser_version=parser_ver,
            provenance="census",
            schema_fingerprint=profile.schema_fingerprint or "",
            field_roles=field_roles,
            adjacent_source_ids=tuple(adjacent_source_ids),
        )



class SourceCardStore:
    """Auditable storage and index for SourceCard records."""

    def __init__(self) -> None:
        self._cards: dict[str, SourceCard] = {}

    def register_card(self, card: SourceCard) -> None:
        self._cards[card.source_id] = card

    def get_card(self, source_id: str) -> SourceCard | None:
        return self._cards.get(source_id)

    def list_cards(self, scope: str | None = None) -> list[SourceCard]:
        if scope is None:
            return list(self._cards.values())
        return [c for c in self._cards.values() if c.scope == scope]

    def count(self) -> int:
        return len(self._cards)

    def all_source_ids(self) -> list[str]:
        return sorted(self._cards.keys())

    @classmethod
    def from_source_profiles(
        cls,
        profiles: Iterable[TelemetrySourceProfile],
        *,
        provider_id: str = "splunk",
        scope: str = "default",
    ) -> SourceCardStore:
        store = cls()
        all_ids = [p.source_id for p in profiles]
        for p in profiles:
            adjacent = [sid for sid in all_ids if sid != p.source_id and sid.split(":")[0] == p.source_id.split(":")[0]]
            card = SourceCard.from_telemetry_source_profile(
                p,
                provider_id=provider_id,
                scope=scope,
                adjacent_source_ids=adjacent,
            )
            store.register_card(card)
        return store


__all__ = [
    "FieldSketch",
    "SourceCard",
    "SourceCardStore",
]
