"""Capability registry schema — deployment configuration.

This is DEPLOYMENT CONFIG: immutable within an investigation.
Set once by the operator; the agent cannot modify it at runtime.
Runtime health observations (source_health, family_collection, field_presence)
live in InvestigationState, NOT here.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class KnownGap:
    """A declared gap in a source's data collection.

    family=None means the gap affects all families.
    host=None means the gap affects all hosts.
    """
    window_start: str
    window_end: str
    family: str | None = None
    host: str | None = None


@dataclass(frozen=True)
class RegistrySource:
    """Configuration for one telemetry source.

    A source absent from the registry does not silently exist —
    the agent treats unknown sources as UNKNOWN-TO-AGENT.
    """
    id: str
    backend: str                                      # cdb_sqlite | kql | spl | esql | edr_api
    event_families: tuple[str, ...]                   # families this source can serve
    indexed_entity_types: tuple[str, ...]             # entity types indexed by this source
    retention_days: int
    coverage_start: str                               # ISO 8601; earliest queryable timestamp
    coverage_end: str | None = None                   # ISO 8601 or None (= +∞)
    known_gaps: tuple[KnownGap, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Registry:
    """The complete capability registry for this deployment.

    Loaded once at startup — hard failure if malformed or incomplete.
    Immutable within an investigation.
    """
    sources: tuple[RegistrySource, ...]

    def source_by_id(self, source_id: str) -> RegistrySource | None:
        for s in self.sources:
            if s.id == source_id:
                return s
        return None

    def supports_family(self, source_id: str, family: str) -> bool:
        """True if source exists and declares this event family."""
        s = self.source_by_id(source_id)
        return s is not None and family in s.event_families

    def indexes_entity_type(self, source_id: str, entity_type: str) -> bool:
        """True if source exists and indexes this entity type."""
        s = self.source_by_id(source_id)
        return s is not None and entity_type in s.indexed_entity_types

    def all_source_ids(self) -> list[str]:
        return [s.id for s in self.sources]
