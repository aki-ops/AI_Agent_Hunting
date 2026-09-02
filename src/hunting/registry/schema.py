"""Provider-scope deployment manifest contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class KnownGap:
    window_start: str
    window_end: str
    scope_id: str | None = None
    entity: str | None = None


@dataclass(frozen=True)
class RegistryScope:
    id: str
    native_partition: dict[str, str]
    retention_days: int
    coverage_start: str
    coverage_end: str | None = None
    known_gaps: tuple[KnownGap, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RegistryOperation:
    id: str
    scope_ids: tuple[str, ...]
    params_schema: dict[str, Any] = field(default_factory=dict)
    pagination: str = "none"
    limit_semantics: str = "provider-defined"


@dataclass(frozen=True)
class RegistrySource:
    id: str
    backend: str
    scopes: tuple[RegistryScope, ...]
    operations: tuple[RegistryOperation, ...]


@dataclass(frozen=True)
class Registry:
    sources: tuple[RegistrySource, ...]

    def source_by_id(self, source_id: str) -> RegistrySource | None:
        return next((source for source in self.sources if source.id == source_id), None)

    def scope_by_id(self, scope_id: str) -> RegistryScope | None:
        for source in self.sources:
            for scope in source.scopes:
                if scope.id == scope_id:
                    return scope
        return None

    def operation_by_id(self, operation_id: str) -> RegistryOperation | None:
        for source in self.sources:
            for operation in source.operations:
                if operation.id == operation_id:
                    return operation
        return None

    def all_source_ids(self) -> list[str]:
        return [source.id for source in self.sources]

    def all_scope_ids(self) -> list[str]:
        return [scope.id for source in self.sources for scope in source.scopes]
