"""Load and validate a provider-scope manifest."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hunting.registry.schema import (
    KnownGap,
    Registry,
    RegistryOperation,
    RegistryScope,
    RegistrySource,
)

_VALID_BACKENDS = frozenset({
    "cdb_sqlite", "kql", "spl", "esql", "edr_api", "ids_api", "cloud_api",
})


def load_registry(path: str | Path) -> Registry:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Registry not found: {path}")
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("Registry YAML must be a mapping at the top level")
    providers = data.get("providers", data.get("sources"))
    if not isinstance(providers, list) or not providers:
        raise ValueError("Registry must have a non-empty 'providers' list")
    sources = tuple(_parse_source(item, i) for i, item in enumerate(providers))
    all_scope_ids = [scope.id for source in sources for scope in source.scopes]
    if len(all_scope_ids) != len(set(all_scope_ids)):
        raise ValueError("scope IDs must be globally unique")
    return Registry(sources=sources)


def _parse_source(src: Any, index: int) -> RegistrySource:
    loc = f"providers[{index}]"
    if not isinstance(src, dict):
        raise ValueError(f"{loc} must be a mapping")
    _require(src, "id", loc, str)
    _require(src, "backend", loc, str)
    _require(src, "scopes", loc, list)
    _require(src, "operations", loc, list)
    source_id = src["id"].strip()
    if not source_id:
        raise ValueError(f"{loc}.id must not be empty")
    if src["backend"] not in _VALID_BACKENDS:
        raise ValueError(f"{loc}({source_id}): unknown backend '{src['backend']}'")
    scopes = tuple(_parse_scope(scope, source_id, i) for i, scope in enumerate(src["scopes"] or []))
    if not scopes:
        raise ValueError(f"{loc}({source_id}): scopes must not be empty")
    operations = tuple(_parse_operation(op, source_id, i) for i, op in enumerate(src["operations"] or []))
    if not operations:
        raise ValueError(f"{loc}({source_id}): operations must not be empty")
    scope_ids = {scope.id for scope in scopes}
    for operation in operations:
        unknown = set(operation.scope_ids) - scope_ids
        if unknown:
            raise ValueError(f"operation {operation.id} references unknown scopes: {sorted(unknown)}")
    return RegistrySource(source_id, src["backend"], scopes, operations)


def _parse_scope(scope: Any, source_id: str, index: int) -> RegistryScope:
    loc = f"provider({source_id}).scopes[{index}]"
    if not isinstance(scope, dict):
        raise ValueError(f"{loc} must be a mapping")
    for key in ("id", "native_partition", "retention_days", "coverage_start"):
        if key not in scope:
            raise ValueError(f"{loc}: missing required field '{key}'")
    scope_id = str(scope["id"]).strip()
    if not scope_id or not isinstance(scope["native_partition"], dict) or not scope["native_partition"]:
        raise ValueError(f"{loc}: id and native_partition must be non-empty")
    retention = scope["retention_days"]
    if not isinstance(retention, int) or isinstance(retention, bool) or retention <= 0:
        raise ValueError(f"{loc}: retention_days must be a positive integer")
    gaps = tuple(_parse_gap(gap, scope_id, i) for i, gap in enumerate(scope.get("known_gaps", [])))
    return RegistryScope(
        id=scope_id,
        native_partition={str(k): str(v) for k, v in scope["native_partition"].items()},
        retention_days=retention,
        coverage_start=str(scope["coverage_start"]),
        coverage_end=None if scope.get("coverage_end") is None else str(scope["coverage_end"]),
        known_gaps=gaps,
    )


def _parse_operation(operation: Any, source_id: str, index: int) -> RegistryOperation:
    loc = f"provider({source_id}).operations[{index}]"
    if not isinstance(operation, dict):
        raise ValueError(f"{loc} must be a mapping")
    for key in ("id", "scope_ids"):
        if key not in operation:
            raise ValueError(f"{loc}: missing required field '{key}'")
    operation_id = str(operation["id"]).strip()
    scope_ids = operation["scope_ids"]
    if not operation_id or not isinstance(scope_ids, list) or not scope_ids:
        raise ValueError(f"{loc}: id and non-empty scope_ids are required")
    return RegistryOperation(
        id=operation_id,
        scope_ids=tuple(str(scope_id) for scope_id in scope_ids),
        params_schema=dict(operation.get("params_schema", {})),
        pagination=str(operation.get("pagination", "none")),
        limit_semantics=str(operation.get("limit_semantics", "provider-defined")),
    )


def _parse_gap(gap: Any, scope_id: str, index: int) -> KnownGap:
    loc = f"scope({scope_id}).known_gaps[{index}]"
    if not isinstance(gap, dict) or "window_start" not in gap or "window_end" not in gap:
        raise ValueError(f"{loc}: window_start and window_end are required")
    return KnownGap(
        window_start=str(gap["window_start"]),
        window_end=str(gap["window_end"]),
        scope_id=scope_id,
        entity=None if gap.get("entity") is None else str(gap["entity"]),
    )


def _require(data: dict[str, Any], key: str, loc: str, expected: type) -> None:
    if key not in data or not isinstance(data[key], expected):
        raise ValueError(f"{loc}: '{key}' must be a {expected.__name__}")
