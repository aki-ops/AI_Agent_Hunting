"""Registry loader — reads and validates registry.yaml.

Hard failure on any missing or invalid field.
The system refuses to start rather than infer a universe.
"""
from __future__ import annotations
from pathlib import Path

import yaml

from hunting.registry.schema import KnownGap, Registry, RegistrySource


# These are the only valid values per the closed enums in the spec
_VALID_BACKENDS = frozenset({"cdb_sqlite", "kql", "spl", "esql", "edr_api"})
_VALID_FAMILIES = frozenset({
    "process_creation", "logon", "network_bind",
    "file_write", "registry", "dns", "scheduled_task",
})
_VALID_ENTITY_TYPES = frozenset({"host", "account", "process", "ip", "file", "domain"})


def load_registry(path: str | Path) -> Registry:
    """Load and validate a registry.yaml file.

    Raises:
        FileNotFoundError: path does not exist
        ValueError: any required field missing, unknown value, or empty list
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Registry not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("Registry YAML must be a mapping at the top level")
    if "sources" not in data:
        raise ValueError("Registry must have a 'sources' key")
    if not isinstance(data["sources"], list) or len(data["sources"]) == 0:
        raise ValueError("Registry 'sources' must be a non-empty list")

    sources = tuple(_parse_source(src, i) for i, src in enumerate(data["sources"]))
    return Registry(sources=sources)


def _parse_source(src: dict, index: int) -> RegistrySource:
    loc = f"sources[{index}]"

    # --- Required fields ---
    _require(src, "id", loc, str)
    _require(src, "backend", loc, str)
    _require(src, "event_families", loc, list)
    _require(src, "indexed_entity_types", loc, list)
    _require(src, "retention_days", loc, int)

    sid = src["id"].strip()
    if not sid:
        raise ValueError(f"{loc}: 'id' must be a non-empty string")

    backend = src["backend"]
    if backend not in _VALID_BACKENDS:
        raise ValueError(
            f"{loc}({sid}): unknown backend '{backend}'. Valid: {sorted(_VALID_BACKENDS)}"
        )

    families = src["event_families"]
    if len(families) == 0:
        raise ValueError(f"{loc}({sid}): 'event_families' must not be empty")
    for fam in families:
        if fam not in _VALID_FAMILIES:
            raise ValueError(
                f"{loc}({sid}): unknown event_family '{fam}'. Valid: {sorted(_VALID_FAMILIES)}"
            )

    entity_types = src["indexed_entity_types"]
    for et in entity_types:
        if et not in _VALID_ENTITY_TYPES:
            raise ValueError(
                f"{loc}({sid}): unknown entity_type '{et}'. Valid: {sorted(_VALID_ENTITY_TYPES)}"
            )

    retention = src["retention_days"]
    if retention <= 0:
        raise ValueError(f"{loc}({sid}): 'retention_days' must be a positive integer")

    # --- Optional fields ---
    coverage_start = str(src.get("coverage_start", ""))
    coverage_end_raw = src.get("coverage_end", None)
    coverage_end = str(coverage_end_raw) if coverage_end_raw is not None else None

    # --- Known gaps ---
    gaps = tuple(_parse_gap(g, sid, j) for j, g in enumerate(src.get("known_gaps", [])))

    return RegistrySource(
        id=sid,
        backend=backend,
        event_families=tuple(families),
        indexed_entity_types=tuple(entity_types),
        retention_days=retention,
        coverage_start=coverage_start,
        coverage_end=coverage_end,
        known_gaps=gaps,
    )


def _parse_gap(gap: dict, source_id: str, index: int) -> KnownGap:
    loc = f"source({source_id}).known_gaps[{index}]"
    if not isinstance(gap, dict):
        raise ValueError(f"{loc}: each known_gap must be a mapping")
    for key in ("window_start", "window_end"):
        if key not in gap:
            raise ValueError(f"{loc}: missing required key '{key}'")
    return KnownGap(
        window_start=str(gap["window_start"]),
        window_end=str(gap["window_end"]),
        family=gap.get("family"),
        host=gap.get("host"),
    )


def _require(d: dict, key: str, loc: str, expected_type: type) -> None:
    if key not in d:
        raise ValueError(f"{loc}: missing required field '{key}'")
    if not isinstance(d[key], expected_type):
        raise ValueError(f"{loc}: '{key}' must be a {expected_type.__name__}")
