"""M4 Planner — query compilation, frontier management, deterministic sampling, and bucket splitting.

Responsibilities:
  - Compiles EvidenceRequirement → CapabilityBinding → ProviderOperation using CapabilityMatcher.
  - Records unsupported requirements without fabricating queries.
  - Manages KNOWN_wild (per known ProviderScope) and KNOWN_inst (from discovered entities).
  - Restricts wildcard selection to SAMPLE; restricts entity expansion to EXPAND.
  - Implements provider-scope-stratified deterministic sampling with seed and budget ledger.
  - Implements cursor pagination and time-split fallback for PARTIAL results.
  - Bounds split depth with min_bucket (default 5 min = 300s); never re-issues the same truncated query forever.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from hunting.contracts.capabilities import CapabilityMatcher
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import ANY, EntityRef
from hunting.contracts.expectations import EvidenceRequirement
from hunting.contracts.queries import (
    Diagnostic,
    Query,
    QueryGenerator,
    QueryIntent,
)


def requirement_to_intent(req: EvidenceRequirement) -> QueryIntent:
    """Map an EvidenceRequirement to its canonical QueryIntent."""
    mapping = {
        EvidenceRequirement.PROCESS_ANCESTRY: QueryIntent.PROCESS_LINEAGE,
        EvidenceRequirement.AUTHENTICATION_ACTIVITY: QueryIntent.LOGON_HISTORY,
        EvidenceRequirement.NETWORK_CONNECTION: QueryIntent.NETWORK_CONNECTIONS,
        EvidenceRequirement.FILE_MODIFICATION: QueryIntent.FILE_WRITES,
        EvidenceRequirement.DNS_ACTIVITY: QueryIntent.DNS_QUERIES,
        EvidenceRequirement.PERSISTENCE_CHANGE: QueryIntent.PERSISTENCE_ARTIFACTS,
        EvidenceRequirement.SCOPE_RECORDS: QueryIntent.BROAD_SWEEP,
    }
    return mapping.get(req, QueryIntent.BROAD_SWEEP)


def compile_query_plan(
    requirement: EvidenceRequirement,
    matcher: CapabilityMatcher,
    entity: EntityRef,
    window: str,
    preferred_provider: str | None = None,
    backend: str = "cdb_sqlite",
    query_id: str = "q-001",
) -> tuple[Query | None, Diagnostic | None]:
    """Compile an EvidenceRequirement into an executable Query.

    Never fabricates a query when no valid capability binding exists.
    """
    match_res = matcher.match(requirement, preferred_provider=preferred_provider)
    if not match_res.is_supported or not match_res.binding or not match_res.operation:
        return None, (match_res.diagnostic or Diagnostic.UNSUPPORTED_REQUIREMENT)

    intent = requirement_to_intent(requirement)
    scope_id = match_res.operation.scope_ids[0] if match_res.operation.scope_ids else "default"

    query = Query(
        id=query_id,
        intent=intent,
        entity=entity,
        provider_scope_id=scope_id,
        operation_id=match_res.operation.id,
        evidence_requirement=requirement,
        window=window,
        backend=backend,
        generated_by=QueryGenerator.TEMPLATE,
        cost=1,
    )
    return query, None


class FrontierManager:
    """Manages the searchable universe: KNOWN_wild and KNOWN_inst."""

    def __init__(self, known_scopes: list[ProviderScope]) -> None:
        self.known_scopes = list(known_scopes)
        self.wildcard_cells: list[Cell] = []
        self.instance_cells: list[Cell] = []
        self._observed_entities: set[EntityRef] = set()

    def build_wildcards(self, window: str) -> list[Cell]:
        """Build finite wildcard cells for every known ProviderScope."""
        cells = [Cell(scope, ANY, window) for scope in self.known_scopes]
        self.wildcard_cells.extend(cells)
        return cells

    def add_instance_entity(self, entity: EntityRef, window: str) -> list[Cell]:
        """Add instance cells for a discovered entity across all known scopes."""
        if isinstance(entity, type(ANY)) or entity == ANY:
            raise ValueError("Instance cells cannot be created for ANY wildcard")

        if entity in self._observed_entities:
            return []

        self._observed_entities.add(entity)
        new_cells = [Cell(scope, entity, window) for scope in self.known_scopes]
        self.instance_cells.extend(new_cells)
        return new_cells

    def select_expand_candidates(self) -> list[Cell]:
        """Select instance cells eligible for EXPAND action."""
        return [c for c in self.instance_cells if c.state in {CellState.UNEXPLORED, CellState.PARTIAL}]

    def select_sample_candidates(self) -> list[Cell]:
        """Select wildcard cells eligible for SAMPLE action."""
        return [c for c in self.wildcard_cells if c.state in {CellState.UNEXPLORED, CellState.PARTIAL}]


def sample_wildcard_cells(
    candidates: list[Cell],
    budget: int,
    seed: int,
) -> list[Cell]:
    """Provider-scope-stratified deterministic sampling.

    Enforces:
      - Equal allocation across known scope strata when budget permits.
      - Fully reproducible selection given the same seed.
    """
    if not candidates or budget <= 0:
        return []

    # Group by scope_id
    strata: dict[str, list[Cell]] = {}
    for c in candidates:
        if not c.is_wildcard:
            raise ValueError("sample_wildcard_cells only accepts wildcard cells (SAMPLE action)")
        strata.setdefault(c.provider_scope.scope_id, []).append(c)

    rng = random.Random(seed)
    num_strata = len(strata)
    base_per_stratum = max(1, budget // num_strata)

    selected: list[Cell] = []
    for scope_id, cell_list in sorted(strata.items()):
        # Sort deterministically before sampling
        sorted_cells = sorted(cell_list, key=lambda c: c.time_bucket)
        sample_count = min(len(sorted_cells), base_per_stratum)
        chosen = rng.sample(sorted_cells, sample_count)
        selected.extend(chosen)

    return selected[:budget]


def split_partial_cell(
    cell: Cell,
    min_bucket_seconds: int = 300,
) -> tuple[Cell, Cell] | None:
    """Split a truncated (PARTIAL) cell into two child time buckets.

    Bounds split depth with min_bucket (default 5 min = 300s).
    If cell duration <= min_bucket, marks cell UNREACHABLE ('irreducibly_truncated')
    and returns None.
    """
    start_str, end_str = cell.time_bucket.split("/", 1)
    start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))

    duration = (end_dt - start_dt).total_seconds()
    if duration <= min_bucket_seconds:
        # Cannot split further — irreducible truncation
        cell.state = CellState.UNREACHABLE
        return None

    mid_dt = start_dt + timedelta(seconds=duration / 2)
    start_iso = start_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mid_iso = mid_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    left_child = Cell(cell.provider_scope, cell.entity, f"{start_iso}/{mid_iso}")
    right_child = Cell(cell.provider_scope, cell.entity, f"{mid_iso}/{end_iso}")
    return left_child, right_child


__all__ = [
    "requirement_to_intent",
    "compile_query_plan",
    "FrontierManager",
    "sample_wildcard_cells",
    "split_partial_cell",
]
