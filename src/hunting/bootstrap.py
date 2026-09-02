"""Investigation bootstrapping and frontier cell generation (C2).

Implements:
  - Alert ingest and Seed creation (handles entity-bearing and entity-free)
  - Time window normalization (anchor ± W)
  - KNOWN_wild generation for every known ProviderScope
  - KNOWN_inst generation for discovered alert entities
  - Retention, coverage bounds, known gaps marking cells UNREACHABLE
  - Known scopes without an operation marking cells UNQUERYABLE
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import ANY
from hunting.contracts.state import Alert, Seed, TimeWindow
from hunting.normalization import (
    assign_stable_scope_id,
    extract_alert_entities,
    normalize_time_window,
)
from hunting.registry.schema import Registry, RegistryScope


@dataclass(frozen=True)
class BootstrapResult:
    seed: Seed
    wildcard_cells: list[Cell]
    instance_cells: list[Cell]

    @property
    def all_cells(self) -> list[Cell]:
        return self.wildcard_cells + self.instance_cells

    @property
    def has_instance_candidates(self) -> bool:
        return len(self.instance_cells) > 0

    @property
    def selectable_cells(self) -> list[Cell]:
        """Cells eligible for selection (UNEXPLORED or PARTIAL).

        Excludes UNREACHABLE (retention/gap) and UNQUERYABLE (no adapter).
        """
        return [
            c for c in self.all_cells
            if c.state in {CellState.UNEXPLORED, CellState.PARTIAL}
        ]


def parse_interval(interval_str: str) -> tuple[datetime, datetime]:
    """Parse 'start/end' ISO 8601 string to (start_dt, end_dt)."""
    start_str, end_str = interval_str.split("/", 1)
    start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    return start_dt, end_dt


def is_window_in_gap(window_start: datetime, window_end: datetime, gap_start_iso: str, gap_end_iso: str) -> bool:
    """Check if window overlaps with a known gap."""
    gap_start = datetime.fromisoformat(gap_start_iso.replace("Z", "+00:00"))
    gap_end = datetime.fromisoformat(gap_end_iso.replace("Z", "+00:00"))
    return not (window_end <= gap_start or window_start >= gap_end)


def determine_cell_state(
    scope_reg: RegistryScope,
    has_operation: bool,
    time_bucket: str,
    as_of: datetime | None = None,
) -> CellState:
    """Evaluate scope configuration against window to determine initial cell state."""
    if not has_operation:
        return CellState.UNQUERYABLE

    window_start, window_end = parse_interval(time_bucket)

    # Check retention: if the query window has rolled off backend retention relative to as_of
    ref_time = as_of or datetime.now(timezone.utc)
    if scope_reg.retention_days and scope_reg.retention_days > 0:
        retention_cutoff = ref_time - timedelta(days=scope_reg.retention_days)
        if window_end <= retention_cutoff:
            return CellState.UNREACHABLE

    # Check coverage_end (if set)
    if scope_reg.coverage_end:
        cov_end = datetime.fromisoformat(scope_reg.coverage_end.replace("Z", "+00:00"))
        if window_start >= cov_end:
            return CellState.UNREACHABLE

    # Check coverage_start
    if scope_reg.coverage_start:
        cov_start = datetime.fromisoformat(scope_reg.coverage_start.replace("Z", "+00:00"))
        if window_end <= cov_start:
            return CellState.UNREACHABLE

    # Check known gaps
    for gap in scope_reg.known_gaps:
        if is_window_in_gap(window_start, window_end, gap.window_start, gap.window_end):
            return CellState.UNREACHABLE

    return CellState.UNEXPLORED


def bootstrap_investigation(
    alert: Alert,
    registry: Registry,
    seed_radius_seconds: int = 7200,
    as_of: datetime | None = None,
) -> BootstrapResult:
    """Bootstrap investigation from an alert and deployment registry."""
    entities = extract_alert_entities(alert)

    raw_ts = (
        (alert.fields or {}).get("timestamp")
        or alert.received_at
        or "2026-01-01T00:00:00Z"
    )
    window_str = normalize_time_window(str(raw_ts), radius_seconds=seed_radius_seconds)
    start_str, end_str = window_str.split("/", 1)
    seed_window = TimeWindow(start=start_str, end=end_str)

    seed = Seed(
        entities=entities,
        window=seed_window,
        source=alert.source,
        raw_ref=alert.id,
    )

    wildcard_cells: list[Cell] = []
    instance_cells: list[Cell] = []

    for source in registry.sources:
        # Collect operations targeting scopes of this source
        supported_scope_ids = {
            scope_id
            for op in source.operations
            for scope_id in op.scope_ids
        }

        for scope_reg in source.scopes:
            has_op = scope_reg.id in supported_scope_ids
            scope_state = determine_cell_state(scope_reg, has_op, window_str, as_of=as_of)

            stable_id = assign_stable_scope_id(source.id, scope_reg.native_partition, scope_reg.id)
            provider_scope = ProviderScope(
                provider_id=source.id,
                native_partition=scope_reg.native_partition,
                scope_id=stable_id,
            )

            # Wildcard cell (KNOWN_wild)
            wildcard_cell = Cell(
                provider_scope=provider_scope,
                entity=ANY,
                time_bucket=window_str,
                state=scope_state,
            )
            wildcard_cells.append(wildcard_cell)

            # Instance cells (KNOWN_inst) for each extracted entity
            for ent in entities:
                instance_cell = Cell(
                    provider_scope=provider_scope,
                    entity=ent,
                    time_bucket=window_str,
                    state=scope_state,
                )
                instance_cells.append(instance_cell)

    return BootstrapResult(
        seed=seed,
        wildcard_cells=wildcard_cells,
        instance_cells=instance_cells,
    )


__all__ = ["BootstrapResult", "bootstrap_investigation"]
