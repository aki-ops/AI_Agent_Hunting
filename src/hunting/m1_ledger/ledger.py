"""M1 Observation Ledger — single source of truth for evidence, coverage, and query outcomes.

Responsibilities:
  - Append-only store for Observations, QueryResults, ControlResults, and Diagnostics.
  - Records observed_fields[(provider_scope_id, native_type)] -> set[str].
  - Maintains unattributed observations list independent of semantic mapping.
  - Keeps UNMAPPED observations accessible for abduction and reporting.
  - Tracks wildcard cells and instance cells separately.
  - Stores partial parents as audit-only split records; excludes them from active coverage.
  - Enforces: complete scope scan marks scope coverage; targeted evidence query cannot.
"""
from __future__ import annotations

from hunting.contracts.cells import Cell, CellState
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.observations import Observation
from hunting.contracts.queries import (
    ControlResult,
    Diagnostic,
    QueryIntent,
    QueryResult,
)
from hunting.contracts.validators import validate_cell, validate_observation


class ObservationLedger:
    """The append-only Observation Ledger."""

    def __init__(self) -> None:
        self._observations: list[Observation] = []
        self._observation_by_id: dict[str, Observation] = {}
        self._query_results: list[QueryResult] = []
        self._control_results: list[ControlResult] = []
        self._diagnostics: list[Diagnostic] = []

        # observed_fields[(scope_id, native_type)] -> set[field_names]
        self._observed_fields: dict[tuple[str, str | None], set[str]] = {}

        # Tracking cells separately
        self._wildcard_cells: dict[str, Cell] = {}
        self._instance_cells: dict[str, Cell] = {}
        self._split_parents: list[Cell] = []  # audit-only, excluded from active coverage

        # Unattributed & unmapped tracking
        self._unattributed_ids: list[str] = []
        self._unmapped_ids: list[str] = []

    # -----------------------------------------------------------------------
    # Observation management
    # -----------------------------------------------------------------------

    def add_observation(self, obs: Observation) -> None:
        """Append an observation to the ledger."""
        validate_observation(obs)

        if obs.id in self._observation_by_id:
            # Append-only: cannot overwrite an existing observation
            raise ValueError(f"Observation with ID '{obs.id}' already exists in ledger")

        self._observations.append(obs)
        self._observation_by_id[obs.id] = obs

        # Record observed fields for this (scope, native_type) pair
        scope_key = (obs.provider_scope.scope_id, obs.native_type)
        if scope_key not in self._observed_fields:
            self._observed_fields[scope_key] = set()
        self._observed_fields[scope_key].update(obs.fields.keys())

        # Track unattributed
        if obs.is_unexplained and obs.id not in self._unattributed_ids:
            self._unattributed_ids.append(obs.id)

        # Track unmapped
        if obs.is_unmapped and obs.id not in self._unmapped_ids:
            self._unmapped_ids.append(obs.id)

    @property
    def observations(self) -> list[Observation]:
        return list(self._observations)

    @property
    def unattributed_observations(self) -> list[Observation]:
        """All observations not yet attributed, regardless of semantic_type."""
        return [self._observation_by_id[oid] for oid in self._unattributed_ids if self._observation_by_id[oid].is_unexplained]

    @property
    def unmapped_observations(self) -> list[Observation]:
        """All observations without semantic mapping, kept available to M2 and reporting."""
        return [self._observation_by_id[oid] for oid in self._unmapped_ids]

    def mark_attributed(self, observation_id: str, explanation_id: str) -> None:
        """Record attribution of an observation by an explanation."""
        obs = self._observation_by_id.get(observation_id)
        if not obs:
            raise KeyError(f"Observation '{observation_id}' not found in ledger")
        if explanation_id not in obs.attributed_by:
            obs.attributed_by.append(explanation_id)
        if observation_id in self._unattributed_ids and not obs.is_unexplained:
            self._unattributed_ids.remove(observation_id)

    def observed_fields_for(self, scope_id: str, native_type: str | None) -> set[str]:
        """Return the set of observed field names for a (scope, native_type) pair."""
        return set(self._observed_fields.get((scope_id, native_type), set()))

    @property
    def diagnostics(self) -> list[Diagnostic]:
        """All recorded query and control diagnostics."""
        return list(self._diagnostics)

    # -----------------------------------------------------------------------
    # Cell tracking (wildcard vs instance separation + split parents)
    # -----------------------------------------------------------------------

    def _cell_key(self, cell: Cell) -> str:
        ent_str = "ANY" if cell.is_wildcard else str(getattr(cell.entity, "name", cell.entity))
        return f"{cell.provider_scope.scope_id}:{ent_str}:{cell.time_bucket}"

    def register_cell(self, cell: Cell) -> None:
        """Register a cell in the active ledger."""
        validate_cell(cell)
        key = self._cell_key(cell)
        if cell.is_wildcard:
            self._wildcard_cells[key] = cell
        else:
            self._instance_cells[key] = cell

    def record_split_parent(self, parent_cell: Cell, left_child: Cell, right_child: Cell) -> None:
        """Store partial parent as audit-only split record; exclude from active coverage."""
        parent_cell.split_parent = True
        parent_cell.state = CellState.PARTIAL
        key = self._cell_key(parent_cell)

        # Remove from active cells so it does not count in active coverage denominator
        if parent_cell.is_wildcard and key in self._wildcard_cells:
            del self._wildcard_cells[key]
        elif not parent_cell.is_wildcard and key in self._instance_cells:
            del self._instance_cells[key]

        self._split_parents.append(parent_cell)

        # Register children
        self.register_cell(left_child)
        self.register_cell(right_child)

    # -----------------------------------------------------------------------
    # Query execution & scope vs targeted coverage
    # -----------------------------------------------------------------------

    def record_query_outcome(
        self,
        query_intent: QueryIntent,
        cell: Cell,
        result: QueryResult,
    ) -> None:
        """Record query result and update cell coverage state.

        Rule: Complete scope scan (BroadSweep) can mark scope coverage (EXPLORED).
        Targeted evidence query (specific entity) can ONLY mark the instance cell,
        never the whole provider scope!
        """
        self._query_results.append(result)

        if result.diagnostic:
            self._diagnostics.append(result.diagnostic)

        if not result.executed_ok:
            return

        if result.complete:
            # Rule: Complete scope scan (BroadSweep) can mark scope coverage (EXPLORED).
            # Targeted query (e.g. DNS_QUERIES, ProcessLineage) CANNOT mark a wildcard cell as EXPLORED.
            if cell.is_wildcard:
                if query_intent == QueryIntent.BROAD_SWEEP:
                    cell.state = CellState.EXPLORED
                # Targeted query on wildcard cell leaves it un-explored at scope level
            else:
                cell.state = CellState.EXPLORED
        else:
            # Query was truncated / partial
            cell.state = CellState.PARTIAL

    def record_control_result(self, result: ControlResult) -> None:
        """Record control result. Controls never mint observations."""
        self._control_results.append(result)
        if result.diagnostic:
            self._diagnostics.append(result.diagnostic)

    # -----------------------------------------------------------------------
    # Coverage accounting
    # -----------------------------------------------------------------------

    def build_coverage_bound(self, unknown_sources: list[str] | None = None) -> CoverageBound:
        """Build the accurate CoverageBound based on ledger state."""
        w_counts = self._count_cell_states(list(self._wildcard_cells.values()))
        i_counts = self._count_cell_states(list(self._instance_cells.values()))

        # Separate split parents by wildcard vs instance
        w_split_parents = sum(1 for p in self._split_parents if p.is_wildcard)
        i_split_parents = sum(1 for p in self._split_parents if not p.is_wildcard)

        return CoverageBound(
            known_cells_wildcard=len(self._wildcard_cells),
            explored_cells_wildcard=w_counts.get(CellState.EXPLORED, 0),
            partial_cells_wildcard=w_counts.get(CellState.PARTIAL, 0) + w_split_parents,
            unexplored_cells_wildcard=w_counts.get(CellState.UNEXPLORED, 0),
            unqueryable_cells_wildcard=w_counts.get(CellState.UNQUERYABLE, 0),
            unreachable_cells_wildcard=w_counts.get(CellState.UNREACHABLE, 0),

            known_cells_instance=len(self._instance_cells),
            explored_cells_instance=i_counts.get(CellState.EXPLORED, 0),
            partial_cells_instance=i_counts.get(CellState.PARTIAL, 0) + i_split_parents,
            unexplored_cells_instance=i_counts.get(CellState.UNEXPLORED, 0),
            unqueryable_cells_instance=i_counts.get(CellState.UNQUERYABLE, 0),
            unreachable_cells_instance=i_counts.get(CellState.UNREACHABLE, 0),

            unknown_sources=list(unknown_sources or []),
            unmapped_observations=len(self._unmapped_ids),
        )


    def _count_cell_states(self, cells: list[Cell]) -> dict[CellState, int]:
        counts: dict[CellState, int] = {}
        for c in cells:
            counts[c.state] = counts.get(c.state, 0) + 1
        return counts


__all__ = ["ObservationLedger"]
