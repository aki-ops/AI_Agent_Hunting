"""Provider-scoped coverage contracts.

Cell deliberately has no EventFamily axis. A Cell records the provider-native
scope, entity (or wildcard) and time region whose coverage is being accounted.
Query operations and semantic mappings are separate contracts.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from hunting.contracts.entities import EntityRef, AnyEntity


@dataclass(frozen=True)
class ProviderScope:
    provider_id: str
    native_partition: Mapping[str, str]
    scope_id: str = ""

    def __post_init__(self) -> None:
        if not self.provider_id.strip():
            raise ValueError("provider_id must not be empty")
        if not self.native_partition:
            raise ValueError("native_partition must not be empty")


class CellState(str, Enum):
    UNEXPLORED = "unexplored"
    EXPLORED = "explored"
    PARTIAL = "partial"
    UNQUERYABLE = "unqueryable"
    UNREACHABLE = "unreachable"


@dataclass
class Cell:
    """Coverage unit: (ProviderScope, entity/ANY, time_bucket)."""

    provider_scope: ProviderScope
    entity: EntityRef
    time_bucket: str
    state: CellState = CellState.UNEXPLORED
    split_parent: bool = False

    def __post_init__(self) -> None:
        if not self.time_bucket.strip():
            raise ValueError("time_bucket must not be empty")

    @property
    def is_wildcard(self) -> bool:
        return isinstance(self.entity, AnyEntity)


__all__ = ["ProviderScope", "Cell", "CellState"]
