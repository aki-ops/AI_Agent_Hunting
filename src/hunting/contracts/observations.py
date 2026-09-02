"""Observation ledger contracts.

Native provider records are preserved even when semantic mapping is absent.
Raw content remains in protected storage and is never sent to an LLM.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import EntityRef, AnyEntity


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


@dataclass
class Observation:
    id: str
    provider_scope: ProviderScope
    cell_id: str
    timestamp: str
    epistemic_type: EpistemicType
    native_type: str | None = None
    semantic_type: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    taint: dict[str, TaintLabel] = field(default_factory=dict)
    entities: list[EntityRef] = field(default_factory=list)
    provenance: Provenance | None = None
    raw_ref: str | None = None
    attributed_by: list[str] = field(default_factory=list)
    demanding: bool = False

    def __post_init__(self) -> None:
        if any(isinstance(entity, AnyEntity) for entity in self.entities):
            raise ValueError("Observation.entities cannot contain ANY")
