"""Observation ledger contracts.

Native provider records are preserved even when semantic mapping is absent.
Raw content remains in protected storage and is never sent to an LLM.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import AnyEntity, EntityRef


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
    native_partition: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SemanticType:
    """Optional post-hoc semantic label.

    An observation without a semantic label (semantic_type=None or mapped_by='unmapped')
    is still a valid, complete observation in the ledger.
    """
    vocabulary: str          # e.g. "ocsf", "attack_data_component", "local", "native"
    value: str               # e.g. "process_creation", "dns_query"
    confidence_basis: str = "exact"
    mapped_by: str = "adapter"  # "deterministic_rule" | "adapter" | "unmapped"


@dataclass
class Observation:
    id: str
    provider_scope: ProviderScope
    cell_id: str
    timestamp: str
    epistemic_type: EpistemicType
    native_type: str | None = None
    semantic_type: SemanticType | str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    taint: dict[str, TaintLabel] = field(default_factory=dict)
    entities: list[EntityRef] = field(default_factory=list)
    provenance: Provenance | None = None
    raw_ref: str | None = None
    attributed_by: list[str] = field(default_factory=list)
    demanding: bool = False

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Observation.id must not be empty")
        if not self.timestamp.strip():
            raise ValueError("Observation.timestamp must not be empty")
        if any(isinstance(entity, AnyEntity) for entity in self.entities):
            raise ValueError("Observation.entities cannot contain ANY")

    @property
    def is_unmapped(self) -> bool:
        """True if this observation has no semantic mapping."""
        if self.semantic_type is None:
            return True
        if isinstance(self.semantic_type, SemanticType):
            return self.semantic_type.mapped_by == "unmapped"
        return False

    @property
    def is_unexplained(self) -> bool:
        """True if no explanation currently accounts for this observation."""
        return len(self.attributed_by) == 0

    def elevate_epistemic_type(self, new_type: EpistemicType) -> None:
        """Inviolable rule: TESTIMONY may NEVER become OBSERVED."""
        if self.epistemic_type == EpistemicType.TESTIMONY and new_type == EpistemicType.OBSERVED:
            raise ValueError("Inviolable constraint: TESTIMONY cannot become OBSERVED")
        self.epistemic_type = new_type


__all__ = [
    "EpistemicType",
    "TaintLabel",
    "Provenance",
    "SemanticType",
    "Observation",
]
