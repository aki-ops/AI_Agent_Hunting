"""Knowledge and Behavior Compiler data models.

Fulfills Phase 1 requirements:
- Versioned CVE/TTP/IOC/behavior records with source citations.
- Structured decomposition of CVE into:
    exposure -> preconditions -> exploitation indicators -> post-exploitation -> gaps
- Behavior templates for process, remote authentication, network, file, persistence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunting.contracts.hunt import EvidenceRequirementV4


class BehaviorCategory(str, Enum):
    PROCESS = "process"
    REMOTE_AUTHENTICATION = "remote_authentication"
    NETWORK = "network"
    FILE = "file"
    PERSISTENCE = "persistence"


@dataclass(frozen=True)
class CVEPhases:
    """Explicit 5-phase breakdown of a CVE threat profile."""
    exposure: tuple[str, ...] = field(default_factory=tuple)
    preconditions: tuple[str, ...] = field(default_factory=tuple)
    exploitation_indicators: tuple[str, ...] = field(default_factory=tuple)
    post_exploitation: tuple[str, ...] = field(default_factory=tuple)
    gaps: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.exposure:
            raise ValueError("CVEPhases.exposure must not be empty")
        if not self.exploitation_indicators:
            raise ValueError("CVEPhases.exploitation_indicators must not be empty")


@dataclass(frozen=True)
class KnowledgeRecord:
    """Versioned threat knowledge record with authoritative source citations."""
    id: str
    version: str
    kind: str  # "cve" | "ttp" | "ioc" | "behavior"
    title: str
    description: str
    source_citations: tuple[str, ...] = field(default_factory=tuple)
    phases: CVEPhases | None = None

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("KnowledgeRecord.id must not be empty")
        if not self.version.strip():
            raise ValueError("KnowledgeRecord.version must not be empty")
        if not self.source_citations:
            raise ValueError(f"KnowledgeRecord '{self.id}' must provide at least one source citation")


@dataclass
class BehaviorTemplate:
    """Reusable hunting behavior template defining observable evidence requirements."""
    id: str
    category: BehaviorCategory
    name: str
    description: str
    requirements: list[EvidenceRequirementV4]
    required_fields: list[str]
    falsification_condition: str
    source_citations: list[str]

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("BehaviorTemplate.id must not be empty")
        if not self.requirements:
            raise ValueError("BehaviorTemplate.requirements must not be empty")
        if not self.falsification_condition.strip():
            raise ValueError("BehaviorTemplate.falsification_condition must not be empty")
        if not self.source_citations:
            raise ValueError("BehaviorTemplate.source_citations must not be empty")
        if not self.required_fields:
            raise ValueError("BehaviorTemplate.required_fields must not be empty")


__all__ = [
    "BehaviorCategory",
    "CVEPhases",
    "KnowledgeRecord",
    "BehaviorTemplate",
]
