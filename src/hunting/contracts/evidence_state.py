"""Evidence state contracts tracking artifact detection and attribute observations.

Separates artifact detection (e.g. software present on host) from attribute
observation (e.g. software_version observed in telemetry).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AnswerAttributeState(str, Enum):
    OBSERVED = "OBSERVED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass
class ArtifactEvidence:
    """Represents an observed entity or artifact on an endpoint/network."""
    type: str  # "software", "process", "account", "host", "domain", "ip"
    name: str  # e.g. "Tor Browser", "tor.exe"
    host: str = ""
    path: str | None = None
    process_name: str | None = None
    detected: bool = True
    observation_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "name": self.name,
            "host": self.host,
            "path": self.path,
            "process_name": self.process_name,
            "detected": self.detected,
            "observation_ids": list(self.observation_ids),
        }


@dataclass
class AttributeEvidence:
    """Represents the observation state of a specific requested attribute."""
    name: str  # e.g. "software_version", "email_address", "client_ip"
    status: AnswerAttributeState = AnswerAttributeState.UNKNOWN
    values: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "values": list(self.values),
            "observation_ids": list(self.observation_ids),
        }


@dataclass
class EvidenceState:
    """Container tracking artifact detection and attribute resolution."""
    artifact: ArtifactEvidence | None = None
    attributes: dict[str, AttributeEvidence] = field(default_factory=dict)

    def is_artifact_detected(self) -> bool:
        return bool(self.artifact and self.artifact.detected)

    def get_attribute_status(self, attr_name: str) -> AnswerAttributeState:
        if attr_name in self.attributes:
            return self.attributes[attr_name].status
        return AnswerAttributeState.UNKNOWN

    def get_attribute_values(self, attr_name: str) -> list[str]:
        if attr_name in self.attributes:
            return list(self.attributes[attr_name].values)
        return []

    def set_attribute(
        self,
        attr_name: str,
        status: AnswerAttributeState,
        values: list[str] | None = None,
        obs_ids: list[str] | None = None,
    ) -> None:
        self.attributes[attr_name] = AttributeEvidence(
            name=attr_name,
            status=status,
            values=list(values or []),
            observation_ids=list(obs_ids or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.to_dict() if self.artifact else None,
            "attributes": {k: v.to_dict() for k, v in self.attributes.items()},
        }


__all__ = [
    "AnswerAttributeState",
    "ArtifactEvidence",
    "AttributeEvidence",
    "EvidenceState",
]
