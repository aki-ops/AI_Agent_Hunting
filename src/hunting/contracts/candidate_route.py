"""Provider-neutral candidate routes between semantic goals and operations.

Retrieval is not proof.  A route is the auditable bridge that says how a
provider operation may be used for one *specific* goal.  Keeping the goal
identity on the route prevents two goals with the same relation wording from
sharing capability state accidentally.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RouteClass(str, Enum):
    EXECUTABLE = "EXECUTABLE"
    MAPPING_REQUIRED = "MAPPING_REQUIRED"
    DISCOVERY_ONLY = "DISCOVERY_ONLY"


class RouteMode(str, Enum):
    EXPLORE = "EXPLORE"
    DISCRIMINATE = "DISCRIMINATE"
    PROVE = "PROVE"


class RouteAdmission(str, Enum):
    ADMITTED = "ADMITTED"
    PROPOSED = "PROPOSED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class CandidateRoute:
    """One goal-scoped, provider-scoped route candidate.

    ``route_class`` is about executability, not correctness of the incident
    claim.  ``mode`` is an execution permission and defaults to EXPLORE;
    only an approved proof-capable operation may be admitted as PROVE.
    """

    route_id: str
    goal_id: str
    provider_id: str
    source_id: str
    operation_id: str | None = None
    subject_type: str = "entity"
    object_type: str = "entity"
    input_role_bindings: dict[str, str] = field(default_factory=dict)
    output_role_bindings: dict[str, str] = field(default_factory=dict)
    supported_constraint_keys: tuple[str, ...] = ()
    mode: RouteMode = RouteMode.EXPLORE
    frontier_stage: str = "F1_METADATA"
    route_class: RouteClass = RouteClass.DISCOVERY_ONLY
    discovery_provenance: tuple[str, ...] = ()
    admission_status: RouteAdmission = RouteAdmission.PROPOSED
    rejection_reasons: tuple[str, ...] = ()
    proof_contract_id: str | None = None
    schema_fingerprint: str = ""
    score: float = 0.0

    def __post_init__(self) -> None:
        for name in ("route_id", "goal_id", "provider_id", "source_id"):
            value = str(getattr(self, name)).strip()
            if not value:
                raise ValueError(f"{name} must not be empty")
            object.__setattr__(self, name, value)
        if not isinstance(self.route_class, RouteClass):
            object.__setattr__(self, "route_class", RouteClass(str(self.route_class)))
        if not isinstance(self.mode, RouteMode):
            object.__setattr__(self, "mode", RouteMode(str(self.mode)))
        if not isinstance(self.admission_status, RouteAdmission):
            object.__setattr__(self, "admission_status", RouteAdmission(str(self.admission_status)))
        object.__setattr__(self, "input_role_bindings", dict(self.input_role_bindings))
        object.__setattr__(self, "output_role_bindings", dict(self.output_role_bindings))
        object.__setattr__(self, "supported_constraint_keys", tuple(dict.fromkeys(
            str(key).strip().casefold() for key in self.supported_constraint_keys if str(key).strip()
        )))
        object.__setattr__(self, "discovery_provenance", tuple(self.discovery_provenance))
        object.__setattr__(self, "rejection_reasons", tuple(self.rejection_reasons))

    @property
    def executable(self) -> bool:
        return (
            self.route_class == RouteClass.EXECUTABLE
            and self.admission_status == RouteAdmission.ADMITTED
            and bool(self.operation_id)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "goal_id": self.goal_id,
            "provider_id": self.provider_id,
            "source_id": self.source_id,
            "operation_id": self.operation_id,
            "subject_type": self.subject_type,
            "object_type": self.object_type,
            "input_role_bindings": dict(self.input_role_bindings),
            "output_role_bindings": dict(self.output_role_bindings),
            "supported_constraint_keys": list(self.supported_constraint_keys),
            "mode": self.mode.value,
            "frontier_stage": self.frontier_stage,
            "route_class": self.route_class.value,
            "discovery_provenance": list(self.discovery_provenance),
            "admission_status": self.admission_status.value,
            "rejection_reasons": list(self.rejection_reasons),
            "proof_contract_id": self.proof_contract_id,
            "schema_fingerprint": self.schema_fingerprint,
            "score": self.score,
            "executable": self.executable,
        }


__all__ = ["CandidateRoute", "RouteAdmission", "RouteClass", "RouteMode"]
