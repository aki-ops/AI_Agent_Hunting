"""Proof contract data models and semantic capability levels.

These contracts provide the deterministic authority required to promote an
observed telemetry row into a verified semantic relation or answer value.
LLM proposals alone can NEVER grant proof authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} must not be empty")
    return text


class ProofCapabilityLevel(str, Enum):
    """Three-tier capability hierarchy for telemetry sources and operations."""

    STRUCTURALLY_VALID = "STRUCTURALLY_VALID"
    RETRIEVAL_CAPABLE = "RETRIEVAL_CAPABLE"
    PROOF_CAPABLE = "PROOF_CAPABLE"


class ProofContractStatus(str, Enum):
    """Lifecycle status of a human-reviewed proof contract."""

    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    RETIRED = "RETIRED"


ROLE_INCOMPATIBLE_FIELDS: dict[str, set[str]] = {
    "person": {"query", "search", "url", "uri", "dest_ip", "src_ip", "ip", "port", "dest_port", "src_port", "bytes", "status", "eventcode", "count", "proto"},
    "user": {"query", "search", "url", "uri", "dest_ip", "src_ip", "ip", "port", "dest_port", "src_port", "bytes", "status", "eventcode", "count", "proto"},
    "account": {"query", "search", "url", "uri", "dest_ip", "src_ip", "ip", "port", "dest_port", "src_port", "bytes", "status", "eventcode", "count", "proto"},
    "endpoint": {"query", "search", "url", "uri", "email", "subject", "body", "mail", "password", "hash", "md5", "sha256"},
    "host": {"query", "search", "url", "uri", "email", "subject", "body", "mail", "password", "hash", "md5", "sha256"},
    "domain": {"user", "username", "account", "src_user", "dest_user", "process", "pid", "file_path", "filename", "hash"},
    "process_name": {"user", "username", "account", "dest_ip", "src_ip", "domain", "url", "uri", "email"},
}


@dataclass(frozen=True)
class ProofContract:
    """Specification of conditions under which telemetry proves a semantic relation."""

    contract_id: str
    version: str
    relation: str
    required_entity_roles: tuple[str, ...] = ()
    required_value_roles: tuple[str, ...] = ()
    required_action_roles: tuple[str, ...] = ()
    required_state_roles: tuple[str, ...] = ()
    artifact_identity_roles: tuple[str, ...] = ()
    temporal_bound_seconds: float | None = None
    min_completeness_required: bool = True
    refutation_conditions: tuple[str, ...] = ()
    status: ProofContractStatus = ProofContractStatus.APPROVED
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "contract_id", _required(self.contract_id, "contract_id"))
        object.__setattr__(self, "version", _required(self.version, "version"))
        object.__setattr__(self, "relation", _required(self.relation, "relation").casefold())
        if self.temporal_bound_seconds is not None and float(self.temporal_bound_seconds) <= 0:
            raise ValueError("temporal_bound_seconds must be positive")
        for name in (
            "required_entity_roles",
            "required_value_roles",
            "required_action_roles",
            "required_state_roles",
            "artifact_identity_roles",
            "refutation_conditions",
        ):
            items = tuple(dict.fromkeys(str(x).strip().casefold() for x in getattr(self, name) if str(x).strip()))
            object.__setattr__(self, name, items)

    @property
    def is_approved(self) -> bool:
        return self.status == ProofContractStatus.APPROVED

    def validate_capability_conformance(
        self,
        *,
        relation: str,
        input_roles: dict[str, str],
        output_roles: dict[str, str],
        action_roles: dict[str, str] | None = None,
        state_roles: dict[str, str] | None = None,
        artifact_identity_roles: dict[str, str] | None = None,
    ) -> tuple[bool, tuple[str, ...]]:
        """Check if an operation's declared roles satisfy this proof contract."""
        if not self.is_approved:
            return False, (f"contract_{self.contract_id}_is_{self.status.value}",)

        if str(relation).strip().casefold() != self.relation:
            return False, (f"relation_mismatch:{relation}_vs_{self.relation}",)

        input_role_keys = {str(k).strip().casefold() for k in input_roles.keys()}
        output_role_keys = {str(k).strip().casefold() for k in output_roles.keys()}
        provided_roles = input_role_keys | output_role_keys

        missing_entities = [r for r in self.required_entity_roles if r not in provided_roles]
        if missing_entities:
            return False, (f"missing_entity_roles:{','.join(missing_entities)}",)

        missing_values = [r for r in self.required_value_roles if r not in provided_roles]
        if missing_values:
            return False, (f"missing_value_roles:{','.join(missing_values)}",)

        # Enforce directional separation: input roles must cover entity or value, output roles the other
        req_entities = set(self.required_entity_roles)
        req_values = set(self.required_value_roles)
        valid_direction = (
            (req_entities.issubset(input_role_keys) and req_values.issubset(output_role_keys))
            or (req_values.issubset(input_role_keys) and req_entities.issubset(output_role_keys))
        )
        if not valid_direction:
            return False, ("roles_do_not_satisfy_contract_direction",)

        # Native field semantic validation
        for role, field_name in list(input_roles.items()) + list(output_roles.items()):
            r_norm = str(role).strip().casefold()
            f_norm = str(field_name).strip().casefold()
            incompat = ROLE_INCOMPATIBLE_FIELDS.get(r_norm, set())
            if f_norm in incompat:
                return False, (f"native_field_semantically_incompatible:{role}->{field_name}",)

        if self.required_action_roles:
            act = {str(k).strip().casefold() for k in (action_roles or {}).keys()}
            missing_actions = [r for r in self.required_action_roles if r not in act]
            if missing_actions:
                return False, (f"missing_action_roles:{','.join(missing_actions)}",)

        if self.required_state_roles:
            st = {str(k).strip().casefold() for k in (state_roles or {}).keys()}
            missing_states = [r for r in self.required_state_roles if r not in st]
            if missing_states:
                return False, (f"missing_state_roles:{','.join(missing_states)}",)

        if self.artifact_identity_roles:
            aid = {str(k).strip().casefold() for k in (artifact_identity_roles or {}).keys()}
            missing_aid = [r for r in self.artifact_identity_roles if r not in aid]
            if missing_aid:
                return False, (f"missing_artifact_identity_roles:{','.join(missing_aid)}",)

        return True, ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "version": self.version,
            "relation": self.relation,
            "required_entity_roles": list(self.required_entity_roles),
            "required_value_roles": list(self.required_value_roles),
            "required_action_roles": list(self.required_action_roles),
            "required_state_roles": list(self.required_state_roles),
            "artifact_identity_roles": list(self.artifact_identity_roles),
            "temporal_bound_seconds": self.temporal_bound_seconds,
            "min_completeness_required": self.min_completeness_required,
            "refutation_conditions": list(self.refutation_conditions),
            "status": self.status.value,
            "description": self.description,
        }


__all__ = [
    "ProofCapabilityLevel",
    "ProofContractStatus",
    "ProofContract",
]
