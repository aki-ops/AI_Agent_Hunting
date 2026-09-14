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
    # v9 additions:
    evaluator_id: str = "generic_observed_relation"
    evaluator_version: str = "1.0"
    subject_types: tuple[str, ...] = ()
    object_types: tuple[str, ...] = ()
    directional_role_bindings: tuple[tuple[str, str], ...] = ()
    action_requirements: tuple[str, ...] = ()
    state_requirements: tuple[str, ...] = ()
    correlation_requirements: tuple[str, ...] = ()
    constraint_evaluators: tuple[str, ...] = ()
    negative_evidence_licensed: bool = False
    scope_and_limitations: str = ""

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
            "subject_types",
            "object_types",
            "action_requirements",
            "state_requirements",
            "correlation_requirements",
            "constraint_evaluators",
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
            "evaluator_id": self.evaluator_id,
            "evaluator_version": self.evaluator_version,
            "subject_types": list(self.subject_types),
            "object_types": list(self.object_types),
            "directional_role_bindings": [list(item) for item in self.directional_role_bindings],
            "action_requirements": list(self.action_requirements),
            "state_requirements": list(self.state_requirements),
            "correlation_requirements": list(self.correlation_requirements),
            "constraint_evaluators": list(self.constraint_evaluators),
            "negative_evidence_licensed": self.negative_evidence_licensed,
            "scope_and_limitations": self.scope_and_limitations,
        }


@dataclass(frozen=True)
class ProofResult:
    """Canonical outcome of deterministic proof evaluation (v9)."""

    contract_id: str | None = None
    contract_version: str | None = None
    evaluator_id: str = "default"
    evaluator_version: str = "1.0"
    verified: bool = False
    verdict: str = "UNPROVEN"  # "PROVEN", "UNPROVEN", "REFUTED", "PROOF_GAP", "RETRIEVAL_ONLY"
    reason_codes: tuple[str, ...] = ()
    subject_binding: str | None = None
    object_binding: str | None = None
    bindings: tuple[tuple[str, str], ...] = ()
    satisfied_obligations: tuple[str, ...] = ()
    missing_obligations: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    cited_fields: tuple[tuple[str, str], ...] = ()
    completeness_satisfied: bool = False
    coverage_satisfied: bool = False
    limitations: tuple[str, ...] = ()
    diagnostic: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.bindings, dict):
            object.__setattr__(self, "bindings", tuple((str(k), str(v)) for k, v in self.bindings.items()))
        elif isinstance(self.bindings, (list, set)):
            object.__setattr__(self, "bindings", tuple(self.bindings))
        if isinstance(self.cited_fields, dict):
            object.__setattr__(self, "cited_fields", tuple((str(k), str(v)) for k, v in self.cited_fields.items()))
        elif isinstance(self.cited_fields, (list, set)):
            object.__setattr__(self, "cited_fields", tuple(self.cited_fields))
        for name in (
            "reason_codes",
            "satisfied_obligations",
            "missing_obligations",
            "citations",
            "limitations",
        ):
            val = getattr(self, name)
            if not isinstance(val, tuple):
                object.__setattr__(self, name, tuple(val))

    @property
    def status(self) -> str:
        """Status string compatible with legacy and v9 proof states."""
        return "VERIFIED" if self.verified else self.verdict

    @property
    def is_proven(self) -> bool:
        return self.verified

    @property
    def proved(self) -> bool:
        return self.verified

    @property
    def cited_observation_ids(self) -> tuple[str, ...]:
        return self.citations

    @property
    def bindings_dict(self) -> dict[str, str]:
        return dict(self.bindings)

    @property
    def cited_fields_dict(self) -> dict[str, str]:
        return dict(self.cited_fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "evaluator_id": self.evaluator_id,
            "evaluator_version": self.evaluator_version,
            "verified": self.verified,
            "verdict": self.verdict,
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "subject_binding": self.subject_binding,
            "object_binding": self.object_binding,
            "bindings": dict(self.bindings),
            "satisfied_obligations": list(self.satisfied_obligations),
            "missing_obligations": list(self.missing_obligations),
            "citations": list(self.citations),
            "cited_fields": dict(self.cited_fields),
            "completeness_satisfied": self.completeness_satisfied,
            "coverage_satisfied": self.coverage_satisfied,
            "limitations": list(self.limitations),
            "diagnostic": self.diagnostic,
        }


__all__ = [
    "ProofCapabilityLevel",
    "ProofContractStatus",
    "ProofContract",
    "ProofResult",
    "ROLE_INCOMPATIBLE_FIELDS",
]

