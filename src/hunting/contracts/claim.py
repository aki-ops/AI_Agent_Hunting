"""Claim and ClaimGraph contracts — v6 architecture.

This module is the source-of-truth contract for the semantic layer.
See 01_FINAL-ARCHITECTURE.md §3.2 (ClaimGraph) for design rationale.

Design invariants enforced here:
- Every Claim must have an AcceptanceRule (no bare assertions).
- No claim may contain raw SPL/KQL/SQL in any field.
- Every non-prerequisite claim must trace to the originating request.
- No scenario-specific subclasses (no EmailClaim, TorClaim, CVEClaim).
  The predicate and value_type fields carry all semantic differentiation.
- ClaimStatus transitions are unidirectional: UNPROVEN -> SUPPORTED / REFUTED / PARTIAL.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

# ---------------------------------------------------------------------------
# SPL/KQL/SQL guard — used by ClaimGraph validation
# ---------------------------------------------------------------------------

_NATIVE_SYNTAX_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bindex\s*=\s*\w+", re.IGNORECASE),
    re.compile(r"\bsourcetype\s*=\s*\w+", re.IGNORECASE),
    re.compile(r"\|\s*(stats|eval|rex|spath|table|where)\b", re.IGNORECASE),
    re.compile(r"\bSELECT\b.+\bFROM\b", re.IGNORECASE),
    re.compile(r"\b(DeviceEvents|SecurityEvent)\s*\|", re.IGNORECASE),
    re.compile(r"\blet\s+\w+\s*=\s*", re.IGNORECASE),
    re.compile(r"\bEventID\s*==?\s*\d+", re.IGNORECASE),
)

_SPL_KQL_DESCRIPTION = (
    "raw SPL (index=, |stats, |eval), SQL (SELECT FROM), "
    "or KQL (DeviceEvents|, let x=)"
)


def _contains_native_syntax(text: str) -> bool:
    return any(pat.search(text) for pat in _NATIVE_SYNTAX_PATTERNS)


def _check_no_native_syntax(field_name: str, value: str | None) -> None:
    if value and _contains_native_syntax(value):
        raise ValueError(
            f"Claim.{field_name} contains {_SPL_KQL_DESCRIPTION}. "
            "Claims must use provider-neutral predicates only."
        )


# ---------------------------------------------------------------------------
# ClaimStatus
# ---------------------------------------------------------------------------


class ClaimStatus(str, Enum):
    UNPROVEN = "UNPROVEN"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    INCONCLUSIVE = "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# AcceptanceRule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AcceptanceRule:
    """Machine-checkable conditions required to promote a Claim to SUPPORTED.

    All conditions are AND-ed. The verifier evaluates deterministically.
    """
    min_observations: int = 1
    required_fields: tuple[str, ...] = ()
    required_roles: tuple[str, ...] = ()
    requires_query_complete: bool = False
    value_must_match: str | None = None
    custom_doc: str | None = None

    def __post_init__(self) -> None:
        if self.min_observations < 1:
            raise ValueError("AcceptanceRule.min_observations must be >= 1")
        if self.value_must_match and _contains_native_syntax(self.value_must_match):
            raise ValueError(
                f"AcceptanceRule.value_must_match contains {_SPL_KQL_DESCRIPTION}"
            )
        if isinstance(self.required_roles, list):
            object.__setattr__(self, "required_roles", tuple(self.required_roles))


# ---------------------------------------------------------------------------
# RefutationRule
# ---------------------------------------------------------------------------


class RefutationCondition(str, Enum):
    FIELD_ABSENT = "field_absent"
    FIELD_EQUALS = "field_equals"
    FIELD_NOT_CONTAINS = "field_not_contains"
    CONTRADICTORY_CLAIM = "contradictory_claim"


@dataclass(frozen=True)
class RefutationRule:
    """Conditions that definitively refute a claim."""
    condition: RefutationCondition
    field: str = ""
    value: str = ""
    contradicts_claim_id: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.value and _contains_native_syntax(self.value):
            raise ValueError(
                f"RefutationRule.value contains {_SPL_KQL_DESCRIPTION}"
            )
        if self.condition == RefutationCondition.CONTRADICTORY_CLAIM and not self.contradicts_claim_id:
            raise ValueError(
                "RefutationRule with CONTRADICTORY_CLAIM must specify contradicts_claim_id"
            )


# ---------------------------------------------------------------------------
# ClaimEvidenceRequirement — observation shape a claim needs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimEvidenceRequirement:
    """Observation shape required to test a claim. Not a vendor event family."""

    id: str
    fact_kind: str
    required_fields: tuple[str, ...] = ()
    field_roles: tuple[str, ...] = ()
    required_roles: tuple[str, ...] = ()
    completeness_required: bool = False

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("ClaimEvidenceRequirement.id must not be empty")
        if not self.fact_kind.strip():
            raise ValueError("ClaimEvidenceRequirement.fact_kind must not be empty")
        _check_no_native_syntax("fact_kind", self.fact_kind)
        if isinstance(self.required_fields, list):
            object.__setattr__(self, "required_fields", tuple(self.required_fields))
        if isinstance(self.field_roles, list):
            object.__setattr__(self, "field_roles", tuple(self.field_roles))
        if isinstance(self.required_roles, list):
            object.__setattr__(self, "required_roles", tuple(self.required_roles))


# ---------------------------------------------------------------------------
# Claim
# ---------------------------------------------------------------------------


@dataclass
class Claim:
    """An atomic, verifiable assertion derived from a hunt request.

    Invariants enforced in __post_init__:
    - No raw provider syntax in any field.
    - source_request_id must be non-empty for non-prerequisite claims.
    - acceptance_rule must be provided.
    - No EmailClaim/TorClaim/CVEClaim subclasses.
    """

    id: str
    claim_type: Literal["attribute", "relation", "behaviour", "controlled_absence"]
    subject: str
    predicate: str
    provenance: Literal["request", "cti_source", "verified_observation"]
    source_request_id: str
    object_or_value: str | None = None
    value_type: str | None = None
    dependencies: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    observation_requirements: tuple[ClaimEvidenceRequirement, ...] = ()
    acceptance_rule: AcceptanceRule = field(default_factory=AcceptanceRule)
    refutation_rule: RefutationRule | None = None
    optional: bool = False
    is_prerequisite: bool = False
    reason: str = ""
    status: ClaimStatus = ClaimStatus.UNPROVEN
    _cited_observation_ids: list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Claim.id must not be empty")
        if not self.subject.strip():
            raise ValueError("Claim.subject must not be empty")
        if not self.predicate.strip():
            raise ValueError("Claim.predicate must not be empty")

        if not self.is_prerequisite and not self.source_request_id.strip():
            raise ValueError(
                "Claim.source_request_id must not be empty for non-prerequisite claims. "
                "Every claim must trace back to the originating HuntRequest."
            )

        _check_no_native_syntax("predicate", self.predicate)
        _check_no_native_syntax("object_or_value", self.object_or_value)
        _check_no_native_syntax("reason", self.reason)

        if self.acceptance_rule is None:
            raise ValueError(
                f"Claim '{self.id}' has no AcceptanceRule. "
                "Every claim must declare how it can be verified."
            )

        if isinstance(self.dependencies, list):
            object.__setattr__(self, "dependencies", tuple(self.dependencies))
        if isinstance(self.evidence_requirements, list):
            object.__setattr__(self, "evidence_requirements", tuple(self.evidence_requirements))
        if isinstance(self.observation_requirements, list):
            object.__setattr__(self, "observation_requirements", tuple(self.observation_requirements))

    def is_resolved(self) -> bool:
        return self.status in {
            ClaimStatus.SUPPORTED,
            ClaimStatus.REFUTED,
            ClaimStatus.UNKNOWN,
            ClaimStatus.INCONCLUSIVE,
        }

    def cite(self, observation_id: str) -> None:
        if observation_id not in self._cited_observation_ids:
            self._cited_observation_ids.append(observation_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "claim_type": self.claim_type,
            "subject": self.subject,
            "predicate": self.predicate,
            "object_or_value": self.object_or_value,
            "value_type": self.value_type,
            "provenance": self.provenance,
            "source_request_id": self.source_request_id,
            "dependencies": list(self.dependencies),
            "evidence_requirements": list(self.evidence_requirements),
            "observation_requirements": [
                {
                    "id": req.id,
                    "fact_kind": req.fact_kind,
                    "required_fields": list(req.required_fields),
                    "field_roles": list(req.field_roles),
                    "required_roles": list(req.required_roles),
                    "completeness_required": req.completeness_required,
                }
                for req in self.observation_requirements
            ],
            "acceptance_rule": {
                "min_observations": self.acceptance_rule.min_observations,
                "required_fields": list(self.acceptance_rule.required_fields),
                "required_roles": list(self.acceptance_rule.required_roles),
                "requires_query_complete": self.acceptance_rule.requires_query_complete,
                "value_must_match": self.acceptance_rule.value_must_match,
            },
            "refutation_rule": (
                {
                    "condition": self.refutation_rule.condition.value,
                    "field": self.refutation_rule.field,
                    "value": self.refutation_rule.value,
                    "reason": self.refutation_rule.reason,
                }
                if self.refutation_rule
                else None
            ),
            "optional": self.optional,
            "is_prerequisite": self.is_prerequisite,
            "reason": self.reason,
            "status": self.status.value,
            "cited_observation_ids": list(self._cited_observation_ids),
        }


# ---------------------------------------------------------------------------
# ClaimGraph
# ---------------------------------------------------------------------------


@dataclass
class ClaimGraph:
    """Validated semantic plan proposed by the LLM, accepted after deterministic checks.

    See 01_FINAL-ARCHITECTURE.md §3.2 for full contract definition.
    """

    id: str
    request_id: str
    objective: str
    claims: list[Claim]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("ClaimGraph.id must not be empty")
        if not self.request_id.strip():
            raise ValueError("ClaimGraph.request_id must not be empty")
        if not self.objective.strip():
            raise ValueError("ClaimGraph.objective must not be empty")
        _check_no_native_syntax("objective", self.objective)

        seen_ids: set[str] = set()
        for claim in self.claims:
            if claim.id in seen_ids:
                raise ValueError(
                    f"Duplicate Claim.id '{claim.id}' in ClaimGraph '{self.id}'"
                )
            seen_ids.add(claim.id)
            if not claim.is_prerequisite and claim.source_request_id != self.request_id:
                raise ValueError(
                    f"Claim '{claim.id}' source_request_id '{claim.source_request_id}' "
                    f"does not match ClaimGraph.request_id '{self.request_id}'. "
                    "Non-prerequisite claims must originate from the graph request."
                )

        for claim in self.claims:
            for dep_id in claim.dependencies:
                if dep_id not in seen_ids:
                    raise ValueError(
                        f"Claim '{claim.id}' depends on '{dep_id}' "
                        f"which is not in ClaimGraph '{self.id}'"
                    )

        self._validate_no_cycles(seen_ids)

    def _validate_no_cycles(self, claim_ids: set[str]) -> None:
        adj: dict[str, list[str]] = {c.id: list(c.dependencies) for c in self.claims}
        visited: set[str] = set()
        in_stack: set[str] = set()

        def dfs(node: str) -> None:
            if node in in_stack:
                raise ValueError(
                    f"ClaimGraph '{self.id}' has a dependency cycle involving claim '{node}'"
                )
            if node in visited:
                return
            visited.add(node)
            in_stack.add(node)
            for dep in adj.get(node, []):
                dfs(dep)
            in_stack.discard(node)

        for cid in claim_ids:
            if cid not in visited:
                dfs(cid)

    def get_claim(self, claim_id: str) -> "Claim | None":
        return next((c for c in self.claims if c.id == claim_id), None)

    def unresolved_claims(self) -> list["Claim"]:
        return [c for c in self.claims if not c.is_resolved()]

    def supported_claims(self) -> list["Claim"]:
        return [c for c in self.claims if c.status == ClaimStatus.SUPPORTED]

    def refuted_claims(self) -> list["Claim"]:
        return [c for c in self.claims if c.status == ClaimStatus.REFUTED]

    def is_resolved(self) -> bool:
        return all(c.is_resolved() or c.optional for c in self.claims)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "request_id": self.request_id,
            "objective": self.objective,
            "claims": [c.to_dict() for c in self.claims],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, request_id: str | None = None) -> "ClaimGraph":
        graph_request_id = str(request_id or data.get("request_id", "")).strip()
        claims: list[Claim] = []
        for item in data.get("claims", []):
            if not isinstance(item, dict):
                raise ValueError("ClaimGraph.claims must contain JSON objects")

            acceptance_data = item.get("acceptance_rule")
            if not isinstance(acceptance_data, dict):
                raise ValueError(f"Claim '{item.get('id', '')}' has no AcceptanceRule")
            acceptance = AcceptanceRule(
                min_observations=int(acceptance_data.get("min_observations", 1)),
                required_fields=tuple(str(value).strip() for value in acceptance_data.get("required_fields", []) if str(value).strip()),
                required_roles=tuple(str(value).strip() for value in acceptance_data.get("required_roles", []) if str(value).strip()),
                requires_query_complete=bool(acceptance_data.get("requires_query_complete", False)),
                value_must_match=(str(acceptance_data["value_must_match"]).strip() if acceptance_data.get("value_must_match") is not None else None),
                custom_doc=(str(acceptance_data["custom_doc"]).strip() if acceptance_data.get("custom_doc") is not None else None),
            )

            refutation = None
            refutation_data = item.get("refutation_rule")
            if isinstance(refutation_data, dict):
                refutation = RefutationRule(
                    condition=RefutationCondition(str(refutation_data.get("condition", "")).strip().lower()),
                    field=str(refutation_data.get("field", "")).strip(),
                    value=str(refutation_data.get("value", "")).strip(),
                    contradicts_claim_id=(str(refutation_data["contradicts_claim_id"]).strip() if refutation_data.get("contradicts_claim_id") else None),
                    reason=str(refutation_data.get("reason", "")).strip(),
                )

            observation_requirements = tuple(
                ClaimEvidenceRequirement(
                    id=str(req.get("id", "")).strip(),
                    fact_kind=str(req.get("fact_kind", "")).strip(),
                    required_fields=tuple(str(value).strip() for value in req.get("required_fields", []) if str(value).strip()),
                    field_roles=tuple(str(value).strip() for value in req.get("field_roles", []) if str(value).strip()),
                    required_roles=tuple(str(value).strip() for value in req.get("required_roles", []) if str(value).strip()),
                    completeness_required=bool(req.get("completeness_required", False)),
                )
                for req in item.get("observation_requirements", [])
                if isinstance(req, dict)
            )
            claims.append(
                Claim(
                    id=str(item.get("id", "")).strip(),
                    claim_type=str(item.get("claim_type", "")).strip().lower(),
                    subject=str(item.get("subject", "")).strip(),
                    predicate=str(item.get("predicate", "")).strip(),
                    provenance=str(item.get("provenance", "request")).strip().lower(),
                    source_request_id=str(item.get("source_request_id", graph_request_id)).strip(),
                    object_or_value=(str(item["object_or_value"]).strip() if item.get("object_or_value") is not None else None),
                    value_type=(str(item["value_type"]).strip() if item.get("value_type") is not None else None),
                    dependencies=tuple(str(value).strip() for value in item.get("dependencies", []) if str(value).strip()),
                    evidence_requirements=tuple(str(value).strip() for value in item.get("evidence_requirements", []) if str(value).strip()),
                    observation_requirements=observation_requirements,
                    acceptance_rule=acceptance,
                    refutation_rule=refutation,
                    optional=bool(item.get("optional", False)),
                    is_prerequisite=bool(item.get("is_prerequisite", False)),
                    reason=str(item.get("reason", "")).strip(),
                )
            )

        return cls(
            id=str(data.get("id", "")).strip(),
            request_id=graph_request_id,
            objective=str(data.get("objective", "")).strip(),
            claims=claims,
            metadata=dict(data.get("metadata", {})) if isinstance(data.get("metadata", {}), dict) else {},
        )


__all__ = [
    "ClaimStatus",
    "AcceptanceRule",
    "RefutationCondition",
    "RefutationRule",
    "ClaimEvidenceRequirement",
    "Claim",
    "ClaimGraph",
]
