"""Question-side expectation contracts.

Expectations describe evidence requirements, not vendor event families. Native
provider records may satisfy the same requirement across different adapters.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunting.contracts.entities import Account, AnyEntity, Domain, EntityRef, IPAddress


class EvidenceRequirement(str, Enum):
    PROCESS_ANCESTRY = "process_ancestry"
    AUTHENTICATION_ACTIVITY = "authentication_activity"
    NETWORK_CONNECTION = "network_connection"
    FILE_MODIFICATION = "file_modification"
    DNS_ACTIVITY = "dns_activity"
    PERSISTENCE_CHANGE = "persistence_change"
    WEB_REQUEST = "web_request"
    SCOPE_RECORDS = "scope_records"


class TestStatus(str, Enum):
    __test__ = False
    UNTESTED = "untested"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    UNTESTABLE = "untestable"
    INCONCLUSIVE = "inconclusive"


class FieldOp(str, Enum):
    EQUALS = "equals"
    CONTAINS = "contains"
    EXISTS = "exists"
    ABSENT = "absent"


@dataclass(frozen=True)
class FieldPredicate:
    field: str
    op: FieldOp
    value: str = ""


def is_entity_compatible_with_requirement(
    entity: EntityRef, requirement: EvidenceRequirement | str
) -> bool:
    """Check if an entity type is semantically compatible with an evidence requirement."""
    req_str = requirement.value if isinstance(requirement, EvidenceRequirement) else str(requirement).lower()
    if isinstance(entity, Domain):
        return req_str in (
            EvidenceRequirement.WEB_REQUEST.value,
            EvidenceRequirement.DNS_ACTIVITY.value,
            EvidenceRequirement.NETWORK_CONNECTION.value,
            "dns_query",
            "web_request",
            "web",
            "http",
            "dns",
            "net",
        )
    if isinstance(entity, Account):
        return req_str in (
            EvidenceRequirement.PROCESS_ANCESTRY.value,
            EvidenceRequirement.AUTHENTICATION_ACTIVITY.value,
            EvidenceRequirement.SCOPE_RECORDS.value,
            "process_ancestry",
            "process",
            "proc",
            "authentication_activity",
            "auth",
            "logon",
            "scope_records",
            "scope",
            "baseline",
        )
    if isinstance(entity, IPAddress):
        return req_str in (
            EvidenceRequirement.NETWORK_CONNECTION.value,
            EvidenceRequirement.DNS_ACTIVITY.value,
            EvidenceRequirement.WEB_REQUEST.value,
            EvidenceRequirement.SCOPE_RECORDS.value,
            "network_connection",
            "network",
            "net",
            "dns_activity",
            "dns",
            "web_request",
            "web",
            "http",
            "scope_records",
            "scope",
            "baseline",
        )
    return True


@dataclass
class Expectation:
    id: str
    owner_explanation_id: str
    evidence_requirement: EvidenceRequirement
    predicted_observation: str
    entity_ref: EntityRef
    field_predicate: FieldPredicate | None
    provider_scope_id: str | None
    time_window: str
    falsification_condition: str
    discriminates: list[str] = field(default_factory=list)
    test_status: TestStatus = TestStatus.UNTESTED

    def __post_init__(self) -> None:
        if isinstance(self.entity_ref, AnyEntity):
            raise ValueError("Expectation.entity_ref cannot be ANY")
        if not self.time_window.strip():
            raise ValueError("Expectation.time_window must not be empty")
        if not is_entity_compatible_with_requirement(self.entity_ref, self.evidence_requirement):
            raise ValueError(
                f"Entity {type(self.entity_ref).__name__} is incompatible with requirement {self.evidence_requirement}"
            )
