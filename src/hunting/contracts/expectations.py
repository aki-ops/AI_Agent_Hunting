"""Question-side expectation contracts.

Expectations describe evidence requirements, not vendor event families. Native
provider records may satisfy the same requirement across different adapters.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunting.contracts.entities import AnyEntity, EntityRef


class EvidenceRequirement(str, Enum):
    PROCESS_ANCESTRY = "process_ancestry"
    AUTHENTICATION_ACTIVITY = "authentication_activity"
    NETWORK_CONNECTION = "network_connection"
    FILE_MODIFICATION = "file_modification"
    DNS_ACTIVITY = "dns_activity"
    PERSISTENCE_CHANGE = "persistence_change"
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
