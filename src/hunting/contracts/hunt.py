"""Canonical v4 Threat Hunting Contracts.

As specified in 01_FINAL-ARCHITECTURE.md:
Pure hypothesis-driven, evidence-grounded threat-hunting contracts:
- HuntRequest: Ingests HYPOTHESIS, TTP, IOC, CVE, CTI_REPORT, NL_QUESTION, SCHEDULED without alert.
- HuntObjective: Goal and scope derived from request.
- Hypothesis: Candidate explanation of adversary behavior.
- EvidenceRequirementV4 / EvidenceRequirementSpec: Question-side evidence shape.
- QueryPlan: Provider-specific execution plan.
- EvidenceCard: Compressed evidence group with fingerprints and summaries.
- HuntState: Data-only state container (Action Controller is sole state-transition authority).
- FinalHuntAccount: Auditable report emitted at termination.
- Distinct epistemic outcomes and stopping decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.cells import Cell
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.entities import AnyEntity, EntityRef
from hunting.contracts.expectations import Expectation, FieldPredicate
from hunting.contracts.observations import Observation
from hunting.contracts.queries import QueryResult


class HuntRequestKind(str, Enum):
    HYPOTHESIS = "HYPOTHESIS"
    TTP = "TTP"
    IOC = "IOC"
    CVE = "CVE"
    CTI_REPORT = "CTI_REPORT"
    NL_QUESTION = "NL_QUESTION"
    SCHEDULED = "SCHEDULED"


@dataclass(frozen=True)
class TimePolicy:
    start: str | None = None
    end: str | None = None
    lookback_days: int = 14


@dataclass
class HuntRequest:
    """Entrypoint contract for pure hypothesis-driven threat hunting.

    Never requires an alert or PoC. Entities, time policy, and provider hints
    are optional and deployment-configured, never fabricated.
    """
    id: str
    kind: HuntRequestKind
    content: str
    entities: list[EntityRef] = field(default_factory=list)
    time_policy: TimePolicy | None = None
    provider_hints: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("HuntRequest.id must not be empty")
        if not self.content.strip():
            raise ValueError("HuntRequest.content must not be empty")
        if isinstance(self.kind, str) and not isinstance(self.kind, HuntRequestKind):
            self.kind = HuntRequestKind(self.kind)


@dataclass
class HuntObjective:
    """Compiled search objective binding request to search target."""
    request_id: str
    target_hypotheses: list[str] = field(default_factory=list)
    time_window: str = ""
    target_scopes: list[str] = field(default_factory=list)
    kind: HuntRequestKind | str | None = None
    statement: str = ""
    entities: list[EntityRef] = field(default_factory=list)
    time_policy: TimePolicy | None = None

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("HuntObjective.request_id must not be empty")


class HypothesisOrigin(str, Enum):
    INPUT = "INPUT"
    LLM_PROPOSAL = "LLM_PROPOSAL"
    RULE = "RULE"
    HUMAN = "HUMAN"


class HypothesisStatus(str, Enum):
    LIVE = "LIVE"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    REFUTED = "REFUTED"
    UNTESTABLE = "UNTESTABLE"


@dataclass
class Hypothesis:
    """A testable proposition of threat actor activity or baseline anomaly."""
    id: str
    statement: str
    origin: HypothesisOrigin = HypothesisOrigin.INPUT
    status: HypothesisStatus = HypothesisStatus.LIVE
    source_refs: list[str] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Hypothesis.id must not be empty")
        if not self.statement.strip():
            raise ValueError("Hypothesis.statement must not be empty")


class RequirementStatus(str, Enum):
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    UNSUPPORTED = "UNSUPPORTED"
    REJECTED = "REJECTED"


@dataclass
class EvidenceRequirementV4:
    """Question-side evidence specification.

    Reusable across entities and providers; describes the evidence required
    to falsify or confirm a hypothesis without vendor-specific event taxonomy.
    """
    id: str
    description: str
    evidence_type: str
    entity_scope: EntityRef | AnyEntity | str = "ANY"
    time_scope: str = ""
    predicate: FieldPredicate | None = None
    supports: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    falsification_condition: str = ""
    source_refs: list[str] = field(default_factory=list)
    status: RequirementStatus = RequirementStatus.PROPOSED

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("EvidenceRequirementV4.id must not be empty")
        if not self.evidence_type.strip():
            raise ValueError("EvidenceRequirementV4.evidence_type must not be empty")


# Convenient alias for canonical v4 question specification
EvidenceRequirementSpec = EvidenceRequirementV4


@dataclass(frozen=True)
class QueryPlan:
    """Provider-specific executable plan bound to an evidence requirement."""
    id: str
    requirement_id: str
    provider_id: str
    scope_id: str
    operation_id: str
    parameters: dict[str, Any] = field(default_factory=dict)
    estimated_cost: int = 1
    completeness_contract: str = "complete"
    is_targeted: bool = False

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("QueryPlan.id must not be empty")
        if not self.requirement_id.strip():
            raise ValueError("QueryPlan.requirement_id must not be empty")


@dataclass
class EvidenceCard:
    """Compressed, deduplicated evidence group representation.

    The ObservationLedger stores every observation, while LLM and evaluators
    receive EvidenceCards to prevent prompt explosion.
    """
    id: str
    fingerprint: str
    representative_observation_ids: list[str] = field(default_factory=list)
    count: int = 1
    entity_summary: dict[str, Any] = field(default_factory=dict)
    time_summary: dict[str, Any] = field(default_factory=dict)
    field_summary: dict[str, Any] = field(default_factory=dict)
    fact_type: str = ""
    completeness: str = "complete"
    relations: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("EvidenceCard.id must not be empty")
        if not self.fingerprint.strip():
            raise ValueError("EvidenceCard.fingerprint must not be empty")


class HuntOutcome(str, Enum):
    """Canonical epistemic outcomes for threat hunting hypotheses."""
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNKNOWN = "UNKNOWN"
    UNREACHABLE = "UNREACHABLE"


class StoppingDecision(str, Enum):
    """Deterministic terminal stopping decisions."""
    STOP_RESOLVED = "STOP_RESOLVED"
    STOP_BOUNDED = "STOP_BOUNDED"
    STOP_EXHAUSTED_BY_BUDGET = "STOP_EXHAUSTED_BY_BUDGET"


@dataclass
class HuntState:
    """Pure data container for hunt state.

    Invariant: HuntState is data only, not an action authority.
    Only the Action Controller changes HuntState.
    """
    objective: HuntObjective | None = None
    hypotheses: list[Hypothesis] = field(default_factory=list)
    requirements: list[EvidenceRequirementV4] = field(default_factory=list)
    expectations: list[Expectation] = field(default_factory=list)
    evidence_cards: list[EvidenceCard] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    queries: list[QueryPlan] = field(default_factory=list)
    query_results: list[QueryResult] = field(default_factory=list)
    cells: list[Cell] = field(default_factory=list)
    coverage: CoverageBound = field(default_factory=CoverageBound)
    stopping_decision: StoppingDecision | None = None
    turn: int = 0
    query_count: int = 0


@dataclass
class FinalHuntAccount:
    """Canonical immutable output emitted at hunt termination."""
    request_id: str
    objective: HuntObjective
    hypotheses: list[Hypothesis]
    evidence_cards: list[EvidenceCard]
    queries: list[dict[str, Any]]
    supporting: list[str]
    contradicting: list[str]
    unknown: list[str]
    unreachable: list[str]
    residuals: list[str]
    coverage_bound: CoverageBound
    stopping_decision: StoppingDecision
    observation_citations: list[str] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    gap_breakdown: dict[str, list[str]] = field(default_factory=dict)

    @property
    def outcome(self) -> HuntOutcome:
        """Derive canonical outcome from supporting / contradicting / unreachable."""
        if self.supporting:
            return HuntOutcome.SUPPORTED
        if self.contradicting and not self.supporting:
            return HuntOutcome.CONTRADICTED
        if self.unreachable and not self.supporting:
            return HuntOutcome.UNREACHABLE
        return HuntOutcome.UNKNOWN  # Rendered as NO_EVIDENCE_FOUND in final report


__all__ = [
    "HuntRequestKind",
    "TimePolicy",
    "HuntRequest",
    "HuntObjective",
    "HypothesisOrigin",
    "HypothesisStatus",
    "Hypothesis",
    "RequirementStatus",
    "EvidenceRequirementV4",
    "EvidenceRequirementSpec",
    "QueryPlan",
    "EvidenceCard",
    "HuntOutcome",
    "StoppingDecision",
    "HuntState",
    "FinalHuntAccount",
]
