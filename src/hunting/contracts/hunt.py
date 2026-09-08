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
from hunting.contracts.hunt_spec import HuntSpec
from hunting.contracts.investigation_model import (
    GraphEdge,
    GraphNode,
    InvestigationModel,
    RelationGraph,
)
from hunting.contracts.observations import Observation
from hunting.contracts.queries import QueryResult
from hunting.contracts.semantic_intent import (
    RequestedObject,
    SemanticEvidenceRequirement,
    SemanticHuntIntent,
    SubjectEntity,
)


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
    # For NL questions, this describes the value the hunt must answer
    # (for example: {"answer_type": "domain", "evidence_types": ["web_request", "dns_activity"]}).
    # It is intentionally structured so reporting does not guess from keywords.
    answer_spec: dict[str, Any] = field(default_factory=dict)
    semantic_intent: SemanticHuntIntent | None = None
    investigation_model: InvestigationModel | None = None
    case: Any | None = None
    case_graph: Any | None = None
    hunt_spec: HuntSpec | None = None

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
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    WEAKENED = "WEAKENED"
    REFUTED = "REFUTED"
    UNTESTABLE = "UNTESTABLE"
    INSUFFICIENTLY_SPECIFIED = "INSUFFICIENTLY_SPECIFIED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"
    UNREACHABLE = "UNREACHABLE"


@dataclass
class Hypothesis:
    """A testable proposition of threat actor activity or baseline anomaly."""
    id: str
    statement: str
    origin: HypothesisOrigin = HypothesisOrigin.INPUT
    status: HypothesisStatus = HypothesisStatus.LIVE
    source_refs: list[str] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    hypothesis_class: str = ""
    required_edge_ids: list[str] = field(default_factory=list)
    required_evidence_types: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("Hypothesis.id must not be empty")
        if not self.statement.strip():
            raise ValueError("Hypothesis.statement must not be empty")


class RequirementStatus(str, Enum):
    DEFINED = "DEFINED"
    PLANNED = "PLANNED"
    EXECUTED = "EXECUTED"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    REJECTED = "REJECTED"
    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    # Epistemic status hierarchy (v5.1)
    UNMAPPED = "UNMAPPED"
    UNOBSERVABLE = "UNOBSERVABLE"
    UNTESTED = "UNTESTED"
    NO_EVIDENCE_FOUND = "NO_EVIDENCE_FOUND"


class AnswerStatus(str, Enum):
    """Forensic answer completeness status."""
    ANSWERED = "ANSWERED"
    FULLY_ANSWERED = "FULLY_ANSWERED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    PARTIALLY_ANSWERED = "PARTIALLY_ANSWERED"
    VERSION_UNAVAILABLE = "VERSION_UNAVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    UNSUPPORTED = "UNSUPPORTED"
    UNANSWERED = "UNANSWERED"
    INCONCLUSIVE = "INCONCLUSIVE"



@dataclass
class ClaimVerdict:
    """Evaluation result for a discrete sub-claim of a hunt hypothesis."""
    claim_id: str
    statement: str
    required_capability: str
    status: str  # SUPPORTED, UNKNOWN, NO_EVIDENCE_FOUND, UNOBSERVABLE, UNMAPPED
    limitations: list[str] = field(default_factory=list)
    cited_evidence_ids: list[str] = field(default_factory=list)


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
    status: RequirementStatus = RequirementStatus.DEFINED
    semantic_intent: str = ""
    necessity: str = "CRITICAL"
    search_hints: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("EvidenceRequirementV4.id must not be empty")
        if not self.evidence_type.strip():
            raise ValueError("EvidenceRequirementV4.evidence_type must not be empty")


# Convenient aliases for canonical v4 question specification
EvidenceRequirementSpec = EvidenceRequirementV4
EvidenceRequirement = EvidenceRequirementV4


@dataclass
class LogicalQueryPlan:
    """Logical execution plan independent of native provider query language."""
    id: str
    requirement_id: str
    provider: str
    scope: str
    data_sources: list[dict[str, Any]] = field(default_factory=list)
    filters: list[dict[str, Any]] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    entity: EntityRef | None = None
    time_window: str = ""
    constraints: dict[str, Any] = field(default_factory=dict)
    limit: int = 100
    is_targeted: bool = False
    evidence_type: str = ""

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("LogicalQueryPlan.id must not be empty")
        if not self.requirement_id.strip():
            raise ValueError("LogicalQueryPlan.requirement_id must not be empty")


@dataclass
class NativeQueryPlan:
    """Provider-compiled native executable query (SPL, SQL, KQL) with bounded time range."""
    id: str
    logical_plan_id: str
    provider: str
    native_query: str
    time_range: tuple[str, str] = ("", "")
    limit: int = 100

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("NativeQueryPlan.id must not be empty")
        if not self.native_query.strip():
            raise ValueError("NativeQueryPlan.native_query must not be empty")


@dataclass
class EvidenceAssessment:
    """Advisory assessment from semantic evaluation layer."""
    card_id: str
    compatible_hypotheses: list[str] = field(default_factory=list)
    confidence: float = 0.0
    reason: str = ""
    missing_evidence: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    interpretation: str = ""
    answer_candidates: list[str] = field(default_factory=list)
    contradicting_hypotheses: list[str] = field(default_factory=list)


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
    summary: str = ""
    why_it_matters: str = ""
    hypotheses: list[str] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)
    confidence: str = "MEDIUM"
    query_ids: list[str] = field(default_factory=list)
    replay: dict[str, Any] = field(default_factory=dict)
    representative_observation_ids: list[str] = field(default_factory=list)
    count: int = 1
    entity_summary: dict[str, Any] = field(default_factory=dict)
    time_summary: dict[str, Any] = field(default_factory=dict)
    field_summary: dict[str, Any] = field(default_factory=dict)
    fact_type: str = ""
    completeness: str = "complete"
    relations: list[dict[str, Any]] = field(default_factory=list)
    supports: list[str] = field(default_factory=list)
    does_not_prove: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("EvidenceCard.id must not be empty")
        if not self.fingerprint.strip():
            raise ValueError("EvidenceCard.fingerprint must not be empty")


class HuntOutcome(str, Enum):
    """Canonical epistemic outcomes for threat hunting hypotheses."""
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_LIMITATIONS = "SUPPORTED_WITH_LIMITATIONS"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INCONCLUSIVE_BUDGET_EXHAUSTED = "INCONCLUSIVE_BUDGET_EXHAUSTED"
    NO_EVIDENCE_FOUND = "NO_EVIDENCE_FOUND"
    UNKNOWN = "UNKNOWN"
    UNREACHABLE = "UNREACHABLE"
    INSUFFICIENTLY_SPECIFIED = "INSUFFICIENTLY_SPECIFIED"
    UNSUPPORTED = "UNSUPPORTED"


class StoppingDecision(str, Enum):
    """Deterministic terminal stopping decisions."""
    STOP_RESOLVED = "STOP_RESOLVED"
    STOP_REFUTED = "STOP_REFUTED"
    STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED = "STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED"
    STOP_INCONCLUSIVE_RELATION_UNPROVEN = "STOP_INCONCLUSIVE_RELATION_UNPROVEN"
    STOP_INCONCLUSIVE_COVERAGE_GAP = "STOP_INCONCLUSIVE_COVERAGE_GAP"
    STOP_EXHAUSTED_BY_BUDGET = "STOP_EXHAUSTED_BY_BUDGET"
    STOP_BUDGET_EXHAUSTED = "STOP_EXHAUSTED_BY_BUDGET"
    STOP_BOUNDED = "STOP_BOUNDED"
    STOP_INSUFFICIENT = "STOP_INSUFFICIENT"
    STOP_UNSUPPORTED = "STOP_UNSUPPORTED"
    STOP_UNSUPPORTED_CAPABILITY = "STOP_UNSUPPORTED_CAPABILITY"
    STOP_UNREACHABLE = "STOP_UNREACHABLE"


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
    logical_query_plans: list[LogicalQueryPlan] = field(default_factory=list)
    native_query_plans: list[NativeQueryPlan] = field(default_factory=list)
    capability_catalog: Any | None = None
    evidence_assessments: list[EvidenceAssessment] = field(default_factory=list)
    semantic_analysis: dict[str, Any] = field(default_factory=dict)
    semantic_intent: SemanticHuntIntent | None = None
    hunt_spec: HuntSpec | None = None
    evidence_state: Any | None = None
    discovery_completed: bool = False
    discovery_anchor_values: list[str] = field(default_factory=list)
    adaptive_decision: dict[str, Any] = field(default_factory=dict)
    investigation_model: InvestigationModel | None = None
    relation_graph: RelationGraph | None = None
    case: Any | None = None
    identity_resolved: bool = False
    identity_mapping: dict[str, str] = field(default_factory=dict)
    llm_usage: dict[str, Any] = field(default_factory=dict)
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
    answer: dict[str, Any] = field(default_factory=dict)
    llm_usage: dict[str, Any] = field(default_factory=dict)
    semantic_analysis: dict[str, Any] = field(default_factory=dict)
    semantic_intent: SemanticHuntIntent | None = None
    evidence_assessments: list[EvidenceAssessment] = field(default_factory=list)
    investigation_model: InvestigationModel | None = None
    relation_graph: RelationGraph | None = None
    evidence_state: Any | None = None
    case: Any | None = None
    provenance_chain: list[Any] = field(default_factory=list)
    answer_status: AnswerStatus | str = AnswerStatus.UNANSWERED
    claim_verdicts: list[ClaimVerdict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def outcome(self) -> HuntOutcome:
        """Derive canonical outcome from supporting / contradicting / unreachable."""
        if self.stopping_decision == StoppingDecision.STOP_INSUFFICIENT:
            return HuntOutcome.INSUFFICIENTLY_SPECIFIED
        if self.stopping_decision in (StoppingDecision.STOP_UNSUPPORTED, StoppingDecision.STOP_UNSUPPORTED_CAPABILITY):
            return HuntOutcome.UNSUPPORTED
        if self.stopping_decision == StoppingDecision.STOP_UNREACHABLE:
            return HuntOutcome.UNREACHABLE
        if self.stopping_decision == StoppingDecision.STOP_REFUTED:
            return HuntOutcome.CONTRADICTED
        if self.stopping_decision in (
            StoppingDecision.STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED,
            StoppingDecision.STOP_INCONCLUSIVE_RELATION_UNPROVEN,
            StoppingDecision.STOP_INCONCLUSIVE_COVERAGE_GAP,
        ):
            return HuntOutcome.INCONCLUSIVE

        attack_hypos = [h for h in self.hypotheses if h.hypothesis_class != "benign_baseline"]
        if not attack_hypos:
            attack_hypos = self.hypotheses

        if self.stopping_decision in (StoppingDecision.STOP_EXHAUSTED_BY_BUDGET, StoppingDecision.STOP_BUDGET_EXHAUSTED):
            if any(h.id in self.supporting for h in attack_hypos):
                return HuntOutcome.SUPPORTED_WITH_LIMITATIONS
            return HuntOutcome.INCONCLUSIVE_BUDGET_EXHAUSTED

        if self.answer_status in (
            AnswerStatus.PARTIALLY_SUPPORTED,
            "PARTIALLY_SUPPORTED",
            AnswerStatus.VERSION_UNAVAILABLE,
            "VERSION_UNAVAILABLE",
        ):
            return HuntOutcome.PARTIALLY_SUPPORTED

        if self.answer_status in (AnswerStatus.PARTIALLY_ANSWERED, "PARTIALLY_ANSWERED"):
            return HuntOutcome.SUPPORTED_WITH_LIMITATIONS


        if any(h.id in self.supporting for h in attack_hypos):
            return HuntOutcome.SUPPORTED
        if all(h.id in self.contradicting for h in attack_hypos) and attack_hypos:
            if not self.residuals and not self.unreachable and not self.unknown:
                return HuntOutcome.CONTRADICTED
            return HuntOutcome.INCONCLUSIVE
        if all(h.id in self.unreachable for h in attack_hypos) and attack_hypos:
            return HuntOutcome.UNREACHABLE
        if any(h.id in self.contradicting for h in attack_hypos):
            return HuntOutcome.INCONCLUSIVE
        if self.evidence_cards:
            return HuntOutcome.INCONCLUSIVE
        return HuntOutcome.UNKNOWN


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
    "EvidenceRequirement",
    "LogicalQueryPlan",
    "NativeQueryPlan",
    "EvidenceAssessment",
    "QueryPlan",
    "EvidenceCard",
    "HuntOutcome",
    "StoppingDecision",
    "HuntState",
    "FinalHuntAccount",
    "SubjectEntity",
    "RequestedObject",
    "SemanticEvidenceRequirement",
    "SemanticHuntIntent",
    "HuntSpec",
    "InvestigationModel",
    "RelationGraph",
    "GraphNode",
    "GraphEdge",
]
