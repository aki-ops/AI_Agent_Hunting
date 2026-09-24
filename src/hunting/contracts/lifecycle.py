"""Provider-neutral lifecycle contracts for reusable hunting knowledge.

These records are control-plane data, not incident proof.  In particular,
knowledge candidates remain reviewable and cannot be promoted by an LLM or a
single run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LifecycleStatus(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


AUTOMATED_PROMOTION_ACTORS = frozenset({
    "llm", "model", "agent", "compiler", "c1", "c2", "c3", "system",
})


class WorkspaceRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    REVIEWER = "reviewer"


WORKSPACE_PERMISSIONS = {
    "read": frozenset({WorkspaceRole.VIEWER, WorkspaceRole.ANALYST, WorkspaceRole.REVIEWER}),
    "annotate": frozenset({WorkspaceRole.ANALYST, WorkspaceRole.REVIEWER}),
    "binding_review": frozenset({WorkspaceRole.ANALYST, WorkspaceRole.REVIEWER}),
    "decide": frozenset({WorkspaceRole.ANALYST, WorkspaceRole.REVIEWER}),
    "promote": frozenset({WorkspaceRole.REVIEWER}),
}

ACT_KINDS = frozenset({
    "detection_candidate",
    "response_recommendation",
    "telemetry_gap",
    "follow_up_hunt",
    "content_defect",
    "no_action",
})

KNOWLEDGE_KINDS = frozenset({"mapping", "query", "package", "baseline", "limitation"})
INCIDENT_KNOWLEDGE_CLASSES = frozenset({
    "incident_conclusion", "negative_universal", "incident", "verdict",
})


@dataclass(frozen=True)
class CapabilityArtifact:
    id: str
    version: str
    owner: str
    status: LifecycleStatus = LifecycleStatus.DRAFT
    input_roles: tuple[str, ...] = ()
    output_roles: tuple[str, ...] = ()
    provider_compiler_ref: str = ""
    supported_entity_types: tuple[str, ...] = ()
    supported_constraints: tuple[str, ...] = ()
    completeness_contract: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    schema_version: str = ""
    parser_version: str = ""
    permission_version: str = ""
    fixtures: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("id", "version", "owner"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must not be empty")
        if not isinstance(self.status, LifecycleStatus):
            object.__setattr__(self, "status", LifecycleStatus(str(self.status)))

    @property
    def executable(self) -> bool:
        return (
            self.status == LifecycleStatus.APPROVED
            and bool(self.provider_compiler_ref)
            and bool(self.fixtures)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "version": self.version, "owner": self.owner,
            "status": self.status.value, "input_roles": list(self.input_roles),
            "output_roles": list(self.output_roles),
            "provider_compiler_ref": self.provider_compiler_ref,
            "supported_entity_types": list(self.supported_entity_types),
            "supported_constraints": list(self.supported_constraints),
            "completeness_contract": dict(self.completeness_contract),
            "limitations": list(self.limitations), "schema_version": self.schema_version,
            "parser_version": self.parser_version, "permission_version": self.permission_version,
            "fixtures": list(self.fixtures),
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True)
class HuntPackage:
    id: str
    version: str
    owner: str
    hypotheses: tuple[str, ...] = ()
    falsification_conditions: tuple[str, ...] = ()
    expected_fact_kinds: tuple[str, ...] = ()
    graph_template: dict[str, Any] = field(default_factory=dict)
    admissible_actions: tuple[str, ...] = ()
    analyst_checkpoints: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()
    completeness_contract: dict[str, Any] = field(default_factory=dict)
    status: LifecycleStatus = LifecycleStatus.DRAFT

    def __post_init__(self) -> None:
        if not all(str(getattr(self, item)).strip() for item in ("id", "version", "owner")):
            raise ValueError("HuntPackage id, version and owner must not be empty")
        if not isinstance(self.status, LifecycleStatus):
            object.__setattr__(self, "status", LifecycleStatus(str(self.status)))

    @property
    def executable(self) -> bool:
        return (
            self.status == LifecycleStatus.APPROVED
            and bool(self.tests)
            and bool(self.graph_template)
        )

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "version": self.version, "owner": self.owner,
                "hypotheses": list(self.hypotheses),
                "falsification_conditions": list(self.falsification_conditions),
                "expected_fact_kinds": list(self.expected_fact_kinds),
                "graph_template": dict(self.graph_template),
                "admissible_actions": list(self.admissible_actions),
                "analyst_checkpoints": list(self.analyst_checkpoints),
                "limitations": list(self.limitations), "tests": list(self.tests),
                "completeness_contract": dict(self.completeness_contract),
                "status": self.status.value}


@dataclass(frozen=True)
class AnalyticPackage:
    id: str
    version: str
    owner: str
    semantic_expression: dict[str, Any]
    internal_representation: dict[str, Any] = field(default_factory=dict)
    transformations: tuple[dict[str, Any], ...] = ()
    supported_backends: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    completeness_contract: dict[str, Any] = field(default_factory=dict)
    status: LifecycleStatus = LifecycleStatus.DRAFT

    def __post_init__(self) -> None:
        if not all(str(getattr(self, item)).strip() for item in ("id", "version", "owner")):
            raise ValueError("AnalyticPackage id, version and owner must not be empty")
        if not isinstance(self.status, LifecycleStatus):
            object.__setattr__(self, "status", LifecycleStatus(str(self.status)))

    @property
    def executable(self) -> bool:
        return (
            self.status == LifecycleStatus.APPROVED
            and bool(self.tests)
            and bool(self.internal_representation or self.semantic_expression)
        )

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "version": self.version, "owner": self.owner,
                "semantic_expression": dict(self.semantic_expression),
                "internal_representation": dict(self.internal_representation),
                "transformations": [dict(item) for item in self.transformations],
                "supported_backends": list(self.supported_backends),
                "tests": list(self.tests), "limitations": list(self.limitations),
                "completeness_contract": dict(self.completeness_contract),
                "status": self.status.value}


@dataclass(frozen=True)
class ActionItem:
    id: str
    kind: str
    source_run_id: str
    evidence_refs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    status: str = "OPEN"
    owner: str = ""
    outcome_ref: str = ""

    def __post_init__(self) -> None:
        if not all(str(getattr(self, item)).strip() for item in ("id", "kind", "source_run_id")):
            raise ValueError("action item identity fields must not be empty")
        kind = str(self.kind).strip().casefold()
        if kind not in ACT_KINDS:
            raise ValueError("unknown action kind")
        object.__setattr__(self, "kind", kind)
        if kind != "no_action" and not self.evidence_refs:
            raise ValueError("action items require cited run evidence")
        if not self.limitations:
            raise ValueError("action items must declare limitations")
        if str(self.owner).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise ValueError("LLM cannot own an Act output")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "source_run_id": self.source_run_id,
                "evidence_refs": list(self.evidence_refs), "limitations": list(self.limitations),
                "status": self.status, "owner": self.owner, "outcome_ref": self.outcome_ref}


@dataclass(frozen=True)
class KnowledgeCandidate:
    id: str
    kind: str
    source_run_id: str
    evidence_refs: tuple[str, ...] = ()
    scope: dict[str, Any] = field(default_factory=dict)
    temporal_validity: dict[str, Any] = field(default_factory=dict)
    confidence_class: str = "UNASSESSED"
    review_status: str = "PENDING_REVIEW"
    required_tests: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all(str(getattr(self, item)).strip() for item in ("id", "kind", "source_run_id")):
            raise ValueError("knowledge candidate identity fields must not be empty")
        kind = str(self.kind).strip().casefold()
        if kind not in KNOWLEDGE_KINDS:
            raise ValueError("unknown knowledge candidate kind")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "confidence_class", str(self.confidence_class or "UNASSESSED").strip().upper())
        object.__setattr__(self, "review_status", str(self.review_status or "PENDING_REVIEW").strip().upper())

    def promotable(self, *, reviewer: str | None, tests_passed: bool) -> bool:
        actor = str(reviewer or "").strip().casefold()
        if actor in AUTOMATED_PROMOTION_ACTORS:
            return False
        if self.confidence_class.casefold() in INCIDENT_KNOWLEDGE_CLASSES:
            return False
        if not dict(self.scope or {}) or not dict(self.temporal_validity or {}):
            return False
        return bool(reviewer and self.evidence_refs and self.required_tests and tests_passed)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "source_run_id": self.source_run_id,
                "evidence_refs": list(self.evidence_refs), "scope": dict(self.scope),
                "temporal_validity": dict(self.temporal_validity),
                "confidence_class": self.confidence_class, "review_status": self.review_status,
                "required_tests": list(self.required_tests)}


@dataclass(frozen=True)
class BindingReview:
    id: str
    run_id: str
    actor: str
    variable_id: str
    selected_values: tuple[str, ...]
    citations: tuple[str, ...] = ()
    rejected_values: tuple[str, ...] = ()
    timestamp: str = ""
    rationale: str = ""

    def __post_init__(self) -> None:
        if not all(str(getattr(self, item)).strip() for item in ("id", "run_id", "actor", "variable_id")):
            raise ValueError("binding review identity fields must not be empty")
        if str(self.actor).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise ValueError("machine actors cannot record binding reviews")
        object.__setattr__(self, "selected_values", tuple(str(item) for item in self.selected_values if str(item).strip()))
        object.__setattr__(self, "rejected_values", tuple(str(item) for item in self.rejected_values if str(item).strip()))
        object.__setattr__(self, "citations", tuple(str(item) for item in self.citations if str(item).strip()))
        if not self.selected_values:
            raise ValueError("binding review requires an explicit selected value")
        if not self.citations:
            raise ValueError("binding review requires citations")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "run_id": self.run_id, "actor": self.actor,
            "variable_id": self.variable_id, "selected_values": list(self.selected_values),
            "rejected_values": list(self.rejected_values), "citations": list(self.citations),
            "timestamp": self.timestamp, "rationale": self.rationale,
        }


@dataclass(frozen=True)
class KnowledgeReuseEvent:
    id: str
    kind: str
    artifact_id: str
    artifact_version: str = ""
    source_run_id: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "artifact_id": self.artifact_id,
            "artifact_version": self.artifact_version, "source_run_id": self.source_run_id,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class AnalystDecision:
    id: str
    run_id: str
    actor: str
    decision: str
    citations: tuple[str, ...] = ()
    timestamp: str = ""
    rationale: str = ""

    def __post_init__(self) -> None:
        if not all(str(getattr(self, item)).strip() for item in ("id", "run_id", "actor", "decision")):
            raise ValueError("analyst decision identity fields must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "run_id": self.run_id, "actor": self.actor,
                "decision": self.decision, "citations": list(self.citations),
                "timestamp": self.timestamp, "rationale": self.rationale}


@dataclass(frozen=True)
class HuntLifecycleRecord:
    run_id: str
    preparation: dict[str, Any] = field(default_factory=dict)
    execution_run_account: dict[str, Any] = field(default_factory=dict)
    action_items: tuple[ActionItem, ...] = ()
    knowledge_candidates: tuple[KnowledgeCandidate, ...] = ()
    analyst_decisions: tuple[AnalystDecision, ...] = ()
    promotion_events: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "preparation": dict(self.preparation),
                "execution_run_account": dict(self.execution_run_account),
                "action_items": [item.to_dict() for item in self.action_items],
                "knowledge_candidates": [item.to_dict() for item in self.knowledge_candidates],
                "analyst_decisions": [item.to_dict() for item in self.analyst_decisions],
                "promotion_events": [dict(item) for item in self.promotion_events]}


@dataclass(frozen=True)
class ContentFeedback:
    id: str
    artifact_id: str
    artifact_version: str
    kind: str
    actor: str
    citations: tuple[str, ...] = ()
    timestamp: str = ""
    note: str = ""
    status: str = "open"

    def __post_init__(self) -> None:
        if not all(str(getattr(self, item)).strip() for item in ("id", "artifact_id", "artifact_version", "kind", "actor")):
            raise ValueError("content feedback identity fields must not be empty")
        kind = str(self.kind).strip().casefold()
        if kind not in {"false_positive", "content_defect"}:
            raise ValueError("feedback kind must be false_positive or content_defect")
        object.__setattr__(self, "kind", kind)
        status = str(self.status).strip().casefold() or "open"
        if status not in {"open", "triaged", "wontfix"}:
            raise ValueError("feedback status must be open, triaged or wontfix")
        object.__setattr__(self, "status", status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "artifact_id": self.artifact_id,
            "artifact_version": self.artifact_version, "kind": self.kind,
            "actor": self.actor, "citations": list(self.citations),
            "timestamp": self.timestamp, "note": self.note, "status": self.status,
        }


@dataclass(frozen=True)
class WorkspaceSnapshot:
    run_id: str
    observation_ids: tuple[str, ...] = ()
    evidence_graph: dict[str, Any] = field(default_factory=dict)
    goal_graph: dict[str, Any] = field(default_factory=dict)
    query_audit: tuple[dict[str, Any], ...] = ()
    analyst_decisions: tuple[AnalystDecision, ...] = ()
    unexamined_routes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    timeline: tuple[dict[str, Any], ...] = ()
    tags: tuple[str, ...] = ()
    comments: tuple[dict[str, Any], ...] = ()
    saved_searches: tuple[dict[str, Any], ...] = ()
    entity_pivot: tuple[dict[str, Any], ...] = ()
    native_events: tuple[dict[str, Any], ...] = ()
    proof_obligations: tuple[dict[str, Any], ...] = ()
    stop_explanation: dict[str, Any] = field(default_factory=dict)
    coverage_view: dict[str, Any] = field(default_factory=dict)
    binding_reviews: tuple[BindingReview, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "observation_ids": list(self.observation_ids),
                "evidence_graph": dict(self.evidence_graph), "goal_graph": dict(self.goal_graph),
                "query_audit": [dict(item) for item in self.query_audit],
                "analyst_decisions": [item.to_dict() for item in self.analyst_decisions],
                "unexamined_routes": list(self.unexamined_routes), "limitations": list(self.limitations),
                "timeline": [dict(item) for item in self.timeline],
                "tags": list(self.tags),
                "comments": [dict(item) for item in self.comments],
                "saved_searches": [dict(item) for item in self.saved_searches],
                "entity_pivot": [dict(item) for item in self.entity_pivot],
                "native_events": [dict(item) for item in self.native_events],
                "proof_obligations": [dict(item) for item in self.proof_obligations],
                "stop_explanation": dict(self.stop_explanation),
                "coverage_view": dict(self.coverage_view),
                "binding_reviews": [item.to_dict() for item in self.binding_reviews]}


__all__ = [
    "LifecycleStatus", "AUTOMATED_PROMOTION_ACTORS", "WorkspaceRole",
    "WORKSPACE_PERMISSIONS", "ACT_KINDS", "KNOWLEDGE_KINDS", "CapabilityArtifact",
    "HuntPackage", "AnalyticPackage", "ActionItem", "KnowledgeCandidate",
    "BindingReview", "KnowledgeReuseEvent", "AnalystDecision", "HuntLifecycleRecord",
    "ContentFeedback", "WorkspaceSnapshot",
]
