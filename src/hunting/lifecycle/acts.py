"""Control-plane Act and Knowledge promotion.

These records are not incident proof.  An LLM or a single run cannot approve
durable knowledge.  Promotion requires a human reviewer, cited evidence and tests.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from hunting.contracts.lifecycle import (
    ACT_KINDS,
    AUTOMATED_PROMOTION_ACTORS,
    KNOWLEDGE_KINDS,
    ActionItem,
    KnowledgeCandidate,
    KnowledgeReuseEvent,
    LifecycleStatus,
    WorkspaceRole,
)


class ActEmitter:
    @staticmethod
    def emit(
        *,
        action_id: str,
        kind: str,
        source_run_id: str,
        actor: str,
        evidence_refs: tuple[str, ...] = (),
        limitations: tuple[str, ...] = (),
        outcome_ref: str = "",
    ) -> ActionItem:
        if str(actor).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise ValueError("LLM cannot emit an Act output")
        if str(kind).strip().casefold() not in ACT_KINDS:
            raise ValueError("unknown action kind")
        return ActionItem(
            id=action_id,
            kind=kind,
            source_run_id=source_run_id,
            evidence_refs=evidence_refs,
            limitations=limitations or ("unspecified limitation",),
            owner=actor,
            outcome_ref=outcome_ref,
        )

    @staticmethod
    def explicit_no_action(*, action_id: str, source_run_id: str, actor: str, limitations: tuple[str, ...]) -> ActionItem:
        return ActEmitter.emit(
            action_id=action_id,
            kind="no_action",
            source_run_id=source_run_id,
            actor=actor,
            limitations=limitations or ("no durable act selected",),
        )


class KnowledgeProposalGate:
    @staticmethod
    def propose(
        *,
        candidate_id: str,
        kind: str,
        source_run_id: str,
        actor: str,
        evidence_refs: tuple[str, ...],
        required_tests: tuple[str, ...],
        scope: dict[str, Any],
        temporal_validity: dict[str, Any],
        confidence_class: str = "UNASSESSED",
    ) -> KnowledgeCandidate:
        if str(actor).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise ValueError("LLM cannot propose durable knowledge")
        if str(kind).strip().casefold() not in KNOWLEDGE_KINDS:
            raise ValueError("unknown knowledge candidate kind")
        if not evidence_refs or not required_tests:
            raise ValueError("knowledge proposal requires cited evidence and tests")
        if not scope or not temporal_validity:
            raise ValueError("knowledge proposal requires scope and temporal validity")
        return KnowledgeCandidate(
            id=candidate_id,
            kind=kind,
            source_run_id=source_run_id,
            evidence_refs=evidence_refs,
            required_tests=required_tests,
            scope=dict(scope),
            temporal_validity=dict(temporal_validity),
            confidence_class=confidence_class,
            review_status="PENDING_REVIEW",
        )


class KnowledgeReuseLedger:
    def __init__(self) -> None:
        self._events: list[KnowledgeReuseEvent] = []

    @property
    def events(self) -> tuple[KnowledgeReuseEvent, ...]:
        return tuple(self._events)

    def record(self, event: KnowledgeReuseEvent) -> KnowledgeReuseEvent:
        self._events.append(event)
        return event

    def approval_rate(self) -> float:
        proposed = [item for item in self._events if item.kind in {"proposed", "approved", "rejected"}]
        approved = [item for item in self._events if item.kind == "approved"]
        return (len(approved) / len(proposed)) if proposed else 0.0

    def reuse_rate(self) -> float:
        approved = [item for item in self._events if item.kind == "approved"]
        reused = [item for item in self._events if item.kind == "reused"]
        return (len(reused) / len(approved)) if approved else 0.0

    def regression_rate(self) -> float:
        reused = [item for item in self._events if item.kind in {"reused", "regressed", "rolled_back"}]
        failed = [item for item in self._events if item.kind in {"regressed", "rolled_back"}]
        return (len(failed) / len(reused)) if reused else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [item.to_dict() for item in self._events],
            "approval_rate": self.approval_rate(),
            "reuse_rate": self.reuse_rate(),
            "regression_rate": self.regression_rate(),
        }


class KnowledgePromotionGate:
    """Human/test gate; no automatic promotion path is provided."""

    @staticmethod
    def promote(
        candidate: KnowledgeCandidate,
        *,
        reviewer: str | None,
        tests_passed: bool,
        role: WorkspaceRole | str = WorkspaceRole.REVIEWER,
    ) -> dict[str, Any]:
        role_value = role if isinstance(role, WorkspaceRole) else WorkspaceRole(str(role).strip().casefold())
        if role_value != WorkspaceRole.REVIEWER:
            raise ValueError("only a reviewer can promote knowledge")
        if not candidate.promotable(reviewer=reviewer, tests_passed=tests_passed):
            raise ValueError("knowledge candidate requires evidence, tests, scope and human review")
        return {
            "candidate_id": candidate.id,
            "source_run_id": candidate.source_run_id,
            "reviewer": reviewer,
            "tests_passed": True,
            "status": LifecycleStatus.APPROVED.value,
        }

    @staticmethod
    def invalidate(candidate: KnowledgeCandidate, *, reason: str) -> KnowledgeCandidate:
        return replace(
            candidate,
            review_status="REVOKED",
            scope={**dict(candidate.scope), "invalidation_reason": reason},
        )


__all__ = [
    "ActEmitter",
    "KnowledgeProposalGate",
    "KnowledgeReuseLedger",
    "KnowledgePromotionGate",
]
