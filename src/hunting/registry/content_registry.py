"""Versioned registries for reusable hunting content.

The registry is deliberately small and in-memory; persistence can be supplied
by a deployment.  Lifecycle transitions are explicit and promotion requires
review plus conformance tests.  An LLM or a single run cannot approve content.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Generic, Iterable, TypeVar

from hunting.contracts.lifecycle import (
    AUTOMATED_PROMOTION_ACTORS,
    AnalyticPackage,
    CapabilityArtifact,
    ContentFeedback,
    HuntPackage,
    KnowledgeCandidate,
    KnowledgeReuseEvent,
    LifecycleStatus,
    WorkspaceRole,
)
from hunting.lifecycle.acts import KnowledgePromotionGate, KnowledgeReuseLedger
from hunting.registry.package_f0 import (
    declares_completeness_or_limitations,
    fixtures_satisfied,
    required_fixtures,
)

T = TypeVar("T", CapabilityArtifact, HuntPackage, AnalyticPackage)


def _conformance_bundle(item: Any) -> tuple[Any, ...]:
    return tuple(getattr(item, "tests", ()) or ()) + tuple(getattr(item, "fixtures", ()) or ())


def _assert_approvable(item: T, *, named_fixtures: bool) -> None:
    if not _conformance_bundle(item):
        raise ValueError("approved content requires conformance fixtures/tests")
    if isinstance(item, CapabilityArtifact) and not item.provider_compiler_ref:
        raise ValueError("approved capability artifact requires provider compiler reference")
    if named_fixtures and not fixtures_satisfied(item):
        required = ", ".join(required_fixtures(item))
        raise ValueError(f"approved content requires fixtures: {required}")
    if named_fixtures and not declares_completeness_or_limitations(item):
        raise ValueError("approved content must declare completeness or limitations")


class VersionedContentRegistry(Generic[T]):
    def __init__(self, items: Iterable[T] = ()) -> None:
        self._items: dict[tuple[str, str], T] = {}
        self._feedback: dict[str, ContentFeedback] = {}
        self._knowledge: dict[str, KnowledgeCandidate] = {}
        self.reuse_ledger = KnowledgeReuseLedger()
        for item in items:
            self.register(item)

    def register(self, item: T) -> T:
        key = (str(getattr(item, "id")), str(getattr(item, "version")))
        if not all(key):
            raise ValueError("content id and version must not be empty")
        if getattr(item, "status", None) == LifecycleStatus.APPROVED:
            _assert_approvable(item, named_fixtures=False)
        self._items[key] = item
        return item

    def get(self, content_id: str, version: str | None = None) -> T | None:
        if version is not None:
            return self._items.get((content_id, version))
        versions = [item for (item_id, _), item in self._items.items() if item_id == content_id]
        return versions[-1] if versions else None

    def list(self, status: LifecycleStatus | None = None) -> tuple[T, ...]:
        items = tuple(self._items.values())
        return tuple(item for item in items if status is None or item.status == status)

    def transition(
        self,
        content_id: str,
        version: str,
        status: LifecycleStatus,
        *,
        actor: str = "",
    ) -> T:
        item = self.get(content_id, version)
        if item is None:
            raise KeyError(f"unknown content {content_id}@{version}")
        if not isinstance(status, LifecycleStatus):
            status = LifecycleStatus(str(status))
        if status == LifecycleStatus.APPROVED:
            if str(actor).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
                raise ValueError("LLM or automated run cannot approve content")
            _assert_approvable(item, named_fixtures=True)
        updated = replace(item, status=status)
        self._items[(content_id, version)] = updated
        return updated

    def invalidate_for_drift(
        self,
        *,
        schema_version: str | None = None,
        parser_version: str | None = None,
        permission_version: str | None = None,
        reason: str = "compatibility drift",
    ) -> tuple[T, ...]:
        changed: list[T] = []
        for key, item in list(self._items.items()):
            incompatible = (
                isinstance(item, CapabilityArtifact)
                and (
                    (schema_version and item.schema_version != schema_version)
                    or (parser_version and item.parser_version != parser_version)
                    or (permission_version and item.permission_version != permission_version)
                )
            )
            if incompatible and item.status == LifecycleStatus.APPROVED:
                updated = replace(item, status=LifecycleStatus.REVOKED,
                                  limitations=tuple(item.limitations) + (reason,))
                self._items[key] = updated
                changed.append(updated)
        self.invalidate_knowledge(reason=reason)
        return tuple(changed)

    def register_knowledge(self, candidate: KnowledgeCandidate) -> KnowledgeCandidate:
        self._knowledge[candidate.id] = candidate
        self.reuse_ledger.record(KnowledgeReuseEvent(
            id=f"proposed:{candidate.id}",
            kind="proposed",
            artifact_id=candidate.id,
            source_run_id=candidate.source_run_id,
        ))
        return candidate

    def get_knowledge(self, candidate_id: str) -> KnowledgeCandidate | None:
        return self._knowledge.get(candidate_id)

    def promote_knowledge(
        self,
        candidate_id: str,
        *,
        reviewer: str,
        tests_passed: bool,
        role: WorkspaceRole | str = WorkspaceRole.REVIEWER,
    ) -> KnowledgeCandidate:
        candidate = self.get_knowledge(candidate_id)
        if candidate is None:
            raise KeyError(f"unknown knowledge candidate {candidate_id}")
        KnowledgePromotionGate.promote(
            candidate, reviewer=reviewer, tests_passed=tests_passed, role=role,
        )
        updated = replace(candidate, review_status="APPROVED")
        self._knowledge[candidate_id] = updated
        self.reuse_ledger.record(KnowledgeReuseEvent(
            id=f"approved:{candidate_id}",
            kind="approved",
            artifact_id=candidate_id,
            source_run_id=candidate.source_run_id,
        ))
        return updated

    def invalidate_knowledge(self, *, reason: str) -> tuple[KnowledgeCandidate, ...]:
        changed: list[KnowledgeCandidate] = []
        for key, candidate in list(self._knowledge.items()):
            if candidate.review_status in {"PENDING_REVIEW", "APPROVED"}:
                updated = KnowledgePromotionGate.invalidate(candidate, reason=reason)
                self._knowledge[key] = updated
                self.reuse_ledger.record(KnowledgeReuseEvent(
                    id=f"revoked:{key}:{reason}",
                    kind="rolled_back",
                    artifact_id=key,
                    source_run_id=candidate.source_run_id,
                ))
                changed.append(updated)
        return tuple(changed)

    def record_feedback(self, feedback: ContentFeedback) -> ContentFeedback:
        item = self.get(feedback.artifact_id, feedback.artifact_version)
        if item is None:
            raise KeyError(f"unknown content {feedback.artifact_id}@{feedback.artifact_version}")
        self._feedback[feedback.id] = feedback
        return feedback

    def list_feedback(
        self,
        artifact_id: str | None = None,
        status: str | None = None,
    ) -> tuple[ContentFeedback, ...]:
        items = tuple(self._feedback.values())
        if artifact_id is not None:
            items = tuple(item for item in items if item.artifact_id == artifact_id)
        if status is not None:
            items = tuple(item for item in items if item.status == status)
        return items

    def triage_feedback(self, feedback_id: str, *, status: str, reviewer: str) -> ContentFeedback:
        feedback = self._feedback.get(feedback_id)
        if feedback is None:
            raise KeyError(f"unknown feedback {feedback_id}")
        if str(reviewer).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise ValueError("LLM cannot triage content feedback")
        updated = replace(feedback, status=status)
        self._feedback[feedback_id] = updated
        return updated


__all__ = ["VersionedContentRegistry", "KnowledgePromotionGate"]
