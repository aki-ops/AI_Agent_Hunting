"""Append-only investigation workspace model.

This is the backend contract for a future UI.  It presents native evidence,
query audit and graph snapshots without allowing annotations or analyst text
to mutate proof/runtime state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from hunting.contracts.lifecycle import (
    AUTOMATED_PROMOTION_ACTORS,
    WORKSPACE_PERMISSIONS,
    AnalystDecision,
    BindingReview,
    WorkspaceRole,
    WorkspaceSnapshot,
)

_ALLOWED_ANNOTATION_KINDS = {"annotation", "tag", "comment", "saved_search"}
_MUTATION_KINDS = {
    "proof", "goal", "evidence", "budget", "stop", "binding", "graph",
    "semantic_goal_graph", "outcome", "controller", "query",
}
_MUTATION_PAYLOAD_KEYS = {
    "proof_results", "stopping_decision", "semantic_goal_graph", "budget",
    "goal_graph", "evidence_graph", "outcome_contract", "controller_state",
}


def _as_role(role: WorkspaceRole | str) -> WorkspaceRole:
    if isinstance(role, WorkspaceRole):
        return role
    return WorkspaceRole(str(role).strip().casefold())


@dataclass(frozen=True)
class WorkspaceEvent:
    event_id: str
    run_id: str
    kind: str
    actor: str
    payload: dict[str, Any]
    citations: tuple[str, ...] = ()
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "run_id": self.run_id, "kind": self.kind,
                "actor": self.actor, "payload": dict(self.payload),
                "citations": list(self.citations), "timestamp": self.timestamp}


class InvestigationWorkspace:
    def __init__(
        self,
        run_id: str,
        *,
        roles: Mapping[str, WorkspaceRole | str] | None = None,
        default_role: WorkspaceRole | str = WorkspaceRole.VIEWER,
    ) -> None:
        if not str(run_id).strip():
            raise ValueError("run_id must not be empty")
        self.run_id = run_id
        self._events: list[WorkspaceEvent] = []
        self._roles: dict[str, WorkspaceRole] = {}
        for actor, role in dict(roles or {}).items():
            self.grant(str(actor), role)
        self.default_role = _as_role(default_role)

    @property
    def events(self) -> tuple[WorkspaceEvent, ...]:
        return tuple(self._events)

    def grant(self, actor: str, role: WorkspaceRole | str) -> None:
        name = str(actor).strip()
        if not name:
            raise ValueError("actor must not be empty")
        if name.casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise ValueError("machine actors cannot receive analyst or reviewer roles")
        self._roles[name.casefold()] = _as_role(role)

    def role_for(self, actor: str) -> WorkspaceRole:
        name = str(actor).strip().casefold()
        if name in AUTOMATED_PROMOTION_ACTORS:
            return WorkspaceRole.VIEWER
        return self._roles.get(name, self.default_role)

    def authorize(self, action: str, actor: str) -> WorkspaceRole:
        role = self.role_for(actor)
        allowed = WORKSPACE_PERMISSIONS.get(str(action).strip().casefold(), frozenset())
        if role not in allowed:
            raise PermissionError(f"{actor} lacks {action} permission")
        if str(action).strip().casefold() != "read" and str(actor).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise PermissionError("machine actors cannot write workspace records")
        return role

    def append_annotation(self, event: WorkspaceEvent) -> None:
        if event.kind in _MUTATION_KINDS or any(key in event.payload for key in _MUTATION_PAYLOAD_KEYS):
            raise ValueError("workspace cannot mutate runtime/proof state")
        self.authorize("annotate", event.actor)
        self._append(event, allowed=_ALLOWED_ANNOTATION_KINDS)

    def append_decision(self, decision: AnalystDecision) -> None:
        if decision.run_id != self.run_id:
            raise ValueError("decision belongs to another run")
        if str(decision.actor).strip().casefold() in AUTOMATED_PROMOTION_ACTORS:
            raise ValueError("machine actors cannot record analyst decisions")
        self.authorize("decide", decision.actor)
        self._append(WorkspaceEvent(
            event_id=decision.id, run_id=decision.run_id, kind="analyst_decision",
            actor=decision.actor, payload=decision.to_dict(),
            citations=decision.citations, timestamp=decision.timestamp,
        ), allowed={"analyst_decision"})

    def append_binding_review(self, review: BindingReview) -> None:
        if review.run_id != self.run_id:
            raise ValueError("binding review belongs to another run")
        self.authorize("binding_review", review.actor)
        self._append(WorkspaceEvent(
            event_id=review.id, run_id=review.run_id, kind="binding_review",
            actor=review.actor, payload=review.to_dict(),
            citations=review.citations, timestamp=review.timestamp,
        ), allowed={"binding_review"})

    def _append(self, event: WorkspaceEvent, *, allowed: set[str]) -> None:
        if event.run_id != self.run_id:
            raise ValueError("workspace event belongs to another run")
        if event.kind in _MUTATION_KINDS or event.kind not in allowed:
            raise ValueError("workspace cannot mutate runtime/proof state")
        if any(key in event.payload for key in _MUTATION_PAYLOAD_KEYS):
            raise ValueError("workspace cannot mutate runtime/proof state")
        if any(item.event_id == event.event_id for item in self._events):
            raise ValueError("workspace event IDs are immutable and unique")
        if not event.citations and event.kind in {"analyst_decision", "binding_review"}:
            raise ValueError("analyst decisions require citations")
        self._events.append(event)

    def snapshot(
        self,
        *,
        observation_ids: tuple[str, ...] = (),
        evidence_graph: dict[str, Any] | None = None,
        goal_graph: dict[str, Any] | None = None,
        query_audit: tuple[dict[str, Any], ...] = (),
        unexamined_routes: tuple[str, ...] = (),
        limitations: tuple[str, ...] = (),
        timeline: tuple[dict[str, Any], ...] = (),
        entity_pivot: tuple[dict[str, Any], ...] = (),
        native_events: tuple[dict[str, Any], ...] = (),
        proof_obligations: tuple[dict[str, Any], ...] = (),
        stop_explanation: dict[str, Any] | None = None,
        coverage_view: dict[str, Any] | None = None,
    ) -> WorkspaceSnapshot:
        decisions = tuple(
            AnalystDecision(
                id=event.event_id,
                run_id=event.run_id,
                actor=event.actor,
                decision=str(event.payload.get("decision", "")),
                citations=event.citations,
                timestamp=event.timestamp,
                rationale=str(event.payload.get("rationale", "")),
            )
            for event in self._events if event.kind == "analyst_decision"
        )
        reviews = tuple(
            BindingReview(
                id=event.event_id,
                run_id=event.run_id,
                actor=event.actor,
                variable_id=str(event.payload.get("variable_id", "")),
                selected_values=tuple(event.payload.get("selected_values") or ()),
                rejected_values=tuple(event.payload.get("rejected_values") or ()),
                citations=event.citations,
                timestamp=event.timestamp,
                rationale=str(event.payload.get("rationale", "")),
            )
            for event in self._events if event.kind == "binding_review"
        )
        tags = tuple(
            str(event.payload.get("tag") or event.payload.get("text") or "")
            for event in self._events if event.kind == "tag"
        )
        comments = tuple(
            {"event_id": event.event_id, "text": str(event.payload.get("text", "")),
             "actor": event.actor, "citations": list(event.citations)}
            for event in self._events if event.kind in {"comment", "annotation"}
        )
        saved_searches = tuple(
            dict(event.payload) for event in self._events if event.kind == "saved_search"
        )
        return WorkspaceSnapshot(
            run_id=self.run_id,
            observation_ids=tuple(observation_ids),
            evidence_graph=dict(evidence_graph or {}),
            goal_graph=dict(goal_graph or {}),
            query_audit=tuple(dict(item) for item in query_audit),
            analyst_decisions=decisions,
            unexamined_routes=tuple(unexamined_routes),
            limitations=tuple(limitations),
            timeline=tuple(dict(item) for item in timeline),
            tags=tags,
            comments=comments,
            saved_searches=saved_searches,
            entity_pivot=tuple(dict(item) for item in entity_pivot),
            native_events=tuple(dict(item) for item in native_events),
            proof_obligations=tuple(dict(item) for item in proof_obligations),
            stop_explanation=dict(stop_explanation or {}),
            coverage_view=dict(coverage_view or {}),
            binding_reviews=reviews,
        )


__all__ = ["InvestigationWorkspace", "WorkspaceEvent"]
