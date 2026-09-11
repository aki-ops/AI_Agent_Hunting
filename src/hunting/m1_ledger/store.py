"""Observation Store — forensic persistence and traceability.

Maintains raw provider events and provides full bidirectional traceability:
observation_id -> EvidenceCard -> EvidenceRequirement -> Hypothesis -> QueryResult -> native query -> raw event.

Inviolable Invariant:
Raw events are stored for local forensics and query replay, and MUST NEVER
be fed into LLM prompt contexts.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hunting.contracts.observations import Observation


class ObservationStore:
    """Forensic observation store managing raw events and traceability links."""

    def __init__(self) -> None:
        self._observations: dict[str, Observation] = {}
        self._by_query_id: dict[str, list[str]] = {}
        self._by_card_id: dict[str, list[str]] = {}
        self._card_by_obs_id: dict[str, str] = {}

    def add_observation(self, obs: Observation, query_id: str | None = None) -> None:
        """Register an observation and index by its query ID if present."""
        self._observations[obs.id] = obs
        qid = query_id or obs.query_id or (obs.provenance.query_id if obs.provenance else None)
        if qid:
            if obs.query_id is None:
                obs.query_id = qid
            self._by_query_id.setdefault(qid, []).append(obs.id)

    def get_observation(self, obs_id: str) -> Observation | None:
        """Retrieve an observation by its unique identifier."""
        return self._observations.get(obs_id)

    def get_raw_event(self, obs_id: str) -> dict[str, Any] | None:
        """Retrieve the raw unparsed provider event for an observation."""
        obs = self.get_observation(obs_id)
        if obs is None:
            return None
        return dict(obs.raw_event) if obs.raw_event else dict(obs.fields)

    def get_by_query(self, query_id: str) -> list[Observation]:
        """Retrieve all observations produced by a specific query ID."""
        obs_ids = self._by_query_id.get(query_id, [])
        return [self._observations[oid] for oid in obs_ids if oid in self._observations]

    def link_card(self, card_id: str, observation_ids: list[str]) -> None:
        """Link an EvidenceCard ID to a set of observation IDs."""
        self._by_card_id[card_id] = list(observation_ids)
        for oid in observation_ids:
            self._card_by_obs_id[oid] = card_id

    def get_by_card(self, card_id: str) -> list[Observation]:
        """Retrieve all observations associated with an EvidenceCard ID."""
        obs_ids = self._by_card_id.get(card_id, [])
        return [self._observations[oid] for oid in obs_ids if oid in self._observations]

    def get_trace(self, obs_id: str, state: Any | None = None) -> dict[str, Any]:
        """Trace an observation back through card, requirement, hypothesis, query, and raw event.

        Traceability chain:
        observation_id -> EvidenceCard -> EvidenceRequirement -> Hypothesis -> QueryResult -> native query -> raw event.
        """
        obs = self.get_observation(obs_id)
        trace: dict[str, Any] = {
            "observation_id": obs_id,
            "found": obs is not None,
            "timestamp": obs.timestamp if obs else None,
            "native_type": obs.native_type if obs else None,
            "provider_scope": obs.provider_scope.scope_id if (obs and obs.provider_scope) else None,
            "cell_id": obs.cell_id if obs else None,
            "query_id": obs.query_id if obs else None,
            "raw_event": self.get_raw_event(obs_id) if obs else None,
            "card_id": self._card_by_obs_id.get(obs_id),
            "evidence_card": None,
            "requirements": [],
            "hypotheses": [],
            "query_result": None,
            "native_query": None,
        }

        if state is None or obs is None:
            return trace

        # Link EvidenceCard
        card_id = trace["card_id"]
        if not card_id and hasattr(state, "evidence_cards"):
            for c in state.evidence_cards:
                if obs_id in getattr(c, "representative_observation_ids", []):
                    card_id = c.id
                    trace["card_id"] = card_id
                    break

        if card_id and hasattr(state, "evidence_cards"):
            for c in state.evidence_cards:
                if c.id == card_id:
                    trace["evidence_card"] = {
                        "id": c.id,
                        "fact_type": getattr(c, "fact_type", ""),
                        "summary": getattr(c, "summary", ""),
                        "count": getattr(c, "count", 1),
                    }
                    trace["requirements"] = list(getattr(c, "requirements", []))
                    trace["hypotheses"] = list(getattr(c, "hypotheses", []))
                    break

        # Link Query and QueryResult
        qid = obs.query_id
        if qid and hasattr(state, "queries"):
            for q in state.queries:
                if getattr(q, "id", None) == qid:
                    trace["query_parameters"] = getattr(q, "parameters", {})
                    rid = getattr(q, "requirement_id", None)
                    if rid and rid not in trace["requirements"]:
                        trace["requirements"].append(rid)
                    break

        if hasattr(state, "query_results"):
            for qr in state.query_results:
                if qid and getattr(qr, "query_id", None) == qid:
                    trace["native_query"] = getattr(qr, "native_query", None)
                    trace["query_result"] = {
                        "rows_count": len(getattr(qr, "rows", []) or []),
                        "executed_ok": qr.executed_ok,
                        "complete": qr.complete,
                    }
                    break

        # If hypotheses not yet populated from card, infer from requirements
        if not trace["hypotheses"] and trace["requirements"] and hasattr(state, "hypotheses"):
            for h in state.hypotheses:
                for req_id in trace["requirements"]:
                    if req_id in getattr(h, "requirements", []):
                        if h.id not in trace["hypotheses"]:
                            trace["hypotheses"].append(h.id)

        return trace

    def export_jsonl(self, file_path: str | Path) -> None:
        """Export all observations as newline-delimited JSON with UTF-8 encoding."""
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            for obs in self._observations.values():
                row = {
                    "observation_id": obs.id,
                    "provider_id": obs.provider_scope.provider_id if obs.provider_scope else "",
                    "scope_id": obs.provider_scope.scope_id if obs.provider_scope else "",
                    "cell_id": obs.cell_id,
                    "timestamp": obs.timestamp,
                    "native_type": obs.native_type,
                    "semantic_type": (
                        obs.semantic_type.value if hasattr(obs.semantic_type, "value") else str(obs.semantic_type)
                    ) if obs.semantic_type else None,
                    "query_id": obs.query_id,
                    "raw_ref": obs.raw_ref,
                    "fields": obs.fields,
                    "raw_event": obs.raw_event or obs.fields,
                }
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    @classmethod
    def load_jsonl(cls, file_path: str | Path) -> list[dict[str, Any]]:
        """Load observations from JSONL file."""
        records: list[dict[str, Any]] = []
        p = Path(file_path)
        if not p.exists():
            return records
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    records.append(json.loads(line_str))
        return records


__all__ = ["ObservationStore"]
