"""Append-only evidence graph reconstructed from immutable telemetry.

This graph is an evidence index, not the desired semantic goal graph.  Its
edges carry observation provenance and an explicit ``proof_status``; graph
proximity or co-occurrence never becomes semantic proof automatically.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from hunting.contracts.observations import Observation
from hunting.evidence.facts import EvidenceFact, extract_facts


def _stable_id(prefix: str, payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"


@dataclass(frozen=True)
class EvidenceNode:
    id: str
    node_type: str
    payload: dict[str, Any]
    provenance_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type,
            "payload": dict(self.payload),
            "provenance_ids": list(self.provenance_ids),
        }


@dataclass(frozen=True)
class EvidenceEdge:
    id: str
    source_id: str
    target_id: str
    edge_type: str
    observation_ids: tuple[str, ...] = ()
    proof_status: str = "NOT_PROOF"
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "observation_ids": list(self.observation_ids),
            "proof_status": self.proof_status,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class FieldFact:
    id: str
    fact_node_id: str
    field_name: str
    value: Any
    native_field_name: str
    observation_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fact_node_id": self.fact_node_id,
            "field_name": self.field_name,
            "value": self.value,
            "native_field_name": self.native_field_name,
            "observation_id": self.observation_id,
        }


@dataclass
class EvidenceGraph:
    nodes: dict[str, EvidenceNode] = field(default_factory=dict)
    edges: dict[str, EvidenceEdge] = field(default_factory=dict)
    field_facts: dict[str, FieldFact] = field(default_factory=dict)
    observation_ids: list[str] = field(default_factory=list)

    def add_node(self, node: EvidenceNode) -> None:
        existing = self.nodes.get(node.id)
        if existing is not None and existing != node:
            # The same stable entity/fact identity may be observed by more
            # than one query.  Merge only provenance; never merge payloads or
            # replace a conflicting fact.
            if existing.node_type == node.node_type and existing.payload == node.payload:
                self.nodes[node.id] = EvidenceNode(
                    id=existing.id,
                    node_type=existing.node_type,
                    payload=dict(existing.payload),
                    provenance_ids=tuple(sorted(set(existing.provenance_ids) | set(node.provenance_ids))),
                )
                return
            raise ValueError(f"evidence node collision: {node.id}")
        self.nodes[node.id] = node

    def add_edge(self, edge: EvidenceEdge) -> None:
        existing = self.edges.get(edge.id)
        if existing is not None and existing != edge:
            raise ValueError(f"evidence edge collision: {edge.id}")
        self.edges[edge.id] = edge

    def append_observation(self, observation: Observation) -> tuple[str, ...]:
        """Append one observation and deterministic facts without overwriting."""
        if observation.id in self.observation_ids:
            return tuple(node_id for node_id in self.nodes if observation.id in self.nodes[node_id].provenance_ids)
        self.observation_ids.append(observation.id)
        observation_payload = {
            "timestamp": observation.timestamp,
            "native_type": observation.native_type,
            "provider_scope": getattr(observation.provider_scope, "scope_id", ""),
            "query_id": observation.query_id or getattr(observation.provenance, "query_id", None),
            "native_fields": dict(observation.native_fields or observation.fields),
            "raw_ref": observation.raw_ref,
        }
        observation_node_id = f"observation:{observation.id}"
        self.add_node(EvidenceNode(observation_node_id, "observation", observation_payload, (observation.id,)))
        added: list[str] = [observation_node_id]
        for fact in extract_facts(observation):
            fact_id = _stable_id("fact", {"observation_id": fact.observation_id, "type": fact.fact_type, "fields": fact.fields})
            fact_node = EvidenceNode(
                fact_id,
                "fact",
                {
                    "fact_type": fact.fact_type,
                    "timestamp": fact.timestamp,
                    "primary_entity": repr(fact.primary_entity),
                    "fields": dict(fact.fields),
                },
                (fact.observation_id,),
            )
            self.add_node(fact_node)
            added.append(fact_id)
            self.add_edge(EvidenceEdge(
                id=_stable_id("edge", (observation_node_id, fact_id, "contains_fact")),
                source_id=observation_node_id,
                target_id=fact_id,
                edge_type="contains_fact",
                observation_ids=(fact.observation_id,),
            ))
            for field_name, value in fact.fields.items():
                field_id = _stable_id("field", (fact_id, field_name, value))
                field_fact = FieldFact(field_id, fact_id, field_name, value, field_name, fact.observation_id)
                self.field_facts[field_id] = field_fact
                self.add_node(EvidenceNode(field_id, "field_fact", field_fact.to_dict(), (fact.observation_id,)))
                self.add_edge(EvidenceEdge(
                    id=_stable_id("edge", (fact_id, field_id, "has_field")),
                    source_id=fact_id,
                    target_id=field_id,
                    edge_type="has_field",
                    observation_ids=(fact.observation_id,),
                ))
            for relation in fact.relations:
                source_id = _stable_id("entity", repr(relation.source_entity))
                target_id = _stable_id("entity", repr(relation.target_entity))
                self.add_node(EvidenceNode(source_id, "entity", {"entity": repr(relation.source_entity)}, (fact.observation_id,)))
                self.add_node(EvidenceNode(target_id, "entity", {"entity": repr(relation.target_entity)}, (fact.observation_id,)))
                self.add_edge(EvidenceEdge(
                    id=_stable_id("edge", (source_id, target_id, relation.relation_type, fact.observation_id)),
                    source_id=source_id,
                    target_id=target_id,
                    edge_type="observed_transition",
                    observation_ids=(fact.observation_id,),
                    attributes={"relation_type": relation.relation_type},
                ))
        return tuple(added)

    @classmethod
    def from_observations(cls, observations: Iterable[Observation]) -> "EvidenceGraph":
        graph = cls()
        for observation in observations:
            graph.append_observation(observation)
        return graph

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges.values()],
            "field_facts": [fact.to_dict() for fact in self.field_facts.values()],
            "observation_ids": list(self.observation_ids),
            "proof_note": "Graph proximity and co-occurrence are not proof.",
        }


__all__ = ["EvidenceEdge", "EvidenceGraph", "EvidenceNode", "FieldFact"]
