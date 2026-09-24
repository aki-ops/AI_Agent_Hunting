"""Append-only evidence graph reconstructed from immutable telemetry.

This graph is an evidence index, not the desired semantic goal graph.  Its
edges carry observation provenance and an explicit ``proof_status``; graph
proximity or co-occurrence never becomes semantic proof automatically.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from hunting.contracts.observations import Observation
from hunting.evidence.facts import extract_facts


class EvidenceEdgeClass(str, Enum):
    """Distinct evidence-graph relation classes. None of these is proof."""

    OBSERVED_TRANSITION = "observed_transition"
    PROVENANCE_DEPENDENCY = "provenance_dependency"
    CAUSAL_ATTRIBUTION = "causal_attribution"


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
    edge_class: str = EvidenceEdgeClass.OBSERVED_TRANSITION.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "edge_class": self.edge_class,
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
            "provider_id": getattr(observation.provider_scope, "provider_id", ""),
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
                edge_class=EvidenceEdgeClass.PROVENANCE_DEPENDENCY.value,
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
                    edge_class=EvidenceEdgeClass.PROVENANCE_DEPENDENCY.value,
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
                    edge_class=EvidenceEdgeClass.OBSERVED_TRANSITION.value,
                    observation_ids=(fact.observation_id,),
                    attributes={"relation_type": relation.relation_type},
                ))
        return tuple(added)

    def add_causal_attribution(
        self,
        *,
        source_id: str,
        target_id: str,
        observation_ids: tuple[str, ...],
        contract_id: str,
    ) -> EvidenceEdge:
        """Record a declared causal edge. Proximity never authorizes this."""
        cited = tuple(str(item) for item in observation_ids if str(item).strip())
        if not cited:
            raise ValueError("causal attribution requires cited observations")
        if not str(contract_id).strip():
            raise ValueError("causal attribution requires an approved correlation or identity contract")
        unknown = [item for item in cited if item not in self.observation_ids]
        if unknown:
            raise ValueError(f"causal attribution cites unknown observations: {unknown}")
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError("causal attribution requires existing evidence nodes")
        edge = EvidenceEdge(
            id=_stable_id("edge", (source_id, target_id, "causal_attribution", contract_id, cited)),
            source_id=source_id,
            target_id=target_id,
            edge_type="causal_attribution",
            edge_class=EvidenceEdgeClass.CAUSAL_ATTRIBUTION.value,
            observation_ids=cited,
            proof_status="NOT_PROOF",
            attributes={"contract_id": str(contract_id)},
        )
        self.add_edge(edge)
        return edge

    @classmethod
    def from_observations(cls, observations: Iterable[Observation]) -> "EvidenceGraph":
        graph = cls()
        for observation in observations:
            graph.append_observation(observation)
        return graph

    @classmethod
    def from_run_account(cls, account: dict[str, Any]) -> "EvidenceGraph":
        """Rebuild the graph from immutable run-account records only."""
        if not isinstance(account, dict):
            raise ValueError("run account must be an object")
        payload = account.get("semantic_evidence_analysis")
        if not isinstance(payload, dict):
            payload = account
        raw_observations = payload.get("observations", account.get("observations", []))
        if isinstance(raw_observations, list) and raw_observations:
            observations: list[Observation] = []
            for item in raw_observations:
                if isinstance(item, Observation):
                    observations.append(item)
                elif isinstance(item, dict):
                    observations.append(Observation.from_dict(item))
            return cls.from_observations(observations)
        graph_raw = payload.get("evidence_graph", account.get("evidence_graph", {}))
        if isinstance(graph_raw, dict) and graph_raw:
            return cls.from_dict(graph_raw)
        return cls()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EvidenceGraph":
        """Rehydrate the audit projection without inventing observations."""
        graph = cls(
            observation_ids=[str(value) for value in raw.get("observation_ids", [])],
        )
        for item in raw.get("nodes", []):
            if not isinstance(item, dict):
                continue
            node = EvidenceNode(
                id=str(item.get("id", "")),
                node_type=str(item.get("node_type", "")),
                payload=dict(item.get("payload", {}) or {}),
                provenance_ids=tuple(str(value) for value in item.get("provenance_ids", [])),
            )
            if node.id:
                graph.add_node(node)
        for item in raw.get("edges", []):
            if not isinstance(item, dict):
                continue
            edge = EvidenceEdge(
                id=str(item.get("id", "")),
                source_id=str(item.get("source_id", "")),
                target_id=str(item.get("target_id", "")),
                edge_type=str(item.get("edge_type", "")),
                observation_ids=tuple(str(value) for value in item.get("observation_ids", [])),
                proof_status=str(item.get("proof_status", "NOT_PROOF")),
                attributes=dict(item.get("attributes", {}) or {}),
                edge_class=str(item.get("edge_class") or item.get("edge_type") or EvidenceEdgeClass.OBSERVED_TRANSITION.value),
            )
            if edge.id:
                graph.add_edge(edge)
        for item in raw.get("field_facts", []):
            if not isinstance(item, dict):
                continue
            field_fact = FieldFact(
                id=str(item.get("id", "")),
                fact_node_id=str(item.get("fact_node_id", "")),
                field_name=str(item.get("field_name", "")),
                value=item.get("value"),
                native_field_name=str(item.get("native_field_name", "")),
                observation_id=str(item.get("observation_id", "")),
            )
            if field_fact.id:
                graph.field_facts[field_fact.id] = field_fact
        return graph

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges.values()],
            "field_facts": [fact.to_dict() for fact in self.field_facts.values()],
            "observation_ids": list(self.observation_ids),
            "proof_note": "Graph proximity and co-occurrence are not proof.",
        }


__all__ = ["EvidenceEdge", "EvidenceEdgeClass", "EvidenceGraph", "EvidenceNode", "FieldFact"]
