"""Investigation Model and Relation Graph Contracts.

Core state representation for the General Cyclical Investigation Loop.
Center of State: A typed Relation Graph with explicit nodes, edges, claims,
mandatory unknowns, and acceptance criteria.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class NodeStatus(str, Enum):
    """Lifecycle status of a node in the investigation graph."""
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    CONFLICTING = "CONFLICTING"


class NodeType(str, Enum):
    """Permitted entity types in the relation graph."""
    PERSON = "person"
    ACCOUNT = "account"
    HOST = "host"
    ENDPOINT = "endpoint"
    IP = "ip"
    PROCESS = "process"
    DOMAIN = "domain"
    FILE = "file"
    SOFTWARE = "software"
    CVE = "cve"
    EVENT = "event"


class RelationType(str, Enum):
    """Permitted relationship types between graph nodes."""
    OWNS = "owns"
    LOGGED_ON_TO = "logged_on_to"
    ASSIGNED_IP = "assigned_ip"
    ORIGINATED_FROM = "originated_from"
    RESOLVED_TO = "resolved_to"
    REQUESTED = "requested"
    CONNECTED_TO = "connected_to"
    EXECUTED = "executed"
    ACCESSED = "accessed"
    COMMUNICATED_WITH = "communicated_with"
    SPAWNED = "spawned"
    MODIFIED = "modified"
    WROTE = "wrote"
    PRECEDED_BY = "preceded_by"


@dataclass
class GraphNode:
    """A node in the investigation relation graph."""
    id: str
    type: str  # NodeType or custom string
    value: str
    status: NodeStatus = NodeStatus.UNKNOWN
    confidence: float = 1.0
    source: str = "input"  # "input" | "telemetry" | "llm_inference" | "correlation"
    timestamp: datetime | str | None = None
    origin_query_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type if isinstance(self.type, str) else self.type.value,
            "value": self.value,
            "status": self.status.value if isinstance(self.status, NodeStatus) else str(self.status),
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": str(self.timestamp) if self.timestamp is not None else None,
            "origin_query_id": self.origin_query_id,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GraphNode:
        st_raw = str(data.get("status", "UNKNOWN")).upper()
        try:
            status = NodeStatus(st_raw)
        except ValueError:
            status = NodeStatus.UNKNOWN
        return cls(
            id=str(data.get("id", "")).strip(),
            type=str(data.get("type", "unknown")).strip().lower(),
            value=str(data.get("value", "")).strip(),
            status=status,
            confidence=float(data.get("confidence", 1.0)),
            source=str(data.get("source", "input")).strip(),
            timestamp=data.get("timestamp"),
            origin_query_id=data.get("origin_query_id"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class GraphEdge:
    """A directed edge in the investigation relation graph."""
    id: str
    source_id: str
    target_id: str
    relation_type: str  # RelationType or string
    status: NodeStatus = NodeStatus.UNKNOWN
    confidence: float = 1.0
    source: str = "input"  # "input" | "telemetry" | "llm_inference" | "correlation"
    timestamp: datetime | str | None = None
    origin_query_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type if isinstance(self.relation_type, str) else self.relation_type.value,
            "status": self.status.value if isinstance(self.status, NodeStatus) else str(self.status),
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": str(self.timestamp) if self.timestamp is not None else None,
            "origin_query_id": self.origin_query_id,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GraphEdge:
        st_raw = str(data.get("status", "UNKNOWN")).upper()
        try:
            status = NodeStatus(st_raw)
        except ValueError:
            status = NodeStatus.UNKNOWN
        return cls(
            id=str(data.get("id", "")).strip(),
            source_id=str(data.get("source_id", "")).strip(),
            target_id=str(data.get("target_id", "")).strip(),
            relation_type=str(data.get("relation_type", "")).strip().lower(),
            status=status,
            confidence=float(data.get("confidence", 1.0)),
            source=str(data.get("source", "input")).strip(),
            timestamp=data.get("timestamp"),
            origin_query_id=data.get("origin_query_id"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class RelationGraph:
    """The centralized relationship graph storing investigation knowledge."""
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, GraphEdge] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        """Add or update a node in the graph."""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add or update an edge in the graph."""
        self.edges[edge.id] = edge

    def get_node(self, node_id: str) -> GraphNode | None:
        return self.nodes.get(node_id)

    def get_node_by_value(self, value: str, node_type: str | None = None) -> GraphNode | None:
        v_lower = value.strip().lower()
        for node in self.nodes.values():
            if node.value.strip().lower() == v_lower:
                if node_type is None or node.type.lower() == node_type.lower():
                    return node
        return None

    def get_edges_from(self, source_id: str) -> list[GraphEdge]:
        return [e for e in self.edges.values() if e.source_id == source_id]

    def get_edges_to(self, target_id: str) -> list[GraphEdge]:
        return [e for e in self.edges.values() if e.target_id == target_id]

    def find_path(self, start_id: str, end_id: str, visited: set[str] | None = None) -> list[GraphEdge] | None:
        """Find a directed chain of KNOWN edges between start_id and end_id."""
        if visited is None:
            visited = set()
        if start_id == end_id:
            return []
        visited.add(start_id)

        for edge in self.get_edges_from(start_id):
            if edge.status != NodeStatus.KNOWN:
                continue
            if edge.target_id == end_id:
                return [edge]
            if edge.target_id not in visited:
                sub_path = self.find_path(edge.target_id, end_id, visited)
                if sub_path is not None:
                    return [edge] + sub_path
        return None

    def get_unknown_edges(self) -> list[GraphEdge]:
        """Return all edges that are currently UNKNOWN or CONFLICTING."""
        return [e for e in self.edges.values() if e.status in (NodeStatus.UNKNOWN, NodeStatus.CONFLICTING)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": {eid: e.to_dict() for eid, e in self.edges.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RelationGraph:
        graph = cls()
        for nid, nd in data.get("nodes", {}).items():
            graph.nodes[nid] = GraphNode.from_dict(nd)
        for eid, ed in data.get("edges", {}).items():
            graph.edges[eid] = GraphEdge.from_dict(ed)
        return graph


@dataclass
class InvestigationClaim:
    """A specific factual proposition extracted from the user's input."""
    id: str
    statement: str
    subject_node_id: str
    target_node_id: str
    required_relations: list[str] = field(default_factory=list)
    status: str = "PENDING"  # PENDING | VERIFIED | REFUTED | INCONCLUSIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "statement": self.statement,
            "subject_node_id": self.subject_node_id,
            "target_node_id": self.target_node_id,
            "required_relations": list(self.required_relations),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationClaim:
        return cls(
            id=str(data.get("id", "")).strip(),
            statement=str(data.get("statement", "")).strip(),
            subject_node_id=str(data.get("subject_node_id", "")).strip(),
            target_node_id=str(data.get("target_node_id", "")).strip(),
            required_relations=[str(r).strip() for r in data.get("required_relations", []) if str(r).strip()],
            status=str(data.get("status", "PENDING")).strip(),
        )


@dataclass
class InvestigationUnknown:
    """An explicit unknown entity or relationship that must be resolved."""
    id: str
    entity_type: str  # e.g., 'endpoint', 'client_ip', 'domain'
    description: str
    relation_to_resolve: str  # e.g., 'person -> logged_on_to -> endpoint'
    mandatory: bool = True
    status: str = "UNRESOLVED"  # UNRESOLVED | RESOLVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type,
            "description": self.description,
            "relation_to_resolve": self.relation_to_resolve,
            "mandatory": self.mandatory,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationUnknown:
        return cls(
            id=str(data.get("id", "")).strip(),
            entity_type=str(data.get("entity_type", "")).strip(),
            description=str(data.get("description", "")).strip(),
            relation_to_resolve=str(data.get("relation_to_resolve", "")).strip(),
            mandatory=bool(data.get("mandatory", True)),
            status=str(data.get("status", "UNRESOLVED")).strip(),
        )


@dataclass
class AcceptanceCriterion:
    """Deterministic acceptance criterion required to verify or refute an answer."""
    id: str
    description: str
    required_path: list[str] = field(default_factory=list)  # e.g. ["person", "endpoint", "ip", "domain"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "required_path": list(self.required_path),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AcceptanceCriterion:
        return cls(
            id=str(data.get("id", "")).strip(),
            description=str(data.get("description", "")).strip(),
            required_path=[str(p).strip() for p in data.get("required_path", []) if str(p).strip()],
        )


@dataclass
class InvestigationModel:
    """Canonical investigation contract emitted by LLM Semantic Investigator and held in state."""
    question: str
    claims: list[InvestigationClaim] = field(default_factory=list)
    subjects: list[GraphNode] = field(default_factory=list)
    requested_answer: dict[str, Any] = field(default_factory=dict)
    assumptions: list[str] = field(default_factory=list)
    unknowns: list[InvestigationUnknown] = field(default_factory=list)
    evidence_requirements: list[dict[str, Any]] = field(default_factory=list)
    required_correlations: list[str] = field(default_factory=list)
    acceptance_criteria: list[AcceptanceCriterion] = field(default_factory=list)
    alternative_explanations: list[str] = field(default_factory=list)
    graph: RelationGraph = field(default_factory=RelationGraph)

    def validate_provider_isolation(self) -> list[str]:
        """Check that output is provider-neutral with zero SPL/SQL/index leaks."""
        leaks: list[str] = []
        forbidden_tokens = ["index=", "sourcetype=", "| table", "| stats", "| eval", "select *", "from events"]
        full_text = (
            f"{self.question} "
            + " ".join(c.statement for c in self.claims)
            + " ".join(u.description for u in self.unknowns)
            + " ".join(self.required_correlations)
            + " ".join(self.assumptions)
            + " ".join(self.alternative_explanations)
        ).lower()

        for token in forbidden_tokens:
            if token in full_text:
                leaks.append(f"Forbidden provider syntax found in investigation model: '{token}'")
        return leaks

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "claims": [c.to_dict() for c in self.claims],
            "subjects": [s.to_dict() for s in self.subjects],
            "requested_answer": dict(self.requested_answer),
            "assumptions": list(self.assumptions),
            "unknowns": [u.to_dict() for u in self.unknowns],
            "evidence_requirements": list(self.evidence_requirements),
            "required_correlations": list(self.required_correlations),
            "acceptance_criteria": [a.to_dict() for a in self.acceptance_criteria],
            "alternative_explanations": list(self.alternative_explanations),
            "graph": self.graph.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationModel:
        claims = [InvestigationClaim.from_dict(c) for c in data.get("claims", []) if isinstance(c, dict)]
        subjects = [GraphNode.from_dict(s) for s in data.get("subjects", []) if isinstance(s, dict)]
        unknowns = [InvestigationUnknown.from_dict(u) for u in data.get("unknowns", []) if isinstance(u, dict)]
        criteria = [AcceptanceCriterion.from_dict(a) for a in data.get("acceptance_criteria", []) if isinstance(a, dict)]
        graph_data = data.get("graph", {})
        graph = RelationGraph.from_dict(graph_data) if isinstance(graph_data, dict) else RelationGraph()

        return cls(
            question=str(data.get("question", "")).strip(),
            claims=claims,
            subjects=subjects,
            requested_answer=dict(data.get("requested_answer", {})),
            assumptions=[str(a).strip() for a in data.get("assumptions", []) if str(a).strip()],
            unknowns=unknowns,
            evidence_requirements=list(data.get("evidence_requirements", [])),
            required_correlations=[str(r).strip() for r in data.get("required_correlations", []) if str(r).strip()],
            acceptance_criteria=criteria,
            alternative_explanations=[str(e).strip() for e in data.get("alternative_explanations", []) if str(e).strip()],
            graph=graph,
        )


def build_investigation_model_from_intent(
    intent: Any,
    hypotheses: list[Any] | None = None,
    requirements: list[Any] | None = None,
) -> InvestigationModel:
    """Build a typed InvestigationModel and initialized RelationGraph from semantic intent."""
    hypotheses = hypotheses or []
    requirements = requirements or []
    graph = RelationGraph()
    unknowns: list[InvestigationUnknown] = []
    acceptance_criteria: list[AcceptanceCriterion] = []
    claims: list[InvestigationClaim] = []

    subj_type = getattr(intent.subject, "type", "unknown") if hasattr(intent, "subject") else "unknown"
    subj_val = getattr(intent.subject, "value", "") if hasattr(intent, "subject") else ""
    req_obj_type = getattr(intent.requested_object, "type", "unknown") if hasattr(intent, "requested_object") else "unknown"

    # Subject Node
    subj_node = GraphNode(
        id=f"node-subj-{subj_type}",
        type=subj_type,
        value=subj_val,
        status=NodeStatus.KNOWN if subj_val else NodeStatus.UNKNOWN,
        source="input",
    )
    graph.add_node(subj_node)

    # Target Node
    target_node = GraphNode(
        id="node-target-object",
        type=req_obj_type,
        value="UNKNOWN_TARGET",
        status=NodeStatus.UNKNOWN,
        source="inference",
    )
    graph.add_node(target_node)

    if subj_type in ("person", "user"):
        # Person requires: person -> logged_on_to -> endpoint -> originated_from -> IP -> requested -> target
        endpoint_node = GraphNode(
            id="node-endpoint",
            type=NodeType.ENDPOINT.value,
            value="UNKNOWN_ENDPOINT",
            status=NodeStatus.UNKNOWN,
            source="inference",
        )
        ip_node = GraphNode(
            id="node-client-ip",
            type=NodeType.IP.value,
            value="UNKNOWN_IP",
            status=NodeStatus.UNKNOWN,
            source="inference",
        )
        graph.add_node(endpoint_node)
        graph.add_node(ip_node)

        edge1 = GraphEdge(
            id="edge-person-endpoint",
            source_id=subj_node.id,
            target_id=endpoint_node.id,
            relation_type=RelationType.LOGGED_ON_TO.value,
            status=NodeStatus.UNKNOWN,
            source="inference",
        )
        edge2 = GraphEdge(
            id="edge-endpoint-ip",
            source_id=endpoint_node.id,
            target_id=ip_node.id,
            relation_type=RelationType.ORIGINATED_FROM.value,
            status=NodeStatus.UNKNOWN,
            source="inference",
        )
        edge3 = GraphEdge(
            id="edge-ip-target",
            source_id=ip_node.id,
            target_id=target_node.id,
            relation_type=RelationType.REQUESTED.value,
            status=NodeStatus.UNKNOWN,
            source="inference",
        )
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        graph.add_edge(edge3)

        unknowns.append(
            InvestigationUnknown(
                id="unk-endpoint",
                entity_type="endpoint",
                description=f"Identify workstation endpoint used by {subj_val}",
                relation_to_resolve=f"person({subj_val}) -> logged_on_to -> endpoint",
                mandatory=True,
                status="UNRESOLVED",
            )
        )
        unknowns.append(
            InvestigationUnknown(
                id="unk-client-ip",
                entity_type="ip",
                description=f"Identify client IP address assigned to {subj_val}'s endpoint",
                relation_to_resolve="endpoint -> originated_from -> ip",
                mandatory=True,
                status="UNRESOLVED",
            )
        )
        acceptance_criteria.append(
            AcceptanceCriterion(
                id="crit-user-provenance-chain",
                description=f"Complete chain from {subj_val} through endpoint and IP to target object",
                required_path=["person", "endpoint", "ip", req_obj_type],
            )
        )
    elif subj_type in ("host", "endpoint"):
        edge1 = GraphEdge(
            id="edge-host-target",
            source_id=subj_node.id,
            target_id=target_node.id,
            relation_type=RelationType.CONNECTED_TO.value,
            status=NodeStatus.UNKNOWN,
            source="inference",
        )
        graph.add_edge(edge1)
        unknowns.append(
            InvestigationUnknown(
                id="unk-host-activity",
                entity_type=req_obj_type,
                description=f"Activity connecting {subj_val} to {req_obj_type}",
                relation_to_resolve=f"host({subj_val}) -> connected_to -> {req_obj_type}",
                mandatory=True,
                status="UNRESOLVED",
            )
        )
        acceptance_criteria.append(
            AcceptanceCriterion(
                id="crit-host-chain",
                description=f"Connection between {subj_val} and target object",
                required_path=[subj_type, req_obj_type],
            )
        )
    else:
        acceptance_criteria.append(
            AcceptanceCriterion(
                id="crit-generic-chain",
                description="Evidence supporting investigation objective",
                required_path=[subj_type, req_obj_type],
            )
        )

    # Create claims from hypotheses
    for h in hypotheses:
        claims.append(
            InvestigationClaim(
                id=h.id,
                statement=h.statement,
                subject_node_id=subj_node.id,
                target_node_id=target_node.id,
                required_relations=list(getattr(intent, "required_correlations", [])),
                status="PENDING",
            )
        )

    return InvestigationModel(
        question=getattr(intent, "question", "") or getattr(intent, "original_request", ""),
        claims=claims,
        subjects=[subj_node],
        requested_answer=intent.requested_object.to_dict() if hasattr(intent, "requested_object") else {},
        assumptions=list(getattr(intent, "assumptions", [])),
        unknowns=unknowns,
        evidence_requirements=[r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in getattr(intent, "evidence_requirements", [])],
        required_correlations=list(getattr(intent, "required_correlations", [])),
        acceptance_criteria=acceptance_criteria,
        alternative_explanations=[h.statement for h in hypotheses if getattr(h, "hypothesis_class", "") == "benign_baseline"],
        graph=graph,
    )


__all__ = [
    "NodeStatus",
    "NodeType",
    "RelationType",
    "GraphNode",
    "GraphEdge",
    "RelationGraph",
    "InvestigationClaim",
    "InvestigationUnknown",
    "AcceptanceCriterion",
    "InvestigationModel",
    "build_investigation_model_from_intent",
]
