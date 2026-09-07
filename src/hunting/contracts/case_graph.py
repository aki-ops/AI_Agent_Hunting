"""Investigation Case Graph and Epistemic Contracts (v5.0).

Center of State for the Relation-First Threat Hunting Architecture:
Investigation Case Graph (Nodes, Edges, Mandatory Unknowns, Evidence Goals,
Relation Proofs, and Evidence Subgraphs).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class FieldRole(str, Enum):
    """Explicit forensic field roles to prevent server/client and IP conflation."""
    CLIENT_IP = "client_ip"
    SERVER_IP = "server_ip"
    SOURCE_IP = "source_ip"
    DESTINATION_IP = "destination_ip"
    ENDPOINT_HOST = "endpoint_host"
    SERVER_HOST = "server_host"
    SENSOR_HOST = "sensor_host"
    ACCOUNT_NAME = "account_name"
    PERSON_NAME = "person_name"
    DOMAIN_NAME = "domain_name"
    PROCESS_NAME = "process_name"
    FILE_PATH = "file_path"
    COMMAND_LINE = "command_line"
    URI_PATH = "uri_path"
    QUERY_PARAM = "query_param"


class NodeType(str, Enum):
    """Permitted entity node types in the investigation case graph."""
    PERSON = "person"
    ACCOUNT = "account"
    ENDPOINT = "endpoint"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    PROCESS = "process"
    FILE = "file"
    CREDENTIAL = "credential"
    SOFTWARE = "software"
    CVE = "cve"
    EVENT = "event"


class RelationType(str, Enum):
    """Permitted directed relation types between graph nodes."""
    OWNS = "owns"
    LOGGED_ON_TO = "logged_on_to"
    ASSIGNED_IP = "assigned_ip"
    ORIGINATED_FROM = "originated_from"
    REQUESTED = "requested"
    RESOLVED_TO = "resolved_to"
    CONNECTED_TO = "connected_to"
    EXECUTED = "executed"
    ACCESSED = "accessed"
    COMMUNICATED_WITH = "communicated_with"
    SPAWNED = "spawned"
    MODIFIED = "modified"
    WROTE = "wrote"


class NodeStatus(str, Enum):
    """Epistemic status of a node in the graph."""
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    CONFLICTING = "CONFLICTING"


class RelationStatus(str, Enum):
    """Epistemic verification status of a directed edge."""
    UNPROVEN = "UNPROVEN"
    HYPOTHESIZED = "HYPOTHESIZED"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"


@dataclass
class GraphNode:
    """A typed entity node in the investigation graph."""
    id: str
    type: NodeType | str
    value: str
    status: NodeStatus = NodeStatus.UNKNOWN
    confidence: float = 1.0
    field_role: FieldRole | str | None = None
    source: str = "input"  # "input" | "telemetry" | "llm_inference" | "correlation"
    timestamp: datetime | str | None = None
    origin_query_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value if isinstance(self.type, Enum) else str(self.type),
            "value": self.value,
            "status": self.status.value if isinstance(self.status, Enum) else str(self.status),
            "confidence": self.confidence,
            "field_role": self.field_role.value if isinstance(self.field_role, Enum) else (str(self.field_role) if self.field_role else None),
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
        fr_raw = data.get("field_role")
        field_role = None
        if fr_raw:
            try:
                field_role = FieldRole(str(fr_raw).lower())
            except ValueError:
                field_role = str(fr_raw)
        t_raw = str(data.get("type", "endpoint")).strip().lower()
        try:
            ntype = NodeType(t_raw)
        except ValueError:
            ntype = t_raw
        return cls(
            id=str(data.get("id", "")).strip(),
            type=ntype,
            value=str(data.get("value", "")).strip(),
            status=status,
            confidence=float(data.get("confidence", 1.0)),
            field_role=field_role,
            source=str(data.get("source", "input")).strip(),
            timestamp=data.get("timestamp"),
            origin_query_id=data.get("origin_query_id"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class GraphEdge:
    """A directed, typed relation between entities in the investigation graph."""
    id: str
    source_id: str
    source_entity_type: NodeType | str
    relation_type: RelationType | str
    target_id: str
    target_entity_type: NodeType | str
    required_field_roles: dict[str, FieldRole | str] = field(default_factory=dict)
    time_constraints: dict[str, Any] = field(default_factory=dict)
    acceptable_operations: list[str] = field(default_factory=list)
    status: RelationStatus = RelationStatus.UNPROVEN
    confidence: float = 1.0
    citations: list[str] = field(default_factory=list)  # observation IDs
    origin_query_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "source_entity_type": self.source_entity_type.value if isinstance(self.source_entity_type, Enum) else str(self.source_entity_type),
            "relation_type": self.relation_type.value if isinstance(self.relation_type, Enum) else str(self.relation_type),
            "target_id": self.target_id,
            "target_entity_type": self.target_entity_type.value if isinstance(self.target_entity_type, Enum) else str(self.target_entity_type),
            "required_field_roles": {
                k: (v.value if isinstance(v, Enum) else str(v))
                for k, v in self.required_field_roles.items()
            },
            "time_constraints": dict(self.time_constraints),
            "acceptable_operations": list(self.acceptable_operations),
            "status": self.status.value if isinstance(self.status, Enum) else str(self.status),
            "confidence": self.confidence,
            "citations": list(self.citations),
            "origin_query_id": self.origin_query_id,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GraphEdge:
        st_raw = str(data.get("status", "UNPROVEN")).upper()
        try:
            status = RelationStatus(st_raw)
        except ValueError:
            status = RelationStatus.UNPROVEN
        rt_raw = str(data.get("relation_type", "connected_to")).strip().lower()
        try:
            rel_type = RelationType(rt_raw)
        except ValueError:
            rel_type = rt_raw
        src_t = data.get("source_entity_type", "host")
        tgt_t = data.get("target_entity_type", "host")
        req_roles = {}
        for k, v in data.get("required_field_roles", {}).items():
            try:
                req_roles[k] = FieldRole(str(v).lower())
            except ValueError:
                req_roles[k] = str(v)
        return cls(
            id=str(data.get("id", "")).strip(),
            source_id=str(data.get("source_id", "")).strip(),
            source_entity_type=src_t,
            relation_type=rel_type,
            target_id=str(data.get("target_id", "")).strip(),
            target_entity_type=tgt_t,
            required_field_roles=req_roles,
            time_constraints=dict(data.get("time_constraints", {})),
            acceptable_operations=list(data.get("acceptable_operations", [])),
            status=status,
            confidence=float(data.get("confidence", 1.0)),
            citations=list(data.get("citations", [])),
            origin_query_id=data.get("origin_query_id"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class InvestigationUnknown:
    """An unproven variable in the causal chain that must be resolved."""
    id: str
    entity_type: NodeType | str
    variable_name: str
    description: str
    mandatory: bool = True
    resolving_edge_id: str | None = None
    resolved_value: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value if isinstance(self.entity_type, Enum) else str(self.entity_type),
            "variable_name": self.variable_name,
            "description": self.description,
            "mandatory": self.mandatory,
            "resolving_edge_id": self.resolving_edge_id,
            "resolved_value": self.resolved_value,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationUnknown:
        return cls(
            id=str(data.get("id", "")).strip(),
            entity_type=str(data.get("entity_type", "unknown")).strip().lower(),
            variable_name=str(data.get("variable_name", "")).strip(),
            description=str(data.get("description", "")).strip(),
            mandatory=bool(data.get("mandatory", True)),
            resolving_edge_id=data.get("resolving_edge_id"),
            resolved_value=data.get("resolved_value"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class EvidenceGoal:
    """A target relation that an action seeks to prove or disprove."""
    id: str
    target_edge_id: str
    description: str
    necessity: str = "CRITICAL"  # "CRITICAL" | "SUPPORTING"
    acceptable_operations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_edge_id": self.target_edge_id,
            "description": self.description,
            "necessity": self.necessity,
            "acceptable_operations": list(self.acceptable_operations),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceGoal:
        return cls(
            id=str(data.get("id", "")).strip(),
            target_edge_id=str(data.get("target_edge_id", "")).strip(),
            description=str(data.get("description", "")).strip(),
            necessity=str(data.get("necessity", "CRITICAL")).strip().upper(),
            acceptable_operations=list(data.get("acceptable_operations", [])),
        )


@dataclass
class ActionCandidate:
    """A candidate provider operation proposed by the relation planner."""
    operation_name: str
    target_edge_id: str
    bound_source_node_id: str
    bound_source_value: str
    parameters: dict[str, Any] = field(default_factory=dict)
    priority: int = 1
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_name": self.operation_name,
            "target_edge_id": self.target_edge_id,
            "bound_source_node_id": self.bound_source_node_id,
            "bound_source_value": self.bound_source_value,
            "parameters": dict(self.parameters),
            "priority": self.priority,
            "reason": self.reason,
        }


@dataclass
class RelationProof:
    """An immutable proof anchoring an edge to verified observation citations."""
    id: str
    edge_id: str
    source_node_id: str
    source_value: str
    target_node_id: str
    target_value: str
    relation_type: str
    citations: list[str] = field(default_factory=list)
    field_matches: dict[str, str] = field(default_factory=dict)
    verified_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    verified_by: str = "RelationVerifier"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "source_value": self.source_value,
            "target_node_id": self.target_node_id,
            "target_value": self.target_value,
            "relation_type": self.relation_type,
            "citations": list(self.citations),
            "field_matches": dict(self.field_matches),
            "verified_at": self.verified_at,
            "verified_by": self.verified_by,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RelationProof:
        return cls(
            id=str(data.get("id", "")).strip(),
            edge_id=str(data.get("edge_id", "")).strip(),
            source_node_id=str(data.get("source_node_id", "")).strip(),
            source_value=str(data.get("source_value", "")).strip(),
            target_node_id=str(data.get("target_node_id", "")).strip(),
            target_value=str(data.get("target_value", "")).strip(),
            relation_type=str(data.get("relation_type", "")).strip(),
            citations=list(data.get("citations", [])),
            field_matches=dict(data.get("field_matches", {})),
            verified_at=str(data.get("verified_at", "")).strip(),
            verified_by=str(data.get("verified_by", "RelationVerifier")).strip(),
        )


@dataclass
class EvidenceSubgraph:
    """A bounded projection of verified graph nodes, edges, and citations for a claim."""
    claim_id: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    proofs: list[RelationProof] = field(default_factory=list)
    cited_observation_ids: list[str] = field(default_factory=list)

    def render_provenance_path(self) -> str:
        if not self.proofs:
            return "No verified causal path."
        steps = []
        for p in self.proofs:
            steps.append(f"{p.source_value} -[{p.relation_type}]-> {p.target_value} (citations: {', '.join(p.citations)})")
        return " -> ".join(steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "proofs": [p.to_dict() for p in self.proofs],
            "cited_observation_ids": list(self.cited_observation_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceSubgraph:
        return cls(
            claim_id=str(data.get("claim_id", "")).strip(),
            nodes=[GraphNode.from_dict(n) for n in data.get("nodes", [])],
            edges=[GraphEdge.from_dict(e) for e in data.get("edges", [])],
            proofs=[RelationProof.from_dict(p) for p in data.get("proofs", [])],
            cited_observation_ids=list(data.get("cited_observation_ids", [])),
        )


@dataclass
class InvestigationGraph:
    """The relation graph holding the epistemic state of an investigation."""
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, GraphEdge] = field(default_factory=dict)
    proofs: dict[str, RelationProof] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges[edge.id] = edge

    def get_node(self, node_id: str) -> GraphNode | None:
        return self.nodes.get(node_id)

    def get_edge(self, edge_id: str) -> GraphEdge | None:
        return self.edges.get(edge_id)

    def get_unproven_edges(self, only_known_source: bool = True) -> list[GraphEdge]:
        """Return mandatory edges that remain unproven."""
        candidates = []
        for e in self.edges.values():
            if e.status in (RelationStatus.UNPROVEN, RelationStatus.HYPOTHESIZED):
                if only_known_source:
                    src = self.get_node(e.source_id)
                    if src and src.status == NodeStatus.KNOWN:
                        candidates.append(e)
                else:
                    candidates.append(e)
        return candidates

    def promote_edge_to_verified(self, edge_id: str, citations: list[str], field_matches: dict[str, str]) -> RelationProof:
        edge = self.edges.get(edge_id)
        if not edge:
            raise KeyError(f"Edge not found: {edge_id}")
        edge.status = RelationStatus.VERIFIED
        edge.citations = list(set(edge.citations + citations))

        # Promote target node to KNOWN if it was UNKNOWN
        tgt = self.get_node(edge.target_id)
        if tgt and tgt.status != NodeStatus.KNOWN:
            tgt.status = NodeStatus.KNOWN

        src = self.get_node(edge.source_id)
        proof = RelationProof(
            id=f"proof-{edge.id}",
            edge_id=edge.id,
            source_node_id=edge.source_id,
            source_value=src.value if src else "",
            target_node_id=edge.target_id,
            target_value=tgt.value if tgt else "",
            relation_type=edge.relation_type.value if isinstance(edge.relation_type, Enum) else str(edge.relation_type),
            citations=citations,
            field_matches=field_matches,
        )
        self.proofs[proof.id] = proof
        return proof

    def extract_subgraph_for_claim(self, claim_id: str) -> EvidenceSubgraph:
        sub_nodes = list(self.nodes.values())
        sub_edges = [e for e in self.edges.values() if e.status == RelationStatus.VERIFIED]
        sub_proofs = list(self.proofs.values())
        all_cits = set()
        for p in sub_proofs:
            all_cits.update(p.citations)
        return EvidenceSubgraph(
            claim_id=claim_id,
            nodes=sub_nodes,
            edges=sub_edges,
            proofs=sub_proofs,
            cited_observation_ids=list(all_cits),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": {eid: e.to_dict() for eid, e in self.edges.items()},
            "proofs": {pid: p.to_dict() for pid, p in self.proofs.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationGraph:
        graph = cls()
        for nid, ndata in data.get("nodes", {}).items():
            graph.nodes[nid] = GraphNode.from_dict(ndata)
        for eid, edata in data.get("edges", {}).items():
            graph.edges[eid] = GraphEdge.from_dict(edata)
        for pid, pdata in data.get("proofs", {}).items():
            graph.proofs[pid] = RelationProof.from_dict(pdata)
        return graph


@dataclass
class InvestigationCase:
    """The canonical case representation in v5.0."""
    id: str
    request_content: str
    question: str
    graph: InvestigationGraph = field(default_factory=InvestigationGraph)
    claims: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[InvestigationUnknown] = field(default_factory=list)
    evidence_goals: list[EvidenceGoal] = field(default_factory=list)
    acceptance_criteria: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    status: str = "READY_FOR_DISCOVERY"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "request_content": self.request_content,
            "question": self.question,
            "graph": self.graph.to_dict(),
            "claims": list(self.claims),
            "unknowns": [u.to_dict() for u in self.unknowns],
            "evidence_goals": [g.to_dict() for g in self.evidence_goals],
            "acceptance_criteria": list(self.acceptance_criteria),
            "assumptions": list(self.assumptions),
            "status": self.status,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationCase:
        gdata = data.get("graph", {})
        graph = InvestigationGraph.from_dict(gdata) if isinstance(gdata, dict) else InvestigationGraph()
        return cls(
            id=str(data.get("id", "")).strip(),
            request_content=str(data.get("request_content", "")).strip(),
            question=str(data.get("question", "")).strip(),
            graph=graph,
            claims=list(data.get("claims", [])),
            unknowns=[InvestigationUnknown.from_dict(u) for u in data.get("unknowns", [])],
            evidence_goals=[EvidenceGoal.from_dict(g) for g in data.get("evidence_goals", [])],
            acceptance_criteria=list(data.get("acceptance_criteria", [])),
            assumptions=list(data.get("assumptions", [])),
            status=str(data.get("status", "READY_FOR_DISCOVERY")),
            metadata=dict(data.get("metadata", {})),
        )


def build_investigation_case_from_intent(
    intent: Any,
    hypotheses: list[Any],
    requirements: list[Any],
) -> InvestigationCase:
    """Build canonical InvestigationCase and InvestigationGraph from SemanticHuntIntent."""
    graph = InvestigationGraph()
    unknowns: list[InvestigationUnknown] = []
    goals: list[EvidenceGoal] = []
    claims: list[dict[str, Any]] = []

    subj_val = intent.subject.value if intent.subject and intent.subject.value else "TargetEntity"
    subj_type = (intent.subject.type.lower() if intent.subject and intent.subject.type else "entity")
    req_obj_type_raw = (intent.requested_object.type.lower() if intent.requested_object and intent.requested_object.type else "outcome")
    if any(term in req_obj_type_raw for term in ("domain", "fqdn", "website", "site", "url", "web")):
        req_obj_type = NodeType.DOMAIN
    else:
        req_obj_type = req_obj_type_raw

    target_node = GraphNode(
        id="node-target-object",
        type=req_obj_type,
        value="?",
        status=NodeStatus.UNKNOWN,
        source="intent",
        field_role=FieldRole.DOMAIN_NAME if (req_obj_type == NodeType.DOMAIN or "domain" in str(req_obj_type)) else None,
    )
    graph.add_node(target_node)

    if subj_type in ("person", "user"):
        subj_node = GraphNode(
            id="node-subject-person",
            type=NodeType.PERSON,
            value=subj_val,
            status=NodeStatus.KNOWN,
            source="intent",
            field_role=FieldRole.PERSON_NAME,
        )
        acct_node = GraphNode(
            id="node-subject-account",
            type=NodeType.ACCOUNT,
            value="?",
            status=NodeStatus.UNKNOWN,
            source="intent",
            field_role=FieldRole.ACCOUNT_NAME,
        )
        endpoint_node = GraphNode(
            id="node-subject-endpoint",
            type=NodeType.ENDPOINT,
            value="?",
            status=NodeStatus.UNKNOWN,
            source="intent",
            field_role=FieldRole.ENDPOINT_HOST,
        )
        client_ip_node = GraphNode(
            id="node-subject-client-ip",
            type=NodeType.IP,
            value="?",
            status=NodeStatus.UNKNOWN,
            source="intent",
            field_role=FieldRole.CLIENT_IP,
        )

        for n in (subj_node, acct_node, endpoint_node, client_ip_node):
            graph.add_node(n)

        # 1. Person owns Account
        e1 = GraphEdge(
            id="edge-person-owns-account",
            source_id=subj_node.id,
            source_entity_type=NodeType.PERSON,
            relation_type=RelationType.OWNS,
            target_id=acct_node.id,
            target_entity_type=NodeType.ACCOUNT,
            required_field_roles={"source": FieldRole.PERSON_NAME, "target": FieldRole.ACCOUNT_NAME},
            acceptable_operations=["resolve_person_to_account"],
            status=RelationStatus.UNPROVEN,
        )
        # 2. Account logged on to Endpoint
        e2 = GraphEdge(
            id="edge-account-logon-endpoint",
            source_id=acct_node.id,
            source_entity_type=NodeType.ACCOUNT,
            relation_type=RelationType.LOGGED_ON_TO,
            target_id=endpoint_node.id,
            target_entity_type=NodeType.ENDPOINT,
            required_field_roles={"source": FieldRole.ACCOUNT_NAME, "target": FieldRole.ENDPOINT_HOST},
            acceptable_operations=["resolve_account_to_endpoint"],
            status=RelationStatus.UNPROVEN,
        )
        # 3. Endpoint assigned Client IP
        e3 = GraphEdge(
            id="edge-endpoint-assigned-ip",
            source_id=endpoint_node.id,
            source_entity_type=NodeType.ENDPOINT,
            relation_type=RelationType.ASSIGNED_IP,
            target_id=client_ip_node.id,
            target_entity_type=NodeType.IP,
            required_field_roles={"source": FieldRole.ENDPOINT_HOST, "target": FieldRole.CLIENT_IP},
            acceptable_operations=["resolve_endpoint_to_client_ip"],
            status=RelationStatus.UNPROVEN,
        )
        # 4. Client IP requested Target Object
        e4 = GraphEdge(
            id="edge-client-ip-requested-target",
            source_id=client_ip_node.id,
            source_entity_type=NodeType.IP,
            relation_type=RelationType.REQUESTED,
            target_id=target_node.id,
            target_entity_type=req_obj_type,
            required_field_roles={"source": FieldRole.CLIENT_IP, "target": FieldRole.DOMAIN_NAME},
            acceptable_operations=["find_web_activity_from_client_ip", "find_dns_activity_from_client_ip"],
            status=RelationStatus.UNPROVEN,
        )

        for e in (e1, e2, e3, e4):
            graph.add_edge(e)

        unknowns.extend([
            InvestigationUnknown(
                id="unk-account",
                entity_type=NodeType.ACCOUNT,
                variable_name=f"account_for_{subj_val}",
                description=f"Identify account username for {subj_val}",
                resolving_edge_id=e1.id,
            ),
            InvestigationUnknown(
                id="unk-endpoint",
                entity_type=NodeType.ENDPOINT,
                variable_name=f"endpoint_for_{subj_val}",
                description=f"Identify workstation endpoint used by {subj_val}",
                resolving_edge_id=e2.id,
            ),
            InvestigationUnknown(
                id="unk-client-ip",
                entity_type=NodeType.IP,
                variable_name=f"client_ip_for_{subj_val}",
                description=f"Identify client IP address assigned to {subj_val}'s endpoint",
                resolving_edge_id=e3.id,
            ),
            InvestigationUnknown(
                id="unk-target-object",
                entity_type=req_obj_type,
                variable_name=f"target_{req_obj_type}",
                description=f"Identify target {req_obj_type} requested by {subj_val}",
                resolving_edge_id=e4.id,
            ),
        ])

        goals.extend([
            EvidenceGoal(id="goal-acct", target_edge_id=e1.id, description=f"Resolve account for {subj_val}"),
            EvidenceGoal(id="goal-endpoint", target_edge_id=e2.id, description=f"Resolve endpoint for {subj_val}"),
            EvidenceGoal(id="goal-ip", target_edge_id=e3.id, description=f"Resolve client IP for {subj_val}"),
            EvidenceGoal(id="goal-target", target_edge_id=e4.id, description=f"Verify target {req_obj_type} activity"),
        ])
    else:
        subj_node = GraphNode(
            id="node-subject-entity",
            type=subj_type,
            value=subj_val,
            status=NodeStatus.KNOWN,
            source="intent",
        )
        graph.add_node(subj_node)
        e1 = GraphEdge(
            id="edge-subject-to-target",
            source_id=subj_node.id,
            source_entity_type=subj_type,
            relation_type=RelationType.CONNECTED_TO,
            target_id=target_node.id,
            target_entity_type=req_obj_type,
            status=RelationStatus.UNPROVEN,
        )
        graph.add_edge(e1)
        unknowns.append(
            InvestigationUnknown(
                id="unk-target-activity",
                entity_type=req_obj_type,
                variable_name=f"activity_{req_obj_type}",
                description=f"Activity connecting {subj_val} to {req_obj_type}",
                resolving_edge_id=e1.id,
            )
        )
        goals.append(
            EvidenceGoal(id="goal-activity", target_edge_id=e1.id, description=f"Verify activity for {subj_val}")
        )

    all_edge_ids = list(graph.edges.keys())
    for h in hypotheses:
        if not getattr(h, "required_edge_ids", None):
            h.required_edge_ids = list(all_edge_ids)
        claims.append({
            "claim_id": h.id,
            "statement": h.statement,
            "hypothesis_class": getattr(h, "hypothesis_class", "unclassified"),
            "required_edge_ids": list(h.required_edge_ids),
        })

    return InvestigationCase(
        id=f"case-{getattr(intent, 'original_request', '')[:20].strip() or '1'}",
        request_content=getattr(intent, "original_request", ""),
        question=getattr(intent, "question", ""),
        graph=graph,
        claims=claims,
        unknowns=unknowns,
        evidence_goals=goals,
        acceptance_criteria=[
            {"criterion": f"Causal relation path to {req_obj_type} verified with audit citations."}
        ],
        status="READY_FOR_DISCOVERY",
    )
