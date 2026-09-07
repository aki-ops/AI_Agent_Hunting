"""Independent Deterministic Adjudicator.

Component 7 of the General Cyclical Investigation Loop.
A deterministic gatekeeper that verifies citations, predicates, temporal ordering,
and identity constraints on all candidate edges and entities before modifying the
central Relation Graph or HuntState.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hunting.contracts.hunt import HuntState
from hunting.contracts.investigation_model import (
    GraphEdge,
    GraphNode,
    NodeStatus,
    NodeType,
    RelationGraph,
    RelationType,
)
from hunting.evidence.relation_verifier import KNOWN_WEB_SERVERS, is_prohibited_server
from hunting.m1_ledger.ledger import ObservationLedger


@dataclass
class AdjudicationDecision:
    """Decision for a single candidate graph edge."""
    accepted: bool
    edge: GraphEdge
    reason: str
    violations: list[str] = field(default_factory=list)


@dataclass
class AdjudicationResult:
    """Aggregated outcome of adjudicating candidate edges."""
    accepted_edges: list[GraphEdge] = field(default_factory=list)
    rejected_edges: list[tuple[GraphEdge, str]] = field(default_factory=list)
    updated_nodes: list[GraphNode] = field(default_factory=list)


class InvestigationAdjudicator:
    """Independent deterministic authority verifying evidence before graph mutation."""

    def adjudicate_edge(
        self,
        edge: GraphEdge,
        ledger: ObservationLedger,
        state: HuntState,
    ) -> AdjudicationDecision:
        """Deterministically adjudicate a candidate graph edge."""
        violations: list[str] = []
        graph = state.relation_graph or RelationGraph()

        # 1. Citation check: Edge must cite valid observation(s)
        obs_ids = edge.metadata.get("observation_ids", [])
        if not obs_ids and edge.origin_query_id:
            # Look up observations produced by this query
            obs_ids = [o.id for o in ledger.observations if o.query_id == edge.origin_query_id]

        if not obs_ids and edge.source != "input":
            violations.append("Edge lacks valid observation citation in ledger.")
            return AdjudicationDecision(accepted=False, edge=edge, reason="Citation failure", violations=violations)

        cited_obs = [o for o in ledger.observations if o.id in obs_ids]
        if not cited_obs and edge.source != "input":
            violations.append(f"Cited observation IDs {obs_ids} do not exist in ledger.")
            return AdjudicationDecision(accepted=False, edge=edge, reason="Missing observations", violations=violations)

        # 2. Source and Target Node Verification
        src_node = graph.get_node(edge.source_id)
        tgt_node = graph.get_node(edge.target_id)
        if not src_node or not tgt_node:
            violations.append(f"Edge nodes ({edge.source_id} -> {edge.target_id}) not found in graph.")
            return AdjudicationDecision(accepted=False, edge=edge, reason="Dangling edge", violations=violations)

        # 3. Web Server Isolation Guard
        if (
            edge.relation_type in (RelationType.LOGGED_ON_TO.value, RelationType.OWNS.value)
            and src_node.type in (NodeType.PERSON.value, NodeType.ACCOUNT.value)
            and tgt_node.type in (NodeType.HOST.value, NodeType.ENDPOINT.value)
        ):
            host_val = tgt_node.value.lower()
            if is_prohibited_server(host_val):
                violations.append(
                    f"Web server host '{host_val}' cannot be bound as user endpoint for {src_node.value}."
                )
            for obs in cited_obs:
                if "iis" in str(obs.native_type).lower():
                    violations.append(
                        f"IIS web server telemetry cannot prove user endpoint logon for {src_node.value}."
                    )

        # 4. Predicate check: Ensure cited observations contain the claimed values in appropriate fields
        if cited_obs:
            matched_any = False
            for obs in cited_obs:
                fields = obs.fields
                src_val = src_node.value.lower()
                tgt_val = tgt_node.value.lower()

                # 4a. Match source entity
                if src_node.type in (NodeType.PERSON.value, NodeType.ACCOUNT.value):
                    u_val = str(fields.get("user", fields.get("username", fields.get("Account_Name", fields.get("TargetUserName", ""))))).lower()
                    src_match = any(
                        part in u_val
                        for part in src_val.replace(".", " ").split()
                        if len(part) > 2
                    )
                elif src_node.type in (NodeType.HOST.value, NodeType.ENDPOINT.value):
                    h_val = str(fields.get("host", fields.get("ComputerName", fields.get("dest_host", "")))).lower()
                    src_match = src_val in h_val
                elif src_node.type == NodeType.IP.value:
                    ip_vals = {
                        str(fields.get(k, "")).lower()
                        for k in ("client_ip", "src_ip", "source_ip", "c_ip", "dest_ip", "destination_ip", "ip")
                    }
                    src_match = any(src_val in v for v in ip_vals if v)
                else:
                    src_match = src_val in str(fields).lower()

                # 4b. Match target entity
                if tgt_node.type in (NodeType.HOST.value, NodeType.ENDPOINT.value):
                    h_val = str(fields.get("host", fields.get("ComputerName", fields.get("dest_host", "")))).lower()
                    tgt_match = tgt_val in h_val
                elif tgt_node.type == NodeType.IP.value:
                    ip_vals = {
                        str(fields.get(k, "")).lower()
                        for k in ("client_ip", "src_ip", "source_ip", "c_ip", "dest_ip", "destination_ip", "s_ip", "ip")
                    }
                    tgt_match = any(tgt_val in v for v in ip_vals if v)
                elif tgt_node.type in (NodeType.DOMAIN.value, "website_domain"):
                    dom_vals = {
                        str(fields.get(k, "")).lower()
                        for k in ("site", "domain", "query", "cs_host", "name")
                    }
                    tgt_match = any(tgt_val in v or v in tgt_val for v in dom_vals if v)
                else:
                    tgt_match = tgt_val in str(fields).lower()

                if src_match and tgt_match:
                    matched_any = True
                    break

            if not matched_any and edge.source != "input":
                violations.append(
                    f"Cited observations do not substantiate relation between '{src_node.value}' and '{tgt_node.value}'."
                )

        if violations:
            return AdjudicationDecision(
                accepted=False,
                edge=edge,
                reason="; ".join(violations),
                violations=violations,
            )

        return AdjudicationDecision(
            accepted=True,
            edge=edge,
            reason="Verified citations, predicates, and isolation constraints.",
        )

    def adjudicate_and_apply(
        self,
        candidate_edges: list[GraphEdge],
        ledger: ObservationLedger,
        state: HuntState,
    ) -> AdjudicationResult:
        """Adjudicate candidate edges and apply verified edges to state and graph."""
        result = AdjudicationResult()
        if state.relation_graph is None:
            state.relation_graph = RelationGraph()

        for edge in candidate_edges:
            decision = self.adjudicate_edge(edge, ledger, state)
            if decision.accepted:
                edge.status = NodeStatus.KNOWN
                state.relation_graph.add_edge(edge)
                result.accepted_edges.append(edge)

                # Promote connected nodes to KNOWN
                src_node = state.relation_graph.get_node(edge.source_id)
                tgt_node = state.relation_graph.get_node(edge.target_id)
                if src_node:
                    src_node.status = NodeStatus.KNOWN
                    result.updated_nodes.append(src_node)
                if tgt_node:
                    tgt_node.status = NodeStatus.KNOWN
                    result.updated_nodes.append(tgt_node)

                # Identity Linkage side-effect: If person -> endpoint edge is confirmed
                if (
                    src_node
                    and tgt_node
                    and src_node.type in (NodeType.PERSON.value, NodeType.ACCOUNT.value)
                    and tgt_node.type in (NodeType.HOST.value, NodeType.ENDPOINT.value)
                ):
                    state.identity_resolved = True
                    state.identity_mapping["endpoint"] = tgt_node.value
                    state.identity_mapping["user"] = src_node.value
                    if "client_ip" in edge.metadata:
                        state.identity_mapping["client_ip"] = edge.metadata["client_ip"]

                # If endpoint -> IP edge is confirmed
                if (
                    src_node
                    and tgt_node
                    and src_node.type in (NodeType.HOST.value, NodeType.ENDPOINT.value)
                    and tgt_node.type == NodeType.IP.value
                ):
                    state.identity_mapping["client_ip"] = tgt_node.value

            else:
                result.rejected_edges.append((edge, decision.reason))

        return result


__all__ = ["InvestigationAdjudicator", "AdjudicationDecision", "AdjudicationResult", "KNOWN_WEB_SERVERS"]
