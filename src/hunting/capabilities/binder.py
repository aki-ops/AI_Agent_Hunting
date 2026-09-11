"""Claim/capability binder.

Binds unresolved claim/evidence edges to provider-neutral logical operations.
The v6 path uses the runtime CapabilityGraph first; the legacy edge mapping is
kept only as a compatibility fallback for older structured tests.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.capabilities import CapabilityGraph
from hunting.contracts.case_graph import (
    ActionCandidate,
    GraphEdge,
    GraphNode,
)


class CapabilityBinder:
    """Binds unresolved relations to logical provider operations."""

    def __init__(
        self,
        capability_graph: CapabilityGraph | None = None,
        provider_id: str | None = None,
    ) -> None:
        self.capability_graph = capability_graph
        self.provider_id = provider_id

    def set_capability_graph(
        self,
        capability_graph: CapabilityGraph | None,
        provider_id: str | None = None,
    ) -> None:
        """Attach the current provider census for claim-driven binding."""
        self.capability_graph = capability_graph
        if provider_id is not None:
            self.provider_id = provider_id

    SUPPORTED_OPERATIONS = (
        "resolve_person_to_account",
        "resolve_person_to_endpoint",
        "resolve_account_to_endpoint",
        "resolve_endpoint_to_client_ip",
        "find_web_activity_from_client_ip",
        "find_dns_activity_from_client_ip",
        "find_web_activity_from_endpoint",
        "find_process_from_endpoint",
        "find_file_change_from_endpoint",
        "find_file_change_from_process",
        "resolve_account_to_email",
        "find_outbound_message_metadata",
        "resolve_recipient_identity",
        "resolve_role_identity",
    )

    def identify_operation_for_edge(self, edge: GraphEdge, source_node: GraphNode, target_node: GraphNode) -> str | None:
        """Determine the logical operation required to prove or resolve an edge."""
        generic = self._identify_from_capability_graph(edge, source_node)
        if generic:
            return generic

        src_t = source_node.type if isinstance(source_node.type, str) else source_node.type.value
        tgt_t = target_node.type if isinstance(target_node.type, str) else target_node.type.value
        rel_t = edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value

        # 1. Person -> Account
        if src_t == "person" and tgt_t == "account":
            return "resolve_person_to_account"

        # 2. Account -> Email Address
        if (src_t == "account" and tgt_t == "email_address") or rel_t == "has_email":
            return "resolve_account_to_email"

        # 3. Email Address -> Outbound Message
        if (src_t == "email_address" and tgt_t == "message") or rel_t == "sent_message":
            return "find_outbound_message_metadata"

        # 4. Message -> Recipient Email / Identity
        if (src_t == "message" and tgt_t in ("email_address", "person")) or rel_t == "received_message":
            return "resolve_recipient_identity"

        # 5. Recipient Email -> Role / Executive Identity
        if (src_t in ("email_address", "person") and tgt_t == "role") or rel_t == "holds_role":
            return "resolve_role_identity"

        # 6. Account/Person -> Endpoint
        if src_t == "person" and tgt_t in ("endpoint", "host"):
            return "resolve_person_to_endpoint"

        if src_t == "account" and tgt_t in ("endpoint", "host"):
            return "resolve_account_to_endpoint"

        # 7. Endpoint -> IP
        if src_t in ("endpoint", "host") and tgt_t == "ip":
            return "resolve_endpoint_to_client_ip"

        # 8. IP -> Domain / Web / Request
        if src_t == "ip" and tgt_t in ("domain", "event", "software"):
            if rel_t in ("requested", "accessed", "communicated_with"):
                return "find_web_activity_from_client_ip"
            if rel_t in ("resolved_to", "query"):
                return "find_dns_activity_from_client_ip"
            return "find_web_activity_from_client_ip"

        # 9. Endpoint -> Process
        if src_t in ("endpoint", "host") and tgt_t == "process":
            return "find_process_from_endpoint"

        # 10. Process -> File
        if src_t == "process" and tgt_t == "file":
            return "find_file_change_from_process"

        # Artifact requirements may be anchored directly to an endpoint when
        # no process identifier is known yet.  This is deliberately separate
        # from process -> file: the planner must not invent a process pivot.
        if src_t in ("endpoint", "host") and tgt_t in (
            "file", "file_artifact", "software", "software_version", "application", "version", "process", "process_name",
        ):
            if edge.acceptable_operations:
                return edge.acceptable_operations[0]
            if rel_t in ("modified", "wrote"):
                return "find_file_change_from_endpoint"
            return "find_process_from_endpoint"

        if src_t in ("endpoint", "host") and tgt_t == "event":
            return edge.acceptable_operations[0] if edge.acceptable_operations else "find_web_activity_from_endpoint"

        # Fallback to acceptable operations on edge if defined
        if edge.acceptable_operations:
            return edge.acceptable_operations[0]

        return None

    def _identify_from_capability_graph(
        self,
        edge: GraphEdge,
        source_node: GraphNode,
    ) -> str | None:
        """Select an operation from declared claim evidence contracts.

        This method deliberately knows nothing about email, Tor, CVE or any
        other scenario. It matches the edge's provider-neutral fact kinds and
        the source node's typed input against live capabilities.
        """
        graph = self.capability_graph
        if graph is None:
            return None

        source_type = str(
            source_node.type.value if hasattr(source_node.type, "value") else source_node.type
        ).strip().lower()
        fact_kinds = {
            str(value).strip().lower()
            for value in edge.acceptance_predicate.get("fact_kinds", [])
            if str(value).strip()
        }
        required_roles = {
            str(value).strip().lower()
            for value in edge.acceptance_predicate.get("required_roles", [])
            if str(value).strip()
        }
        target_type = str(
            edge.target_entity_type.value
            if hasattr(edge.target_entity_type, "value")
            else edge.target_entity_type
        ).strip().lower()
        explicit = {str(value).strip() for value in edge.acceptable_operations if str(value).strip()}
        candidates = []
        for operation in graph.operations:
            if self.provider_id and operation.provider_id != self.provider_id:
                continue
            if explicit and operation.id not in explicit:
                continue
            outputs = {str(value).strip().lower() for value in operation.output_fact_kinds}
            if fact_kinds and not fact_kinds.intersection(outputs):
                continue
            inputs = {str(value).strip().lower() for value in operation.input_entity_kinds}
            if inputs and "any" not in inputs and source_type not in inputs:
                continue
            candidates.append(operation)

        if not candidates:
            return None
        role_aware = bool(required_roles) and any(operation.output_roles for operation in candidates)
        scored = []
        for operation in candidates:
            role_overlap = required_roles.intersection(
                {str(value).strip().lower() for value in operation.output_roles}
            )
            typed_output_match = target_type in {
                str(value).strip().lower() for value in operation.output_entity_kinds
            }
            if role_aware and not role_overlap and not typed_output_match:
                continue
            scored.append((operation, len(role_overlap) + (1 if typed_output_match else 0)))
        if not scored:
            return None
        scored.sort(key=lambda item: (-item[1], item[0].expected_cost is None, item[0].expected_cost or 0, item[0].id))
        return scored[0][0].id

    def create_candidate(
        self,
        edge: GraphEdge,
        source_node: GraphNode,
        target_node: GraphNode,
        parameters: dict[str, Any] | None = None,
    ) -> ActionCandidate | None:
        """Create a candidate action for an actionable unproven edge."""
        op_name = self.identify_operation_for_edge(edge, source_node, target_node)
        if not op_name:
            return None

        params = dict(parameters or {})
        params["source_node_id"] = source_node.id
        params["source_value"] = source_node.value
        params["source_type"] = source_node.type if isinstance(source_node.type, str) else source_node.type.value
        params["target_node_id"] = target_node.id
        params["target_type"] = target_node.type if isinstance(target_node.type, str) else target_node.type.value
        params["relation_type"] = edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value

        # The claim graph, not the provider operation name, defines whether an
        # edge is a prerequisite.  This keeps execution generic when a provider
        # calls the same capability ``lookup_7`` or exposes a completely new
        # operation.  The name-based ranking remains only for the legacy
        # compatibility path where no runtime capability graph was published.
        if self.capability_graph is not None:
            priority = 1 if bool(edge.metadata.get("is_prerequisite", False)) else 2
        elif op_name in (
            "resolve_person_to_account",
            "resolve_person_to_endpoint",
            "resolve_account_to_email",
            "resolve_account_to_endpoint",
            "resolve_endpoint_to_client_ip",
        ):
            priority = 1
        elif op_name in ("resolve_recipient_identity", "resolve_role_identity"):
            priority = 3
        else:
            priority = 2

        capability_diagnostics: dict[str, Any] = {
            "provider_id": self.provider_id or "legacy",
            "claim_id": edge.metadata.get("claim_id", ""),
            "fact_kinds": list(edge.acceptance_predicate.get("fact_kinds", [])),
        }
        completeness = ""
        expected_cost: int | None = None
        if self.capability_graph is not None:
            operation = next(
                (
                    item for item in self.capability_graph.operations
                    if item.id == op_name and (not self.provider_id or item.provider_id == self.provider_id)
                ),
                None,
            )
            if operation is not None:
                completeness = operation.completeness or operation.limit_semantics
                expected_cost = operation.expected_cost
                capability_diagnostics.update({
                    "input_entity_kinds": list(operation.input_entity_kinds),
                    "output_fact_kinds": list(operation.output_fact_kinds),
                    "output_entity_kinds": list(operation.output_entity_kinds),
                    "output_fields": list(operation.output_fields),
                    "input_roles": list(operation.input_roles),
                    "output_roles": list(operation.output_roles),
                    "native_field_bindings": {
                        name: list(values)
                        for name, values in operation.native_field_bindings.items()
                    },
                    "query_builder": operation.query_builder,
                })

        return ActionCandidate(
            operation_name=op_name,
            target_edge_id=edge.id,
            bound_source_node_id=source_node.id,
            bound_source_value=source_node.value,
            parameters=params,
            priority=priority,
            reason=f"Prove relation {source_node.value} -[{edge.relation_type}]-> {target_node.value or '?'}",
            relevance=1.0,
            completeness=completeness,
            expected_cost=expected_cost,
            diagnostics=capability_diagnostics,
        )

    def compile_operation_query(
        self,
        candidate: ActionCandidate,
        provider_id: str = "splunk",
        index: str = "botsv2",
        limit: int = 101,
    ) -> str:
        """Compile a logical candidate action into a parameterized native query."""
        op = candidate.operation_name
        src_val = candidate.bound_source_value
        clean_val = src_val.replace('"', '').strip()

        if provider_id == "splunk":
            if op == "resolve_person_to_account":
                # Identity discovery is intentionally provider-native but
                # source-agnostic.  Do not assume SMTP/LDAP/Security: a
                # person may appear in EDR, SMB, file, endpoint or any other
                # indexed telemetry.  Only explicit identity fields may be
                # bound as an account.
                return (
                    f'search index="{index}" "{clean_val}" '
                    f'| rex field=_raw "New Logon:[\\s\\S]*?Account Name:\\s*(?<TargetUserName>[^\\r\\n\\s]+)" '
                    f'| rex field=_raw "Account Name:\\s*(?<user>[^\\r\\n\\s]+)" '
                    f'| eval _account_candidate=coalesce(TargetUserName,user,Account_Name,account,username,src_user) '
                    f'| where isnotnull(_account_candidate) AND _account_candidate!="" AND _account_candidate!="-" '
                    f'| dedup _account_candidate | head {limit + 1} '
                    f'| rename _account_candidate as user '
                    f'| table _time, user, host, ComputerName, sourcetype'
                )

            if op == "resolve_account_to_email":
                # Resolve account username to associated email address
                prefix = clean_val.split('@')[0].split('.')[0] if '.' in clean_val else clean_val
                return (
                    f'search index="{index}" (sourcetype="stream:smtp" OR sourcetype="WinEventLog:Security") '
                    f'("{clean_val}" OR "{prefix}*@*" OR "*{clean_val}*") '
                    f'| head {limit} '
                    f'| table _time, host, TargetUserName, user, sender, sender_email, receiver, receiver_email, _raw'
                )

            if op == "find_outbound_message_metadata":
                # Search SMTP streams for outbound email sent by this identity
                eff_limit = max(limit, 500)
                return (
                    f'search index="{index}" sourcetype="stream:smtp" '
                    f'(sender="*{clean_val}*" OR sender_email="*{clean_val}*" OR "{clean_val}") '
                    f'| head {eff_limit} '
                    f'| table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, src_ip, dest_ip, _raw'
                )

            if op == "resolve_recipient_identity":
                # Extract and verify the recipient identity from message metadata
                return (
                    f'search index="{index}" sourcetype="stream:smtp" '
                    f'(msg_id="{clean_val}" OR message_id="{clean_val}" OR "{clean_val}") '
                    f'| head {limit} '
                    f'| table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, _raw'
                )

            if op == "resolve_role_identity":
                # Verify recipient corporate role or executive title
                return (
                    f'search index="{index}" (sourcetype="*active_directory*" OR sourcetype="*ldap*" OR sourcetype="stream:ldap") '
                    f'("{clean_val}") '
                    f'| head {limit} '
                    f'| table _time, host, sender, receiver, subject, title, role, department, _raw'
                )

            if op in ("resolve_person_to_endpoint", "resolve_account_to_endpoint"):
                return (
                    f'search index="{index}" "{clean_val}" '
                    f'| rex field=_raw "Workstation Name:\\s*(?<WorkstationName>[^\\r\\n\\s]+)" '
                    f'| rex field=_raw "New Logon:[\\s\\S]*?Account Name:\\s*(?<TargetUserName>[^\\r\\n\\s]+)" '
                    f'| eval _host_candidate=coalesce(host,ComputerName) '
                    f'| where isnotnull(_host_candidate) AND _host_candidate!="" AND _host_candidate!="-" '
                    f'| dedup _host_candidate | head {limit + 1} '
                    f'| rename _host_candidate as host '
                    f'| table _time, host, ComputerName, TargetUserName, user, IpAddress, WorkstationName, LogonType, sourcetype'
                )

            if op == "resolve_endpoint_to_client_ip":
                return (
                    f'search index="{index}" (sourcetype="WinEventLog:Security" (host="*{clean_val}*" OR ComputerName="*{clean_val}*") EventCode=4624) '
                    f'OR (sourcetype="stream:dhcp" (host="*{clean_val}*" OR dest_mac!="")) '
                    f'| head {limit} '
                    f'| table _time, host, ComputerName, TargetUserName, IpAddress, src_ip, client_ip, c_ip, _raw'
                )

            if op == "find_web_activity_from_client_ip":
                return (
                    f'search index="{index}" (sourcetype="stream:http" OR sourcetype="pan:traffic") '
                    f'(src_ip="{clean_val}" OR client_ip="{clean_val}" OR c_ip="{clean_val}") '
                    f'| where isnotnull(uri) OR isnotnull(site) OR isnotnull(cs_host) '
                    f'| head {limit} '
                    f'| table _time, host, sourcetype, src_ip, dest_ip, site, cs_host, uri, cs_uri_stem, cs_method, status, _raw'
                )

            if op == "find_dns_activity_from_client_ip":
                return (
                    f'search index="{index}" (sourcetype="stream:dns" OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22)) '
                    f'(src_ip="{clean_val}" OR client_ip="{clean_val}" OR c_ip="{clean_val}") '
                    f'| head {limit} '
                    f'| table _time, host, sourcetype, src_ip, dest_ip, query, domain, site, cs_host, _raw'
                )

            if op == "find_process_from_endpoint":
                return (
                    f'search index="{index}" (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) '
                    f'(host="*{clean_val}*" OR ComputerName="*{clean_val}*") '
                    f'| head {limit} '
                    f'| table _time, host, ComputerName, Image, CommandLine, ParentImage, User, ProcessId, _raw'
                )

            if op == "find_file_change_from_endpoint":
                return (
                    f'search index="{index}" (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11) '
                    f'(host="*{clean_val}*" OR ComputerName="*{clean_val}*") '
                    f'| head {limit} '
                    f'| table _time, host, ComputerName, TargetFilename, Image, ProcessId, ProductVersion, FileVersion, Version, _raw'
                )

            if op == "find_file_change_from_process":
                return (
                    f'search index="{index}" (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11) '
                    f'(ProcessId="{clean_val}" OR Image="*{clean_val}*") '
                    f'| head {limit} '
                    f'| table _time, host, TargetFilename, Image, ProcessId, _raw'
                )

            # Fallback
            return f'search index="{index}" "{clean_val}" | head {limit}'

        elif provider_id == "cdb_sqlite":
            if op in ("resolve_person_to_account", "resolve_account_to_endpoint"):
                return f"SELECT * FROM events WHERE event_type = 'logon' AND (user LIKE '%{clean_val}%' OR host LIKE '%{clean_val}%') LIMIT {limit}"
            if op == "resolve_account_to_email":
                return f"SELECT * FROM events WHERE (user LIKE '%{clean_val}%' OR email LIKE '%{clean_val}%') LIMIT {limit}"
            if op == "find_outbound_message_metadata":
                return f"SELECT * FROM events WHERE event_type = 'email' AND (sender LIKE '%{clean_val}%' OR sender_email LIKE '%{clean_val}%') LIMIT {limit}"
            if op == "resolve_recipient_identity":
                return f"SELECT * FROM events WHERE event_type = 'email' AND (msg_id = '{clean_val}' OR receiver LIKE '%{clean_val}%') LIMIT {limit}"
            if op == "resolve_role_identity":
                return f"SELECT * FROM events WHERE (user LIKE '%{clean_val}%' OR role LIKE '%{clean_val}%') LIMIT {limit}"
            if op == "resolve_endpoint_to_client_ip":
                return f"SELECT * FROM events WHERE (host LIKE '%{clean_val}%' OR ip LIKE '%{clean_val}%') LIMIT {limit}"
            if op == "find_web_activity_from_client_ip":
                return f"SELECT * FROM events WHERE event_type = 'web' AND (source_ip = '{clean_val}' OR ip = '{clean_val}') LIMIT {limit}"
            if op == "find_dns_activity_from_client_ip":
                return f"SELECT * FROM events WHERE event_type = 'dns' AND (source_ip = '{clean_val}' OR ip = '{clean_val}') LIMIT {limit}"
            if op == "find_web_activity_from_endpoint":
                return f"SELECT * FROM events WHERE host LIKE '%{clean_val}%' AND (domain IS NOT NULL OR native_type LIKE '%http%' OR native_type LIKE '%web%') LIMIT {limit}"
            if op == "find_file_change_from_endpoint":
                return f"SELECT * FROM events WHERE host LIKE '%{clean_val}%' AND (file_path IS NOT NULL OR action LIKE '%write%' OR action LIKE '%create%') LIMIT {limit}"
            return f"SELECT * FROM events WHERE host = '{clean_val}' OR user = '{clean_val}' LIMIT {limit}"

        return f"-- Provider {provider_id} query for {op} on {clean_val}"
