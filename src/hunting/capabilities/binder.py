"""Relation-First Capability Binder (v5.0).

Binds unresolved relations in the InvestigationCaseGraph to provider-neutral
logical operations and compiles them to native provider queries (Splunk, CDB).
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.case_graph import (
    ActionCandidate,
    GraphEdge,
    GraphNode,
)


class CapabilityBinder:
    """Binds unresolved relations to logical provider operations."""

    SUPPORTED_OPERATIONS = (
        "resolve_person_to_account",
        "resolve_account_to_endpoint",
        "resolve_endpoint_to_client_ip",
        "find_web_activity_from_client_ip",
        "find_dns_activity_from_client_ip",
        "find_process_from_endpoint",
        "find_file_change_from_process",
    )

    def identify_operation_for_edge(self, edge: GraphEdge, source_node: GraphNode, target_node: GraphNode) -> str | None:
        """Determine the logical operation required to prove or resolve an edge."""
        src_t = source_node.type if isinstance(source_node.type, str) else source_node.type.value
        tgt_t = target_node.type if isinstance(target_node.type, str) else target_node.type.value
        rel_t = edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value

        # 1. Person -> Account
        if src_t == "person" and tgt_t == "account":
            return "resolve_person_to_account"

        # 2. Account/Person -> Endpoint
        if src_t in ("person", "account") and tgt_t in ("endpoint", "host"):
            return "resolve_account_to_endpoint"

        # 3. Endpoint -> IP
        if src_t in ("endpoint", "host") and tgt_t == "ip":
            return "resolve_endpoint_to_client_ip"

        # 4. IP -> Domain / Web / Request
        if src_t == "ip" and tgt_t in ("domain", "event", "software"):
            if rel_t in ("requested", "accessed", "communicated_with"):
                return "find_web_activity_from_client_ip"
            if rel_t in ("resolved_to", "query"):
                return "find_dns_activity_from_client_ip"
            return "find_web_activity_from_client_ip"

        # 5. Endpoint -> Process
        if src_t in ("endpoint", "host") and tgt_t == "process":
            return "find_process_from_endpoint"

        # 6. Process -> File
        if src_t == "process" and tgt_t == "file":
            return "find_file_change_from_process"

        # Fallback to acceptable operations on edge if defined
        if edge.acceptable_operations:
            return edge.acceptable_operations[0]

        return None

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

        # Priority calculation: entity resolution is priority 1 (highest), activity queries priority 2
        priority = 1 if op_name in ("resolve_person_to_account", "resolve_account_to_endpoint", "resolve_endpoint_to_client_ip") else 2

        return ActionCandidate(
            operation_name=op_name,
            target_edge_id=edge.id,
            bound_source_node_id=source_node.id,
            bound_source_value=source_node.value,
            parameters=params,
            priority=priority,
            reason=f"Prove relation {source_node.value} -[{edge.relation_type}]-> {target_node.value or '?'}",
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
                # Search Active Directory / Windows Security for account matching person name
                first_name = clean_val.split()[0] if clean_val else clean_val
                return (
                    f'search index="{index}" sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625) '
                    f'("{clean_val}" OR TargetUserName="*{first_name}*") '
                    f'| head {limit} '
                    f'| table _time, host, ComputerName, TargetUserName, user, IpAddress, WorkstationName, LogonType, _raw'
                )

            if op == "resolve_account_to_endpoint":
                first_name = clean_val.split()[0] if clean_val else clean_val
                return (
                    f'search index="{index}" sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625) '
                    f'(TargetUserName="*{clean_val}*" OR TargetUserName="*{first_name}*" OR user="*{clean_val}*" OR "{clean_val}") '
                    f'| head {limit} '
                    f'| table _time, host, ComputerName, TargetUserName, user, IpAddress, WorkstationName, LogonType, _raw'
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
            if op == "resolve_endpoint_to_client_ip":
                return f"SELECT * FROM events WHERE (host LIKE '%{clean_val}%' OR ip LIKE '%{clean_val}%') LIMIT {limit}"
            if op == "find_web_activity_from_client_ip":
                return f"SELECT * FROM events WHERE event_type = 'web' AND (source_ip = '{clean_val}' OR ip = '{clean_val}') LIMIT {limit}"
            if op == "find_dns_activity_from_client_ip":
                return f"SELECT * FROM events WHERE event_type = 'dns' AND (source_ip = '{clean_val}' OR ip = '{clean_val}') LIMIT {limit}"
            return f"SELECT * FROM events WHERE host = '{clean_val}' OR user = '{clean_val}' LIMIT {limit}"

        return f"-- Provider {provider_id} query for {op} on {clean_val}"
