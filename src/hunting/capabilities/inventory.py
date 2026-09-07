"""Runtime Source Inventory (v5.1).

Introspects live provider metadata and event schemas (Splunk sourcetypes, SQLite tables)
to dynamically determine which native telemetry sources can fulfill semantic capability proposals.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from hunting.contracts.case_graph import FieldRole
from hunting.contracts.semantic_intent import SemanticCapabilityProposal

logger = logging.getLogger(__name__)


@dataclass
class SourceSchema:
    """Schema descriptor for a native telemetry source (sourcetype, table, stream)."""
    source_name: str
    event_count: int = 0
    available_fields: set[str] = field(default_factory=set)
    sample_values: dict[str, Any] = field(default_factory=dict)
    field_role_mappings: dict[str, str] = field(default_factory=dict)


class RuntimeSourceInventory:
    """Discovers and caches available provider telemetry sources and their field schemas."""

    # Default candidate field aliases for semantic roles
    ROLE_FIELD_CANDIDATES: dict[str, list[str]] = {
        FieldRole.SENDER_EMAIL.value: ["sender_email", "sender", "from", "from_email", "src_user"],
        FieldRole.RECIPIENT_EMAIL.value: ["receiver_email", "receiver", "to", "recipient", "recipients", "destination_user"],
        FieldRole.MESSAGE_ID.value: ["msg_id", "message_id", "messageid", "internetmessageid"],
        FieldRole.SUBJECT.value: ["subject", "email_subject"],
        FieldRole.CLIENT_IP.value: ["src_ip", "client_ip", "c_ip", "source_ip", "IpAddress"],
        FieldRole.SERVER_IP.value: ["dest_ip", "server_ip", "s_ip", "destination_ip"],
        FieldRole.ENDPOINT_HOST.value: ["host", "ComputerName", "workstation_name", "endpoint"],
        FieldRole.ACCOUNT_NAME.value: ["TargetUserName", "user", "Account_Name", "account", "username"],
        FieldRole.PERSON_NAME.value: ["displayName", "FullName", "person", "user"],
        FieldRole.DOMAIN_NAME.value: ["site", "cs_host", "domain", "query"],
        FieldRole.URI_PATH.value: ["uri", "cs_uri_stem", "url"],
        FieldRole.PROCESS_NAME.value: ["Image", "process_name", "process"],
        FieldRole.FILE_PATH.value: ["TargetFilename", "file_path", "filename"],
        FieldRole.ROLE_NAME.value: ["role", "title", "job_title", "department"],
    }

    def __init__(self, provider_id: str = "splunk", index: str = "botsv2") -> None:
        self.provider_id = provider_id
        self.index = index
        self.sources: dict[str, SourceSchema] = {}
        self._initialize_known_baselines()

    def _initialize_known_baselines(self) -> None:
        """Seed known native telemetry schemas from standard provider capabilities."""
        # stream:smtp in Splunk
        self.register_source(
            SourceSchema(
                source_name="stream:smtp",
                event_count=600000,
                available_fields={
                    "sender", "sender_email", "receiver", "receiver_email",
                    "subject", "msg_id", "src_ip", "dest_ip", "timestamp", "content",
                },
                field_role_mappings={
                    FieldRole.SENDER_EMAIL.value: "sender_email",
                    FieldRole.RECIPIENT_EMAIL.value: "receiver_email",
                    FieldRole.MESSAGE_ID.value: "msg_id",
                    FieldRole.SUBJECT.value: "subject",
                    FieldRole.CLIENT_IP.value: "src_ip",
                    FieldRole.SERVER_IP.value: "dest_ip",
                },
            )
        )
        # ms:o365:management
        self.register_source(
            SourceSchema(
                source_name="ms:o365:management",
                event_count=4000,
                available_fields={"UserId", "Operation", "CreationTime", "ClientIP", "MessageId", "Recipients"},
                field_role_mappings={
                    FieldRole.ACCOUNT_NAME.value: "UserId",
                    FieldRole.SENDER_EMAIL.value: "UserId",
                    FieldRole.CLIENT_IP.value: "ClientIP",
                    FieldRole.MESSAGE_ID.value: "MessageId",
                },
            )
        )
        # WinEventLog:Security
        self.register_source(
            SourceSchema(
                source_name="WinEventLog:Security",
                event_count=500000,
                available_fields={"EventCode", "TargetUserName", "user", "ComputerName", "host", "IpAddress", "WorkstationName"},
                field_role_mappings={
                    FieldRole.ACCOUNT_NAME.value: "TargetUserName",
                    FieldRole.ENDPOINT_HOST.value: "ComputerName",
                    FieldRole.CLIENT_IP.value: "IpAddress",
                },
            )
        )
        # stream:http
        self.register_source(
            SourceSchema(
                source_name="stream:http",
                event_count=1000000,
                available_fields={"src_ip", "dest_ip", "c_ip", "s_ip", "site", "cs_host", "uri", "status", "http_method"},
                field_role_mappings={
                    FieldRole.CLIENT_IP.value: "c_ip",
                    FieldRole.SERVER_IP.value: "s_ip",
                    FieldRole.DOMAIN_NAME.value: "site",
                    FieldRole.URI_PATH.value: "uri",
                },
            )
        )
        # stream:dns
        self.register_source(
            SourceSchema(
                source_name="stream:dns",
                event_count=1000000,
                available_fields={"src_ip", "dest_ip", "query", "domain", "record_type", "response"},
                field_role_mappings={
                    FieldRole.CLIENT_IP.value: "src_ip",
                    FieldRole.SERVER_IP.value: "dest_ip",
                    FieldRole.DOMAIN_NAME.value: "query",
                },
            )
        )

    def introspect_provider(self, adapter: Any) -> None:
        """Dynamically discover provider sources and update schemas from live adapter."""
        if hasattr(adapter, "discovered_sourcetypes") and adapter.discovered_sourcetypes:
            for st, count in adapter.discovered_sourcetypes.items():
                if st in self.sources:
                    self.sources[st].event_count = count
                else:
                    schema = SourceSchema(
                        source_name=st,
                        event_count=count,
                        available_fields=set(),
                        field_role_mappings={},
                    )
                    self.register_source(schema)

    def register_source(self, schema: SourceSchema) -> None:
        """Register or update a source schema in the inventory."""
        self.sources[schema.source_name] = schema

    def match_capability_proposal(
        self,
        proposal: SemanticCapabilityProposal,
    ) -> tuple[str, SourceSchema | None, dict[str, str]]:
        """Match a capability proposal against discovered sources.

        Returns:
            (status, matched_schema, field_bindings)
            where status is one of:
            - 'BOUND': matched source with all required roles
            - 'UNOBSERVABLE': candidate source found but missing required roles
            - 'UNSUPPORTED': no candidate source found in provider inventory
        """
        required = [str(r).lower() for r in proposal.required_roles]

        best_source: SourceSchema | None = None
        best_bindings: dict[str, str] = {}
        best_match_count = 0

        for source_name, schema in self.sources.items():
            bindings: dict[str, str] = {}
            for role in required:
                # 1. Check direct field role mappings
                if role in schema.field_role_mappings:
                    bindings[role] = schema.field_role_mappings[role]
                    continue

                # 2. Check candidate field names in schema.available_fields
                candidates = self.ROLE_FIELD_CANDIDATES.get(role, [role])
                for cand in candidates:
                    if cand.lower() in {f.lower() for f in schema.available_fields}:
                        bindings[role] = cand
                        break

            matched_count = len(bindings)
            if matched_count > best_match_count:
                best_match_count = matched_count
                best_source = schema
                best_bindings = bindings

        if not best_source or best_match_count == 0:
            return "UNSUPPORTED", None, {}

        if best_match_count == len(required):
            return "BOUND", best_source, best_bindings

        # Candidate found but missing required roles
        return "UNOBSERVABLE", best_source, best_bindings
