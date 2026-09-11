"""Splunk Live Provider Adapter for Enterprise SIEM Telemetry.

Implements the production-grade M5 provider adapter for Splunk Enterprise:
  - Dual Binding Architecture:
      Mode 1: Dynamic Auto-Discovery (zero-config, introspects /services/data/indexes
              and | metadata type=sourcetypes).
      Mode 2: Declarative YAML Manifest (reads configs/splunk_botsv2.yaml with
              explicit sourcetypes, event filters, and search-time rex extractions).
  - Strict Completeness Contract (L+1 Rule): queries fetch limit + 1 internally
    to determine EOF vs truncation.
  - Negative Evidence Controls: ScopeHealthControl, AnyRecordInScope,
    and PredicateObservabilityControl.
  - Parameterized SPL generation preventing injection.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3
import yaml

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.contracts.capabilities import CapabilityDescriptor, ProviderCapabilityCatalog
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import (
    ANY,
    Account,
    AnyEntity,
    Domain,
    EntityRef,
    File,
    Host,
    IPAddress,
    Process,
)
from hunting.contracts.expectations import (
    EvidenceRequirement,
    FieldOp,
    FieldPredicate,
)
from hunting.contracts.native_query import NativeQueryCandidate
from hunting.contracts.queries import (
    CapabilityBinding,
    ControlResult,
    Diagnostic,
    ProviderOperation,
    QueryOutcome,
    QueryResult,
)
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile
from hunting.m5_adapter.allowlist import (
    validate_query_params,
    validate_time_window_format,
)
from hunting.m5_adapter.controls import (
    execute_any_record_in_scope,
    execute_predicate_observability_control,
    execute_scope_health_control,
)
from hunting.query_safety.native_query_gate import NativeQueryGate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

# Standard observable fields supported by SplunkLiveAdapter
OBSERVABLE_FIELDS = (
    "timestamp",
    "host",
    "user",
    "pid",
    "ppid",
    "cmdline",
    "image",
    "parent_image",
    "destination_ip",
    "destination_port",
    "source_ip",
    "source_port",
    "protocol",
    "file_path",
    "domain",
    "query",
    "logon_type",
    "status",
    "hash",
    "uri",
    "client_ip",
    "server_ip",
    "c_ip",
    "s_ip",
    "http_method",
    "method",
    "site",
    "cs_host",
    "sender",
    "sender_email",
    "receiver",
    "receiver_email",
    "subject",
    "msg_id",
    "message_id",
    "title",
    "role",
    "department",
)

SOURCETYPE_FIELD_ROLE_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "WinEventLog:Security": {
        "account_name": ["TargetUserName", "user", "Account_Name"],
        # BotSv2's Sysmon and process telemetry use Splunk's ``host`` as the
        # endpoint key.  ComputerName remains a retained alias, not the
        # primary binding value.
        "endpoint_host": ["host", "ComputerName", "workstation_name"],
        "client_ip": ["IpAddress"],
    },
    "stream:http": {
        "client_ip": ["src_ip", "c_ip", "client_ip"],
        "server_ip": ["dest_ip", "s_ip", "server_ip"],
        "domain_name": ["site", "cs_host", "domain"],
        "server_host": ["site", "cs_host"],
    },
    "stream:dns": {
        "client_ip": ["src_ip", "c_ip", "client_ip"],
        "server_ip": ["dest_ip", "s_ip", "server_ip"],
        "domain_name": ["query", "domain", "site"],
    },
    "iis": {
        "client_ip": ["c_ip"],
        "server_ip": ["s_ip"],
        "server_host": ["host", "cs_host"],
        "domain_name": ["cs_host", "site"],
    },
    "pan:traffic": {
        "client_ip": ["src_ip"],
        "server_ip": ["dest_ip"],
    },
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational": {
        "endpoint_host": ["host", "ComputerName"],
        "process_name": ["Image", "process_name"],
        "client_ip": ["SourceIp"],
        "server_ip": ["DestinationIp"],
    },
    "stream:smtp": {
        "sender_email": ["sender_email", "sender"],
        "recipient_email": ["receiver_email", "receiver"],
        "message_id": ["msg_id"],
        "subject": ["subject"],
        "client_ip": ["src_ip"],
        "server_ip": ["dest_ip"],
    },
    "ms:o365:management": {
        "account_name": ["UserId"],
        "sender_email": ["UserId"],
        "client_ip": ["ClientIP"],
        "message_id": ["MessageId"],
    },
}


class SplunkLiveAdapter:
    """Production live adapter querying Splunk REST API."""

    @classmethod
    def validate_field_role_against_sourcetype(
        cls,
        field_role: str,
        field_name: str,
        sourcetype: str,
    ) -> bool:
        """Validate whether field_name in sourcetype can legitimately fulfill the declared field_role.

        Prevents conflating server_ip/dest_ip with client_ip, or server host (IIS) with endpoint_host.
        """
        role_key = str(getattr(field_role, "value", field_role)).lower()
        f_clean = field_name.strip().lower()

        # Immediate hard rejection of known invalid conflations
        if role_key == "client_ip" and f_clean in ("dest_ip", "destination_ip", "server_ip", "s_ip"):
            return False
        if role_key == "endpoint_host" and ("iis" in sourcetype.lower() or f_clean in ("site", "domain")):
            return False

        for st_pattern, role_map in SOURCETYPE_FIELD_ROLE_MAPPINGS.items():
            if st_pattern.lower() in sourcetype.lower():
                allowed_fields = [f.lower() for f in role_map.get(role_key, [])]
                if allowed_fields:
                    return f_clean in allowed_fields

        # Default fallback: allow if not an explicitly blocked conflation
        return True

    def __init__(
        self,
        splunk_url: str = "https://localhost:8089",
        auth: tuple[str, str] = ("admin", "12345678"),
        index: str = "botsv2",
        manifest_path: str | Path | None = None,
        verify_ssl: bool = False,
        timeout: int = 60,
        profile_source_limit: int | None = None,
    ) -> None:
        self.splunk_url = splunk_url.rstrip("/")
        self.auth = auth
        self.index = index
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.provider_id = "splunk"
        configured_profile_limit = os.getenv("SPLUNK_PROFILE_SOURCE_LIMIT", "").strip()
        if profile_source_limit is None and configured_profile_limit:
            try:
                profile_source_limit = int(configured_profile_limit)
            except ValueError as exc:
                raise ValueError("SPLUNK_PROFILE_SOURCE_LIMIT must be an integer") from exc
        if profile_source_limit is not None and profile_source_limit <= 0:
            raise ValueError("profile_source_limit must be positive or None")
        # None means profile every discovered native source. A limit is an
        # operational safeguard only and is always exposed as an explicit
        # census gap; it must never look like complete discovery.
        self.profile_source_limit = profile_source_limit
        self.profile_discovery_audit: dict[str, Any] = {}

        self.scope = ProviderScope(
            provider_id="splunk",
            native_partition={"index": index},
            scope_id=f"splunk_{index}",
            coverage_start="2016-01-01T00:00:00Z",
            retention_days=4000,
        )

        self.manifest: dict[str, Any] | None = None
        self.discovered_sourcetypes: dict[str, int] = {}
        self.source_profiles: list[TelemetrySourceProfile] = []
        self.binding_mode: str = "discovery"

        # Initialize Mode 2 (Manifest) if manifest_path is provided
        if manifest_path is not None and str(manifest_path).strip():
            mpath = Path(manifest_path)
            if mpath.exists() and mpath.is_file():
                self._load_manifest(mpath)

        # If no manifest was loaded, use dynamic auto-discovery (Mode 1)
        if self.manifest is None:
            self.binding_mode = "discovery"
            try:
                self._discover_capabilities()
            except Exception as err:
                logger.debug(f"Dynamic auto-discovery deferred (Splunk offline or unreachable): {err}")

    # -----------------------------------------------------------------------
    # Manifest & Discovery
    # -----------------------------------------------------------------------

    def _load_manifest(self, path: Path) -> None:
        """Load declarative sourcetype and field mappings from YAML manifest (Mode 2)."""
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        self.manifest = data
        if "index" in data and not self.index:
            self.index = str(data["index"])
            self.scope = ProviderScope(
                provider_id="splunk",
                native_partition={"index": self.index},
                scope_id=f"splunk_{self.index}",
                coverage_start="2016-01-01T00:00:00Z",
                retention_days=data.get("retention_days", 4000),
            )
        self.binding_mode = "manifest"

    def _discover_capabilities(self) -> None:
        """Introspect Splunk metadata to discover sourcetypes and event counts (Mode 1)."""
        spl = f'| metadata type=sourcetypes index="{self.index}" | table sourcetype, totalCount'
        resp = requests.post(
            f"{self.splunk_url}/services/search/jobs",
            data={
                "search": spl,
                "earliest_time": "0",
                "output_mode": "json",
                "exec_mode": "oneshot",
            },
            auth=self.auth,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            self.discovered_sourcetypes = {
                r.get("sourcetype"): int(r.get("totalCount", 0))
                for r in results
                if r.get("sourcetype")
            }
            self.binding_mode = "discovery"
        else:
            raise ConnectionError(f"Failed to discover sourcetypes: HTTP {resp.status_code} - {resp.text}")

    def _discover_telemetry_profiles(self, profile_limit: int | None = None) -> list[TelemetrySourceProfile]:
        """Collect native field metadata without assigning semantics.

        This intentionally uses ``fieldsummary`` instead of the old
        sourcetype-name mapping. ``profile_limit`` is an optional operational
        limit; if it excludes sources, the returned audit marks discovery
        incomplete rather than pretending that the source meaning is known.
        """
        profiles: list[TelemetrySourceProfile] = []
        discovered = list(self.discovered_sourcetypes.items())
        selected = discovered if profile_limit is None else discovered[:profile_limit]
        selected_names = {str(native_type) for native_type, _ in selected}
        failed: list[str] = []
        for native_type, event_count in selected:
            safe_type = str(native_type).replace('"', '')[:200]
            source_id = f"splunk:{self.index}:{safe_type}"
            spl = f'search index="{self.index}" sourcetype="{safe_type}" | head 20 | fieldsummary | table field count distinct_count'
            try:
                resp = requests.post(
                    f"{self.splunk_url}/services/search/jobs",
                    data={
                        "search": spl,
                        "earliest_time": "0",
                        "output_mode": "json",
                        "exec_mode": "oneshot",
                    },
                    auth=self.auth,
                    verify=self.verify_ssl,
                    timeout=min(self.timeout, 15),
                )
                if resp.status_code != 200:
                    continue
                fields: list[TelemetryFieldProfile] = []
                for item in resp.json().get("results", []):
                    name = str(item.get("field", "")).strip()
                    if not name:
                        continue
                    fields.append(TelemetryFieldProfile(
                        field_id=f"{source_id}:field:{name}",
                        name=name,
                        primitive_type="unknown",
                    ))
                profiles.append(TelemetrySourceProfile(
                    source_id=source_id,
                    provider_id=self.provider_id,
                    partition_id=self.scope.scope_id,
                    native_type=safe_type,
                    event_count=int(event_count or 0),
                    fields=tuple(fields),
                    retention_days=self.scope.retention_days,
                    permissions=("search_job_create", "results_read", "read"),
                    query_primitives=("search", "fieldsummary", "table", "head"),
                ))
            except Exception as err:
                failed.append(safe_type)
                logger.debug("Telemetry profile discovery failed for %s: %s", safe_type, err)
        unprofiled = [
            str(native_type)
            for native_type, _ in discovered
            if str(native_type) not in selected_names
        ]
        self.profile_discovery_audit = {
            "discovered_source_count": len(discovered),
            "requested_profile_count": len(selected),
            "profiled_source_count": len(profiles),
            "failed_source_types": failed,
            "unprofiled_source_types": unprofiled,
            "profile_source_limit": profile_limit,
            "complete": not failed and not unprofiled,
        }
        return profiles

    def list_indexes(self, count: int = 0) -> list[dict[str, Any]]:
        """List all indexes on Splunk server via REST API with event counts."""
        resp = requests.get(
            f"{self.splunk_url}/services/data/indexes",
            params={"output_mode": "json", "count": count},
            auth=self.auth,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise ConnectionError(f"Failed to query indexes: HTTP {resp.status_code} - {resp.text}")

        entries = resp.json().get("entry", [])
        result = []
        for entry in entries:
            name = entry.get("name")
            content = entry.get("content", {})
            result.append({
                "name": name,
                "total_events": int(content.get("totalEventCount", 0)),
                "min_time": content.get("minTime", ""),
                "max_time": content.get("maxTime", ""),
                "disabled": bool(content.get("disabled", False)),
            })
        return sorted(result, key=lambda x: x["name"])

    def resolve_ip_to_host(self, ip: str, window: str | None = None) -> str | None:
        """Resolve an internal IP address to a host name in Splunk."""
        if not ip:
            return None
        ip_clean = str(ip).strip()
        # 1. Prioritize web server logs (iis/apache/nginx) where the IP is the server address
        spl_web = f'search index="{self.index}" "{ip_clean}" (sourcetype="*iis*" OR sourcetype="*web*" OR sourcetype="*apache*" OR sourcetype="*nginx*") | head 5 | table host'
        try:
            resp = requests.post(
                f"{self.splunk_url}/services/search/jobs",
                data={
                    "search": spl_web,
                    "earliest_time": "0",
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                },
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=min(self.timeout, 10),
            )
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                for r in results:
                    if r.get("host"):
                        h_val = str(r["host"]).strip()
                        if h_val:
                            return h_val
        except Exception as e:
            logger.debug(f"resolve_ip_to_host web lookup failed for {ip_clean}: {e}")

        # 2. Fallback to endpoint/system sourcetypes
        spl_sys = f'search index="{self.index}" "{ip_clean}" (sourcetype="*sysmon*" OR sourcetype="*wineventlog*") | head 20 | stats count by host | sort -count | head 1 | table host'
        try:
            resp = requests.post(
                f"{self.splunk_url}/services/search/jobs",
                data={
                    "search": spl_sys,
                    "earliest_time": "0",
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                },
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=min(self.timeout, 10),
            )
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                if results and "host" in results[0]:
                    h_val = str(results[0]["host"]).strip()
                    if h_val:
                        return h_val
        except Exception as e:
            logger.debug(f"resolve_ip_to_host endpoint lookup failed for {ip_clean}: {e}")
        return None

    @classmethod
    def is_available(
        cls,
        splunk_url: str = "https://localhost:8089",
        auth: tuple[str, str] = ("admin", "12345678"),
        verify_ssl: bool = False,
        timeout: int = 2,
    ) -> bool:
        """Probe whether Splunk REST API is live and reachable."""
        try:
            resp = requests.get(
                f"{splunk_url.rstrip('/')}/services/server/info",
                params={"output_mode": "json"},
                auth=auth,
                verify=verify_ssl,
                timeout=timeout,
            )
            return resp.status_code == 200
        except Exception:
            return False

    @classmethod
    def auto_select_index(
        cls,
        splunk_url: str = "https://localhost:8089",
        auth: tuple[str, str] = ("admin", "12345678"),
        verify_ssl: bool = False,
        timeout: int = 10,
    ) -> dict[str, Any]:
        """Introspect available indexes and select the primary active telemetry index."""
        temp_adapter = cls(
            splunk_url=splunk_url,
            auth=auth,
            index="botsv2",
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        indexes = temp_adapter.list_indexes()
        active_indexes = [
            idx for idx in indexes
            if not idx["name"].startswith("_")
            and not idx["disabled"]
            and idx["total_events"] > 0
            and idx["name"] not in ("history", "summary")
        ]
        if not active_indexes:
            active_indexes = [idx for idx in indexes if not idx["name"].startswith("_") and not idx["disabled"]]

        if not active_indexes:
            raise RuntimeError("No active telemetry indexes discovered on Splunk server.")

        active_indexes.sort(key=lambda x: x["total_events"], reverse=True)
        return active_indexes[0]

    def validate_index(self) -> None:
        """Pre-flight check verifying target index exists and has events."""
        indexes = self.list_indexes()
        index_names = {idx["name"] for idx in indexes}
        if self.index not in index_names:
            avail = sorted(list(index_names))
            raise ValueError(f"Target index '{self.index}' does not exist on Splunk. Available indexes: {avail}")

    # -----------------------------------------------------------------------
    # Descriptors for Query Planner and Engine
    # -----------------------------------------------------------------------

    def discover_full_capabilities(self) -> ProviderCapabilityCatalog:
        """Introspect Splunk provider to construct a full ProviderCapabilityCatalog."""
        if not self.is_available(splunk_url=self.splunk_url, auth=self.auth, verify_ssl=self.verify_ssl, timeout=self.timeout):
            return ProviderCapabilityCatalog(
                provider_id=self.provider_id,
                status="UNREACHABLE",
                details={"error": f"Splunk service unreachable at {self.splunk_url}"},
            )

        try:
            indexes_info = self.list_indexes()
            index_names = [idx["name"] for idx in indexes_info if not idx["name"].startswith("_") and not idx["disabled"]]
        except Exception as e:
            logger.warning(f"Failed to list indexes: {e}")
            index_names = [self.index]

        try:
            self._discover_capabilities()
        except Exception as e:
            logger.warning(f"Failed to discover sourcetypes: {e}")

        supported_types: list[str] = []
        if self.manifest and "bindings" in self.manifest:
            supported_types = list(self.manifest["bindings"].keys())
        else:
            # Dynamic discovery must not classify a source from its name. The
            # semantic types become available only through relation-scoped
            # source profiling, validation and a successful bounded probe.
            supported_types = ["scope_records"]

        descriptor = self.get_capability_descriptor()
        schemas: dict[str, dict[str, Any]] = {
            sourcetype: {
                "event_count": count,
                "fields": sorted(
                    {
                        field
                        for role_fields in SOURCETYPE_FIELD_ROLE_MAPPINGS.get(
                            sourcetype,
                            {},
                        ).values()
                        for field in role_fields
                    }
                ),
            }
            for sourcetype, count in self.discovered_sourcetypes.items()
        }
        aliases: dict[str, tuple[str, ...]] = {}
        for role_map in SOURCETYPE_FIELD_ROLE_MAPPINGS.values():
            for role, fields in role_map.items():
                aliases[role] = tuple(
                    dict.fromkeys((*aliases.get(role, ()), *fields))
                )

        self.source_profiles = self._discover_telemetry_profiles(self.profile_source_limit)
        return ProviderCapabilityCatalog(
            provider_id=self.provider_id,
            status="ONLINE",
            indices=index_names,
            sourcetypes=self.discovered_sourcetypes,
            supported_evidence_types=supported_types,
            observable_fields=list(OBSERVABLE_FIELDS),
            retention_days=self.scope.retention_days,
            details={
                "binding_mode": self.binding_mode,
                "active_index": self.index,
                "splunk_url": self.splunk_url,
                "suppress_schema_profile_fallback": True,
                "semantic_bindings_from_descriptor": bool(self.manifest),
                "profile_discovery": dict(self.profile_discovery_audit),
            },
            operations=list(descriptor.operations),
            permissions=["search_job_create", "results_read", "read"],
            completeness_semantics="complete only on EOF; limit+1 detects pagination",
            partitions={
                self.scope.scope_id: {
                    "native_partition": dict(self.scope.native_partition),
                    "coverage_start": self.scope.coverage_start,
                    "coverage_end": self.scope.coverage_end,
                    "retention_days": self.scope.retention_days,
                    "known_gaps": [dict(value) for value in self.scope.known_gaps],
                }
            },
            schemas=schemas,
            aliases=aliases,
            source_profiles=self.source_profiles,
        )

    def get_capability_descriptor(self) -> CapabilityDescriptor:
        """Return published CapabilityDescriptor for SplunkLiveAdapter."""
        op_scope_ids = (self.scope.scope_id,)

        def operation(
            operation_id: str,
            fact_kinds: tuple[str, ...],
            input_kinds: tuple[str, ...],
            output_fields: tuple[str, ...],
            *,
            params_schema: dict[str, Any] | None = None,
            semantic_intents: tuple[str, ...] = (),
            pagination: str = "offset",
            input_roles: tuple[str, ...] = (),
            output_roles: tuple[str, ...] = (),
            output_entity_kinds: tuple[str, ...] = (),
            native_field_bindings: dict[str, tuple[str, ...]] | None = None,
            guaranteed_relations: tuple[str, ...] = (),
            output_value_bindings: dict[str, tuple[str, ...]] | None = None,
            output_binding_entity_kinds: dict[str, str] | None = None,
            supported_constraints: tuple[str, ...] = (),
            searchable_constraints: tuple[str, ...] = (),
            query_builder: str = "",
            allow_constraint_relaxation: bool = True,
        ) -> ProviderOperation:
            relation_by_fact = {
                "identity_binding": "associated_with",
                "web_request": "visited",
                "web_request_activity": "visited",
                "web_navigation": "visited",
                "dns_activity": "resolved",
                "network_connection": "communicated_with",
                "process_ancestry": "executed",
                "server_side_execution": "executed",
                "file_modification": "modified",
                "file_artifact": "modified",
                "authentication_activity": "authenticated",
                "remote_authentication": "authenticated",
                "persistence_change": "persisted",
                "software_version": "has_version",
            }
            declared_relations = guaranteed_relations or tuple(dict.fromkeys(
                relation_by_fact[fact] for fact in fact_kinds if fact in relation_by_fact
            ))
            value_fields = tuple(
                field_name for field_name in output_fields
                if field_name.casefold() not in {"timestamp", "host", "user", "native_type", "sourcetype"}
            )
            derived_output_kinds = output_entity_kinds or tuple(dict.fromkeys(
                kind for field_name in output_fields
                for kind, markers in {
                    "account": ("user", "username"),
                    "host": ("host", "computer"),
                    "ip": ("ip", "client_ip", "server_ip", "source_ip", "destination_ip"),
                    "domain": ("domain", "site", "query", "cs_host"),
                    "process": ("image", "process", "cmdline"),
                    "file": ("file_path", "path", "targetfilename"),
                    "email_address": ("email", "sender_email", "receiver_email"),
                    "version": ("version", "productversion", "fileversion"),
                }.items() if field_name.casefold() in {marker.casefold() for marker in markers}
            ))
            # Keep identity resolution typed: finding an account may expose
            # an incidental email field in the same raw event, but that does
            # not make the operation an account-to-email resolver.  Otherwise
            # the planner can skip the required identity grounding hop.
            if operation_id == "resolve_person_to_account" and not output_entity_kinds:
                derived_output_kinds = ("account",)
            if operation_id == "resolve_person_to_account" and output_value_bindings is None:
                output_value_bindings = {"object": ("user",)}
            if not searchable_constraints and operation_id in {
                "cdb_file_writes", "cdb_file_search", "find_file_change_from_endpoint",
                "find_file_change_from_process",
            }:
                # These are retrieval hints only.  Sysmon/file telemetry can
                # return a candidate containing the terms, but cannot prove
                # that a file was encrypted or is a presentation without a
                # provider-specific semantic proof contract.
                searchable_constraints = (
                    "format", "file_type", "artifact_type", "kind", "name", "extension", "keyword",
                )
            if not searchable_constraints and operation_id in {
                "cdb_process_lineage", "cdb_process_search", "find_process_from_endpoint",
            }:
                # Retrieval hints narrow process collection but do not prove
                # the semantic restriction; the engine still requires a
                # declared proof-capable constraint before SUPPORT.
                searchable_constraints = (
                    "software", "software_type", "software_name", "process_name",
                    "image", "command", "keyword", "name",
                )
            return ProviderOperation(
                operation_id,
                "splunk",
                op_scope_ids,
                params_schema=params_schema or {"window": "interval"},
                pagination=pagination,
                limit_semantics="complete only on EOF",
                semantic_intents=semantic_intents,
                input_entity_kinds=input_kinds,
                output_entity_kinds=derived_output_kinds,
                output_fields=output_fields,
                output_fact_kinds=fact_kinds,
                input_roles=input_roles,
                output_roles=output_roles,
                native_field_bindings=native_field_bindings or {},
                guaranteed_relations=declared_relations,
                output_value_bindings=output_value_bindings or ({"object": value_fields} if value_fields else {}),
                output_binding_entity_kinds=output_binding_entity_kinds or {},
                supported_constraints=supported_constraints,
                searchable_constraints=searchable_constraints,
                query_builder=query_builder,
                completeness="limit+1 EOF proof",
                legacy_alias=operation_id.startswith("cdb_"),
                allow_constraint_relaxation=allow_constraint_relaxation,
            )

        process_fields = (
            "timestamp", "host", "user", "pid", "ppid", "cmdline",
            "image", "parent_image", "ProductVersion", "FileVersion", "Version",
        )
        file_fields = (
            "timestamp", "host", "user", "image", "file_path",
            "ProductVersion", "FileVersion", "Version",
        )
        web_fields = (
            "timestamp", "host", "client_ip", "server_ip", "domain", "site",
            "cs_host", "uri", "http_method", "method",
        )
        message_fields = (
            "timestamp", "sender", "sender_email", "receiver",
            "receiver_email", "msg_id", "message_id", "subject",
        )
        operations = (
            operation("cdb_scope_scan", ("scope_records", "operational_baseline"), ("ANY",), OBSERVABLE_FIELDS),
            operation("search_text", ("scope_records", "operational_baseline"), ("ANY",), OBSERVABLE_FIELDS, params_schema={"terms": "list[string]", "term_groups": "list[list[string]]", "window": "interval"}),
            operation("discover_schema", ("schema_metadata",), ("ANY",), ("field", "count")),
            operation("sample_records", ("scope_records",), ("ANY",), OBSERVABLE_FIELDS, params_schema={"window": "interval", "limit": "integer"}),
            operation("cdb_broad_sweep", ("scope_records",), ("ANY",), OBSERVABLE_FIELDS),
            operation("cdb_process_lineage", ("process_ancestry", "server_side_execution"), ("host", "account", "process"), process_fields),
            operation("cdb_process_search", ("process_ancestry", "server_side_execution"), ("host", "account", "process"), process_fields),
            operation("cdb_logon_history", ("authentication_activity", "remote_authentication"), ("host", "account", "person"), ("timestamp", "host", "user", "client_ip", "logon_type", "status")),
            operation("cdb_auth_search", ("authentication_activity", "remote_authentication"), ("host", "account", "person"), ("timestamp", "host", "user", "client_ip", "logon_type", "status")),
            operation("cdb_file_writes", ("file_modification", "file_artifact"), ("host", "account", "process", "file"), file_fields),
            operation("cdb_file_search", ("file_modification", "file_artifact", "software_version"), ("host", "process", "file"), file_fields, semantic_intents=("software_version",)),
            operation("cdb_web_requests", ("web_request", "web_request_activity", "web_navigation"), ("host", "account", "ip", "domain"), web_fields),
            operation("splunk_search_web", ("web_request", "web_request_activity", "web_navigation"), ("host", "account", "ip", "domain"), web_fields, pagination="cursor"),
            operation("cdb_broad_sweep", ("scope_records", "operational_baseline"), ("ANY",), OBSERVABLE_FIELDS),
            operation("cdb_scope_scan", ("scope_records", "operational_baseline"), ("ANY",), OBSERVABLE_FIELDS),
            operation("search_text", ("scope_records", "operational_baseline"), ("ANY",), OBSERVABLE_FIELDS, params_schema={"terms": "list[string]", "term_groups": "list[list[string]]", "window": "interval"}),
            operation("cdb_dns_queries", ("dns_activity",), ("host", "account", "ip", "domain"), ("timestamp", "host", "client_ip", "server_ip", "domain", "query")),
            operation("cdb_dns_search", ("dns_activity",), ("host", "account", "ip", "domain"), ("timestamp", "host", "client_ip", "server_ip", "domain", "query")),
            operation("cdb_persistence_artifacts", ("persistence_change",), ("host", "account", "process", "file"), ("timestamp", "host", "user", "image", "file_path")),
            operation("cdb_persistence_search", ("persistence_change",), ("host", "account", "process", "file"), ("timestamp", "host", "user", "image", "file_path")),
            operation("cdb_network_connections", ("network_connection",), ("host", "account", "process", "ip", "domain"), ("timestamp", "host", "user", "image", "client_ip", "server_ip", "destination_ip", "destination_port", "protocol")),
            operation("cdb_net_search", ("network_connection",), ("host", "account", "process", "ip", "domain"), ("timestamp", "host", "user", "image", "client_ip", "server_ip", "destination_ip", "destination_port", "protocol")),
            operation("find_process_from_endpoint", ("process_ancestry", "server_side_execution", "software_version"), ("host", "process"), process_fields, semantic_intents=("software_version",)),
            operation("find_file_change_from_endpoint", ("file_modification", "file_artifact", "software_version"), ("host", "file"), file_fields, semantic_intents=("software_version",), output_entity_kinds=("file",), output_value_bindings={"object": ("file_path", "TargetFilename", "target_path", "path", "filename")}, output_binding_entity_kinds={"object": "file"}, allow_constraint_relaxation=False),
            operation("find_file_change_from_process", ("file_modification", "file_artifact", "software_version"), ("process", "file"), file_fields, semantic_intents=("software_version",), output_entity_kinds=("file",), output_value_bindings={"object": ("file_path", "TargetFilename")}, output_binding_entity_kinds={"object": "file"}),
            operation("find_web_activity_from_endpoint", ("web_request", "web_request_activity", "web_navigation"), ("host",), web_fields),
            operation("find_web_activity_from_client_ip", ("web_request", "web_request_activity", "web_navigation"), ("ip",), web_fields),
            operation("find_dns_activity_from_client_ip", ("dns_activity",), ("ip",), ("timestamp", "host", "client_ip", "server_ip", "domain", "query")),
            operation("resolve_account_to_email", ("identity_binding",), ("account",), ("user", "sender_email"), input_roles=("account_identity",), output_roles=("account_identity", "attribute_value"), output_entity_kinds=("email_address",), native_field_bindings={"account_identity": ("user",), "attribute_value": ("sender_email",)}, query_builder="splunk.identity.account_to_email.v1"),
            operation("resolve_person_to_account", ("identity_binding",), ("person",), ("user", "sender_email"), input_roles=("subject_identity",), output_roles=("subject_identity", "account_identity"), output_entity_kinds=("account",), native_field_bindings={"subject_identity": ("user",), "account_identity": ("user",)}, output_value_bindings={"object": ("user",)}, query_builder="splunk.identity.person_to_account.v1"),
            operation(
                "resolve_account_to_endpoint", ("identity_binding",), ("account",),
                ("user", "host", "client_ip", "ComputerName", "WorkstationName", "IpAddress"),
                output_entity_kinds=("host", "ip"),
                output_value_bindings={
                    # WorkstationName in Windows logon telemetry identifies
                    # the client workstation, not the endpoint producing the
                    # event.  Binding it as the investigated host caused the
                    # engine to pivot to unrelated machines.
                    # In this Splunk deployment, ``host`` is the endpoint
                    # identity used by Sysmon/process events.  ComputerName
                    # is retained in the observation but is only a fallback;
                    # binding it first made downstream searches use a DNS
                    # name that did not match the process host field.
                    "object": ("host", "ComputerName"),
                    "client_ip": ("client_ip", "IpAddress", "src_ip", "c_ip"),
                },
                output_binding_entity_kinds={"object": "host", "client_ip": "ip"},
                guaranteed_relations=("associated_with",),
            ),
            operation(
                "resolve_person_to_endpoint", ("identity_binding",), ("person",),
                ("user", "host", "ComputerName", "sourcetype"),
                input_roles=("subject_identity",),
                output_roles=("subject_identity", "endpoint_identity"),
                output_entity_kinds=("host",),
                output_value_bindings={"object": ("host", "ComputerName")},
                output_binding_entity_kinds={"object": "host"},
                guaranteed_relations=("associated_with",),
                query_builder="splunk.identity.person_to_endpoint.v1",
            ),
            operation("resolve_endpoint_to_client_ip", ("identity_binding",), ("host",), ("host", "client_ip")),
            operation("find_outbound_message_metadata", ("outbound_message_metadata",), ("account", "email_address", "person"), message_fields, input_roles=("subject_identity", "account_identity"), output_roles=("subject_identity", "attribute_value", "message_context"), output_entity_kinds=("email_address", "message"), native_field_bindings={"subject_identity": ("sender", "user"), "attribute_value": ("sender_email", "receiver_email"), "message_context": ("msg_id", "message_id", "subject")}, query_builder="splunk.message.metadata.v1"),
            operation("resolve_recipient_identity", ("recipient_identity",), ("message",), message_fields),
            operation("resolve_role_identity", ("role_identity",), ("person", "account", "email_address"), ("title", "role", "department", "receiver_email")),
            operation("cdb_process_lineage", ("process_ancestry", "server_side_execution"), ("host", "account", "process"), process_fields),
            operation("cdb_process_search", ("process_ancestry", "server_side_execution"), ("host", "account", "process"), process_fields),
            operation("cdb_logon_history", ("authentication_activity", "remote_authentication"), ("host", "account", "person"), ("timestamp", "host", "user", "client_ip", "logon_type", "status")),
            operation("cdb_auth_search", ("authentication_activity", "remote_authentication"), ("host", "account", "person"), ("timestamp", "host", "user", "client_ip", "logon_type", "status")),
            operation("cdb_network_connections", ("network_connection",), ("host", "account", "process", "ip", "domain"), ("timestamp", "host", "user", "image", "client_ip", "server_ip", "destination_ip", "destination_port", "protocol")),
            operation("cdb_net_search", ("network_connection",), ("host", "account", "process", "ip", "domain"), ("timestamp", "host", "user", "image", "client_ip", "server_ip", "destination_ip", "destination_port", "protocol")),
            operation("cdb_file_writes", ("file_modification",), ("host", "account", "process", "file"), file_fields),
            operation("cdb_file_search", ("file_modification", "software_version"), ("host", "process", "file"), file_fields, semantic_intents=("software_version",)),
            operation("cdb_dns_queries", ("dns_activity",), ("host", "account", "ip", "domain"), ("timestamp", "host", "client_ip", "server_ip", "domain", "query")),
            operation("cdb_dns_search", ("dns_activity",), ("host", "account", "ip", "domain"), ("timestamp", "host", "client_ip", "server_ip", "domain", "query")),
            operation("cdb_persistence_artifacts", ("persistence_change",), ("host", "account", "process", "file"), ("timestamp", "host", "user", "image", "file_path")),
            operation("cdb_persistence_search", ("persistence_change",), ("host", "account", "process", "file"), ("timestamp", "host", "user", "image", "file_path")),
            operation("cdb_web_requests", ("web_request",), ("host", "account", "ip", "domain"), web_fields),
            operation("splunk_search_process", ("process_ancestry",), ("host", "account", "process"), process_fields, pagination="cursor"),
            operation("splunk_search_web", ("web_request",), ("host", "account", "ip", "domain"), web_fields, pagination="cursor"),
            operation("resolve_person_to_account", ("identity_binding",), ("person",), ("user", "sender_email"), input_roles=("subject_identity",), output_roles=("subject_identity", "account_identity"), output_entity_kinds=("account",), native_field_bindings={"subject_identity": ("user",), "account_identity": ("user",)}, output_value_bindings={"object": ("user",)}, query_builder="splunk.identity.person_to_account.v1"),
            operation(
                "resolve_account_to_endpoint", ("identity_binding",), ("account",),
                ("user", "host", "client_ip", "ComputerName", "WorkstationName", "IpAddress"),
                output_entity_kinds=("host", "ip"),
                output_value_bindings={
                    "object": ("host", "ComputerName"),
                    "client_ip": ("client_ip", "IpAddress", "src_ip", "c_ip"),
                },
                output_binding_entity_kinds={"object": "host", "client_ip": "ip"},
                guaranteed_relations=("associated_with",),
            ),
            operation(
                "resolve_person_to_endpoint", ("identity_binding",), ("person",),
                ("user", "host", "ComputerName", "sourcetype"),
                input_roles=("subject_identity",),
                output_roles=("subject_identity", "endpoint_identity"),
                output_entity_kinds=("host",),
                output_value_bindings={"object": ("host", "ComputerName")},
                output_binding_entity_kinds={"object": "host"},
                guaranteed_relations=("associated_with",),
                query_builder="splunk.identity.person_to_endpoint.v1",
            ),
            operation("resolve_endpoint_to_client_ip", ("identity_binding",), ("host",), ("host", "client_ip")),
            operation("find_web_activity_from_client_ip", ("web_request",), ("ip",), web_fields),
            operation("find_dns_activity_from_client_ip", ("dns_activity",), ("ip",), ("timestamp", "host", "client_ip", "server_ip", "domain", "query")),
            operation("find_web_activity_from_endpoint", ("web_request",), ("host",), web_fields),
            operation("find_process_from_endpoint", ("process_ancestry", "software_version"), ("host", "process"), process_fields, semantic_intents=("software_version",)),
            operation("find_file_change_from_endpoint", ("file_modification", "software_version"), ("host", "file"), file_fields, semantic_intents=("software_version",), output_entity_kinds=("file",), output_value_bindings={"object": ("file_path", "TargetFilename", "target_path", "path", "filename")}, output_binding_entity_kinds={"object": "file"}, allow_constraint_relaxation=False),
            operation("find_file_change_from_process", ("file_modification", "software_version"), ("process", "file"), file_fields, semantic_intents=("software_version",), output_entity_kinds=("file",), output_value_bindings={"object": ("file_path", "TargetFilename")}, output_binding_entity_kinds={"object": "file"}),
            operation("resolve_account_to_email", ("identity_binding",), ("account",), ("user", "sender_email"), input_roles=("account_identity",), output_roles=("account_identity", "attribute_value"), output_entity_kinds=("email_address",), native_field_bindings={"account_identity": ("user",), "attribute_value": ("sender_email",)}, query_builder="splunk.identity.account_to_email.v1"),
            operation("find_outbound_message_metadata", ("outbound_message_metadata",), ("account", "email_address", "person"), message_fields, input_roles=("subject_identity", "account_identity"), output_roles=("subject_identity", "attribute_value", "message_context"), output_entity_kinds=("email_address", "message"), native_field_bindings={"subject_identity": ("sender", "user"), "attribute_value": ("sender_email", "receiver_email"), "message_context": ("msg_id", "message_id", "subject")}, query_builder="splunk.message.metadata.v1"),
            operation("resolve_recipient_identity", ("recipient_identity",), ("message",), message_fields),
            operation("resolve_role_identity", ("role_identity",), ("person", "account", "email_address"), ("title", "role", "department", "receiver_email")),
        )
        bindings = (
            CapabilityBinding(EvidenceRequirement.SCOPE_RECORDS, "splunk", "cdb_broad_sweep", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.PROCESS_ANCESTRY, "splunk", "cdb_process_lineage", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.AUTHENTICATION_ACTIVITY, "splunk", "cdb_logon_history", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.NETWORK_CONNECTION, "splunk", "cdb_network_connections", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.FILE_MODIFICATION, "splunk", "cdb_file_writes", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.DNS_ACTIVITY, "splunk", "cdb_dns_queries", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.PERSISTENCE_CHANGE, "splunk", "cdb_persistence_artifacts", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.WEB_REQUEST, "splunk", "cdb_web_requests", confidence="EXACT"),
        )
        return CapabilityDescriptor(
            provider_id="splunk",
            scopes=(self.scope,),
            operations=operations,
            bindings=bindings,
        )

    def get_versioned_descriptor(self) -> VersionedCapabilityDescriptor:
        """Return published VersionedCapabilityDescriptor for CanonicalQueryPlanner."""
        cap = self.get_capability_descriptor()
        return VersionedCapabilityDescriptor(
            provider_id="splunk",
            version="9.2.1",
            deployment_env="enterprise-prod",
            scopes=(self.scope,),
            operations=cap.operations,
            bindings=cap.bindings,
            supported_entity_kinds=("host", "account", "process", "ip", "file", "domain", "ANY"),
            permissions=("search_job_create", "results_read", "read"),
            observable_fields=OBSERVABLE_FIELDS,
            completeness_contract="complete",
        )

    # -----------------------------------------------------------------------
    # SPL Construction & Parameterization
    # -----------------------------------------------------------------------

    def _build_runtime_source_spl(
        self,
        runtime_capability: dict[str, Any],
        entity: EntityRef | None,
        window: str,
        limit: int,
        offset: int,
    ) -> tuple[str, str, str]:
        """Build SPL from an audited source profile, without source heuristics."""
        source_id = str(runtime_capability.get("source_id", "")).strip()
        prefix = f"splunk:{self.index}:"
        if not source_id.startswith(prefix):
            raise ValueError("runtime source is not part of the active Splunk index")
        native_type = source_id[len(prefix):].replace('"', "")[:200]
        if not native_type or any(char in native_type for char in "\r\n|"):
            raise ValueError("runtime source contains invalid native type")

        def safe_field(name: Any) -> str | None:
            value = str(name).strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,199}", value):
                return None
            return value

        input_bindings = runtime_capability.get("native_field_bindings", {})
        output_bindings = runtime_capability.get("output_value_bindings", {})
        native_fields = [
            safe_field(name)
            for values in (*input_bindings.values(), *output_bindings.values())
            if isinstance(values, (list, tuple))
            for name in values
        ]
        fields = list(dict.fromkeys(field for field in native_fields if field))
        if not fields:
            raise ValueError("runtime capability has no safe native fields")

        clauses = [f'search index="{self.index}" sourcetype="{native_type}"']
        if entity is not None and not isinstance(entity, AnyEntity):
            if isinstance(entity, Account):
                value = entity.username
            elif isinstance(entity, Host):
                value = entity.name
            elif isinstance(entity, IPAddress):
                value = entity.address
            elif isinstance(entity, Domain):
                value = entity.name
            elif isinstance(entity, File):
                value = entity.path
            elif isinstance(entity, Process):
                value = str(entity.pid)
            else:
                value = str(entity)
            value = str(value or "").replace('"', "")[:200].strip()
            fields_for_input = [
                safe_field(name)
                for values in input_bindings.values()
                if isinstance(values, (list, tuple))
                for name in values
            ]
            fields_for_input = list(dict.fromkeys(field for field in fields_for_input if field))
            if value and fields_for_input:
                clauses.append("(" + " OR ".join(
                    f'{field}="{value}"' for field in fields_for_input
                ) + ")")

        start_dt, end_dt = validate_time_window_format(window)
        page_clause = (
            f"| head {limit + 1}"
            if offset <= 0
            else f"| head {offset + limit + 1} | tail {limit + 1}"
        )
        projection = list(dict.fromkeys(["_time", "host", "sourcetype", *fields, "_raw"]))
        spl = " ".join(clauses) + f" {page_clause} | table " + ", ".join(projection)
        return (
            spl,
            start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def _resolve_evidence_kind(self, operation_id: str) -> str:
        """Map operation_id to canonical evidence requirement kind."""
        op = operation_id.lower()
        if "process" in op or "lineage" in op:
            return "process_ancestry"
        if "web" in op or "http" in op:
            return "web_request"
        if "auth" in op or "logon" in op:
            return "authentication_activity"
        if "net" in op or "network" in op:
            return "network_connection"
        if "file" in op or "write" in op:
            return "file_modification"
        if "dns" in op:
            return "dns_activity"
        if "persistence" in op:
            return "persistence_change"
        return "scope_records"

    def _build_spl(
        self,
        operation_id: str,
        entity: EntityRef | None,
        window: str,
        predicate: FieldPredicate | None,
        limit: int,
        offset: int = 0,
        search_terms: list[str] | tuple[str, ...] | None = None,
        search_groups: list[list[str]] | None = None,
    ) -> tuple[str, str, str]:
        """Construct safe parameterized SPL with search-time rex extractions and L+1 completeness limit."""
        start_dt, end_dt = validate_time_window_format(window)
        earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Splunk has no implicit offset for oneshot searches.  Fetch one
        # extra row and use head+tail for bounded offset pagination so the
        # executor never mistakes a repeated first page for new evidence.
        page_clause = (
            f"| head {limit + 1}"
            if offset <= 0
            else f"| head {offset + limit + 1} | tail {limit + 1}"
        )

        if operation_id == "search_text":
            # Terms are data, never native SPL.  Quote and escape them here so
            # the provider adapter remains the only component that knows SPL.
            safe_terms = [
                str(term).replace('"', "")[:200].strip()
                for term in (search_terms or [])
                if str(term).strip()
            ]
            if not safe_terms and entity and not isinstance(entity, AnyEntity):
                safe_terms = [str(entity).replace('"', "")[:200].strip()]
            safe_groups: list[list[str]] = []
            for group in search_groups or []:
                terms_iter = group.terms if hasattr(group, "terms") else group
                aliases = [str(term).replace('"', "")[:200].strip() for term in terms_iter if str(term).strip()]
                if aliases:
                    safe_groups.append(aliases)
            if safe_groups:
                term_clause = " ".join(
                    "(" + " OR ".join(f'"{term}"' for term in group) + ")"
                    for group in safe_groups
                )
            else:
                term_clause = " ".join(f'"{term}"' for term in safe_terms)
            search_head = f'search index="{self.index}"'
            if term_clause:
                search_head += f" {term_clause}"
            rex_version = (
                " | rex field=_raw \"(?i)<Data Name=[\\\"']ProductVersion[\\\"']>(?<ProductVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)<Data Name=[\\\"']FileVersion[\\\"']>(?<FileVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)ProductVersion[:= ]+(?<ProductVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)FileVersion[:= ]+(?<FileVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)version[\\\"':= ]+(?<Version>[0-9]+(\\.[0-9]+)+)\""
                " | rex field=_raw \"(?i)[/\\\\\\(][a-zA-Z0-9_.-]*(?:install|setup|browser|update|v)[-_ ]*(?<software_version>[0-9]+(\\.[0-9]+)+)\""
            )
            return (
                f'{search_head}{rex_version} | head {limit + 1} '
                '| table _time, host, sourcetype, user, Image, CommandLine, Path, '
                'TargetFilename, ProductVersion, FileVersion, Version, uri, site, _raw',
                earliest_iso,
                latest_iso,
            )

        if operation_id == "discover_schema":
            return (
                f'search index="{self.index}" | head {limit + 1} | fieldsummary',
                earliest_iso,
                latest_iso,
            )

        if operation_id == "sample_records":
            return (
                f'search index="{self.index}" | head {limit + 1} | table _time, host, sourcetype, user, Image, CommandLine, Path, TargetFilename, ProductVersion, FileVersion, Version, uri, site, _raw',
                earliest_iso,
                latest_iso,
            )

        # Handle relation-first operations (v5.0)
        if operation_id == "resolve_person_to_account":
            if isinstance(entity, str):
                ent_val = entity
            elif isinstance(entity, Account):
                ent_val = entity.username or (str(entity.kind) if str(entity.kind) != "account" else "")
            else:
                ent_val = str(getattr(entity, "username", getattr(entity, "name", str(entity or ""))))
            # Identity discovery deliberately starts from the supplied subject
            # across the selected index.  A fixed SMTP/LDAP/Security source
            # list is not a valid identity model: BotSv2 (and real estates)
            # may expose a person only in an endpoint, file, SMB, EDR or other
            # native record.  The adapter may extract an account only from an
            # explicitly named identity field; a display-name hit alone is
            # never silently converted into an account.
            ent_val = ent_val.replace('"', '').replace('*', '').strip()[:200]
            spl = (
                f'search index="{self.index}" "{ent_val}" '
                f'| rex field=_raw "New Logon:[\\s\\S]*?Account Name:\\s*(?<TargetUserName>[^\\r\\n\\s]+)" '
                f'| rex field=_raw "Account Name:\\s*(?<user>[^\\r\\n\\s]+)" '
                f'| eval _account_candidate=coalesce(TargetUserName,user,Account_Name,account,username,src_user) '
                f'| where isnotnull(_account_candidate) AND _account_candidate!="" AND _account_candidate!="-" '
                f'| dedup _account_candidate '
                f'{page_clause} '
                f'| rename _account_candidate as user '
                f'| table _time, user, host, ComputerName, sourcetype'
            )
            return spl, earliest_iso, latest_iso

        if operation_id in ("resolve_person_to_endpoint", "resolve_account_to_endpoint"):
            if isinstance(entity, str):
                ent_val = entity
            elif isinstance(entity, Account):
                ent_val = entity.username or (str(entity.kind) if str(entity.kind) != "account" else "")
            else:
                ent_val = str(getattr(entity, "username", getattr(entity, "name", str(entity or ""))))
            ent_val = ent_val.replace('"', '').strip()
            # Endpoint discovery is a relation lookup, not a Windows-logon
            # lookup.  Searching only EventCode 4624 used to discard valid
            # EDR, Sysmon, SMB, file and macOS records and then made the first
            # surviving host look authoritative.  Return the complete set of
            # distinct native endpoint keys; the executor must preserve all
            # candidates and never infer a device class from its name.
            spl = (
                f'search index="{self.index}" "{ent_val}" '
                f'| rex field=_raw "Workstation Name:\\s*(?<WorkstationName>[^\\r\\n\\s]+)" '
                f'| rex field=_raw "New Logon:[\\s\\S]*?Account Name:\\s*(?<TargetUserName>[^\\r\\n\\s]+)" '
                f'| eval _host_candidate=coalesce(host,ComputerName) '
                f'| where isnotnull(_host_candidate) AND _host_candidate!="" AND _host_candidate!="-" '
                f'| dedup _host_candidate '
                f'{page_clause} '
                f'| rename _host_candidate as host '
                f'| table _time, host, ComputerName, TargetUserName, user, IpAddress, WorkstationName, LogonType, sourcetype'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "resolve_endpoint_to_client_ip":
            if isinstance(entity, str):
                ent_val = entity
            elif isinstance(entity, Host):
                ent_val = entity.name or (str(entity.kind) if str(entity.kind) != "host" else "")
            else:
                ent_val = str(getattr(entity, "name", str(entity or "")))
            ent_val = ent_val.replace('"', '').strip()
            spl = (
                f'search index="{self.index}" ((sourcetype="stream:dns" ("{ent_val}" OR hostname="*{ent_val}*" OR name="*{ent_val}*")) '
                f'OR ((sourcetype="WinEventLog:Security" OR sourcetype="wineventlog:security") ("{ent_val}" OR host="*{ent_val}*" OR ComputerName="*{ent_val}*") EventCode=4624) '
                f'OR (sourcetype="*sysmon*" (host="*{ent_val}*" OR ComputerName="*{ent_val}*") "*EventID>3<*") '
                f'OR (sourcetype="stream:dhcp" host="*{ent_val}*")) '
                f'| rex field=_raw "\\"host_addr\\":\\[\\"(?<IpAddress>[^\\"]+)\\"" '
                f'| rex field=_raw "\\"src_ip\\":\\"(?<src_ip>[^\\"]+)\\"" '
                f'| rex field=_raw "Source Network Address:\\s*(?<IpAddress>[^\\r\\n\\s]+)" '
                f'| rex field=_raw "New Logon:[\\s\\S]*?Account Name:\\s*(?<TargetUserName>[^\\r\\n\\s]+)" '
                f'| rex field=_raw "Workstation Name:\\s*(?<WorkstationName>[^\\r\\n\\s]+)" '
                f'| where (isnotnull(IpAddress) AND IpAddress!="-" AND IpAddress!="127.0.0.1" AND IpAddress!="0.0.0.0") '
                f'OR (isnotnull(src_ip) AND src_ip!="-" AND src_ip!="127.0.0.1" AND src_ip!="0.0.0.0") '
                f'{page_clause} '
                f'| table _time, host, ComputerName, WorkstationName, TargetUserName, IpAddress, src_ip, client_ip, c_ip, hostname, name, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "find_web_activity_from_client_ip":
            if isinstance(entity, str):
                ent_val = entity
            elif isinstance(entity, IPAddress):
                ent_val = entity.address or (str(entity.kind) if str(entity.kind) != "ip" else "")
            else:
                ent_val = str(getattr(entity, "address", getattr(entity, "ip", str(entity or ""))))
            ent_val = ent_val.replace('"', '').strip()
            pred_filter = ""
            if predicate:
                fn = predicate.field.strip().lower()
                val = str(predicate.value).strip() if predicate.value is not None else ""
                if fn in ("site", "domain"):
                    root_val = val[4:] if val.lower().startswith("www.") else val
                    pred_filter = f'| where like(lower(site), "%{root_val.lower()}%") OR like(lower(cs_host), "%{root_val.lower()}%")'
            spl = (
                f'search index="{self.index}" (sourcetype="stream:http" OR sourcetype="pan:traffic") '
                f'(src_ip="{ent_val}" OR client_ip="{ent_val}" OR c_ip="{ent_val}" OR src="{ent_val}") '
                f'| eval site=coalesce(site, cs_host) '
                f'| where isnotnull(site) AND site!="" AND NOT (site like "%:8014%") '
                f'{pred_filter} '
                f'| dedup site '
                f'{page_clause} '
                f'| table _time, host, sourcetype, src_ip, dest_ip, site, cs_host, uri, cs_uri_stem, cs_method, status, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "find_dns_activity_from_client_ip":
            if isinstance(entity, str):
                ent_val = entity
            elif isinstance(entity, IPAddress):
                ent_val = entity.address or (str(entity.kind) if str(entity.kind) != "ip" else "")
            else:
                ent_val = str(getattr(entity, "address", getattr(entity, "ip", str(entity or ""))))
            ent_val = ent_val.replace('"', '').strip()
            spl = (
                f'search index="{self.index}" (sourcetype="stream:dns" OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22)) '
                f'(src_ip="{ent_val}" OR client_ip="{ent_val}" OR c_ip="{ent_val}") '
                f'{page_clause} '
                f'| table _time, host, sourcetype, src_ip, dest_ip, query, domain, site, cs_host, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "find_web_activity_from_endpoint":
            ent_val = str(getattr(entity, "name", "") or (getattr(entity, "kind", "") if isinstance(entity, Host) else entity or "")).replace('"', '').strip()
            spl = (
                f'search index="{self.index}" (sourcetype="stream:http" OR sourcetype="pan:traffic") '
                f'(host="*{ent_val}*" OR ComputerName="*{ent_val}*") '
                f'{page_clause} '
                f'| table _time, host, ComputerName, sourcetype, src_ip, client_ip, site, cs_host, uri, cs_uri_stem, cs_method, status, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "find_process_from_endpoint":
            ent_val = str(getattr(entity, "name", "") or (getattr(entity, "kind", "") if isinstance(entity, Host) else entity or "")).replace('"', '').strip()
            extra_filter = ""
            safe_terms = [
                str(t).replace('"', '')[:200].strip()
                for t in (search_terms or [])
                if str(t).strip() and str(t).strip().casefold() != ent_val.casefold()
            ]
            if safe_terms:
                extra_filter = " (" + " OR ".join(f'"{t}"' for t in safe_terms) + ")"
            rex_version = (
                " | rex field=_raw \"(?i)<Data Name=[\\\"']ProductVersion[\\\"']>(?<ProductVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)<Data Name=[\\\"']FileVersion[\\\"']>(?<FileVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)ProductVersion[:= ]+(?<ProductVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)FileVersion[:= ]+(?<FileVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)version[\\\"':= ]+(?<Version>[0-9]+(\\.[0-9]+)+)\""
            )
            spl = (
                # BotSv2 stores Sysmon's event ID in XML (_raw); EventCode is
                # not consistently extracted.  Accept both representations so
                # a valid process record is not discarded by a field-schema
                # assumption.
                f'search index="{self.index}" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR "*EventID>1<*") '
                f'(host="*{ent_val}*" OR ComputerName="*{ent_val}*"){extra_filter}'
                f'{rex_version} '
                f'{page_clause} '
                f'| table _time, host, ComputerName, Image, CommandLine, ParentImage, User, ProcessId, ProductVersion, FileVersion, Version, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "find_file_change_from_endpoint":
            ent_val = str(getattr(entity, "name", "") or (getattr(entity, "kind", "") if isinstance(entity, Host) else entity or "")).replace('"', '').strip()
            # File identity is not equivalent to one event family.  A file
            # may be present in Sysmon, EDR, audit, osquery or a native file
            # inventory.  Keep the operation contract typed (host -> file),
            # but let the Splunk adapter search the selected host across the
            # index and constrain by declared file terms.  This is the native
            # equivalent of a hunter starting with host=<candidate> and a
            # file predicate; it must not discard the answer because Sysmon
            # EventCode=11 is absent.
            safe_terms = [
                str(t).replace('"', '')[:200].strip()
                for t in (search_terms or [])
                if str(t).strip() and str(t).strip().casefold() != ent_val.casefold()
            ]
            # Retrieval aliases are supplied by the semantic compiler as
            # provider-neutral data terms.  Do not translate a scenario name
            # here (for example PowerPoint -> *.pptx): that would make the
            # adapter a hidden case-specific planner.  A provider may only
            # consume terms that were declared by the semantic/capability
            # contract and validated before reaching this method.
            expanded_terms = list(dict.fromkeys(safe_terms))
            term_clause = ""
            if expanded_terms:
                term_predicates: list[str] = []
                for term in expanded_terms:
                    # Bare wildcard terms are intentional: BotSv2's osquery
                    # file_events stores target_path inside _raw rather than
                    # extracting TargetFilename/file_path.  A field-only
                    # query therefore misses the exact artifact even though
                    # the native Splunk search `(*.pptx OR ...)` finds it.
                    raw_token = term if term.startswith("*.") else f'"{term}"'
                    term_predicates.append(
                        f'TargetFilename="{term}" OR file_path="{term}" OR path="{term}" OR {raw_token}'
                    )
                term_clause = " (" + " OR ".join(term_predicates) + ")"
            # Require one declared file-path marker as well as the filename
            # predicate.  Without this schema guard, a process snapshot whose
            # command line merely mentions ``.pptx`` becomes a file result and
            # causes unrelated hosts to fan out.  This is field-contract
            # grounding, not a sourcetype/event-family assumption.
            file_record_marker = ' ("target_path" OR "TargetFilename" OR "file_path")'
            rex_version = (
                " | rex field=_raw \"(?i)<Data Name=[\\\"']ProductVersion[\\\"']>(?<ProductVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)<Data Name=[\\\"']FileVersion[\\\"']>(?<FileVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)ProductVersion[:= ]+(?<ProductVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)FileVersion[:= ]+(?<FileVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)version[\\\"':= ]+(?<Version>[0-9]+(\\.[0-9]+)+)\""
            )
            spl = (
                f'search index="{self.index}" (host="{ent_val}" OR ComputerName="{ent_val}")'
                f'{file_record_marker}{term_clause}{rex_version} '
                f'{page_clause} '
                f'| table _time, host, ComputerName, sourcetype, TargetFilename, file_path, path, Image, ProcessId, ProductVersion, FileVersion, Version, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "find_file_change_from_process":
            ent_val = str(getattr(entity, "name", "") or (getattr(entity, "kind", "") if isinstance(entity, Process) else entity or "")).replace('"', '').strip()
            rex_version = (
                " | rex field=_raw \"(?i)<Data Name=[\\\"']ProductVersion[\\\"']>(?<ProductVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)<Data Name=[\\\"']FileVersion[\\\"']>(?<FileVersion>[^<]+)</Data>\""
                " | rex field=_raw \"(?i)ProductVersion[:= ]+(?<ProductVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)FileVersion[:= ]+(?<FileVersion>[^\\r\\n,]+)\""
                " | rex field=_raw \"(?i)version[\\\"':= ]+(?<Version>[0-9]+(\\.[0-9]+)+)\""
            )
            spl = (
                f'search index="{self.index}" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=11 OR "*EventID>11<*") '
                f'(ProcessId="{ent_val}" OR Image="*{ent_val}*")'
                f'{rex_version} '
                f'{page_clause} '
                f'| table _time, host, TargetFilename, Image, ProcessId, ProductVersion, FileVersion, Version, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "resolve_account_to_email":
            if isinstance(entity, str):
                ent_val = entity
            elif isinstance(entity, Account):
                ent_val = entity.username or (str(entity.kind) if str(entity.kind) != "account" else "")
            else:
                ent_val = str(getattr(entity, "username", getattr(entity, "name", str(entity or ""))))
            ent_val = ent_val.replace('"', '').strip()
            prefix = ent_val.split('@')[0].split('.')[0] if '.' in ent_val else ent_val
            spl = (
                f'search index="{self.index}" sourcetype="stream:smtp" '
                f'("{ent_val}" OR "{prefix}*@*" OR "*{ent_val}*") '
                f'| head {limit + 1} '
                f'| table _time, host, TargetUserName, user, sender, sender_email, receiver, receiver_email, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "find_outbound_message_metadata":
            ent_val = str(getattr(entity, "value", str(entity or ""))).replace('"', '').strip()
            eff_limit = max(limit + 1, 500)
            spl = (
                f'search index="{self.index}" sourcetype="stream:smtp" '
                f'(sender="*{ent_val}*" OR sender_email="*{ent_val}*" OR "{ent_val}") '
                f'| head {eff_limit} '
                f'| table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, src_ip, dest_ip, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "resolve_recipient_identity":
            ent_val = str(getattr(entity, "value", str(entity or ""))).replace('"', '').strip()
            spl = (
                f'search index="{self.index}" sourcetype="stream:smtp" '
                f'(msg_id="{ent_val}" OR message_id="{ent_val}" OR "{ent_val}") '
                f'| head {limit + 1} '
                f'| table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, _raw'
            )
            return spl, earliest_iso, latest_iso

        if operation_id == "resolve_role_identity":
            ent_val = str(getattr(entity, "value", str(entity or ""))).replace('"', '').strip()
            spl = (
                f'search index="{self.index}" (sourcetype="*active_directory*" OR sourcetype="*ldap*" OR sourcetype="stream:ldap") '
                f'("{ent_val}") '
                f'| head {limit + 1} '
                f'| table _time, host, sender, receiver, subject, title, role, department, _raw'
            )
            return spl, earliest_iso, latest_iso

        kind = self._resolve_evidence_kind(operation_id)
        spl_parts: list[str] = [f'search index="{self.index}"']
        rex_clauses: list[str] = []

        # 1. Resolve sourcetype, event filter, and extractions (Mode 2 vs Mode 1)
        if self.binding_mode == "manifest" and self.manifest and "bindings" in self.manifest:
            m_bindings = self.manifest.get("bindings", {})
            m_cfg = m_bindings.get(kind, {})
            st = m_cfg.get("sourcetype")
            ef = m_cfg.get("event_filter")
            if st and st != "*":
                spl_parts.append(f'sourcetype="{st}"')
            if ef and ef != "*":
                if ("<" in ef or ">" in ef) and not (ef.startswith('"') or ef.startswith("'") or ef.startswith("(")):
                    spl_parts.append(f'"{ef}"')
                else:
                    spl_parts.append(ef)
            for _, rex_expr in m_cfg.get("extractions", {}).items():
                if rex_expr.startswith("<") or "(?<" in rex_expr:
                    rex_clauses.append(f'| rex field=_raw "{rex_expr}"')
        else:
            # Mode 1: Dynamic Discovery Heuristic
            if kind == "process_ancestry":
                spl_parts.append('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>1<*"')
                rex_clauses.extend([
                    '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'CommandLine\'>(?<cmdline>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'ParentImage\'>(?<parent_image>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'User\'>(?<user>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'ProcessId\'>(?<pid>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'ParentProcessId\'>(?<ppid>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'Hashes\'>(?<hash>[^<]+)</Data>"',
                ])
            elif kind == "network_connection":
                spl_parts.append('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>3<*"')
                rex_clauses.extend([
                    '| rex field=_raw "<Data Name=\'DestinationIp\'>(?<destination_ip>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'DestinationPort\'>(?<destination_port>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'SourceIp\'>(?<source_ip>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'SourcePort\'>(?<source_port>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'Protocol\'>(?<protocol>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'User\'>(?<user>[^<]+)</Data>"',
                ])
            elif kind == "file_modification":
                spl_parts.append('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "*EventID>11<*"')
                rex_clauses.extend([
                    '| rex field=_raw "<Data Name=\'TargetFilename\'>(?<file_path>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
                    '| rex field=_raw "(?i)<Data Name=[\'\\"]ProductVersion[\'\\"]>(?<ProductVersion>[^<]+)</Data>"',
                    '| rex field=_raw "(?i)<Data Name=[\'\\"]FileVersion[\'\\"]>(?<FileVersion>[^<]+)</Data>"',
                    '| rex field=_raw "(?i)ProductVersion[:= ]+(?<ProductVersion>[^\\r\\n,]+)"',
                    '| rex field=_raw "(?i)FileVersion[:= ]+(?<FileVersion>[^\\r\\n,]+)"',
                    '| rex field=_raw "(?i)version[\\\'\\\":= ]+(?<Version>[0-9]+(\\.[0-9]+)+)"',
                    '| rex field=_raw "(?i)[/\\\\\\(][a-zA-Z0-9_.-]*(?:install|setup|browser|update|v)[-_ ]*(?<software_version>[0-9]+(\\.[0-9]+)+)"',
                ])
            elif kind == "authentication_activity":
                spl_parts.append('sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)')
                rex_clauses.extend([
                    '| rex field=Message "Account Name:\\s*(?<user>[^\\r\\n]+)"',
                    '| rex field=Message "Logon Type:\\s*(?<logon_type>\\d+)"',
                ])
            elif kind == "dns_activity":
                spl_parts.append('sourcetype="stream:dns"')
            elif kind == "web_request":
                spl_parts.append('(sourcetype="stream:http" OR sourcetype="iis")')
            elif kind == "persistence_change":
                spl_parts.append('sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ("*EventID>12<*" OR "*EventID>13<*")')
                rex_clauses.extend([
                    '| rex field=_raw "<Data Name=\'TargetObject\'>(?<registry_key>[^<]+)</Data>"',
                    '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
                ])

        # 2. Entity filtering
        if entity and entity != ANY and not isinstance(entity, AnyEntity):
            if isinstance(entity, Host):
                spl_parts.append(f'host="{entity.name}"')
            elif isinstance(entity, Account):
                spl_parts.append(f'(user="{entity.username}" OR "*Account Name*={entity.username}*" OR "*User*>{entity.username}<*")')
            elif isinstance(entity, Process):
                spl_parts.append(f'host="{entity.host}" "*ProcessId>{entity.pid}<*"')
            elif isinstance(entity, IPAddress):
                spl_parts.append(f'("{entity.address}")')
            elif isinstance(entity, Domain):
                d_name = entity.name
                if d_name.lower().startswith("www."):
                    d_root = d_name[4:]
                    spl_parts.append(f'("{d_name}" OR "{d_root}")')
                else:
                    spl_parts.append(f'("{d_name}")')
            elif isinstance(entity, File):
                spl_parts.append(f'host="{entity.host}" ("{entity.path}")')

        # 2.5 Search terms filtering for targeted operations
        if search_groups:
            term_clause = " ".join(
                "(" + " OR ".join(f'"{str(term).replace(chr(34), "")}"' for term in group if str(term).strip()) + ")"
                for group in search_groups if group
            )
            if term_clause and term_clause not in spl_parts:
                spl_parts.append(term_clause)
        elif search_terms:
            safe_terms = [str(term).replace('"', "")[:200].strip() for term in search_terms if str(term).strip()]
            if safe_terms:
                term_clause = "(" + " OR ".join(f'"{t}"' for t in safe_terms) + ")"
                if term_clause not in spl_parts:
                    spl_parts.append(term_clause)

        # 3. Predicate filtering (SPL search-time)
        filter_clauses: list[str] = []
        if predicate:
            fn = predicate.field.strip().lower()
            val = str(predicate.value).strip() if predicate.value is not None else ""
            if fn in ("site", "domain"):
                if predicate.op == FieldOp.EQUALS:
                    filter_clauses.append(f'| eval site=coalesce(site, cs_host) | where lower(site)="{val.lower()}"')
                elif predicate.op == FieldOp.CONTAINS:
                    filter_clauses.append(f'| eval site=coalesce(site, cs_host) | where like(lower(site), "%{val.lower()}%")')
                elif predicate.op == FieldOp.EXISTS:
                    filter_clauses.append('| eval site=coalesce(site, cs_host) | where isnotnull(site) AND site!=""')
                elif predicate.op == FieldOp.ABSENT:
                    filter_clauses.append('| eval site=coalesce(site, cs_host) | where isnull(site) OR site==""')
                if val:
                    root_val = val[4:] if val.lower().startswith("www.") else val
                    dom_spl = f'(site="*{root_val}*" OR cs_host="*{root_val}*" OR "{val}" OR "{root_val}")'
                    if dom_spl not in spl_parts:
                        spl_parts.append(dom_spl)
            elif predicate.op == FieldOp.EQUALS:
                filter_clauses.append(f'| where {fn}="{val}"')
            elif predicate.op == FieldOp.CONTAINS:
                filter_clauses.append(f'| where like(lower({fn}), "%{val.lower()}%")')
            elif predicate.op == FieldOp.EXISTS:
                filter_clauses.append(f'| where isnotnull({fn}) AND {fn}!=""')
            elif predicate.op == FieldOp.ABSENT:
                filter_clauses.append(f'| where isnull({fn}) OR {fn}==""')

        # 4. Strict L+1 Completeness contract: fetch limit + 1
        query_parts = [" ".join(spl_parts)]
        query_parts.extend(rex_clauses)
        query_parts.extend(filter_clauses)
        query_parts.append(page_clause)
        query_parts.append("| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, ProductVersion, FileVersion, Version, TargetFilename, _raw")

        spl_final = "\n".join(query_parts)
        return spl_final, earliest_iso, latest_iso

    # -----------------------------------------------------------------------
    # Query Execution (L+1 rule, EOF completeness)
    # -----------------------------------------------------------------------

    def execute_capability_probe(
        self,
        *,
        profile: TelemetrySourceProfile,
        probe: Any,
        time_window: str | None = None,
        query_id: str = "probe-001",
    ) -> QueryResult:
        """Execute a bounded source/field co-occurrence probe.

        The sourcetype and fields come from the census profile object, not from
        an LLM-generated query string. The response is capability evidence only.
        """
        prefix = f"splunk:{self.index}:"
        if profile.provider_id != self.provider_id or not profile.source_id.startswith(prefix):
            return QueryResult(
                query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                complete=False, diagnostic=Diagnostic.UNSUPPORTED_REQUIREMENT,
                truncation_reason="profile does not belong to this Splunk index",
                provider=self.provider_id, index=self.index,
            )
        native_type = profile.source_id[len(prefix):].replace('"', '')[:200]
        fields = []
        for field_id in getattr(probe, "field_ids", ()):
            field = profile.field(field_id)
            if field is None or not field.name.strip():
                return QueryResult(
                    query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                    complete=False, diagnostic=Diagnostic.PARSE_FAILED,
                    truncation_reason=f"probe field is not in source profile: {field_id}",
                    provider=self.provider_id, index=self.index,
                )
            fields.append(field.name.replace('"', '')[:200])
        fields = list(dict.fromkeys(fields or ["_time", "host", "sourcetype"]))
        max_rows = min(max(int(getattr(probe, "max_rows", 20)), 1), 1000)
        table_clause = ", ".join(fields)
        spl = f'search index="{self.index}" sourcetype="{native_type}" | table {table_clause} | head {max_rows + 1}'
        try:
            start_dt, end_dt = validate_time_window_format(time_window or "NOW-1d/NOW")
            response = requests.post(
                f"{self.splunk_url}/services/search/jobs",
                data={
                    "search": spl,
                    "earliest_time": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "latest_time": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                },
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=min(self.timeout, int(getattr(probe, "timeout_seconds", 10))),
            )
            if response.status_code != 200:
                raise ConnectionError(f"HTTP {response.status_code}: {response.text[:200]}")
            raw_rows = response.json().get("results", [])
        except Exception as error:
            return QueryResult(
                query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                complete=False, diagnostic=Diagnostic.QUERY_FAILED,
                truncation_reason=str(error), native_query=spl,
                provider=self.provider_id, index=self.index, sourcetype=native_type,
            )
        returned = [dict(row) for row in raw_rows[:max_rows]]
        complete = len(raw_rows) <= max_rows
        return QueryResult(
            query_id=query_id,
            outcome=QueryOutcome.ROWS if returned else QueryOutcome.UNKNOWN,
            executed_ok=True,
            complete=complete,
            rows=returned,
            observed_fields=list(dict.fromkeys(key for row in returned for key in row)),
            native_query=spl,
            provider=self.provider_id,
            index=self.index,
            sourcetype=native_type,
            row_count=len(returned),
            cursor=None if complete else str(max_rows),
            truncation_reason=None if complete else "probe_limit_exceeded",
        )

    def execute_query(
        self,
        operation_id: str,
        entity: EntityRef | None,
        window: str,
        predicate: FieldPredicate | None = None,
        limit: int = 100,
        offset: int = 0,
        query_id: str = "q-001",
        native_query: str | None = None,
        search_terms: list[str] | tuple[str, ...] | None = None,
        search_groups: list[list[str]] | None = None,
        parameters: dict[str, Any] | None = None,
        native_query_candidate: NativeQueryCandidate | None = None,
        query_intent: dict[str, Any] | None = None,
    ) -> QueryResult:
        """Execute safe parameterized SPL over Splunk REST API with EOF completeness check."""
        start_time = time.perf_counter()
        parameters = dict(parameters or {})
        # Semantic parameters are intentionally carried to the provider
        # boundary.  Only declared native predicates may be translated by
        # this adapter; unknown qualifiers remain auditable and are never
        # guessed into SPL.
        eff_limit = max(limit, 500) if operation_id == "find_outbound_message_metadata" else limit
        params = {"window": window, "limit": limit}
        validate_query_params(operation_id, params)

        if native_query_candidate is not None:
            if native_query and native_query.strip() and native_query.strip() != native_query_candidate.query_text.strip():
                return QueryResult(
                    query_id=query_id,
                    outcome=QueryOutcome.UNKNOWN,
                    executed_ok=False,
                    complete=False,
                    diagnostic=Diagnostic.PARSE_FAILED,
                    truncation_reason="native query and candidate disagree",
                    provider=self.provider_id,
                    index=self.index,
                )
            gate_result = NativeQueryGate().validate(
                native_query_candidate,
                known_sources=[self.index],
                known_fields=[
                    *OBSERVABLE_FIELDS,
                    "sourcetype", "_time", "_raw", "Path", "TargetFilename",
                    "Image", "CommandLine", "ParentImage", "ProcessId",
                    *[
                        field.name
                        for profile in self.source_profiles
                        for field in profile.fields
                    ],
                ],
                executed_query_signatures=parameters.get("executed_query_signatures", ()),
            )
            if not gate_result.accepted:
                return QueryResult(
                    query_id=query_id,
                    outcome=QueryOutcome.UNKNOWN,
                    executed_ok=False,
                    complete=False,
                    diagnostic=Diagnostic.PARSE_FAILED,
                    truncation_reason="; ".join(gate_result.reasons),
                    native_query=native_query_candidate.query_text,
                    provider=self.provider_id,
                    index=self.index,
                )
            spl = gate_result.normalized_query
            start_dt, end_dt = validate_time_window_format(window)
            earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        elif native_query and native_query.strip():
            spl = native_query.strip()
            if not spl.lower().startswith("search") and not spl.startswith("|"):
                spl = f"search {spl}"
            start_dt, end_dt = validate_time_window_format(window)
            earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            constraint_terms = parameters.get("constraint_search_terms", [])
            if isinstance(constraint_terms, (list, tuple)):
                search_terms = [*(search_terms or ()), *[str(value) for value in constraint_terms if str(value).strip()]]
            if operation_id.startswith("runtime:") and isinstance(parameters.get("runtime_capability"), dict):
                try:
                    spl, earliest_iso, latest_iso = self._build_runtime_source_spl(
                        parameters["runtime_capability"], entity, window, limit, offset
                    )
                except Exception as error:
                    return QueryResult(
                        query_id=query_id,
                        outcome=QueryOutcome.UNKNOWN,
                        executed_ok=False,
                        complete=False,
                        diagnostic=Diagnostic.PARSE_FAILED,
                        truncation_reason=f"runtime capability rejected: {error}",
                        provider=self.provider_id,
                        index=self.index,
                    )
            else:
                spl, earliest_iso, latest_iso = self._build_spl(
                    operation_id=operation_id,
                    entity=entity,
                    window=window,
                    predicate=predicate,
                    limit=limit,
                    offset=offset,
                    search_terms=search_terms,
                    search_groups=search_groups,
                )
        self.last_query_text = spl

        query_sid = str(parameters.get("sid") or f"hunt_{query_id}_{int(time.time() * 1000)}")
        dispatch_max_time = str(parameters.get("dispatch_max_time") or getattr(self, "dispatch_max_time", 60))

        try:
            resp = requests.post(
                f"{self.splunk_url}/services/search/jobs",
                data={
                    "search": spl,
                    "earliest_time": earliest_iso,
                    "latest_time": latest_iso,
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                    "count": 0,
                    "id": query_sid,
                    "dispatch.max_time": dispatch_max_time,
                },
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                elapsed = round((time.perf_counter() - start_time) * 1000, 2)
                return QueryResult(
                    query_id=query_id,
                    outcome=QueryOutcome.UNKNOWN,
                    executed_ok=False,
                    complete=False,
                    diagnostic=Diagnostic.QUERY_FAILED,
                    truncation_reason=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    native_query=spl,
                    provider=self.provider_id,
                    index=self.index,
                    execution_time_ms=elapsed,
                    sid=query_sid,
                )
            resp.encoding = "utf-8"
            raw_results = resp.json().get("results", [])
        except requests.exceptions.Timeout:
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)
            self.cancel_search_job(query_sid)
            return QueryResult(
                query_id=query_id,
                outcome=QueryOutcome.UNKNOWN,
                executed_ok=False,
                complete=False,
                diagnostic=Diagnostic.QUERY_FAILED,
                truncation_reason=f"client_timeout_cancelled_sid:{query_sid}",
                native_query=spl,
                provider=self.provider_id,
                index=self.index,
                execution_time_ms=elapsed,
                sid=query_sid,
            )
        except Exception as err:
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)
            return QueryResult(
                query_id=query_id,
                outcome=QueryOutcome.UNKNOWN,
                executed_ok=False,
                complete=False,
                diagnostic=Diagnostic.QUERY_FAILED,
                truncation_reason=str(err),
                native_query=spl,
                provider=self.provider_id,
                index=self.index,
                execution_time_ms=elapsed,
                sid=query_sid,
            )

        # Normalize rows into standard dictionary structure
        normalized_rows: list[dict[str, Any]] = []
        for r in raw_results:
            row: dict[str, Any] = {
                "timestamp": r.get("_time", ""),
                "host": r.get("host", ""),
                "native_type": r.get("sourcetype", ""),
                "raw_ref": r.get("_raw", "")[:200],
                "raw_event": dict(r),
            }

            # Priority 1: Direct or manifest extractions from r
            for k, val in r.items():
                if k not in ("_raw", "_time") and val is not None and val != "":
                    row[k] = val

            # Priority 1.5: Auto-flatten Sysmon/Windows XML <Data Name='Key'>Value</Data> tags from _raw
            raw_text = r.get("_raw", "")
            if isinstance(raw_text, str) and "<Data Name=" in raw_text:
                import re
                for m in re.finditer(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>", raw_text):
                    xml_k, xml_v = m.group(1), m.group(2).strip()
                    if xml_k and xml_v and (xml_k not in row or not row[xml_k]):
                        row[xml_k] = xml_v
                eid_m = re.search(r"<EventID>(\d+)</EventID>", raw_text)
                if eid_m and "EventCode" not in row:
                    row["EventCode"] = eid_m.group(1)

            # Normalize user from TargetUserName if user is empty, "-" or machine account ending in $
            if row.get("TargetUserName") and (not row.get("user") or row.get("user") == "-" or str(row.get("user")).endswith("$")):
                row["user"] = row["TargetUserName"]

            # Priority 2: Fallback to parsing _raw JSON if available (e.g. stream:dns, stream:http)
            raw_json: dict[str, Any] = {}
            if isinstance(raw_text, str) and "{" in raw_text and "}" in raw_text:
                trimmed = raw_text.strip()
                s_idx = trimmed.find("{")
                e_idx = trimmed.rfind("}")
                if s_idx != -1 and e_idx != -1 and e_idx > s_idx:
                    try:
                        raw_json = json.loads(trimmed[s_idx : e_idx + 1])
                    except Exception:
                        raw_json = {}

            if raw_json and isinstance(raw_json, dict):
                # Extract and normalize JSON fields if not already populated
                # osquery and several EDR collectors put the useful artifact
                # fields under a nested ``columns`` object.  Preserve those
                # typed native fields instead of reducing the observation to
                # an opaque raw string.
                columns = raw_json.get("columns")
                if isinstance(columns, dict):
                    for column_name, column_value in columns.items():
                        if column_value not in (None, "", [], {}) and column_name not in row:
                            row[str(column_name)] = column_value
                if "query" in raw_json and "query" not in row:
                    q_val = raw_json["query"]
                    if isinstance(q_val, list) and q_val:
                        row["query"] = str(q_val[0])
                    elif q_val:
                        row["query"] = str(q_val)
                if "name" in raw_json and "name" not in row:
                    n_val = raw_json["name"]
                    row["name"] = str(n_val[0]) if isinstance(n_val, list) and n_val else str(n_val)
                if "hostname" in raw_json and "hostname" not in row:
                    h_val = raw_json["hostname"]
                    row["hostname"] = str(h_val[0]) if isinstance(h_val, list) and h_val else str(h_val)
                if "host_addr" in raw_json and "host_addr" not in row:
                    ha_val = raw_json["host_addr"]
                    row["host_addr"] = str(ha_val[0]) if isinstance(ha_val, list) and ha_val else str(ha_val)
                if "site" in raw_json and "site" not in row:
                    row["site"] = str(raw_json["site"])
                if "cs_host" in raw_json and "site" not in row:
                    row["site"] = str(raw_json["cs_host"])
                if "uri" in raw_json and "uri" not in row:
                    row["uri"] = str(raw_json["uri"])
                if "cs_uri_stem" in raw_json and "uri" not in row:
                    row["uri"] = str(raw_json["cs_uri_stem"])
                if "src_ip" in raw_json and "src_ip" not in row:
                    row["src_ip"] = str(raw_json["src_ip"])
                if "src_ip" in raw_json and "client_ip" not in row:
                    row["client_ip"] = str(raw_json["src_ip"])
                if "src_ip" in raw_json and "source_ip" not in row:
                    row["source_ip"] = str(raw_json["src_ip"])
                if "c_ip" in raw_json and "client_ip" not in row:
                    row["client_ip"] = str(raw_json["c_ip"])
                if "dest_ip" in raw_json and "destination_ip" not in row:
                    row["destination_ip"] = str(raw_json["dest_ip"])
                if "s_ip" in raw_json and "server_ip" not in row:
                    row["server_ip"] = str(raw_json["s_ip"])
                if "user" in raw_json and not row.get("user"):
                    row["user"] = str(raw_json["user"])
                if "host" in raw_json and not row.get("host"):
                    row["host"] = str(raw_json["host"])

                # Email / SMTP fields
                if "sender" in raw_json and not row.get("sender"):
                    s_val = raw_json["sender"]
                    row["sender"] = str(s_val[0]) if isinstance(s_val, list) and s_val else str(s_val)
                if "sender_email" in raw_json and not row.get("sender_email"):
                    se_val = raw_json["sender_email"]
                    row["sender_email"] = str(se_val[0]) if isinstance(se_val, list) and se_val else str(se_val)
                if "sender_mail_from" in raw_json and not row.get("sender_email"):
                    sm_val = raw_json["sender_mail_from"]
                    row["sender_email"] = str(sm_val[0]) if isinstance(sm_val, list) and sm_val else str(sm_val)
                if "receiver" in raw_json and not row.get("receiver"):
                    rc_val = raw_json["receiver"]
                    row["receiver"] = str(rc_val[0]) if isinstance(rc_val, list) and rc_val else str(rc_val)
                if "receiver_email" in raw_json and not row.get("receiver_email"):
                    re_val = raw_json["receiver_email"]
                    row["receiver_email"] = str(re_val[0]) if isinstance(re_val, list) and re_val else str(re_val)
                if "receiver_rcpt_to" in raw_json and not row.get("receiver_email"):
                    rr_val = raw_json["receiver_rcpt_to"]
                    row["receiver_email"] = str(rr_val[0]) if isinstance(rr_val, list) and rr_val else str(rr_val)
                if "msg_id" in raw_json and not row.get("msg_id"):
                    m_val = raw_json["msg_id"]
                    row["msg_id"] = str(m_val[0]) if isinstance(m_val, list) and m_val else str(m_val)
                if "subject" in raw_json and not row.get("subject"):
                    sb_val = raw_json["subject"]
                    row["subject"] = str(sb_val[0]) if isinstance(sb_val, list) and sb_val else str(sb_val)

            # Ensure email address extraction from sender / receiver headers
            if not row.get("sender_email") and row.get("sender"):
                import re
                m = re.search(r'[\w\.-]+@[\w\.-]+', str(row["sender"]))
                if m:
                    row["sender_email"] = m.group(0).lower()
            if not row.get("receiver_email") and row.get("receiver"):
                import re
                m = re.search(r'[\w\.-]+@[\w\.-]+', str(row["receiver"]))
                if m:
                    row["receiver_email"] = m.group(0).lower()

            # Field harmonization
            if isinstance(row.get("query"), list) and row["query"]:
                row["query"] = str(row["query"][0])

            if "name" in row and "site" not in row:
                row["site"] = row["name"]
            if "name" in row and "domain" not in row:
                row["domain"] = row["name"]
            if "query" in row and "domain" not in row:
                row["domain"] = row["query"]
            if "query" in row and "site" not in row:
                row["site"] = row["query"]

            if "c_ip" in r and "client_ip" not in row:
                row["client_ip"] = r["c_ip"]
            if "s_ip" in r and "server_ip" not in row:
                row["server_ip"] = r["s_ip"]
            if "dest_ip" in r and "destination_ip" not in row:
                row["destination_ip"] = r["dest_ip"]
            if "dest_ip" in r and "server_ip" not in row:
                row["server_ip"] = r["dest_ip"]
            if "dest_ip" in r and "dest_ip" not in row:
                row["dest_ip"] = r["dest_ip"]
            if "src_ip" in r and "source_ip" not in row:
                row["source_ip"] = r["src_ip"]
            if "src_ip" in r and "client_ip" not in row:
                row["client_ip"] = r["src_ip"]
            if "dest" in r and "dest" not in row:
                row["dest"] = r["dest"]
            if "cs_uri_stem" in r and "uri" not in row:
                row["uri"] = r["cs_uri_stem"]
            if "cs_method" in r and "http_method" not in row:
                row["http_method"] = r["cs_method"]
            if "cs_host" in r and "site" not in row:
                row["site"] = r["cs_host"]
            if "site" in row and "domain" not in row:
                row["domain"] = row["site"]
            if "source_ip" in row and "client_ip" not in row:
                row["client_ip"] = row["source_ip"]
            if "destination_ip" in row and "server_ip" not in row:
                row["server_ip"] = row["destination_ip"]

            # Also catch uppercase fields from standard Splunk extractions if present
            if "Image" in r and "image" not in row:
                row["image"] = r["Image"]
            if "CommandLine" in r and "cmdline" not in row:
                row["cmdline"] = r["CommandLine"]
            if "ParentImage" in r and "parent_image" not in row:
                row["parent_image"] = r["ParentImage"]
            if "ProcessId" in r and "pid" not in row:
                row["pid"] = r["ProcessId"]
            if "DestinationIp" in r and "destination_ip" not in row:
                row["destination_ip"] = r["DestinationIp"]

            # Canonicalize common Windows/native field names while retaining
            # the original fields above for audit and replay.  Evidence and
            # grouping operate on these semantic aliases, not on one vendor's
            # capitalization convention.
            path_val = row.get("Path") or row.get("TargetFilename") or r.get("Path") or r.get("TargetFilename")
            if path_val:
                row.setdefault("path", path_val)
                row.setdefault("file_path", path_val)
                row.setdefault("TargetFilename", path_val)
            name_val = row.get("Name") or row.get("Image") or r.get("Name") or r.get("Image")
            if name_val:
                row.setdefault("process_name", name_val)
                row.setdefault("image", name_val)
                row.setdefault("Image", name_val)
            cmd_val = row.get("CommandLine") or row.get("cmdline") or r.get("CommandLine") or r.get("cmdline")
            if cmd_val:
                row.setdefault("cmdline", cmd_val)
                row.setdefault("CommandLine", cmd_val)

            ver_val = row.get("ProductVersion") or row.get("FileVersion") or row.get("Version") or r.get("ProductVersion") or r.get("FileVersion") or r.get("Version")
            if ver_val and str(ver_val).strip() not in (None, "", "-"):
                row.setdefault("software_version", str(ver_val).strip())

            normalized_rows.append(row)

        # Evaluate L+1 completeness contract
        target_limit = eff_limit if "eff_limit" in locals() else limit
        if len(normalized_rows) > target_limit:
            return_rows = normalized_rows[:target_limit]
            complete = False
            cursor = str(offset + target_limit)
        else:
            return_rows = normalized_rows
            complete = True
            cursor = None

        outcome = QueryOutcome.ROWS if return_rows else QueryOutcome.UNKNOWN
        observed_fields = list({k for r in return_rows for k in r.keys()})
        native_types = list({str(r["native_type"]) for r in return_rows if r.get("native_type")})
        elapsed = round((time.perf_counter() - start_time) * 1000, 2)

        scan_count: int | None = None
        resp_headers = getattr(resp, "headers", None)
        if resp_headers and "X-Splunk-ScanCount" in resp_headers:
            try:
                scan_count = int(resp_headers["X-Splunk-ScanCount"])
            except ValueError:
                pass
        elif hasattr(resp, "json"):
            try:
                json_data = resp.json()
                if isinstance(json_data, dict) and "scan_count" in json_data:
                    scan_count = int(json_data["scan_count"])
            except Exception:
                pass
        if scan_count is None:
            scan_count = len(raw_results)

        return QueryResult(
            query_id=query_id,
            outcome=outcome,
            executed_ok=True,
            complete=complete,
            rows=return_rows,
            observed_fields=observed_fields,
            native_types=native_types,
            cursor=cursor,
            native_query=spl,
            provider=self.provider_id,
            index=self.index,
            sourcetype=native_types[0] if native_types else None,
            execution_time_ms=elapsed,
            row_count=len(return_rows),
            sid=query_sid,
            scan_count=scan_count,
        )

    def cancel_search_job(self, sid: str) -> bool:
        """Cancel a running search job in Splunk by SID."""
        if not sid or not str(sid).strip():
            return False
        try:
            resp = requests.post(
                f"{self.splunk_url}/services/search/jobs/{sid}/control",
                data={"action": "cancel"},
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=5,
            )
            return resp.status_code in (200, 204)
        except Exception as err:
            logger.warning("Failed to cancel search job %s: %s", sid, err)
            return False

    # -----------------------------------------------------------------------
    # Negative Evidence Controls (never mint observations)
    # -----------------------------------------------------------------------

    def control_health(self, window: str, as_of: datetime | None = None) -> ControlResult:
        """Run ScopeHealthControl against Splunk instance."""
        is_reachable = True
        try:
            resp = requests.get(
                f"{self.splunk_url}/services/server/info",
                params={"output_mode": "json"},
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=5,
            )
            is_reachable = (resp.status_code == 200)
        except Exception:
            is_reachable = False

        ref_as_of = as_of or datetime.now(timezone.utc)
        return execute_scope_health_control(self.scope, window, as_of=ref_as_of, is_reachable=is_reachable)

    def control_any_record(
        self,
        window: str,
        entity: EntityRef | None = None,
        requirement: EvidenceRequirement | None = None,
    ) -> ControlResult:
        """Run AnyRecordInScope against index, optionally scoped to entity/requirement."""
        start_dt, end_dt = validate_time_window_format(window)
        earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        spl_filters = [f'search index="{self.index}"']
        if entity and entity != ANY and not isinstance(entity, AnyEntity):
            if isinstance(entity, Host):
                spl_filters.append(f'host="{entity.name}"')
            elif isinstance(entity, Account):
                spl_filters.append(f'user="{entity.username}"')

        if requirement:
            if requirement == EvidenceRequirement.PROCESS_ANCESTRY:
                spl_filters.append('(sourcetype="*Sysmon*" OR sourcetype="*process*")')
            elif requirement == EvidenceRequirement.FILE_MODIFICATION:
                spl_filters.append('(sourcetype="*Sysmon*" OR sourcetype="*file*")')
            elif requirement == EvidenceRequirement.AUTHENTICATION_ACTIVITY:
                spl_filters.append('(sourcetype="*Security*" OR sourcetype="*WinEventLog*")')
            elif requirement == EvidenceRequirement.WEB_REQUEST:
                spl_filters.append('(sourcetype="stream:http" OR sourcetype="iis")')
            elif requirement == EvidenceRequirement.DNS_ACTIVITY:
                spl_filters.append('sourcetype="stream:dns"')

        spl = " ".join(spl_filters) + " | head 1"
        try:
            resp = requests.post(
                f"{self.splunk_url}/services/search/jobs",
                data={
                    "search": spl,
                    "earliest_time": earliest_iso,
                    "latest_time": latest_iso,
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                },
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                count = len(resp.json().get("results", []))
                return execute_any_record_in_scope(self.scope, record_count=count)
            return execute_any_record_in_scope(self.scope, record_count=0, executed_ok=False)
        except Exception:
            return execute_any_record_in_scope(self.scope, record_count=0, executed_ok=False)

    def control_observability(
        self,
        requirement: EvidenceRequirement,
        predicate: FieldPredicate | None,
        observed_fields: set[str] | None = None,
    ) -> ControlResult:
        """Run PredicateObservabilityControl against Splunk observable fields."""
        fields = observed_fields if observed_fields is not None else set(OBSERVABLE_FIELDS)
        return execute_predicate_observability_control(self.scope, requirement, predicate, fields)


__all__ = ["SplunkLiveAdapter", "OBSERVABLE_FIELDS"]
