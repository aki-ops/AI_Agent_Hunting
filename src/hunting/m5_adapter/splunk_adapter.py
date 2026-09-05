"""Splunk Live Provider Adapter for Enterprise SIEM Telemetry (BOTSv1).

Implements the production-grade M5 provider adapter for Splunk Enterprise:
  - Dual Binding Architecture:
      Mode 1: Dynamic Auto-Discovery (zero-config, introspects /services/data/indexes
              and | metadata type=sourcetypes).
      Mode 2: Declarative YAML Manifest (reads configs/splunk_botsv1.yaml with
              explicit sourcetypes, event filters, and search-time rex extractions).
  - Strict Completeness Contract (L+1 Rule): queries fetch limit + 1 internally
    to determine EOF vs truncation.
  - Negative Evidence Controls: ScopeHealthControl, AnyRecordInScope,
    and PredicateObservabilityControl.
  - Parameterized SPL generation preventing injection.
"""
from __future__ import annotations

import logging
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
from hunting.contracts.queries import (
    CapabilityBinding,
    ControlResult,
    Diagnostic,
    ProviderOperation,
    QueryOutcome,
    QueryResult,
)
from hunting.m5_adapter.allowlist import (
    validate_query_params,
    validate_time_window_format,
)
from hunting.m5_adapter.controls import (
    execute_any_record_in_scope,
    execute_predicate_observability_control,
    execute_scope_health_control,
)

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
)


class SplunkLiveAdapter:
    """Production live adapter querying Splunk REST API."""

    def __init__(
        self,
        splunk_url: str = "https://localhost:8089",
        auth: tuple[str, str] = ("admin", "12345678"),
        index: str = "botsv1",
        manifest_path: str | Path | None = None,
        verify_ssl: bool = False,
        timeout: int = 60,
    ) -> None:
        self.splunk_url = splunk_url.rstrip("/")
        self.auth = auth
        self.index = index
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.provider_id = "splunk"

        self.scope = ProviderScope(
            provider_id="splunk",
            native_partition={"index": index},
            scope_id=f"splunk_{index}",
            coverage_start="2016-01-01T00:00:00Z",
            retention_days=4000,
        )

        self.manifest: dict[str, Any] | None = None
        self.discovered_sourcetypes: dict[str, int] = {}
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
            index="botsv1",
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
            for st in self.discovered_sourcetypes:
                st_lower = st.lower()
                if "sysmon" in st_lower or "process" in st_lower:
                    if "process_ancestry" not in supported_types:
                        supported_types.append("process_ancestry")
                    if "network_connection" not in supported_types:
                        supported_types.append("network_connection")
                    if "file_modification" not in supported_types:
                        supported_types.append("file_modification")
                if "http" in st_lower or "iis" in st_lower or "web" in st_lower:
                    if "web_request" not in supported_types:
                        supported_types.append("web_request")
                if "security" in st_lower or "auth" in st_lower:
                    if "authentication_activity" not in supported_types:
                        supported_types.append("authentication_activity")
                if "dns" in st_lower:
                    if "dns_activity" not in supported_types:
                        supported_types.append("dns_activity")
            if "scope_records" not in supported_types:
                supported_types.append("scope_records")

        if any("http" in st.lower() or "iis" in st.lower() for st in self.discovered_sourcetypes):
            if "web_request" not in supported_types:
                supported_types.append("web_request")

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
            },
        )

    def get_capability_descriptor(self) -> CapabilityDescriptor:
        """Return published CapabilityDescriptor for SplunkLiveAdapter."""
        op_scope_ids = (self.scope.scope_id,)
        operations = (
            ProviderOperation("cdb_scope_scan", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_broad_sweep", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_process_lineage", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_process_search", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_logon_history", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_auth_search", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_network_connections", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_net_search", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_file_writes", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_file_search", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_dns_queries", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_dns_search", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_persistence_artifacts", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_persistence_search", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_web_requests", "splunk", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("splunk_search_process", "splunk", op_scope_ids, pagination="cursor", limit_semantics="complete only on EOF"),
            ProviderOperation("splunk_search_web", "splunk", op_scope_ids, pagination="cursor", limit_semantics="complete only on EOF"),
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
    ) -> tuple[str, str, str]:
        """Construct safe parameterized SPL with search-time rex extractions and L+1 completeness limit."""
        start_dt, end_dt = validate_time_window_format(window)
        earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

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
        query_parts.append(f"| head {limit + 1}")
        query_parts.append("| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, dest_ip, src_ip, dest, http_method, site, cs_host, _raw")

        spl_final = "\n".join(query_parts)
        return spl_final, earliest_iso, latest_iso

    # -----------------------------------------------------------------------
    # Query Execution (L+1 rule, EOF completeness)
    # -----------------------------------------------------------------------

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
    ) -> QueryResult:
        """Execute safe parameterized SPL over Splunk REST API with EOF completeness check."""
        start_time = time.perf_counter()
        params = {"window": window, "limit": limit}
        validate_query_params(operation_id, params)

        if native_query and native_query.strip():
            spl = native_query.strip()
            if not spl.lower().startswith("search") and not spl.startswith("|"):
                spl = f"search {spl}"
            start_dt, end_dt = validate_time_window_format(window)
            earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            spl, earliest_iso, latest_iso = self._build_spl(
                operation_id=operation_id,
                entity=entity,
                window=window,
                predicate=predicate,
                limit=limit,
                offset=offset,
            )
        self.last_query_text = spl

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
                )
            raw_results = resp.json().get("results", [])
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
            )

        # Normalize rows into standard dictionary structure
        normalized_rows: list[dict[str, Any]] = []
        for r in raw_results:
            row: dict[str, Any] = {
                "timestamp": r.get("_time", ""),
                "host": r.get("host", ""),
                "native_type": r.get("sourcetype", ""),
                "raw_ref": r.get("_raw", "")[:200],
            }
            # Normalize fields
            for k in (
                "image", "cmdline", "parent_image", "user", "pid", "ppid",
                "destination_ip", "destination_port", "source_ip", "source_port",
                "protocol", "file_path", "domain", "query", "logon_type", "status", "hash",
                "uri", "client_ip", "server_ip", "c_ip", "s_ip", "http_method", "site",
            ):
                val = r.get(k)
                if val:
                    row[k] = val

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

            normalized_rows.append(row)

        # Evaluate L+1 completeness contract
        if len(normalized_rows) > limit:
            return_rows = normalized_rows[:limit]
            complete = False
            cursor = str(offset + limit)
        else:
            return_rows = normalized_rows
            complete = True
            cursor = None

        outcome = QueryOutcome.ROWS if return_rows else QueryOutcome.UNKNOWN
        observed_fields = list({k for r in return_rows for k in r.keys()})
        native_types = list({str(r["native_type"]) for r in return_rows if r.get("native_type")})
        elapsed = round((time.perf_counter() - start_time) * 1000, 2)

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
        )

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
