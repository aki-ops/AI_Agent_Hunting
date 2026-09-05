"""Native query compilers for provider backends (Splunk, CDB).

Translates a provider-neutral LogicalQueryPlan into an executable NativeQueryPlan.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from hunting.contracts.entities import (
    ANY,
    Account,
    AnyEntity,
    Domain,
    File,
    Host,
    IPAddress,
    Process,
)
from hunting.contracts.hunt import LogicalQueryPlan, NativeQueryPlan
from hunting.m5_adapter.allowlist import validate_time_window_format

logger = logging.getLogger(__name__)


class NativeQueryCompiler(ABC):
    """Abstract compiler translating LogicalQueryPlan to provider native query."""

    @abstractmethod
    def compile(self, plan: LogicalQueryPlan) -> NativeQueryPlan:
        """Compile logical query plan into executable native query plan."""
        raise NotImplementedError


class SplunkQueryCompiler(NativeQueryCompiler):
    """Compiles LogicalQueryPlan into safe, parameterized SPL for Splunk."""

    def __init__(self, default_index: str = "botsv1") -> None:
        self.default_index = default_index

    def compile(self, plan: LogicalQueryPlan) -> NativeQueryPlan:
        """Compile LogicalQueryPlan into NativeQueryPlan with SPL query."""
        # 1. Resolve time window
        start_dt, end_dt = validate_time_window_format(plan.time_window)
        earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # 2. Determine index and sourcetype from data_sources or requirement_id
        index = self.default_index
        sourcetype: str | None = None
        event_filter: str | None = None

        if plan.data_sources:
            ds = plan.data_sources[0]
            index = ds.get("index", self.default_index)
            sourcetype = ds.get("sourcetype")
            event_filter = ds.get("event_filter")

        # Derive sourcetype if not specified in data_sources
        ev_type = (getattr(plan, "evidence_type", "") or "").lower()
        if not ev_type:
            req_id_lower = plan.requirement_id.lower()
            ev_type = req_id_lower.rsplit("-", 1)[-1] if "-" in req_id_lower else req_id_lower

        rex_clauses: list[str] = []

        if "process" in ev_type or "proc" in ev_type:
            sourcetype = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            event_filter = "*EventID>1<*"
            rex_clauses.extend([
                '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'CommandLine\'>(?<cmdline>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'ParentImage\'>(?<parent_image>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'User\'>(?<user>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'ProcessId\'>(?<pid>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'ParentProcessId\'>(?<ppid>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'Hashes\'>(?<hash>[^<]+)</Data>"',
            ])
        elif "file" in ev_type:
            sourcetype = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            event_filter = "*EventID>11<*"
            rex_clauses.extend([
                '| rex field=_raw "<Data Name=\'TargetFilename\'>(?<file_path>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
            ])
        elif "net" in ev_type or "beacon" in ev_type:
            sourcetype = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            event_filter = "*EventID>3<*"
            rex_clauses.extend([
                '| rex field=_raw "<Data Name=\'DestinationIp\'>(?<destination_ip>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'DestinationPort\'>(?<destination_port>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'SourceIp\'>(?<source_ip>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'SourcePort\'>(?<source_port>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'Protocol\'>(?<protocol>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
            ])
        elif "auth" in ev_type:
            sourcetype = "WinEventLog:Security"
            event_filter = "(EventCode=4624 OR EventCode=4625)"
            rex_clauses.extend([
                '| rex field=Message "Account Name:\\s*(?<user>[^\\r\\n]+)"',
                '| rex field=Message "Logon Type:\\s*(?<logon_type>\\d+)"',
            ])
        elif "dns" in ev_type:
            sourcetype = "stream:dns"
        elif "pers" in ev_type:
            sourcetype = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            event_filter = '("*EventID>12<*" OR "*EventID>13<*")'
            rex_clauses.extend([
                '| rex field=_raw "<Data Name=\'TargetObject\'>(?<registry_key>[^<]+)</Data>"',
                '| rex field=_raw "<Data Name=\'Image\'>(?<image>[^<]+)</Data>"',
            ])
        elif "web" in ev_type or "http" in ev_type:
            sourcetype = '(sourcetype="stream:http" OR sourcetype="iis")'

        if "sourcetype" in plan.constraints and plan.constraints["sourcetype"]:
            sourcetype = plan.constraints["sourcetype"]

        spl_parts: list[str] = [f'search index="{index}"']
        if sourcetype and sourcetype != "*":
            if sourcetype.startswith("(") and sourcetype.endswith(")"):
                spl_parts.append(sourcetype)
            elif " OR " in sourcetype:
                spl_parts.append(f"({sourcetype})")
            else:
                spl_parts.append(f'sourcetype="{sourcetype}"')
        if event_filter and event_filter != "*":
            spl_parts.append(event_filter)

        # 3. Entity Filtering
        entity = plan.entity
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

        # Domain filtering from constraints or filters - ONLY for web/net/dns queries
        is_web_or_net = any(k in ev_type for k in ("web", "http", "net", "network", "beacon", "dns"))
        domain_constraint = plan.constraints.get("domain") or plan.constraints.get("site")
        if not domain_constraint and is_web_or_net:
            for f in plan.filters:
                if f.get("field") in ("site", "domain") and f.get("value"):
                    domain_constraint = f.get("value")
                    break
        if is_web_or_net and domain_constraint:
            d_name = str(domain_constraint).strip()
            d_root = d_name[4:] if d_name.lower().startswith("www.") else d_name
            dom_spl = f'(site="*{d_root}*" OR cs_host="*{d_root}*" OR "{d_name}" OR "{d_root}")'
            if dom_spl not in spl_parts and f'("{d_name}" OR "{d_root}")' not in spl_parts:
                spl_parts.append(dom_spl)

        # 4. Predicate filters
        filter_clauses: list[str] = []
        for f in plan.filters:
            fn = str(f.get("field", "")).strip().lower()
            op = str(f.get("op", "EXISTS")).upper()
            val = str(f.get("value", "")).strip()
            if not fn:
                continue
            if fn in ("site", "domain"):
                if is_web_or_net:
                    if op == "EQUALS":
                        filter_clauses.append(f'| eval site=coalesce(site, cs_host) | where lower(site)="{val.lower()}"')
                    elif op == "CONTAINS":
                        filter_clauses.append(f'| eval site=coalesce(site, cs_host) | where like(lower(site), "%{val.lower()}%")')
                    elif op == "EXISTS":
                        filter_clauses.append('| eval site=coalesce(site, cs_host) | where isnotnull(site) AND site!=""')
                    elif op == "ABSENT":
                        filter_clauses.append('| eval site=coalesce(site, cs_host) | where isnull(site) OR site==""')
            elif op == "EQUALS":
                filter_clauses.append(f'| where {fn}="{val}"')
            elif op == "CONTAINS":
                filter_clauses.append(f'| where like(lower({fn}), "%{val.lower()}%")')
            elif op == "EXISTS":
                filter_clauses.append(f'| where isnotnull({fn}) AND {fn}!=""')
            elif op == "ABSENT":
                filter_clauses.append(f'| where isnull({fn}) OR {fn}==""')

        # 5. Strict L+1 Completeness contract: fetch limit + 1
        custom_query = plan.constraints.get("custom_query") or plan.constraints.get("custom_field")
        if custom_query and str(custom_query).strip():
            cq = str(custom_query).strip()
            if cq.startswith("```"):
                lines = [line for line in cq.splitlines() if not line.startswith("```")]
                cq = "\n".join(lines).strip()
            if cq.lower().startswith("search ") or cq.startswith("|"):
                spl_final = cq
                if f"head {plan.limit + 1}" not in spl_final and "| head" not in spl_final:
                    spl_final = f"{spl_final}\n| head {plan.limit + 1}"
                if "| table" not in spl_final:
                    spl_final = f"{spl_final}\n| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, http_method, site, cs_host, _raw"
                return NativeQueryPlan(
                    id=f"nqp-{plan.id}",
                    logical_plan_id=plan.id,
                    provider="splunk",
                    native_query=spl_final,
                    time_range=(earliest_iso, latest_iso),
                    limit=plan.limit,
                )
            elif not cq.startswith("{"):
                spl_parts.append(f"({cq})")

        query_parts = [" ".join(spl_parts)]
        query_parts.extend(rex_clauses)
        query_parts.extend(filter_clauses)
        query_parts.append(f"| head {plan.limit + 1}")
        query_parts.append("| table _time, host, sourcetype, image, cmdline, parent_image, user, pid, ppid, destination_ip, destination_port, source_ip, source_port, protocol, file_path, domain, query, logon_type, status, hash, uri, cs_uri_stem, cs_method, client_ip, server_ip, c_ip, s_ip, http_method, site, cs_host, _raw")

        spl_final = "\n".join(query_parts)
        return NativeQueryPlan(
            id=f"nqp-{plan.id}",
            logical_plan_id=plan.id,
            provider="splunk",
            native_query=spl_final,
            time_range=(earliest_iso, latest_iso),
            limit=plan.limit,
        )


class CdbQueryCompiler(NativeQueryCompiler):
    """Compiles LogicalQueryPlan into native CDB parameters."""

    def compile(self, plan: LogicalQueryPlan) -> NativeQueryPlan:
        """Compile LogicalQueryPlan into NativeQueryPlan for CDB."""
        custom_query = plan.constraints.get("custom_query") or plan.constraints.get("custom_field")
        if custom_query and str(custom_query).strip():
            query_text = f"CDB_QUERY({plan.requirement_id}, custom={custom_query}, entity={getattr(plan.entity, 'name', 'ANY')}, window={plan.time_window}, limit={plan.limit})"
        else:
            query_text = f"CDB_QUERY({plan.requirement_id}, entity={getattr(plan.entity, 'name', 'ANY')}, window={plan.time_window}, limit={plan.limit})"
        return NativeQueryPlan(
            id=f"nqp-{plan.id}",
            logical_plan_id=plan.id,
            provider="cdb",
            native_query=query_text,
            time_range=("", ""),
            limit=plan.limit,
        )


__all__ = ["NativeQueryCompiler", "SplunkQueryCompiler", "CdbQueryCompiler"]
