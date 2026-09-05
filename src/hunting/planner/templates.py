"""Safe Query Templates for threat hunting execution.

Enforces template-first execution:
- Declares parameterized query plans for core requirements.
- Restricts predicates and operations to safe allowlisted fields.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunting.contracts.expectations import EvidenceRequirement


@dataclass(frozen=True)
class QueryTemplate:
    """Safe parameterized query template."""
    id: str
    requirement_type: str
    operation_id: str
    parameters_template: dict[str, Any]
    allowed_fields: tuple[str, ...]
    allowed_operators: tuple[str, ...]
    estimated_cost: int = 1


def build_default_query_templates() -> dict[str, QueryTemplate]:
    """Construct safe query templates for core evidence requirements."""
    templates: dict[str, QueryTemplate] = {}

    # 1. PROCESS ANCESTRY
    templates[EvidenceRequirement.PROCESS_ANCESTRY.value] = QueryTemplate(
        id="tmpl-q-process-ancestry",
        requirement_type=EvidenceRequirement.PROCESS_ANCESTRY.value,
        operation_id="cdb_process_lineage",
        parameters_template={"host": "{host}", "window": "{window}"},
        allowed_fields=("host", "image", "parent_image", "cmdline", "pid"),
        allowed_operators=("EQUALS", "CONTAINS", "EXISTS"),
        estimated_cost=1,
    )

    # 2. AUTHENTICATION ACTIVITY
    templates[EvidenceRequirement.AUTHENTICATION_ACTIVITY.value] = QueryTemplate(
        id="tmpl-q-logon-history",
        requirement_type=EvidenceRequirement.AUTHENTICATION_ACTIVITY.value,
        operation_id="cdb_logon_history",
        parameters_template={"user": "{user}", "window": "{window}"},
        allowed_fields=("user", "logon_type", "source_ip", "status"),
        allowed_operators=("EQUALS", "CONTAINS"),
        estimated_cost=1,
    )

    # 3. NETWORK CONNECTION
    templates[EvidenceRequirement.NETWORK_CONNECTION.value] = QueryTemplate(
        id="tmpl-q-network-conn",
        requirement_type=EvidenceRequirement.NETWORK_CONNECTION.value,
        operation_id="cdb_network_connections",
        parameters_template={"ip": "{ip}", "window": "{window}"},
        allowed_fields=("destination_ip", "destination_port", "protocol"),
        allowed_operators=("EQUALS", "CONTAINS"),
        estimated_cost=1,
    )

    # 4. FILE MODIFICATION
    templates[EvidenceRequirement.FILE_MODIFICATION.value] = QueryTemplate(
        id="tmpl-q-file-writes",
        requirement_type=EvidenceRequirement.FILE_MODIFICATION.value,
        operation_id="cdb_file_writes",
        parameters_template={"path": "{path}", "window": "{window}"},
        allowed_fields=("file_path", "action", "hash"),
        allowed_operators=("EQUALS", "CONTAINS", "EXISTS"),
        estimated_cost=1,
    )

    # 5. DNS ACTIVITY
    templates[EvidenceRequirement.DNS_ACTIVITY.value] = QueryTemplate(
        id="tmpl-q-dns-queries",
        requirement_type=EvidenceRequirement.DNS_ACTIVITY.value,
        operation_id="cdb_dns_queries",
        parameters_template={"domain": "{domain}", "window": "{window}"},
        allowed_fields=("query", "query_type", "response"),
        allowed_operators=("EQUALS", "CONTAINS"),
        estimated_cost=1,
    )

    # 6. PERSISTENCE CHANGE
    templates[EvidenceRequirement.PERSISTENCE_CHANGE.value] = QueryTemplate(
        id="tmpl-q-persistence",
        requirement_type=EvidenceRequirement.PERSISTENCE_CHANGE.value,
        operation_id="cdb_persistence_artifacts",
        parameters_template={"host": "{host}", "window": "{window}"},
        allowed_fields=("task_name", "registry_key", "service_name"),
        allowed_operators=("EQUALS", "CONTAINS", "EXISTS"),
        estimated_cost=1,
    )

    # 7. SCOPE RECORDS (BROAD SWEEP)
    templates[EvidenceRequirement.SCOPE_RECORDS.value] = QueryTemplate(
        id="tmpl-q-broad-sweep",
        requirement_type=EvidenceRequirement.SCOPE_RECORDS.value,
        operation_id="cdb_broad_sweep",
        parameters_template={"window": "{window}", "limit": 100},
        allowed_fields=("window", "limit"),
        allowed_operators=("EQUALS",),
        estimated_cost=2,
    )

    # 8. WEB REQUESTS
    templates[EvidenceRequirement.WEB_REQUEST.value] = QueryTemplate(
        id="tmpl-q-web-requests",
        requirement_type=EvidenceRequirement.WEB_REQUEST.value,
        operation_id="cdb_web_requests",
        parameters_template={"domain": "{domain}", "window": "{window}"},
        allowed_fields=("uri", "domain", "host", "client_ip", "server_ip", "c_ip", "s_ip", "http_method", "site"),
        allowed_operators=("EQUALS", "CONTAINS", "EXISTS"),
        estimated_cost=1,
    )

    return templates


__all__ = ["QueryTemplate", "build_default_query_templates"]
