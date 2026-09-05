"""Deployment-specific versioned capability descriptors."""
from __future__ import annotations

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.contracts.cells import ProviderScope
from hunting.contracts.expectations import EvidenceRequirement
from hunting.contracts.queries import CapabilityBinding, ProviderOperation


def build_default_capability_registry() -> dict[str, VersionedCapabilityDescriptor]:
    """Construct versioned capability descriptors for supported environments."""
    registry: dict[str, VersionedCapabilityDescriptor] = {}

    # 1. CDB SQLite (Local Evaluation / Unit Test Telemetry)
    cdb_scope = ProviderScope(
        provider_id="cdb_sqlite",
        scope_id="cdb_native_scope",
        native_partition={"table": "events"},
        coverage_start="2026-01-01T00:00:00Z",
        retention_days=90,
    )

    cdb_operations = (
        ProviderOperation(
            id="cdb_process_lineage",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"host": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_logon_history",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"user": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_network_connections",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"ip": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_file_writes",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"path": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_dns_queries",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"domain": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_persistence_artifacts",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"host": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_broad_sweep",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"window": "interval", "limit": "integer"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_web_requests",
            provider_id="cdb_sqlite",
            scope_ids=("cdb_native_scope",),
            params_schema={"domain": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
    )

    cdb_bindings = (
        CapabilityBinding(evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY, provider_id="cdb_sqlite", operation_id="cdb_process_lineage", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.AUTHENTICATION_ACTIVITY, provider_id="cdb_sqlite", operation_id="cdb_logon_history", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.NETWORK_CONNECTION, provider_id="cdb_sqlite", operation_id="cdb_network_connections", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.FILE_MODIFICATION, provider_id="cdb_sqlite", operation_id="cdb_file_writes", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.DNS_ACTIVITY, provider_id="cdb_sqlite", operation_id="cdb_dns_queries", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.PERSISTENCE_CHANGE, provider_id="cdb_sqlite", operation_id="cdb_persistence_artifacts", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.SCOPE_RECORDS, provider_id="cdb_sqlite", operation_id="cdb_broad_sweep", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.WEB_REQUEST, provider_id="cdb_sqlite", operation_id="cdb_web_requests", confidence="EXACT"),
    )

    registry["cdb_sqlite"] = VersionedCapabilityDescriptor(
        provider_id="cdb_sqlite",
        version="2026.1.0",
        deployment_env="enterprise-prod",
        scopes=(cdb_scope,),
        operations=cdb_operations,
        bindings=cdb_bindings,
        supported_entity_kinds=("host", "account", "process", "ip", "file", "domain", "ANY"),
        permissions=("read_sqlite",),
        observable_fields=("image", "parent_image", "cmdline", "pid", "user", "logon_type", "destination_ip", "destination_port", "file_path", "task_name", "query", "uri", "site", "http_method"),
        completeness_contract="complete",
    )
    registry["cdb"] = registry["cdb_sqlite"]

    # 2. Splunk Enterprise
    splunk_scope = ProviderScope(
        provider_id="splunk",
        scope_id="splunk_live",
        native_partition={"index": "botsv1"},
        coverage_start="2016-01-01T00:00:00Z",
        retention_days=4000,
    )

    splunk_operations = (
        ProviderOperation(
            id="cdb_process_lineage",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"host": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_logon_history",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"user": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_network_connections",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"ip": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_file_writes",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"path": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_dns_queries",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"domain": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_persistence_artifacts",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"host": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_broad_sweep",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"window": "interval", "limit": "integer"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="cdb_web_requests",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"domain": "string", "window": "interval"},
            pagination="offset",
            limit_semantics="complete up to limit",
        ),
        ProviderOperation(
            id="splunk_search_process",
            provider_id="splunk",
            scope_ids=("splunk_live",),
            params_schema={"search": "spl", "earliest": "time", "latest": "time"},
            pagination="cursor",
            limit_semantics="complete only on EOF",
        ),
    )

    splunk_bindings = (
        CapabilityBinding(evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY, provider_id="splunk", operation_id="cdb_process_lineage", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.AUTHENTICATION_ACTIVITY, provider_id="splunk", operation_id="cdb_logon_history", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.NETWORK_CONNECTION, provider_id="splunk", operation_id="cdb_network_connections", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.FILE_MODIFICATION, provider_id="splunk", operation_id="cdb_file_writes", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.DNS_ACTIVITY, provider_id="splunk", operation_id="cdb_dns_queries", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.PERSISTENCE_CHANGE, provider_id="splunk", operation_id="cdb_persistence_artifacts", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.SCOPE_RECORDS, provider_id="splunk", operation_id="cdb_broad_sweep", confidence="EXACT"),
        CapabilityBinding(evidence_requirement=EvidenceRequirement.WEB_REQUEST, provider_id="splunk", operation_id="cdb_web_requests", confidence="EXACT"),
    )

    registry["splunk"] = VersionedCapabilityDescriptor(
        provider_id="splunk",
        version="9.2.1",
        deployment_env="enterprise-prod",
        scopes=(splunk_scope,),
        operations=splunk_operations,
        bindings=splunk_bindings,
        supported_entity_kinds=("host", "account", "process", "ip", "file", "domain", "ANY"),
        permissions=("search_job_create", "results_read", "read"),
        observable_fields=(
            "Image", "ParentImage", "CommandLine", "ProcessId", "User",
            "image", "parent_image", "cmdline", "pid", "ppid", "user",
            "destination_ip", "destination_port", "source_ip", "source_port",
            "file_path", "logon_type", "domain", "query", "hash",
            "uri", "site", "http_method", "client_ip", "server_ip", "c_ip", "s_ip",
        ),
        completeness_contract="complete",
    )

    return registry


__all__ = ["build_default_capability_registry"]
