"""Deterministic fact extraction from observations.

Extracts:
- Normalized entity references.
- Semantic entity relationships (e.g. parent_of, connected_to, wrote_file).
- Temporal timestamps for event correlation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunting.contracts.entities import (
    Account,
    Domain,
    EntityRef,
    File,
    Host,
    IPAddress,
    Process,
)
from hunting.contracts.observations import Observation


@dataclass(frozen=True)
class EntityRelation:
    """Directed semantic relationship between two entities."""
    source_entity: EntityRef
    relation_type: str  # e.g. "spawned_process", "logged_into", "connected_to", "wrote_file"
    target_entity: EntityRef


@dataclass(frozen=True)
class EvidenceFact:
    """Normalized structured fact extracted deterministically from an observation."""
    observation_id: str
    fact_type: str
    timestamp: str
    primary_entity: EntityRef
    fields: dict[str, Any]
    relations: tuple[EntityRelation, ...] = field(default_factory=tuple)


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely convert value to int, defaulting to default on None or invalid string."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def extract_facts(observation: Observation) -> list[EvidenceFact]:
    """Deterministically extract structured facts and relationships from an observation."""
    facts: list[EvidenceFact] = []
    host_name = observation.fields.get("host") or getattr(observation.provider_scope, "scope_id", "unknown_host")
    host_entity = Host(name=str(host_name))
    timestamp = observation.timestamp
    fields = observation.fields
    relations: list[EntityRelation] = []

    # 1. Process execution fact & ancestry relationship
    if fields.get("image") or fields.get("cmdline"):
        pid = _safe_int(fields.get("pid"), 0)
        proc_entity = Process(host=str(host_name), pid=pid, time=timestamp)
        relations.append(EntityRelation(source_entity=host_entity, relation_type="executed_process", target_entity=proc_entity))

        if fields.get("parent_image"):
            parent_pid = _safe_int(fields.get("parent_pid"), 0)
            parent_proc = Process(host=str(host_name), pid=parent_pid, time=timestamp)
            relations.append(EntityRelation(source_entity=parent_proc, relation_type="spawned_process", target_entity=proc_entity))

        facts.append(
            EvidenceFact(
                observation_id=observation.id,
                fact_type="process_execution",
                timestamp=timestamp,
                primary_entity=proc_entity,
                fields={k: v for k, v in fields.items() if k in ("image", "cmdline", "parent_image", "user") and v is not None},
                relations=tuple(relations),
            )
        )

    # 2. Network connection fact & destination relationship
    elif fields.get("destination_ip") or fields.get("remote_ip") or fields.get("ip"):
        dst_ip = fields.get("destination_ip") or fields.get("remote_ip") or fields.get("ip")
        ip_entity = IPAddress(address=str(dst_ip))
        relations.append(EntityRelation(source_entity=host_entity, relation_type="connected_to", target_entity=ip_entity))

        net_fields = {k: v for k, v in fields.items() if k in ("destination_ip", "destination_port", "protocol", "bytes_out", "ip", "port") and v is not None}
        if "ip" in net_fields and "destination_ip" not in net_fields:
            net_fields["destination_ip"] = net_fields["ip"]
        if "port" in net_fields and "destination_port" not in net_fields:
            net_fields["destination_port"] = net_fields["port"]

        facts.append(
            EvidenceFact(
                observation_id=observation.id,
                fact_type="network_connection",
                timestamp=timestamp,
                primary_entity=ip_entity,
                fields=net_fields,
                relations=tuple(relations),
            )
        )

    # 3. Authentication fact
    elif fields.get("user") and (fields.get("logon_type") or fields.get("status")):
        user_entity = Account(username=str(fields["user"]))
        relations.append(EntityRelation(source_entity=user_entity, relation_type="authenticated_on", target_entity=host_entity))

        facts.append(
            EvidenceFact(
                observation_id=observation.id,
                fact_type="authentication_activity",
                timestamp=timestamp,
                primary_entity=user_entity,
                fields={k: v for k, v in fields.items() if k in ("user", "logon_type", "source_ip", "status") and v is not None},
                relations=tuple(relations),
            )
        )

    # 4. File modification fact
    elif fields.get("file_path") or fields.get("path"):
        path = fields.get("file_path") or fields.get("path")
        file_entity = File(host=str(host_name), path=str(path))
        relations.append(EntityRelation(source_entity=host_entity, relation_type="wrote_file", target_entity=file_entity))

        facts.append(
            EvidenceFact(
                observation_id=observation.id,
                fact_type="file_modification",
                timestamp=timestamp,
                primary_entity=file_entity,
                fields={k: v for k, v in fields.items() if k in ("file_path", "path", "action", "hash") and v is not None},
                relations=tuple(relations),
            )
        )

    # 5. DNS query fact
    elif fields.get("query") or fields.get("domain"):
        dom = fields.get("query") or fields.get("domain")
        domain_entity = Domain(name=str(dom))
        relations.append(EntityRelation(source_entity=host_entity, relation_type="resolved_domain", target_entity=domain_entity))

        facts.append(
            EvidenceFact(
                observation_id=observation.id,
                fact_type="dns_activity",
                timestamp=timestamp,
                primary_entity=domain_entity,
                fields={k: v for k, v in fields.items() if k in ("query", "domain", "query_type", "response") and v is not None},
                relations=tuple(relations),
            )
        )

    # 6. Fallback generic observation fact
    else:
        facts.append(
            EvidenceFact(
                observation_id=observation.id,
                fact_type="generic_telemetry",
                timestamp=timestamp,
                primary_entity=host_entity,
                fields=dict(fields),
                relations=tuple(relations),
            )
        )

    return facts


__all__ = ["EntityRelation", "EvidenceFact", "extract_facts"]
