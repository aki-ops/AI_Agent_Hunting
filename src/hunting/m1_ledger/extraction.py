"""Deterministic envelope extraction and entity parsing for M1 Observation Ledger.

Preserves provider-native records and native types (including unknown/None).
Extracts stable cross-provider envelope fields without assuming a universal schema.
"""
from __future__ import annotations

import hashlib
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import EntityRef, Host
from hunting.contracts.observations import (
    EpistemicType,
    Observation,
    Provenance,
    SemanticType,
)
from hunting.m1_ledger.taint import label_record_taint
from hunting.normalization import (
    normalize_account,
    normalize_domain,
    normalize_file,
    normalize_host,
    normalize_ip,
    normalize_process,
)


def extract_timestamp(record: dict[str, Any]) -> str:
    """Extract standard ISO timestamp from heterogeneous provider records."""
    for key in ("timestamp", "@timestamp", "time", "EventTime", "TimeCreated", "utc_time"):
        val = record.get(key)
        if val:
            return str(val).strip()
    return "UNKNOWN_TIMESTAMP"


def extract_native_type(record: dict[str, Any]) -> str | None:
    """Preserve native provider event code or event type verbatim.

    Returns None if provider record has no native event code.
    """
    for key in ("native_type", "event_id", "EventID", "event_type", "event_code", "opcode"):
        val = record.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return None


def extract_record_entities(record: dict[str, Any], default_host: str = "") -> list[EntityRef]:
    """Deterministically extract typed entity references from record fields."""
    entities: list[EntityRef] = []

    # Host
    host_val = record.get("host") or record.get("Computer") or record.get("workstation") or default_host
    host_ent: Host | None = None
    if host_val:
        host_ent = normalize_host(str(host_val))
        entities.append(host_ent)

    # Account
    user_val = record.get("user") or record.get("username") or record.get("TargetUserName") or record.get("SubjectUserName")
    if user_val:
        entities.append(normalize_account(str(user_val)))

    # Process
    pid_val = record.get("pid") or record.get("process_pid") or record.get("ProcessId") or record.get("NewProcessId")
    if pid_val is not None:
        try:
            pid_int = int(pid_val)
            h_str = host_ent.name if host_ent else "UNKNOWN_HOST"
            t_str = extract_timestamp(record)
            entities.append(normalize_process(h_str, pid_int, t_str))
        except (ValueError, TypeError):
            pass

    # IP
    for ip_key in ("ip", "src_ip", "dst_ip", "ip_address", "IpAddress", "destination_ip", "source_ip"):
        val = record.get(ip_key)
        if val and str(val).strip():
            entities.append(normalize_ip(str(val)))

    # Domain
    for dom_key in ("domain", "query_name", "dns_query", "DestinationDomain"):
        val = record.get(dom_key)
        if val and str(val).strip():
            entities.append(normalize_domain(str(val)))

    # File
    for file_key in ("file_path", "path", "TargetFilename", "Image", "image_path"):
        val = record.get(file_key)
        if val and str(val).strip():
            h_str = host_ent.name if host_ent else "UNKNOWN_HOST"
            entities.append(normalize_file(h_str, str(val)))

    # Deduplicate entities preserving order
    seen: set[tuple[Any, ...]] = set()
    deduped: list[EntityRef] = []
    for e in entities:
        key = (e.kind, getattr(e, "name", None), getattr(e, "username", None), getattr(e, "pid", None), getattr(e, "address", None), getattr(e, "path", None))
        if key not in seen:
            seen.add(key)
            deduped.append(e)

    return deduped


def build_observation(
    record: dict[str, Any],
    provider_scope: ProviderScope,
    cell_id: str,
    raw_ref: str,
    query_id: str,
    collector: str,
    ingest_time: str,
    semantic_type: SemanticType | str | None = None,
    obs_id: str | None = None,
) -> Observation:
    """Build a complete typed Observation from a parsed telemetry record."""
    timestamp = extract_timestamp(record)
    native_type = extract_native_type(record)
    entities = extract_record_entities(record, default_host=provider_scope.native_partition.get("host", ""))
    taint_map = label_record_taint(record)

    prov = Provenance(
        query_id=query_id,
        collector=collector,
        ingest_time=ingest_time,
        native_partition=dict(provider_scope.native_partition),
    )

    if not obs_id:
        # Deterministic hash ID
        identity_basis = f"{cell_id}:{raw_ref}:{timestamp}:{native_type}"
        obs_hash = hashlib.sha256(identity_basis.encode("utf-8")).hexdigest()[:12]
        obs_id = f"obs-{obs_hash}"

    return Observation(
        id=obs_id,
        provider_scope=provider_scope,
        cell_id=cell_id,
        timestamp=timestamp,
        epistemic_type=EpistemicType.OBSERVED,
        native_type=native_type,
        semantic_type=semantic_type,
        fields=dict(record),
        taint=taint_map,
        entities=entities,
        provenance=prov,
        raw_ref=raw_ref,
        attributed_by=[],
        demanding=False,
    )


__all__ = [
    "extract_timestamp",
    "extract_native_type",
    "extract_record_entities",
    "build_observation",
]
