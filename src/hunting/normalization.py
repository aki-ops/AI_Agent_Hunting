"""Deterministic entity and time window normalization.

Normalizes entities and timestamps into canonical contracts:
  - Host: canonical normalized short name
  - Account: canonical (domain, username)
  - Process: (host, pid, first_seen_ts)
  - IP: normalized address
  - File: (host, normalized path)
  - Domain: lower-cased FQDN, trailing dot removed
  - TimeWindow: ISO 8601 interval normalized around alert timestamp ± W
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import (
    Account,
    Domain,
    EntityRef,
    File,
    Host,
    IPAddress,
    Process,
)
from hunting.contracts.state import Alert


def normalize_host(name: str) -> Host:
    """Normalize host identifier."""
    cleaned = name.strip()
    if "\\" in cleaned:
        cleaned = cleaned.split("\\")[-1]
    if "." in cleaned:
        cleaned = cleaned.split(".")[0]
    return Host(name=cleaned.upper())


def normalize_account(user: str, domain: str = "") -> Account:
    """Normalize user account."""
    cleaned = user.strip()
    dom = domain.strip()
    if "\\" in cleaned:
        parts = cleaned.split("\\", 1)
        dom = parts[0]
        cleaned = parts[1]
    elif "@" in cleaned:
        parts = cleaned.split("@", 1)
        cleaned = parts[0]
        dom = parts[1]
    return Account(username=cleaned)


def normalize_domain(fqdn: str) -> Domain:
    """Normalize domain name: lowercased, trailing dot removed."""
    cleaned = fqdn.strip().lower()
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]
    return Domain(name=cleaned)


def normalize_ip(addr: str) -> IPAddress:
    """Normalize IP address."""
    return IPAddress(address=addr.strip())


def normalize_file(host: str, path: str) -> File:
    """Normalize file entity with host context and normalized path."""
    norm_path = path.strip().replace("/", "\\").lower()
    return File(host=normalize_host(host).name, path=norm_path)


def normalize_process(host: str, pid: int, time: str) -> Process:
    """Normalize process entity with host, PID and timestamp."""
    return Process(host=normalize_host(host).name, pid=int(pid), time=time.strip())


def normalize_time_window(iso_ts: str, radius_seconds: int = 7200) -> str:
    """Normalize an anchor timestamp into an interval [ts - radius, ts + radius].

    Returns ISO 8601 string 'start/end'.
    """
    ts_clean = iso_ts.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(ts_clean)
    start_dt = dt - timedelta(seconds=radius_seconds)
    end_dt = dt + timedelta(seconds=radius_seconds)
    start_iso = start_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{start_iso}/{end_iso}"


def extract_alert_entities(alert: Alert) -> list[EntityRef]:
    """Deterministically extract and normalize entities from alert fields.

    Returns an empty list for entity-free alerts.
    """
    entities: list[EntityRef] = []
    fields = alert.fields or {}

    host_val = fields.get("host") or fields.get("computer_name") or fields.get("workstation")
    host_entity: Host | None = None
    if host_val:
        host_entity = normalize_host(str(host_val))
        entities.append(host_entity)

    user_val = fields.get("user") or fields.get("username") or fields.get("account")
    if user_val:
        entities.append(normalize_account(str(user_val)))

    ip_val = fields.get("ip") or fields.get("ip_address") or fields.get("src_ip") or fields.get("dst_ip")
    if ip_val:
        entities.append(normalize_ip(str(ip_val)))

    domain_val = fields.get("domain") or fields.get("query_name")
    if domain_val:
        entities.append(normalize_domain(str(domain_val)))

    pid_val = fields.get("process_pid") or fields.get("pid")
    if pid_val is not None:
        host_str = host_entity.name if host_entity else "UNKNOWN_HOST"
        ts_str = str(fields.get("timestamp") or alert.received_at)
        entities.append(normalize_process(host_str, int(pid_val), ts_str))

    path_val = fields.get("file_path") or fields.get("path")
    if path_val:
        host_str = host_entity.name if host_entity else "UNKNOWN_HOST"
        entities.append(normalize_file(host_str, str(path_val)))

    return entities


def assign_stable_scope_id(provider_id: str, native_partition: Mapping[str, str], current_id: str = "") -> str:
    """Generate or preserve a stable identifier for a ProviderScope."""
    if current_id.strip():
        return current_id.strip()
    sorted_parts = "_".join(f"{k}-{v}" for k, v in sorted(native_partition.items()))
    return f"{provider_id}_{sorted_parts}"
