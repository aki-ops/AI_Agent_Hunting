"""Adapter allowlist validation for native queries and parameters.

Enforces:
  - All operations, fields, and predicates must be explicitly allowlisted.
  - Queries are template/allowlist-first; arbitrary text execution is rejected.
  - Time intervals, limits, and pagination parameters are validated strictly.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from hunting.contracts.expectations import FieldPredicate

_ALLOWLISTED_OPERATIONS = frozenset({
    "cdb_scope_scan",
    "cdb_broad_sweep",
    "cdb_process_search",
    "cdb_process_lineage",
    "cdb_auth_search",
    "cdb_logon_history",
    "cdb_net_search",
    "cdb_network_connections",
    "cdb_persistence_search",
    "cdb_persistence_artifacts",
    "cdb_file_search",
    "cdb_file_writes",
    "cdb_dns_search",
    "cdb_dns_queries",
})

_ALLOWLISTED_FIELDS = frozenset({
    "timestamp",
    "@timestamp",
    "time",
    "host",
    "computer",
    "workstation",
    "user",
    "username",
    "target_user",
    "pid",
    "process_pid",
    "ppid",
    "parent_pid",
    "cmdline",
    "command_line",
    "image",
    "image_path",
    "ip",
    "src_ip",
    "dst_ip",
    "port",
    "src_port",
    "dst_port",
    "domain",
    "query_name",
    "file_path",
    "path",
    "event_id",
    "event_code",
    "native_type",
    "action",
    "status",
})


def validate_operation_id(operation_id: str) -> None:
    """Ensure operation is within allowlist."""
    if operation_id not in _ALLOWLISTED_OPERATIONS:
        raise ValueError(f"Disallowed operation '{operation_id}'; not in adapter allowlist")


def validate_field_name(field_name: str) -> None:
    """Ensure field is within allowlist."""
    if field_name.strip().lower() not in _ALLOWLISTED_FIELDS:
        raise ValueError(f"Disallowed field '{field_name}'; not in adapter allowlist")


def validate_time_window_format(window_str: str) -> tuple[datetime, datetime]:
    """Validate and parse 'start/end' ISO interval or relative lookback."""
    if "/" not in window_str:
        raise ValueError(f"Invalid window format '{window_str}'; expected 'start/end'")
    start_str, end_str = window_str.split("/", 1)

    # Handle NOW-relative format (e.g. NOW-14d/NOW)
    now = datetime.now(timezone.utc)
    if start_str.startswith("NOW-") and end_str == "NOW":
        m = re.match(r"^NOW-(\d+)([dhm])$", start_str)
        if m:
            val, unit = int(m.group(1)), m.group(2)
            if unit == "d":
                delta = timedelta(days=val)
            elif unit == "h":
                delta = timedelta(hours=val)
            else:
                delta = timedelta(minutes=val)
            return now - delta, now

    try:
        start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        if end_str.startswith("P") and end_str.endswith("D"):
            days = int(end_str[1:-1])
            end_dt = start_dt + timedelta(days=days)
        else:
            end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    except Exception as err:
        raise ValueError(f"Malformed ISO timestamp in window '{window_str}': {err}") from err

    if end_dt <= start_dt:
        raise ValueError(f"Invalid window interval '{window_str}': end <= start")
    return start_dt, end_dt


def validate_query_params(
    operation_id: str,
    params: dict[str, Any],
    max_limit: int = 10000,
) -> None:
    """Validate query parameters against adapter allowlist."""
    validate_operation_id(operation_id)

    window = params.get("window")
    if window:
        validate_time_window_format(str(window))

    limit = params.get("limit")
    if limit is not None:
        if not isinstance(limit, int) or limit <= 0 or limit > max_limit:
            raise ValueError(f"Parameter 'limit' must be an integer between 1 and {max_limit}")

    field_filter = params.get("field")
    if field_filter:
        validate_field_name(str(field_filter))

    predicate = params.get("predicate")
    if predicate and isinstance(predicate, FieldPredicate):
        validate_field_name(predicate.field)


__all__ = [
    "validate_operation_id",
    "validate_field_name",
    "validate_time_window_format",
    "validate_query_params",
]
