"""Deterministic per-field taint labelling (C10).

Classifies observation fields as ATTACKER_INFLUENCED or STRUCTURAL:
  - ATTACKER_INFLUENCED: fields where the adversary controlled content or arguments.
  - STRUCTURAL: system/collector generated telemetry metadata.
  - Conservative default: when a field's provenance is unknown, it defaults to ATTACKER_INFLUENCED.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.observations import TaintLabel

_STRUCTURAL_FIELDS = frozenset({
    "ts",
    "timestamp",
    "@timestamp",
    "time",
    "pid",
    "process_pid",
    "process_id",
    "ppid",
    "parent_pid",
    "parent_process_id",
    "host",
    "computer_name",
    "workstation_name",
    "logon_type",
    "protocol",
    "proto",
    "src_port",
    "source_port",
    "dst_port",
    "destination_port",
    "event_id",
    "event_code",
    "opcode",
    "version",
    "collector",
    "provider_id",
    "scope_id",
    "channel",
    "flow_id",
    "session_id",
    "status_code",
})

_ATTACKER_INFLUENCED_FIELDS = frozenset({
    "cmdline",
    "command_line",
    "process_command_line",
    "image",
    "image_path",
    "process_path",
    "path",
    "file_path",
    "target_filename",
    "query_name",
    "dns_query",
    "domain",
    "task_name",
    "scheduled_task_name",
    "action",
    "script_block_text",
    "script_text",
    "url",
    "uri",
    "http_user_agent",
    "user_agent",
    "payload",
    "raw_data",
    "arguments",
    "parameter",
    "registry_value_name",
    "registry_value_data",
})


def label_field_taint(field_name: str, value: Any = None, context: dict[str, Any] | None = None) -> TaintLabel:
    """Deterministically assign taint label to a field name and value."""
    fn_lower = field_name.strip().lower()

    if fn_lower in _STRUCTURAL_FIELDS:
        return TaintLabel.STRUCTURAL

    if fn_lower in _ATTACKER_INFLUENCED_FIELDS:
        return TaintLabel.ATTACKER_INFLUENCED

    # Partial / substring heuristics for common patterns
    if any(s in fn_lower for s in ("cmd", "command", "query", "url", "path", "script", "payload")):
        return TaintLabel.ATTACKER_INFLUENCED

    if any(s in fn_lower for s in ("port", "time", "id", "pid", "status")):
        return TaintLabel.STRUCTURAL

    # Special case: user field when logon failed or attacker-supplied
    if fn_lower in ("user", "username", "target_user"):
        if context and context.get("logon_status") in ("failed", "failure", 4625):
            return TaintLabel.ATTACKER_INFLUENCED
        return TaintLabel.STRUCTURAL

    # Conservative default for unknown/unclassified fields
    return TaintLabel.ATTACKER_INFLUENCED


def label_record_taint(fields: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, TaintLabel]:
    """Apply deterministic taint labelling across all fields of a record."""
    return {
        field_name: label_field_taint(field_name, field_value, context=fields)
        for field_name, field_value in fields.items()
    }


__all__ = ["label_field_taint", "label_record_taint"]
