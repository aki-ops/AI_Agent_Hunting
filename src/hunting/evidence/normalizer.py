"""Deterministic field normalization across telemetry providers.

Preserves native field names verbatim for forensic audit and query replay,
while mapping them to canonical cross-provider semantic field concepts.
"""
from __future__ import annotations

from typing import Any

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "file_path": ("Path", "TargetFilename", "file_path", "path", "image_path", "TargetFileName"),
    "process_name": ("Name", "Image", "process_name", "image", "process", "app", "SourceImage"),
    "command_line": ("CommandLine", "cmdline", "command_line", "process_exec"),
    "software_version": ("ProductVersion", "FileVersion", "Version", "version", "software_version"),
    "host": ("host", "ComputerName", "Computer", "workstation_name", "workstation", "dvc", "dest_nt_host"),
    "user": ("user", "username", "TargetUserName", "Account_Name", "SubjectUserName", "src_user", "dest_user"),
    "domain": ("domain", "site", "cs_host", "query", "dest_host", "destination_host"),
    "destination_ip": ("destination_ip", "dest_ip", "server_ip", "s_ip", "DestinationIp", "remote_ip", "dest"),
    "source_ip": ("source_ip", "src_ip", "client_ip", "c_ip", "SourceIp", "IpAddress", "src"),
    "destination_port": ("destination_port", "dest_port", "server_port", "DestinationPort", "dport"),
    "source_port": ("source_port", "src_port", "client_port", "SourcePort", "sport"),
    "protocol": ("protocol", "proto", "transport"),
    "sender_email": ("sender_email", "sender", "src_user_email"),
    "recipient_email": ("receiver_email", "receiver", "recipient_email", "recipient", "dest_user_email"),
    "message_id": ("msg_id", "message_id", "mid"),
    "subject": ("subject", "mail_subject"),
    "uri": ("uri", "url", "cs_uri_stem", "cs_uri_query"),
    "http_method": ("http_method", "cs_method", "method"),
    "http_status": ("status", "sc_status", "response_code"),
    "timestamp": ("_time", "timestamp", "time", "EventTime", "TimeCreated", "utc_time"),
}

# Reverse mapping: alias (casefold) -> canonical field name
ALIAS_TO_CANONICAL: dict[str, str] = {}
for canonical, aliases in FIELD_ALIASES.items():
    for alias in aliases:
        ALIAS_TO_CANONICAL[alias.casefold()] = canonical


def normalize_telemetry_fields(
    raw_record: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a raw telemetry record into (native_fields, canonical_fields).

    native_fields: Exact key-values as returned by the data provider.
    canonical_fields: Unified semantic representation mapped via FIELD_ALIASES.
    """
    native_fields = dict(raw_record)
    canonical_fields: dict[str, Any] = {}

    for key, value in raw_record.items():
        if value is None or value == "":
            continue
        key_cf = str(key).casefold()
        canonical_name = ALIAS_TO_CANONICAL.get(key_cf)
        if canonical_name and canonical_name not in canonical_fields:
            canonical_fields[canonical_name] = value

    # Explicit multi-field canonical resolution
    for canonical_name, aliases in FIELD_ALIASES.items():
        if canonical_name not in canonical_fields:
            for alias in aliases:
                for r_k, r_v in raw_record.items():
                    if str(r_k).casefold() == alias.casefold() and r_v not in (None, "", [], {}):
                        canonical_fields[canonical_name] = r_v
                        break
                if canonical_name in canonical_fields:
                    break

    return native_fields, canonical_fields


def get_canonical_field(record: dict[str, Any], canonical_name: str, default: Any = None) -> Any:
    """Retrieve a field value by its canonical semantic name."""
    # Check direct canonical key
    if canonical_name in record and record[canonical_name] not in (None, "", [], {}):
        return record[canonical_name]
    # Check known aliases
    aliases = FIELD_ALIASES.get(canonical_name, (canonical_name,))
    for alias in aliases:
        for k, v in record.items():
            if str(k).casefold() == alias.casefold() and v not in (None, "", [], {}):
                return v
    return default
