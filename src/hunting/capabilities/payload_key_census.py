"""Bounded, provider-neutral discovery of keys inside opaque payloads.

The census records only key names and provenance.  It deliberately does not
interpret a key as a semantic fact and never stores payload values.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

from hunting.contracts.source_profile import TelemetryFieldProfile


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
_KEY_PATTERN = re.compile(r"(?:[\"'])([A-Za-z_][A-Za-z0-9_.:-]{0,127})(?:[\"'])\s*:")


def _payload_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            return ""
    return ""


def _json_paths(value: Any, prefix: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).strip()
            if not _IDENTIFIER.fullmatch(key_text):
                continue
            path = f"{prefix}.{key_text}" if prefix else key_text
            yield path
            yield from _json_paths(child, path)
    elif isinstance(value, list):
        # Array indexes are intentionally omitted.  A semantic field should
        # be addressable by its stable object path across rows.
        for child in value[:20]:
            yield from _json_paths(child, prefix)


def discover_payload_fields(
    source_id: str,
    rows: Iterable[dict[str, Any]],
    *,
    evidence_query_id: str,
    parent_fields: tuple[str, ...] = ("_raw", "raw", "payload", "raw_event"),
    max_keys: int = 128,
) -> tuple[tuple[TelemetryFieldProfile, ...], dict[str, Any]]:
    """Discover bounded nested keys from sample rows.

    JSON is parsed first, including a second pass for JSON strings embedded in
    ``_raw``.  Non-JSON payloads fall back to conservative quoted-key
    extraction.  Only names are returned; values are never persisted.
    """
    keys: dict[tuple[str, str], None] = {}
    rows_seen = 0
    hit_key_bound = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        rows_seen += 1
        # Provider-side key census may return only names (no raw payload).
        # This is preferred when available because it avoids transferring
        # sensitive content to the agent while still discovering rare keys.
        provider_key = row.get("payload_key") or row.get("__payload_key")
        if provider_key and _IDENTIFIER.fullmatch(str(provider_key).strip()):
            keys[("_raw", str(provider_key).strip())] = None
            if len(keys) >= max_keys:
                hit_key_bound = True
                break
            continue
        for parent in parent_fields:
            if parent not in row:
                continue
            value = row.get(parent)
            candidates: set[str] = set()
            text = _payload_text(value)
            if isinstance(value, dict) or isinstance(value, list):
                candidates.update(_json_paths(value))
            if text:
                try:
                    parsed = json.loads(text)
                    candidates.update(_json_paths(parsed))
                    if isinstance(parsed, str):
                        try:
                            candidates.update(_json_paths(json.loads(parsed)))
                        except (TypeError, ValueError, json.JSONDecodeError):
                            pass
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
                candidates.update(_KEY_PATTERN.findall(text))
            for key in sorted(candidates):
                if _IDENTIFIER.fullmatch(key):
                    keys[(parent, key)] = None
                if len(keys) >= max_keys:
                    hit_key_bound = True
                    break
            if hit_key_bound:
                break
        if hit_key_bound:
            break

    fields = tuple(
        TelemetryFieldProfile(
            field_id=f"{source_id}:nested:{parent}:{key}",
            name=key,
            primitive_type="unknown",
            origin="nested_payload",
            evidence_query_id=evidence_query_id,
            parent_field=parent,
            nested_key=key,
        )
        for parent, key in sorted(keys)
    )
    # Boundedness is about the key cap, not row count vs max_keys (different units).
    return fields, {
        "source_id": source_id,
        "status": "BOUNDED" if hit_key_bound else "COMPLETE",
        "rows_seen": rows_seen,
        "keys_discovered": len(fields),
        "max_keys": max_keys,
        "evidence_query_id": evidence_query_id,
        "complete": not hit_key_bound,
    }


__all__ = ["discover_payload_fields"]
