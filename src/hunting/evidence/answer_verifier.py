"""Deterministic verification of answers against observed evidence.

The LLM may propose an answer, but it cannot establish that the requested
fields are present, bound to the right entity, and cited. This module performs
that final check without provider-specific assumptions.
"""
from __future__ import annotations

from typing import Any, Iterable

_TYPE_FIELDS: dict[str, tuple[str, ...]] = {
    "software_version": ("ProductVersion", "FileVersion", "Version", "version"),
    "domain": ("domains", "sites", "site", "domain"),
    "uri": ("uri", "url", "urls"),
    "url": ("uri", "url", "urls"),
    "ip_address": ("destination_ips", "dest_ips", "ips", "src_ip", "client_ip"),
    "username": ("user", "users", "username"),
    "email_address": ("sender_email", "recipient_email", "email"),
    "process": ("Image", "image", "process_name", "process_image"),
    "file_path": ("Path", "path", "TargetFilename", "file_path"),
    "timestamp": ("_time", "timestamp", "time"),
}


def _non_empty(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _available_fields(cards: Iterable[Any], observations: Iterable[Any] = ()) -> set[str]:
    fields: set[str] = set()
    for item in list(cards) + list(observations):
        raw = getattr(item, "field_summary", None)
        if raw is None:
            raw = getattr(item, "fields", None)
        if isinstance(raw, dict):
            fields.update(str(key).casefold() for key, value in raw.items() if _non_empty(value))
    return fields


def verify_answer(
    answer: dict[str, Any] | None,
    answer_spec: dict[str, Any] | None,
    cards: Iterable[Any],
    observations: Iterable[Any] = (),
    query_complete: bool = True,
    requires_binding: bool | None = None,
) -> dict[str, Any]:
    """Verify an answer envelope and downgrade unsupported claims.

    This function never creates a value. It only verifies an LLM/deterministic
    candidate against cited evidence and required semantic fields.

    Args:
        requires_binding: If True, the answer value must appear in at least one
            cited observation field. If None, deferred to answer_spec setting.
    """
    candidate = dict(answer or {})
    spec = dict(answer_spec or {})
    cards_list = list(cards)
    observations_list = list(observations)
    valid_card_ids = {str(getattr(card, "id", "")) for card in cards_list}
    cited_card_ids = [
        str(value) for value in candidate.get("card_ids", [])
        if str(value) in valid_card_ids
    ]
    cited_cards = [card for card in cards_list if str(getattr(card, "id", "")) in cited_card_ids]
    answer_type = str(spec.get("answer_type") or candidate.get("answer_type") or "value").strip().lower()
    explicit_required = [str(value).strip() for value in spec.get("required_fields", []) if str(value).strip()]
    required = explicit_required or list(_TYPE_FIELDS.get(answer_type, ()))

    available = _available_fields(cited_cards, observations_list)
    canonical_aliases = {field.casefold() for field in _TYPE_FIELDS.get(answer_type, ())}
    if explicit_required and canonical_aliases and {
        field.casefold() for field in explicit_required
    }.issubset(canonical_aliases):
        missing = [] if any(field.casefold() in available for field in explicit_required) else explicit_required
    elif explicit_required:
        missing = [field for field in explicit_required if field.casefold() not in available]
    else:
        # Built-in type fields are aliases for one semantic field, not a list
        # of fields that must all be present (e.g. domain may be `site`).
        missing = [] if any(field.casefold() in available for field in required) else required
    status = str(candidate.get("status", "INCONCLUSIVE")).upper()
    if status not in {"ANSWERED", "NOT_FOUND", "INCONCLUSIVE", "PARTIAL", "PARTIALLY_ANSWERED"}:
        status = "INCONCLUSIVE"

    # Determine effective requires_binding from spec if not explicitly passed
    effective_binding = requires_binding
    if effective_binding is None:
        effective_binding = bool(spec.get("requires_binding", False))

    reason = ""
    if status == "ANSWERED":
        if not cited_cards:
            status = "INCONCLUSIVE"
            reason = "ANSWER_HAS_NO_VALID_EVIDENCE_CITATION"
        elif missing:
            status = "PARTIAL"
            reason = "REQUIRED_ANSWER_FIELDS_MISSING"
        elif not query_complete:
            status = "INCONCLUSIVE"
            reason = "COVERAGE_INCOMPLETE"
        elif effective_binding:
            # Binding check: the answer value must appear verbatim in at least
            # one cited observation or card field summary.
            answer_value = str(candidate.get("value", "")).strip().lower()
            if answer_value:
                bound = False
                for obs in observations_list:
                    fields = getattr(obs, "fields", {}) or {}
                    for v in fields.values():
                        if answer_value in str(v or "").lower():
                            bound = True
                            break
                    if bound:
                        break
                if not bound:
                    for card in cited_cards:
                        fs = getattr(card, "field_summary", {}) or {}
                        for v in fs.values():
                            if answer_value in str(v or "").lower():
                                bound = True
                                break
                        if bound:
                            break
                if not bound:
                    status = "PARTIAL"
                    reason = "ANSWER_VALUE_NOT_BOUND_TO_EVIDENCE"

    elif status == "NOT_FOUND" and not query_complete:
        status = "INCONCLUSIVE"
        reason = "COVERAGE_INCOMPLETE"

    verified = dict(candidate)
    verified.update({
        "status": status,
        "answer_type": answer_type,
        "card_ids": cited_card_ids,
        "required_fields": required,
        "available_fields": sorted(available),
        "missing_fields": missing,
    })
    if reason:
        verified["reason"] = reason
    if status in {"PARTIAL", "PARTIALLY_ANSWERED", "INCONCLUSIVE"} and missing:
        verified["explanation"] = str(candidate.get("explanation", "")).strip() or (
            "Evidence does not contain all required answer fields: " + ", ".join(missing)
        )
    return verified



__all__ = ["verify_answer"]
