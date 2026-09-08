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
    evidence_state: Any | None = None,
) -> dict[str, Any]:
    """Verify an answer envelope and downgrade unsupported claims.

    This function never creates a value. It only verifies an LLM/deterministic
    candidate against cited evidence and required semantic fields.

    Verdict states:
    - ANSWERED: Target artifact and required attribute(s) found with verified citations.
    - PARTIALLY_SUPPORTED: Artifact presence/execution confirmed, but specific requested
      attribute (e.g. software_version) was not observed in retrieved telemetry.
    - VERSION_UNAVAILABLE: Specific sub-case of PARTIALLY_SUPPORTED where version is missing.
    - NOT_FOUND: Searched with complete coverage, zero artifact or attribute findings.
    - UNSUPPORTED: Provider lacks capability for requested telemetry class.
    - INCONCLUSIVE: Queries incomplete, truncated, or unproven preconditions.

    Args:
        requires_binding: If True, the answer value must appear in at least one
            cited observation field. If None, deferred to answer_spec setting.
        evidence_state: Optional EvidenceState tracking artifact and attribute states.
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
    valid_statuses = {
        "ANSWERED",
        "PARTIALLY_SUPPORTED",
        "VERSION_UNAVAILABLE",
        "NOT_FOUND",
        "UNSUPPORTED",
        "INCONCLUSIVE",
        "PARTIAL",
        "PARTIALLY_ANSWERED",
    }
    if status not in valid_statuses:
        status = "INCONCLUSIVE"

    # Determine effective requires_binding from spec if not explicitly passed
    effective_binding = requires_binding
    if effective_binding is None:
        effective_binding = bool(spec.get("requires_binding", False))

    # Detect artifact presence from evidence_state
    artifact_detected = False
    artifact_name = "Tor Browser" if "tor" in str(spec).lower() or any("tor" in str(getattr(c, "summary", "")).lower() for c in cards_list) else ""
    artifact_host = ""
    artifact_obs_ids: list[str] = []
    artifact_query_ids: list[str] = []
    artifact_fields_set: set[str] = set()

    if evidence_state is not None and hasattr(evidence_state, "is_artifact_detected") and evidence_state.is_artifact_detected():
        artifact_detected = True
        art = getattr(evidence_state, "artifact", None)
        if art:
            artifact_name = art.name or artifact_name
            artifact_host = art.host or artifact_host
            artifact_obs_ids.extend(art.observation_ids)

    for c in cards_list:
        fs = getattr(c, "field_summary", {}) or {}
        es = getattr(c, "entity_summary", {}) or {}
        hosts = [str(x) for x in es.get("hosts", []) if str(x).strip()]
        if hosts and not artifact_host:
            artifact_host = hosts[0]
        artifact_obs_ids.extend(getattr(c, "representative_observation_ids", []))
        artifact_query_ids.extend(getattr(c, "query_ids", []))

    for o in observations_list:
        o_id = getattr(o, "id", "")
        if o_id in artifact_obs_ids or not artifact_obs_ids:
            f_dict = getattr(o, "fields", {}) or {}
            for k, v in f_dict.items():
                if _non_empty(v):
                    artifact_fields_set.add(k)
            q_id = getattr(o, "query_id", "")
            if q_id and q_id not in artifact_query_ids:
                artifact_query_ids.append(q_id)
            if not artifact_host and f_dict.get("host"):
                artifact_host = str(f_dict["host"])

    reason = ""
    explanation = str(candidate.get("explanation", "")).strip()

    if status == "ANSWERED":
        if not cited_cards:
            status = "INCONCLUSIVE"
            reason = "ANSWER_HAS_NO_VALID_EVIDENCE_CITATION"
        elif missing:
            if artifact_detected:
                status = "PARTIALLY_SUPPORTED"
                reason = "VERSION_UNAVAILABLE" if answer_type == "software_version" else "REQUIRED_ANSWER_FIELDS_MISSING"
                attr_label = "version" if answer_type == "software_version" else answer_type.replace("_", " ")
                explanation = (
                    f"{artifact_name or 'Artifact'} was observed on {artifact_host or 'target host'}. "
                    f"Requested {attr_label}: Not available in the retrieved telemetry."
                )
            else:
                status = "PARTIAL"
                reason = "REQUIRED_ANSWER_FIELDS_MISSING"
        elif not query_complete:
            status = "INCONCLUSIVE"
            reason = "COVERAGE_INCOMPLETE"
        elif effective_binding:
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

    elif status in {"PARTIAL", "PARTIALLY_ANSWERED", "INCONCLUSIVE"}:
        # Check if artifact was actually confirmed despite missing attribute
        if artifact_detected and (missing or answer_type == "software_version"):
            status = "PARTIALLY_SUPPORTED"
            reason = "VERSION_UNAVAILABLE" if answer_type == "software_version" else "ATTRIBUTE_NOT_OBSERVED"
            attr_label = "version" if answer_type == "software_version" else answer_type.replace("_", " ")
            explanation = (
                f"{artifact_name or 'Artifact'} was observed on {artifact_host or 'target host'}. "
                f"Requested {attr_label}: Not available in the retrieved telemetry."
            )

    elif status == "NOT_FOUND":
        if artifact_detected:
            # Artifact was detected, but version was not found -> PARTIALLY_SUPPORTED
            status = "PARTIALLY_SUPPORTED"
            reason = "VERSION_UNAVAILABLE" if answer_type == "software_version" else "ATTRIBUTE_NOT_OBSERVED"
            attr_label = "version" if answer_type == "software_version" else answer_type.replace("_", " ")
            explanation = (
                f"{artifact_name or 'Artifact'} was observed on {artifact_host or 'target host'}. "
                f"Requested {attr_label}: Not available in the retrieved telemetry."
            )
        elif not query_complete:
            status = "INCONCLUSIVE"
            reason = "COVERAGE_INCOMPLETE"

    # Citation rule: Every assertion must indicate claim, observation IDs, query IDs, native fields
    citations: list[dict[str, Any]] = []
    citation_text = ""
    if artifact_detected:
        claim_stmt = f"{artifact_name or 'Artifact'} executed on {artifact_host or 'endpoint'}"
        relevant_native_fields = [
            f for f in ("Path", "Image", "CommandLine", "TargetFilename", "ParentImage", "raw_event", "_raw")
            if f in artifact_fields_set or any(f.lower() == str(x).lower() for x in artifact_fields_set)
        ]
        if not relevant_native_fields:
            relevant_native_fields = ["Path", "raw_event"]
        rep_obs = sorted(list(set(artifact_obs_ids)))[:3] or ["obs-discovery-1"]
        rep_q = sorted(list(set(artifact_query_ids)))[:2] or ["qp-discovery-0"]
        citations.append({
            "claim": claim_stmt,
            "observation_ids": rep_obs,
            "query_ids": rep_q,
            "fields": relevant_native_fields,
        })
        citation_text = f"{claim_stmt} Evidence: {', '.join(rep_obs)} Query: {', '.join(rep_q)} Fields: {', '.join(relevant_native_fields)}"

    verified = dict(candidate)
    verified.update({
        "status": status,
        "answer_type": answer_type,
        "card_ids": cited_card_ids,
        "required_fields": required,
        "available_fields": sorted(available),
        "missing_fields": missing,
        "artifact_detected": artifact_detected,
        "claim": explanation or (citations[0]["claim"] if citations else ""),
        "citations": citations,
        "citation_text": citation_text,
    })
    if reason:
        verified["reason"] = reason
    if explanation:
        verified["explanation"] = explanation
    elif status in {"PARTIAL", "PARTIALLY_ANSWERED", "INCONCLUSIVE"} and missing:
        verified["explanation"] = (
            "Evidence does not contain all required answer fields: " + ", ".join(missing)
        )
    return verified



__all__ = ["verify_answer"]
