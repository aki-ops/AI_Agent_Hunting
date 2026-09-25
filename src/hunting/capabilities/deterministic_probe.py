"""Deterministic fallback when C2 LLM profiling is unavailable.

PEAK Execute rule: a temporary 503 must not end the hunt. Use the F1
shortlist that is already in state, probe the census-backed fields, and
materialize a route only when the probe returns events.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.source_profile import SourceCapabilityProposal

_ROLE_HINTS: dict[str, tuple[str, ...]] = {
    "sent_message": ("sender", "receiver", "subject", "msg_id", "message"),
    "sent_email": ("sender", "receiver", "subject", "msg_id", "message"),
    "received_message": ("sender", "receiver", "subject", "msg_id", "message"),
}


def build_fallback_proposals(
    profile: Any,
    requirement: dict[str, Any],
) -> list[SourceCapabilityProposal]:
    """Build at most one probe-only proposal from census field IDs."""
    relation = str(requirement.get("relation", "")).strip().casefold()
    goal_id = str(requirement.get("goal_id", "") or "")
    hints = _ROLE_HINTS.get(relation, ())
    if not hints:
        return []
    by_name = {str(f.name).casefold(): f.field_id for f in getattr(profile, "fields", ())}
    by_id = {str(f.field_id).casefold(): f.field_id for f in getattr(profile, "fields", ())}

    def _find(*names: str) -> str | None:
        for name in names:
            key = name.casefold()
            if key in by_name:
                return by_name[key]
            for fname, fid in by_name.items():
                if key in fname:
                    return fid
            if key in by_id:
                return by_id[key]
        return None

    subject_field = _find("sender", "sender_email", "from")
    object_field = _find("receiver_email", "receiver", "recipient", "to")
    if not subject_field or not object_field:
        return []
    by_field = {str(f.field_id): f for f in getattr(profile, "fields", ())}
    transforms = {
        fid: "extract_nested_key"
        for fid in (subject_field, object_field)
        if getattr(by_field.get(fid), "origin", "") == "nested_payload"
    }
    return [
        SourceCapabilityProposal(
            source_id=profile.source_id,
            relation=relation,
            goal_id=goal_id,
            input_roles={"subject": subject_field},
            output_roles={"recipient": object_field},
            proof_mode="retrieval_only",
            probe_kind="schema",
            searchable_constraints=tuple(hints),
            rationale_refs=("deterministic-fallback-f1-probe",),
            field_transforms=transforms,
        )
    ]
