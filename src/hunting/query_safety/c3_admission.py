"""C3 may propose native syntax only after deterministic compile fails."""
from __future__ import annotations

from typing import Iterable

from hunting.contracts.hunt import LogicalQueryPlan
from hunting.contracts.native_query import NativeQueryCandidate, NativeQueryValidationResult
from hunting.contracts.query_intent import QueryIntentSpec


def should_invoke_c3(
    *,
    admitted: bool,
    deterministic_plan: LogicalQueryPlan | None,
) -> bool:
    """C3 is a quarantined fallback, never a competing default compiler."""
    return bool(admitted) and deterministic_plan is None


def output_roles_match_intent(
    intent: QueryIntentSpec,
    observed_fields: list[str] | tuple[str, ...],
) -> tuple[bool, tuple[str, ...]]:
    """Reject a native proposal whose output roles are not in the intent."""
    expected = tuple(dict.fromkeys(
        str(item).strip()
        for item in (*intent.projection_roles, *intent.expected_output)
        if str(item).strip()
    ))
    if not expected:
        return True, ()
    observed = {str(item).strip().casefold() for item in observed_fields if str(item).strip()}
    missing = tuple(role for role in expected if role.casefold() not in observed)
    return not missing, missing


def _truncated_or_malformed(query_text: str) -> tuple[str, ...]:
    text = str(query_text or "")
    reasons: list[str] = []
    stripped = text.strip()
    if stripped.endswith("...") or stripped.endswith("…") or stripped.endswith("\\"):
        reasons.append("truncated_model_output")
    if stripped.count('"') % 2 == 1 or stripped.count("'") % 2 == 1:
        reasons.append("malformed_unbalanced_quotes")
    if "\x00" in text:
        reasons.append("malformed_nul")
    return tuple(reasons)


def admit_c3_candidate(
    candidate: NativeQueryCandidate,
    *,
    admitted: bool,
    deterministic_plan: LogicalQueryPlan | None,
    known_sources: Iterable[str],
    known_fields: Iterable[str],
    intent: QueryIntentSpec | None = None,
    max_scan_cost: int = 1000,
    executed_query_signatures: Iterable[str] = (),
) -> NativeQueryValidationResult:
    """Parse, allowlist and bound a C3 proposal before any state mutation."""
    if not should_invoke_c3(admitted=admitted, deterministic_plan=deterministic_plan):
        return NativeQueryValidationResult(
            accepted=False,
            reasons=("c3_blocked_deterministic_plan_exists",),
        )
    extra = _truncated_or_malformed(candidate.query_text)
    known = {str(item).casefold() for item in known_sources}
    if candidate.source_ids and known and any(str(item).casefold() not in known for item in candidate.source_ids):
        extra = extra + ("source_not_in_census",)
    from hunting.query_safety.native_query_gate import NativeQueryGate
    gate = NativeQueryGate().validate(
        candidate,
        known_sources=known_sources,
        known_fields=known_fields,
        max_scan_cost=max_scan_cost,
        executed_query_signatures=executed_query_signatures,
        intent=intent,
    )
    reasons = tuple(dict.fromkeys((*extra, *gate.reasons)))
    accepted = not reasons
    return NativeQueryValidationResult(
        accepted=accepted,
        normalized_query=gate.normalized_query if accepted else "",
        estimated_cost=gate.estimated_cost,
        reasons=reasons,
        ast=dict(gate.ast),
        query_signature=gate.query_signature,
    )


__all__ = [
    "admit_c3_candidate",
    "output_roles_match_intent",
    "should_invoke_c3",
]
