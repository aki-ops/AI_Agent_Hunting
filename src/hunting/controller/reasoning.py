"""Deterministic reasoning engine.

Enforces:
- Exact predicates and temporal correlations are evaluated deterministically.
- Multi-hypothesis compatibility: an observation can support multiple hypotheses.
- Competing hypotheses remain active (LIVE or WEAKENED) until genuinely refuted.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from hunting.contracts.expectations import FieldOp, FieldPredicate
from hunting.contracts.hunt import EvidenceCard, Hypothesis, HypothesisStatus


def evaluate_field_predicate(field_value: Any, predicate: FieldPredicate) -> bool:
    """Deterministically evaluate whether a field value satisfies a predicate."""
    if predicate.op == FieldOp.EXISTS:
        return field_value is not None and field_value != ""
    if predicate.op == FieldOp.ABSENT:
        return field_value is None or field_value == ""

    if field_value is None:
        return False

    val_str = str(field_value).strip().lower()
    target_str = str(predicate.value).strip().lower()

    if predicate.op == FieldOp.EQUALS:
        return val_str == target_str
    elif predicate.op == FieldOp.CONTAINS:
        return target_str in val_str

    return False


def evaluate_temporal_correlation(t1_iso: str, t2_iso: str, max_delta_seconds: float) -> bool:
    """Evaluate whether two ISO timestamps fall within a temporal delta bound."""
    try:
        dt1 = datetime.fromisoformat(t1_iso.replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(t2_iso.replace("Z", "+00:00"))
        delta = abs((dt2 - dt1).total_seconds())
        return delta <= max_delta_seconds
    except Exception:
        return False


class HypothesisReasoningEngine:
    """Manages competing hypothesis compatibility and status lifecycle."""

    def evaluate_compatibility(
        self,
        card: EvidenceCard,
        hypotheses: list[Hypothesis],
    ) -> dict[str, bool]:
        """Check compatibility of an EvidenceCard against multiple hypotheses simultaneously.

        Invariant: An evidence card can be compatible with multiple hypotheses.
        'Consistent with H1' does NOT prove H1 nor refute H2.
        """
        compatibility: dict[str, bool] = {}

        for h in hypotheses:
            h_text = h.statement.lower()
            # General compatibility heuristics
            is_compat = False
            if card.fact_type == "process_execution" and ("process" in h_text or "exploit" in h_text or "powershell" in h_text or "activity" in h_text):
                is_compat = True
            elif card.fact_type == "network_connection" and ("network" in h_text or "c2" in h_text or "beacon" in h_text):
                is_compat = True
            elif card.fact_type == "file_modification" and ("file" in h_text or "webshell" in h_text or "artifact" in h_text):
                is_compat = True
            elif card.fact_type == "persistence_change" and ("task" in h_text or "persist" in h_text):
                is_compat = True
            elif card.fact_type == "authentication_activity" and ("auth" in h_text or "logon" in h_text):
                is_compat = True
            elif "investigate" in h_text:
                is_compat = True

            compatibility[h.id] = is_compat

        return compatibility

    def update_hypothesis_status(
        self,
        hypothesis: Hypothesis,
        has_confirming_evidence: bool,
        has_refuting_evidence: bool,
    ) -> None:
        """Update hypothesis status following rigorous epistemic rules.

        - LIVE: Default active state.
        - SUPPORTED: Confirmed by observable evidence.
        - WEAKENED: At least one expectation refuted, but not all.
        - REFUTED: Genuinely refuted by complete observable negative evidence.
        """
        if has_refuting_evidence:
            if has_confirming_evidence:
                hypothesis.status = HypothesisStatus.WEAKENED
            else:
                hypothesis.status = HypothesisStatus.REFUTED
        elif has_confirming_evidence:
            hypothesis.status = HypothesisStatus.SUPPORTED


__all__ = [
    "evaluate_field_predicate",
    "evaluate_temporal_correlation",
    "HypothesisReasoningEngine",
]
