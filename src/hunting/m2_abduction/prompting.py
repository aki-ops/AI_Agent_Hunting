"""Prompt construction for M2 Abduction.

Enforces:
  - Raw log content never reaches the LLM (prompt injection boundary).
  - Only structured, taint-labelled data, entities, provenance, and validated schemas cross the boundary.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.observations import Observation
from hunting.contracts.state import InvestigationState
from hunting.m1_ledger.ledger import ObservationLedger


def sanitize_observation_for_llm(obs: Observation) -> dict[str, Any]:
    """Extract structured, taint-labelled representation of an observation.

    Strict security invariant: Never includes raw_log, raw text, or byte payload.
    """
    entities = [
        {"type": type(e).__name__, "repr": str(e)}
        for e in obs.entities
    ]

    # Include only extracted fields and their deterministic taint labels
    clean_fields: dict[str, Any] = {}
    for k, v in obs.fields.items():
        # Block raw or hidden benchmark fields
        if k in {"raw", "raw_log", "payload", "_raw", "_hidden"}:
            continue
        clean_fields[k] = v

    return {
        "id": obs.id,
        "timestamp": obs.timestamp,
        "native_type": obs.native_type,
        "semantic_type": obs.semantic_type,
        "scope_id": obs.provider_scope.scope_id,
        "epistemic_type": obs.epistemic_type.value,
        "taint": {k: (t.value if hasattr(t, "value") else str(t)) for k, t in obs.taint.items()},
        "entities": entities,
        "fields": clean_fields,
        "is_unmapped": obs.is_unmapped,
        "is_unexplained": obs.is_unexplained,
        "demanding": obs.demanding,
    }


def build_llm_prompt_context(
    state: InvestigationState,
    ledger: ObservationLedger,
    window: str = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
) -> dict[str, Any]:
    """Construct structured prompt context for M2 Abduction.

    Never passes raw log text to the LLM.
    """
    structured_obs = [sanitize_observation_for_llm(o) for o in ledger.observations]

    # Current hypotheses summary
    current_explanations = [
        {
            "id": e.id,
            "label": e.label,
            "class": e.class_.value,
            "status": e.status.value,
            "supported_count": e.supported_count,
            "refuted_count": e.refuted_count,
        }
        for e in state.explanations
    ]

    return {
        "window": window,
        "observations": structured_obs,
        "unattributed_observation_ids": [o.id for o in ledger.unattributed_observations],
        "unmapped_observation_ids": [o.id for o in ledger.unmapped_observations],
        "current_explanations": current_explanations,
    }



__all__ = [
    "sanitize_observation_for_llm",
    "build_llm_prompt_context",
]
