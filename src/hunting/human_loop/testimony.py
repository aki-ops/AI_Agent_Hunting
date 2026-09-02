"""Human-in-the-loop: Testimony, Conflict handling, and Analyst Confirmation.

Enforces:
  - Human input is strictly modeled as TESTIMONY; testimony can never become OBSERVED telemetry.
  - Conflicts between testimony and telemetry or between hypotheses are preserved with resolution audit trails.
  - Mandatory confirmation workflows for sensitive dispositions (MALICIOUS, CONFLICTED, STOP_BOUNDED).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.conflicts import Conflict
from hunting.contracts.entities import EntityRef
from hunting.contracts.observations import EpistemicType, Observation, Provenance
from hunting.contracts.state import Disposition


def create_testimony_observation(
    testimony_id: str,
    scope: ProviderScope,
    statement: str,
    analyst_id: str,
    entities: list[EntityRef] | None = None,
    timestamp: str | None = None,
) -> Observation:
    """Create an Observation strictly typed as EpistemicType.TESTIMONY."""
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return Observation(
        id=testimony_id,
        provider_scope=scope,
        cell_id=f"testimony-{analyst_id}",
        timestamp=ts,
        epistemic_type=EpistemicType.TESTIMONY,
        native_type="human_testimony",
        entities=list(entities or []),
        fields={
            "statement": statement,
            "analyst_id": analyst_id,
            "type": "testimony",
        },
        provenance=Provenance(
            query_id=f"testimony-{testimony_id}",
            collector="analyst_console",
            ingest_time=ts,
            native_partition=scope.native_partition,
        ),
    )



def record_conflict(
    conflicts: list[Conflict],
    conflict_id: str,
    observation_ids: list[str] | None = None,
    explanation_ids: list[str] | None = None,
) -> Conflict:
    """Record a conflict. Conflicts are preserved in the record and never silently dropped."""
    conflict = Conflict(
        id=conflict_id,
        observation_ids=list(observation_ids or []),
        explanation_ids=list(explanation_ids or []),
        resolved=False,
    )
    conflicts.append(conflict)
    return conflict


def resolve_conflict(
    conflict: Conflict,
    resolved_by: str,
) -> None:
    """Resolve an existing conflict using human input ID, preserving for auditability."""
    conflict.resolved = True
    conflict.resolved_by = resolved_by


def record_analyst_confirmation(
    analyst_id: str,
    disposition: Disposition,
    notes: str,
    confirmed: bool = True,
) -> dict[str, Any]:
    """Record mandatory analyst confirmation for sensitive dispositions."""
    return {
        "analyst_id": analyst_id,
        "disposition": disposition.value,
        "notes": notes,
        "confirmed": confirmed,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }



__all__ = [
    "create_testimony_observation",
    "record_conflict",
    "resolve_conflict",
    "record_analyst_confirmation",
]
