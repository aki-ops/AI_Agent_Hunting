"""Observations — evidence stored in the Observation Ledger (M1).

The Ledger is the prompt-injection boundary:
  - raw log content stays here, never reaches the LLM
  - only extracted fields + taint labels are passed to M2
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunting.contracts.entities import EntityRef


class EpistemicType(str, Enum):
    """How an observation came to be.

    OBSERVED   — came from a query result against a telemetry backend
    TESTIMONY  — provided by a human analyst; passes identical constraints,
                 never elevated to OBSERVED
    """
    OBSERVED = "observed"
    TESTIMONY = "testimony"


class TaintLabel(str, Enum):
    """Whether a field's value is attacker-controlled.

    ATTACKER_INFLUENCED — attacker chose the content:
        cmdline, image/path, query_name, task_name, action,
        workstation, target_user (when logon status = failed)
    STRUCTURAL — collector / system generated it:
        ts, pid, parent_pid, host, logon_type, protocol,
        src_port, event_id, collector

    Default when field status is unavailable: ATTACKER_INFLUENCED (conservative).
    """
    ATTACKER_INFLUENCED = "attacker_influenced"
    STRUCTURAL = "structural"


@dataclass(frozen=True)
class Provenance:
    """Where and how an observation entered the ledger."""
    query_id: str
    collector: str    # source system identifier
    ingest_time: str  # ISO 8601 timestamp


@dataclass
class Observation:
    """A single piece of evidence in the Observation Ledger.

    Invariants (enforced by validators):
      - entities may NEVER contain AnyEntity (ANY)
      - attributed_by is DERIVED ONLY — written by recompute_attribution(), never M2
      - TESTIMONY may never become OBSERVED
      - raw log content (fields["content"] etc.) must never be forwarded to any LLM prompt
    """
    id: str
    source: str
    cell_id: str                               # which cell this came from
    timestamp: str                             # ISO 8601
    epistemic_type: EpistemicType
    fields: dict[str, Any] = field(default_factory=dict)
    taint: dict[str, TaintLabel] = field(default_factory=dict)
    entities: list[EntityRef] = field(default_factory=list)  # NEVER AnyEntity
    provenance: Provenance | None = None
    attributed_by: list[str] = field(default_factory=list)   # explanation IDs — derived only
    demanding: bool = False  # True = this obs must be attributed for STOP_RESOLVED
