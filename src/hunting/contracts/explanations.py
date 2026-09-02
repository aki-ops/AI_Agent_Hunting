"""Explanations — candidate accounts of what happened, proposed by M2 (LLM).

Only M3 (Constraint Checker) may change explanation or attribution status.
Rejected explanations are kept in the record — never deleted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ExplanationClass(str, Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"  # novel behaviour — evidence-supported, outside known categories


class ExplanationStatus(str, Enum):
    LIVE = "live"
    WEAKENED = "weakened"  # ≥1 expectation refuted — still attributes observations
    REJECTED = "rejected"  # all expectations refuted — no longer attributes observations


class ExplanationOrigin(str, Enum):
    LLM = "llm"
    HUMAN = "human"  # analyst-provided hypothesis — passes same constraints as LLM


class AttributionStatus(str, Enum):
    SUPPORTED = "supported"
    MISATTRIBUTED = "misattributed"  # C3 (v2): relation re-derivation failed
    TAINTED = "tainted"              # C4 (v2): rests solely on ATTACKER_INFLUENCED fields


@dataclass
class Attribution:
    """Links one explanation to one observation it claims to explain."""
    observation_id: str
    cause: str                                           # why this obs supports the explanation
    status: AttributionStatus = AttributionStatus.SUPPORTED


@dataclass
class Explanation:
    """A candidate account of what happened.

    Invariants:
      - Only M3 may change status (LIVE → WEAKENED → REJECTED)
      - REJECTED explanations stay in the list with rejection_reason set
      - untestable=True blocks STOP_RESOLVED
      - M2 may NOT write attributed_by on Observations (M1 owns that)
      - diversity required: ≥1 BENIGN + ≥1 MALICIOUS if both are plausible
    """
    id: str
    label: str              # short human-readable name, e.g. "lateral-movement-via-wmi"
    class_: ExplanationClass
    status: ExplanationStatus = ExplanationStatus.LIVE
    origin: ExplanationOrigin = ExplanationOrigin.LLM
    untestable: bool = False
    attributions: list[Attribution] = field(default_factory=list)
    expectations: list[str] = field(default_factory=list)   # expectation IDs
    supported_count: int = 0
    refuted_count: int = 0
    arbitrariness: int = 0       # count of non-SUPPORTED attributions — tiebreak only (v2)
    rejection_reason: str | None = None
