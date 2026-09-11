"""Contracts for the quarantined native-query fallback."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class NativeQueryCandidate:
    """Untrusted provider syntax proposed by an LLM."""

    provider: str
    query_text: str
    source_ids: tuple[str, ...] = ()
    time_window: str = ""
    expected_fields: tuple[str, ...] = ()
    max_rows: int = 100
    reason: str = ""

    def __post_init__(self) -> None:
        if not str(self.provider).strip() or not str(self.query_text).strip():
            raise ValueError("provider and query_text must not be empty")
        if self.max_rows <= 0 or self.max_rows > 10000:
            raise ValueError("max_rows must be between 1 and 10000")

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "query_text": self.query_text,
            "source_ids": list(self.source_ids),
            "time_window": self.time_window,
            "expected_fields": list(self.expected_fields),
            "max_rows": self.max_rows,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class NativeQueryValidationResult:
    accepted: bool
    normalized_query: str = ""
    estimated_cost: int | None = None
    reasons: tuple[str, ...] = ()
    ast: dict[str, Any] = field(default_factory=dict)
    query_signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "normalized_query": self.normalized_query,
            "estimated_cost": self.estimated_cost,
            "reasons": list(self.reasons),
            "ast": dict(self.ast),
            "query_signature": self.query_signature,
        }


__all__ = ["NativeQueryCandidate", "NativeQueryValidationResult"]
