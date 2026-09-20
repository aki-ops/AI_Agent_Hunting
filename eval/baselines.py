"""Executable evaluation baselines.

Baselines are deliberately evaluation-only.  They are explicit, reviewed
query packages and never participate in production reasoning or proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BaselineSpec:
    scenario_id: str
    mode: str
    provider_id: str
    operation_id: str
    time_window: str
    search_terms: tuple[str, ...] = ()
    review_status: str = "APPROVED"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BaselineSpec":
        mode = str(raw.get("mode", "")).strip().upper()
        if mode not in {"B0_BASELINE", "B1_DIRECT_QUERY"}:
            raise ValueError(f"unsupported baseline mode: {mode}")
        required = ("scenario_id", "provider_id", "operation_id", "time_window")
        missing = [key for key in required if not str(raw.get(key, "")).strip()]
        if missing:
            raise ValueError(f"baseline spec missing: {', '.join(missing)}")
        return cls(
            scenario_id=str(raw["scenario_id"]),
            mode=mode,
            provider_id=str(raw["provider_id"]),
            operation_id=str(raw["operation_id"]),
            time_window=str(raw["time_window"]),
            search_terms=tuple(str(item).strip() for item in raw.get("search_terms", []) if str(item).strip()),
            review_status=str(raw.get("review_status", "APPROVED")).upper(),
        )


@dataclass(frozen=True)
class BaselineRunAccount:
    """Truthful account for one baseline execution, including failures."""

    scenario_id: str
    mode: str
    status: str
    provider_id: str
    operation_id: str
    query_id: str
    time_window: str
    row_count: int = 0
    complete: bool = False
    elapsed_ms: float = 0.0
    diagnostic: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "mode": self.mode,
            "status": self.status,
            "provider_id": self.provider_id,
            "operation_id": self.operation_id,
            "query_id": self.query_id,
            "time_window": self.time_window,
            "row_count": self.row_count,
            "complete": self.complete,
            "elapsed_ms": self.elapsed_ms,
            "diagnostic": self.diagnostic,
        }


__all__ = ["BaselineRunAccount", "BaselineSpec"]
