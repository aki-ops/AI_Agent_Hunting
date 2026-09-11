"""Unified StepTrace recording every step from Freeze Request (Step A) through Stop (Step J)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HuntStepName(str, Enum):
    """Canonical hunt lifecycle steps from Freeze Request (A) through Stop (J)."""
    STEP_A_FREEZE_REQUEST = "STEP_A_FREEZE_REQUEST"
    STEP_B_COMPILE_GOAL_GRAPH = "STEP_B_COMPILE_GOAL_GRAPH"
    STEP_C_RESOLVE_FRONTIER = "STEP_C_RESOLVE_FRONTIER"
    STEP_D_BIND_CANDIDATES = "STEP_D_BIND_CANDIDATES"
    STEP_E_COMPILE_QUERY_INTENT = "STEP_E_COMPILE_QUERY_INTENT"
    STEP_F_EXECUTE_NATIVE_QUERY = "STEP_F_EXECUTE_NATIVE_QUERY"
    STEP_G_RECORD_OBSERVATIONS = "STEP_G_RECORD_OBSERVATIONS"
    STEP_H_VERIFY_PROOF = "STEP_H_VERIFY_PROOF"
    STEP_I_CHECK_STOPPING = "STEP_I_CHECK_STOPPING"
    STEP_J_REPORT_AND_ACCOUNT = "STEP_J_REPORT_AND_ACCOUNT"


@dataclass
class HuntStepRecord:
    """Audit record for an individual step in the hunt lifecycle."""
    step_name: str
    step_index: int
    timestamp_iso: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    duration_ms: float = 0.0
    status: str = "SUCCESS"
    inputs_summary: dict[str, Any] = field(default_factory=dict)
    outputs_summary: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_name": self.step_name,
            "step_index": self.step_index,
            "timestamp_iso": self.timestamp_iso,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "inputs_summary": dict(self.inputs_summary),
            "outputs_summary": dict(self.outputs_summary),
            "diagnostics": list(self.diagnostics),
        }


@dataclass
class StepTrace:
    """Unified chronological record of all lifecycle steps taken in a hunt run."""
    request_id: str
    steps: list[HuntStepRecord] = field(default_factory=list)

    def record_step(
        self,
        step_name: HuntStepName | str,
        duration_ms: float = 0.0,
        status: str = "SUCCESS",
        inputs_summary: dict[str, Any] | None = None,
        outputs_summary: dict[str, Any] | None = None,
        diagnostics: list[str] | None = None,
    ) -> HuntStepRecord:
        name_str = step_name.value if isinstance(step_name, HuntStepName) else str(step_name)
        record = HuntStepRecord(
            step_name=name_str,
            step_index=len(self.steps) + 1,
            duration_ms=duration_ms,
            status=status,
            inputs_summary=inputs_summary or {},
            outputs_summary=outputs_summary or {},
            diagnostics=diagnostics or [],
        )
        self.steps.append(record)
        return record

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "step_count": len(self.steps),
            "steps": [s.to_dict() for s in self.steps],
        }


__all__ = ["HuntStepName", "HuntStepRecord", "StepTrace"]
