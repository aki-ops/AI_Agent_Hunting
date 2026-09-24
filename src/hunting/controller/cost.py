"""LLM Cost Accounting, Budget Enforcement, and Reservation Scheduling (v9 Workstream H).

Enforces:
- Shared configuration: CLI, tracker, SearchEnvelope, and HuntBudgetLedger read one LLMBudgetPolicy.
- Elimination of max-call drift between 4 and 5 (unified authoritative default = 5).
- Global reservation scheduler reserving mandatory capacity (C1 compiler, C1V ambiguity)
  and recovery capacity before optional calls (C2 source profiler, C3 query gen, C4 evaluator).
- Strict validation: malformed or truncated responses (finish_reason == 'length') are rejected
  and flagged to prevent state/graph corruption.
- Full call audit: every call has phase, reason, payload size, tokens, latency, validation status,
  and explicit is_estimate labeling for provider vs estimated tokens.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any

from hunting.contracts.search_envelope import (
    LLMBudgetPolicy,
    LLMPhase,
    PhaseReservationPolicy,
    normalize_phase,
)


class LLMBudgetError(RuntimeError):
    """Base exception for LLM budget and reservation failures."""


class LLMBudgetExhaustedError(LLMBudgetError):
    """Raised when global budget or component call ceiling is reached."""


class LLMReservationStarvationError(LLMBudgetError):
    """Raised when an optional call would starve reserved mandatory or recovery capacity."""


class LLMPreflightRejectionError(LLMBudgetError):
    """Raised when prompt or projected output exceeds component token ceilings."""


class LLMResponseValidationError(LLMBudgetError):
    """Raised when LLM output fails integrity or completeness validation."""


class LLMTruncatedResponseError(LLMResponseValidationError):
    """Raised when LLM response was truncated by provider length/token ceiling."""


class LLMMalformedResponseError(LLMResponseValidationError):
    """Raised when LLM response is unclosed or malformed JSON."""


MODEL_PRICING: dict[str, dict[str, float]] = {
    "gemini-2.5-flash": {"prompt": 0.075 / 1_000_000, "completion": 0.30 / 1_000_000},
    "gemini-2.5-pro": {"prompt": 1.25 / 1_000_000, "completion": 5.00 / 1_000_000},
    "gemini-1.5-flash": {"prompt": 0.075 / 1_000_000, "completion": 0.30 / 1_000_000},
    "gemini-1.5-pro": {"prompt": 1.25 / 1_000_000, "completion": 5.00 / 1_000_000},
    "gemini-flash": {"prompt": 0.075 / 1_000_000, "completion": 0.30 / 1_000_000},
    "1/gemini-flash-3.8-high-omni": {"prompt": 0.075 / 1_000_000, "completion": 0.30 / 1_000_000},
    "gpt-4o": {"prompt": 2.50 / 1_000_000, "completion": 10.00 / 1_000_000},
    "gpt-4o-mini": {"prompt": 0.15 / 1_000_000, "completion": 0.60 / 1_000_000},
    "claude-3-5-sonnet": {"prompt": 3.00 / 1_000_000, "completion": 15.00 / 1_000_000},
    "1/grok-4.6": {"prompt": 2.00 / 1_000_000, "completion": 10.00 / 1_000_000},
    "stub": {"prompt": 0.0, "completion": 0.0},
}
DEFAULT_FALLBACK_PRICING: dict[str, float] = {"prompt": 0.50 / 1_000_000, "completion": 1.50 / 1_000_000}


def get_model_pricing(model_name: str) -> dict[str, float]:
    """Look up token pricing rates (per token in USD) for given model name."""
    m = model_name.lower().strip()
    for k, v in MODEL_PRICING.items():
        if k in m or m in k:
            return v
    return DEFAULT_FALLBACK_PRICING


COMPONENT_TOKEN_CEILINGS: dict[str, dict[str, int]] = {
    "compiler": {"max_input": 2500, "max_output": 1200},
    # C2 carries the full provider-neutral CapabilityQuery plus a bounded
    # nested-payload census.  A smaller ceiling silently defers the only
    # source-discovery call after adding the required semantic context.
    "source_profiler": {"max_input": 4000, "max_output": 700},
    "planner": {"max_input": 1800, "max_output": 700},
    "adaptive_planner": {"max_input": 1800, "max_output": 700},
    "evaluator": {"max_input": 2500, "max_output": 800},
    "replan": {"max_input": 2000, "max_output": 900},
    "narrative": {"max_input": 1500, "max_output": 600},
    LLMPhase.C1_COMPILER.value: {"max_input": 2500, "max_output": 1200},
    LLMPhase.C1V_AMBIGUITY.value: {"max_input": 1500, "max_output": 600},
    LLMPhase.C2_SOURCE_PROFILER.value: {"max_input": 4000, "max_output": 700},
    LLMPhase.C3_QUERY_GEN.value: {"max_input": 1800, "max_output": 700},
    LLMPhase.C4_DISCRIMINATOR.value: {"max_input": 2500, "max_output": 800},
    LLMPhase.C5_REPLAN.value: {"max_input": 2000, "max_output": 900},
    LLMPhase.C6_NARRATIVE.value: {"max_input": 1500, "max_output": 600},
}


@dataclass
class LLMCallRecord:
    """Individual record of an LLM invocation during a hunt conforming to Gate H."""
    component: str
    phase: str = ""
    reason: str = ""
    payload_size: int = 0
    prompt_len: int = 0
    response_len: int = 0
    estimated_prompt_tokens: int = 0
    estimated_completion_tokens: int = 0
    actual_prompt_tokens: int | None = None
    actual_completion_tokens: int | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    is_estimate: bool = True
    timestamp_iso: str = ""
    duration_ms: float = 0.0
    cost_usd: float = 0.0
    model: str = ""
    configured_model: str = ""
    actual_model: str | None = None
    first_byte_ms: float | None = None
    http_status: int | None = None
    request_id: str | None = None
    error_class: str = ""
    prompt_hash: str = ""
    validation_result: str = ""
    validation_status: str = "VALID"
    selected_operation: str = ""
    search_terms: list[str] = field(default_factory=list)
    status: str = "SUCCESS"
    physical_attempts: int = 1
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "phase": self.phase,
            "reason": self.reason,
            "payload_size": self.payload_size,
            "prompt_len": self.prompt_len,
            "response_len": self.response_len,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_prompt_tokens": self.estimated_prompt_tokens,
            "estimated_completion_tokens": self.estimated_completion_tokens,
            "actual_prompt_tokens": self.actual_prompt_tokens,
            "actual_completion_tokens": self.actual_completion_tokens,
            "is_estimate": self.is_estimate,
            "duration_ms": self.duration_ms,
            "latency_ms": self.duration_ms,
            "cost_usd": self.cost_usd,
            "timestamp": self.timestamp_iso,
            "model": self.model,
            "configured_model": self.configured_model,
            "actual_model": self.actual_model,
            "first_byte_ms": self.first_byte_ms,
            "http_status": self.http_status,
            "request_id": self.request_id,
            "error_class": self.error_class,
            "prompt_hash": self.prompt_hash,
            "validation_result": self.validation_result,
            "validation_status": self.validation_status,
            "selected_operation": self.selected_operation,
            "search_terms": self.search_terms,
            "status": self.status,
            "physical_attempts": self.physical_attempts,
            "error": self.error,
        }


class LLMUsageTracker:
    """Strict per-hunt LLM cost accounting ledger and Global Reservation Scheduler (v9)."""

    def __init__(
        self,
        max_calls: int | None = None,
        max_total_tokens: int | None = None,
        model_name: str | None = None,
        policy: LLMBudgetPolicy | None = None,
        component_limits: dict[str, int] | None = None,
    ) -> None:
        self.policy = policy if policy is not None else LLMBudgetPolicy()
        self.max_calls = max_calls if max_calls is not None else self.policy.max_total_calls
        self.max_total_tokens = max_total_tokens if max_total_tokens is not None else self.policy.max_total_tokens
        self.model_name = model_name if model_name is not None else self.policy.model_name

        default_component_limits = {
            "compiler": 2,
            "source_profiler": 1,
            "planner": 1,
            "evaluator": 1,
            "replan": 1,
            "narrative": 0,
        }
        # Diagnostic correctness runs are governed by the deliberately high
        # per-phase/global policy ceilings.  Retaining legacy component caps
        # here would silently starve C1-C5 despite --unbounded-llm.
        self.component_limits = (
            dict(component_limits)
            if component_limits is not None
            else ({} if self.policy.diagnostic_unbounded else default_component_limits)
        )
        self.calls: list[LLMCallRecord] = []
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def total_tokens(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens

    @property
    def remaining_calls(self) -> int:
        return max(0, self.max_calls - self.call_count)

    @property
    def remaining_tokens(self) -> int:
        return max(0, self.max_total_tokens - self.total_tokens)

    @property
    def estimated_cost_usd(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    @property
    def is_exhausted(self) -> bool:
        return self.call_count >= self.max_calls or self.total_tokens >= self.max_total_tokens

    def phase_call_count(self, phase: str | LLMPhase) -> int:
        norm = normalize_phase(phase)
        return sum(1 for c in self.calls if c.phase == norm.value)

    def is_component_exhausted(self, component: str) -> bool:
        if self.is_exhausted:
            return True
        norm = normalize_phase(component)
        phase_policy = self.policy.get_phase_policy(norm)
        if self.phase_call_count(norm) >= phase_policy.max_calls:
            return True
        limit = self.component_limits.get(component)
        if limit is not None:
            count = sum(1 for c in self.calls if c.component == component)
            if count >= limit:
                return True
        return False

    def reserved_mandatory_capacity(self) -> int:
        """Calculate the remaining calls strictly reserved for mandatory semantic & recovery operations.

        Policy (H2):
        - C1: 1 mandatory + at most 1 repair (up to 2 calls reserved)
        - C1V: at most 1 (ambiguity only)
        """
        c1_calls = [c for c in self.calls if c.phase == LLMPhase.C1_COMPILER.value]
        if not c1_calls:
            c1_reserved = 2
        elif len(c1_calls) == 1:
            first_success = (
                c1_calls[0].status == "SUCCESS"
                and c1_calls[0].validation_status in ("VALID", "SUCCESS")
            )
            c1_reserved = 0 if first_success else 1
        else:
            c1_reserved = 0

        c1v_calls = [c for c in self.calls if c.phase == LLMPhase.C1V_AMBIGUITY.value]
        c1v_reserved = 1 if not c1v_calls else 0

        return c1_reserved + c1v_reserved

    def can_schedule(
        self,
        phase: str | LLMPhase,
        prompt: str = "",
        expected_completion_tokens: int = 0,
        component: str | None = None,
    ) -> tuple[bool, str]:
        """Check if an LLM invocation in given phase is permissible under reservation policy."""
        norm = normalize_phase(phase)
        phase_policy = self.policy.get_phase_policy(norm)

        # 1. Disabled phases (e.g. C6 Narrative)
        if phase_policy.max_calls <= 0:
            return False, f"Phase '{norm.value}' is disabled by policy (max_calls=0)"

        # 2. Component-specific call limit
        comp_key = component or norm.value
        if self.component_limits and comp_key in self.component_limits:
            count = sum(1 for c in self.calls if c.component == comp_key or c.phase == comp_key)
            if count >= self.component_limits[comp_key]:
                return False, f"budget exhausted for component '{comp_key}' ({count} >= {self.component_limits[comp_key]})"

        # 3. Phase-specific call limit
        if self.phase_call_count(norm) >= phase_policy.max_calls:
            return False, f"Phase '{norm.value}' maximum call limit ({phase_policy.max_calls}) reached"

        # 4. Global call limit
        if self.call_count >= self.max_calls:
            return False, f"Global LLM call budget exhausted: maximum {self.max_calls} calls already used"

        # 5. Global token limit
        if self.total_tokens >= self.max_total_tokens:
            return False, f"Global LLM token budget exhausted: {self.total_tokens} >= {self.max_total_tokens}"

        # 6. Global Reservation Scheduler: Optional calls cannot consume reserved mandatory capacity
        if not phase_policy.is_mandatory:
            remaining = self.remaining_calls
            reserved = self.reserved_mandatory_capacity()
            if remaining - reserved < 1:
                return False, (
                    f"Optional phase '{norm.value}' cannot consume reserved mandatory/recovery capacity: "
                    f"remaining calls={remaining}, reserved mandatory={reserved}"
                )

        # 7. Projected token consumption preflight check
        if prompt:
            prompt_tokens = self.estimate_tokens(prompt)
            projected = prompt_tokens + max(0, expected_completion_tokens)
            if projected > self.remaining_tokens:
                return False, (
                    f"LLM budget preflight rejected: Projected tokens ({projected}) exceed remaining global tokens ({self.remaining_tokens})"
                )

        return True, "OK"

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Conservative character-based estimate (preflight only)."""
        return max(1, math.ceil(len(text or "") / 4))

    def preflight(
        self,
        prompt: str,
        *,
        expected_completion_tokens: int = 0,
        component: str = "generic",
        phase: str | LLMPhase | None = None,
        reason: str = "",
    ) -> dict[str, int | str]:
        """Preflight authorization check before physical network execution."""
        norm = normalize_phase(phase or component)
        can_run, denial_reason = self.can_schedule(
            norm,
            prompt=prompt,
            expected_completion_tokens=expected_completion_tokens,
            component=component,
        )
        if not can_run:
            if "reserved" in denial_reason:
                raise LLMReservationStarvationError(denial_reason)
            raise LLMBudgetExhaustedError(denial_reason)

        prompt_tokens = self.estimate_tokens(prompt)
        reserved_completion = max(0, int(expected_completion_tokens))
        ceilings = None if self.policy.diagnostic_unbounded else (
            COMPONENT_TOKEN_CEILINGS.get(norm.value) or COMPONENT_TOKEN_CEILINGS.get(component)
        )
        if ceilings:
            if prompt_tokens > ceilings["max_input"]:
                raise LLMPreflightRejectionError(
                    f"LLM budget preflight rejected phase '{norm.value}' (component '{component}'): "
                    f"estimated prompt {prompt_tokens} exceeds ceiling {ceilings['max_input']}"
                )
            if reserved_completion > ceilings["max_output"]:
                raise LLMPreflightRejectionError(
                    f"LLM budget preflight rejected phase '{norm.value}' (component '{component}'): "
                    f"reserved completion {reserved_completion} exceeds ceiling {ceilings['max_output']}"
                )

        return {
            "component": component,
            "phase": norm.value,
            "estimated_prompt_tokens": prompt_tokens,
            "reserved_completion_tokens": reserved_completion,
            "remaining_tokens": self.remaining_tokens,
        }

    def record_call(
        self,
        component: str,
        prompt: str,
        response: str,
        duration_ms: float = 0.0,
        model: str | None = None,
        configured_model: str | None = None,
        actual_model: str | None = None,
        first_byte_ms: float | None = None,
        http_status: int | None = None,
        request_id: str | None = None,
        error_class: str = "",
        actual_prompt_tokens: int | None = None,
        actual_completion_tokens: int | None = None,
        prompt_hash: str | None = None,
        validation_result: str = "",
        validation_status: str = "VALID",
        selected_operation: str = "",
        search_terms: list[str] | tuple[str, ...] = (),
        status: str = "SUCCESS",
        physical_attempts: int = 1,
        error: str = "",
        phase: str | LLMPhase | None = None,
        reason: str = "",
        payload_size: int = 0,
    ) -> LLMCallRecord:
        """Record an LLM call with complete Gate H metadata."""
        if self.call_count >= self.max_calls:
            raise LLMBudgetExhaustedError(
                f"LLM cost policy violated: maximum {self.max_calls} LLM calls per hunt exceeded (attempted by {component})"
            )

        norm_phase = normalize_phase(phase or component)
        has_actual = (actual_prompt_tokens is not None and actual_prompt_tokens > 0)
        has_actual_comp = (actual_completion_tokens is not None and actual_completion_tokens >= 0)
        is_estimate = not (has_actual and has_actual_comp)

        p_tokens = actual_prompt_tokens if has_actual else self.estimate_tokens(prompt)
        c_tokens = actual_completion_tokens if has_actual_comp else self.estimate_tokens(response)

        active_model = model or self.model_name
        pricing = get_model_pricing(active_model)
        call_cost = (p_tokens * pricing["prompt"]) + (c_tokens * pricing["completion"])
        p_hash = prompt_hash or (hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16] if prompt else "")
        p_size = payload_size or (len(prompt.encode("utf-8")) if prompt else 0)

        val_status = validation_status
        if status == "FAILED" and val_status == "VALID":
            val_status = "FAILED"

        record = LLMCallRecord(
            component=component,
            phase=norm_phase.value,
            reason=reason or norm_phase.value,
            payload_size=p_size,
            prompt_len=len(prompt),
            response_len=len(response),
            estimated_prompt_tokens=self.estimate_tokens(prompt),
            estimated_completion_tokens=self.estimate_tokens(response),
            actual_prompt_tokens=actual_prompt_tokens,
            actual_completion_tokens=actual_completion_tokens,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=p_tokens + c_tokens,
            is_estimate=is_estimate,
            timestamp_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            duration_ms=duration_ms,
            cost_usd=round(call_cost, 6),
            model=active_model,
            configured_model=configured_model or active_model,
            actual_model=actual_model,
            first_byte_ms=first_byte_ms,
            http_status=http_status,
            request_id=request_id,
            error_class=error_class,
            prompt_hash=p_hash,
            validation_result=validation_result,
            validation_status=val_status,
            selected_operation=selected_operation,
            search_terms=list(search_terms),
            status=status,
            physical_attempts=max(0, int(physical_attempts)),
            error=error,
        )
        self.calls.append(record)
        self.total_prompt_tokens += p_tokens
        self.total_completion_tokens += c_tokens

        return record

    def to_dict(self) -> dict[str, Any]:
        """Export ledger summary with audit metadata and explicit estimation labeling."""
        all_actual = len(self.calls) > 0 and all(not c.is_estimate for c in self.calls)
        all_est = len(self.calls) == 0 or all(c.is_estimate for c in self.calls)
        token_mode = "ACTUAL" if all_actual else ("ESTIMATED" if all_est else "HYBRID")

        return {
            "model": self.model_name,
            "max_calls_budget": self.max_calls,
            "calls_made": self.call_count,
            "is_exhausted": self.is_exhausted,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "token_accounting_mode": token_mode,
            "is_estimate": not all_actual,
            "calls": [c.to_dict() for c in self.calls],
        }

    @staticmethod
    def validate_response(response_text: str, finish_reason: str | None = None) -> tuple[bool, str]:
        """Validate response integrity and reject truncated or malformed outputs."""
        if finish_reason and str(finish_reason).upper() in ("MAX_TOKENS", "LENGTH", "TRUNCATED"):
            return False, "Response truncated by provider token ceiling"

        stripped = (response_text or "").strip()
        if not stripped:
            return False, "Empty response received"

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                json.loads(stripped)
            except Exception as err:
                return False, f"Malformed or unclosed JSON structure: {err}"

        return True, "VALID"


__all__ = [
    "LLMPhase",
    "normalize_phase",
    "LLMBudgetError",
    "LLMBudgetExhaustedError",
    "LLMReservationStarvationError",
    "LLMPreflightRejectionError",
    "LLMResponseValidationError",
    "LLMTruncatedResponseError",
    "LLMMalformedResponseError",
    "PhaseReservationPolicy",
    "LLMBudgetPolicy",
    "LLMUsageTracker",
    "LLMCallRecord",
    "MODEL_PRICING",
    "COMPONENT_TOKEN_CEILINGS",
    "get_model_pricing",
]
