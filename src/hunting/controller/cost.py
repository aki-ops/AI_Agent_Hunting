"""LLM Cost Accounting and Budget Enforcement.

Enforces:
- Hard ceiling on LLM calls per hunt (max 3 calls).
- Detailed token and latency accounting per component (Compiler, Planner, Evaluator).
- Zero-cost fallback if budget exhausted.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

MODEL_PRICING: dict[str, dict[str, float]] = {
    "gemini-2.5-flash": {"prompt": 0.075 / 1_000_000, "completion": 0.30 / 1_000_000},
    "gemini-2.5-pro": {"prompt": 1.25 / 1_000_000, "completion": 5.00 / 1_000_000},
    "gemini-1.5-flash": {"prompt": 0.075 / 1_000_000, "completion": 0.30 / 1_000_000},
    "gemini-1.5-pro": {"prompt": 1.25 / 1_000_000, "completion": 5.00 / 1_000_000},
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


@dataclass
class LLMCallRecord:
    """Individual record of an LLM invocation during a hunt."""
    component: str
    prompt_len: int
    response_len: int
    estimated_prompt_tokens: int
    estimated_completion_tokens: int
    timestamp_iso: str
    duration_ms: float = 0.0
    cost_usd: float = 0.0
    model: str = ""


class LLMUsageTracker:
    """Strict per-hunt LLM cost accounting ledger."""

    def __init__(self, max_calls: int = 3, max_total_tokens: int = 12000, model_name: str = "stub") -> None:
        self.max_calls = max_calls
        self.max_total_tokens = max_total_tokens
        self.model_name = model_name
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
    def estimated_cost_usd(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    @property
    def is_exhausted(self) -> bool:
        return self.call_count >= self.max_calls or self.total_tokens >= self.max_total_tokens

    def record_call(
        self,
        component: str,
        prompt: str,
        response: str,
        duration_ms: float = 0.0,
        model: str | None = None,
        actual_prompt_tokens: int | None = None,
        actual_completion_tokens: int | None = None,
    ) -> LLMCallRecord:
        """Record an LLM call and update token and cost accounting."""
        if self.call_count >= self.max_calls:
            raise RuntimeError(
                f"LLM cost policy violated: maximum {self.max_calls} LLM calls per hunt exceeded (attempted by {component})"
            )

        # Prioritize actual token counts from API metadata; fallback to ~4 chars/token
        prompt_tokens = actual_prompt_tokens if (actual_prompt_tokens is not None and actual_prompt_tokens > 0) else max(1, len(prompt) // 4)
        comp_tokens = actual_completion_tokens if (actual_completion_tokens is not None and actual_completion_tokens > 0) else max(1, len(response) // 4)
        active_model = model or self.model_name
        pricing = get_model_pricing(active_model)
        call_cost = (prompt_tokens * pricing["prompt"]) + (comp_tokens * pricing["completion"])

        record = LLMCallRecord(
            component=component,
            prompt_len=len(prompt),
            response_len=len(response),
            estimated_prompt_tokens=prompt_tokens,
            estimated_completion_tokens=comp_tokens,
            timestamp_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            duration_ms=duration_ms,
            cost_usd=round(call_cost, 6),
            model=active_model,
        )
        self.calls.append(record)
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += comp_tokens

        return record

    def to_dict(self) -> dict[str, Any]:
        """Export ledger summary for audit artifacts."""
        return {
            "model": self.model_name,
            "max_calls_budget": self.max_calls,
            "calls_made": self.call_count,
            "is_exhausted": self.is_exhausted,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
            "calls": [
                {
                    "component": c.component,
                    "model": c.model,
                    "prompt_len": c.prompt_len,
                    "response_len": c.response_len,
                    "estimated_prompt_tokens": c.estimated_prompt_tokens,
                    "estimated_completion_tokens": c.estimated_completion_tokens,
                    "cost_usd": c.cost_usd,
                    "timestamp": c.timestamp_iso,
                    "duration_ms": c.duration_ms,
                }
                for c in self.calls
            ],
        }


__all__ = ["LLMUsageTracker", "LLMCallRecord", "MODEL_PRICING", "get_model_pricing"]
