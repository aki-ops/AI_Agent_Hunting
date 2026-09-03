"""M2 Abduction Policy & Trigger Engine.

Implements state-gated micro-batch abduction lifecycle:
- Trigger A: Initial abduction (after initial evidence from first query or broad sweep)
- Trigger B: Evidence delta threshold (pending >= min_new_observations)
- Trigger C: Significant evidence delta (new native type, new entity relationship, high-priority event)
- Trigger D: All current expectations concluded (confirmed, refuted, inconclusive, untestable) & pending remains
- Trigger E: Final flush before termination
- Deduplication Guard: deterministic SHA256 context hash
- Budget Guard: hard limit on calls_per_investigation
- Hypothesis Priority Guard: prioritize testing untested expectations before expanding
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from hunting.contracts.abduction import AbductionRuntime
from hunting.contracts.expectations import TestStatus
from hunting.contracts.state import InvestigationState


@dataclass(frozen=True)
class AbductionPolicyConfig:
    min_new_observations: int = 5
    max_observations_per_call: int = 20
    max_calls_per_investigation: int = 5
    max_retries: int = 2
    backoff_seconds: tuple[float, ...] = (1.0, 2.0)


class AbductionPolicy:
    """State-gated micro-batch policy for M2 Abduction invocation."""

    def __init__(self, config: AbductionPolicyConfig | None = None) -> None:
        self.config = config or AbductionPolicyConfig()

    def compute_context_hash(
        self,
        pending_ids: list[str],
        state: InvestigationState,
    ) -> str:
        """Deterministic context hash to prevent duplicate LLM calls."""
        sorted_pending = sorted(pending_ids)
        expl_summary = [
            (e.id, e.status.value, e.supported_count, e.refuted_count)
            for e in sorted(state.explanations, key=lambda x: x.id)
        ]
        exp_summary = [
            (ex.id, ex.test_status.value)
            for ex in sorted(state.expectations, key=lambda x: x.id)
        ]
        data = {
            "pending": sorted_pending,
            "explanations": expl_summary,
            "expectations": exp_summary,
        }
        encoded = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def should_call(
        self,
        state: InvestigationState,
        runtime: AbductionRuntime,
        action: str | None = None,
        is_final: bool = False,
        significant_signal: bool = False,
    ) -> tuple[bool, str]:
        """Evaluate whether M2 Abduction should be invoked."""
        # Hard cap guard: max calls reached
        if (runtime.calls + runtime.failures) >= self.config.max_calls_per_investigation:
            return False, "Suppressed: max_calls_per_investigation reached"

        # Circuit breaker: if previous epoch failed after all retries, suppress unless significant signal
        if runtime.failures >= 1 and not significant_signal:
            return False, "Suppressed: circuit breaker active (previous abduction failed)"

        # No pending observations
        if not runtime.pending_observation_ids:
            return False, "Suppressed: no pending observations for abduction"


        # Check deduplication hash
        pending_list = sorted(list(runtime.pending_observation_ids))[:self.config.max_observations_per_call]
        ctx_hash = self.compute_context_hash(pending_list, state)
        if ctx_hash == runtime.last_context_hash:
            return False, "Suppressed: context hash unchanged (duplicate call prevented)"

        # Check expectations status
        untested_expectations = [
            e for e in state.expectations
            if e.test_status == TestStatus.UNTESTED
        ]
        has_untested = len(untested_expectations) > 0

        # Trigger A: Initial abduction on first evidence
        if runtime.calls == 0 and len(runtime.pending_observation_ids) > 0:
            return True, "Trigger A: Initial abduction on first evidence"

        # Trigger E: Final flush
        if is_final:
            return True, "Trigger E: Final flush before termination"

        # Trigger C: Significant evidence delta
        if significant_signal:
            return True, "Trigger C: Significant evidence delta detected"

        # Trigger D: All current expectations concluded & pending evidence remains
        if not has_untested and len(state.expectations) > 0 and len(runtime.pending_observation_ids) > 0:
            return True, "Trigger D: All current expectations concluded with pending evidence remaining"

        # Trigger B: Evidence delta threshold
        if len(runtime.pending_observation_ids) >= self.config.min_new_observations:
            if not has_untested:
                return True, f"Trigger B: Evidence delta threshold met ({len(runtime.pending_observation_ids)} pending)"

        return False, "Suppressed: waiting for batch threshold or expectation resolution"


__all__ = [
    "AbductionPolicyConfig",
    "AbductionPolicy",
]
