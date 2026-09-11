"""PoC-driven Auto-Hunt Agent.

Flow
----
1. The analyst picks a PoC from the library (or defines a new one).
2. The deterministic ``compiler`` turns the PoC into a ``SemanticGoalGraph``.
3. The agent runs each ``TestStep`` against the configured adapter using
   ``search_text`` semantics, with progressively narrower predicates.
4. If the adapter returns empty results for the primary steps but the
   fallbacks also fail, the agent **may** call the LLM with the bounded
   ``escalation_hint`` if one is attached.
5. The agent persists a hunt ledger (JSON) and emits a Markdown case-file
   report.

Design invariants
-----------------
- PoC runs are reproducible: same PoC + same adapter state = same output.
- LLM is optional and only fires after local evidence is exhausted.
- Cost is recorded per PoC, per hunt, in the ledger.
- The agent never invents entities that the adapter did not return.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from hunting.controller.cost import LLMUsageTracker
from hunting.contracts.entities import EntityRef, Host
from hunting.poc.compiler import compile_poc, graph_summary
from hunting.poc.library import get_poc, list_pocs
from hunting.poc.models import PoC, TestStep


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _row_text(row: dict[str, Any]) -> str:
    return " ".join(
        f"{k}={v}" for k, v in row.items() if isinstance(v, (str, int, float))
    )


def _compile_terms(step: TestStep) -> list[str]:
    """Turn a TestStep's predicate into a list of literal CDB search terms.

    We deliberately treat MATCHES as a substring: the adapter can search
    columns by LIKE; the regex character class is preserved by leaving it
    as-is so the LIKE still narrows the row set.
    """
    if step.op.value == "EXISTS":
        return [step.target_field]
    if step.op.value in {"EQUALS", "STARTS_WITH", "ENDS_WITH"}:
        return [step.value]
    if step.op.value == "MATCHES":
        return [step.value]
    return [step.value]


@dataclass
class StepResult:
    step_id: str
    description: str
    target_field: str
    op: str
    value: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    row_count: int = 0
    used_fallback: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "description": self.description,
            "target_field": self.target_field,
            "op": self.op,
            "value": self.value,
            "row_count": self.row_count,
            "used_fallback": self.used_fallback,
            "rows": self.rows,
        }


@dataclass
class PocHuntResult:
    poc_id: str
    poc_name: str
    request_id: str
    started_at: str
    finished_at: str
    time_window: str
    step_results: list[StepResult]
    matched_step_ids: list[str]
    total_observations: int
    escalation_called: bool
    escalation_summary: str | None
    llm_calls: int
    llm_tokens: int
    llm_cost_usd: float
    runtime_seconds: float
    verdict: str  # "MATCHED" | "EMPTY" | "ESCALATED" | "INCONCLUSIVE"
    rationale: str
    ledger_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "poc_id": self.poc_id,
            "poc_name": self.poc_name,
            "request_id": self.request_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "time_window": self.time_window,
            "step_results": [s.to_dict() for s in self.step_results],
            "matched_step_ids": list(self.matched_step_ids),
            "total_observations": self.total_observations,
            "escalation_called": self.escalation_called,
            "escalation_summary": self.escalation_summary,
            "llm_calls": self.llm_calls,
            "llm_tokens": self.llm_tokens,
            "llm_cost_usd": self.llm_cost_usd,
            "runtime_seconds": self.runtime_seconds,
            "verdict": self.verdict,
            "rationale": self.rationale,
            "ledger_path": self.ledger_path,
        }


class PocAgent:
    """Runs a single PoC against a configured adapter, with bounded LLM
    escalation.

    Parameters
    ----------
    adapter
        A provider adapter exposing ``execute_query(operation_id="search_text", search_terms=...)``.
        The CDB adapter in this repo is the reference implementation.
    llm_caller
        Optional callable ``(question: str, max_tokens: int) -> str``.
        Provided only when escalation should be allowed. None disables
        escalation even if the PoC declares a hint.
    llm_tracker
        Optional ``LLMUsageTracker``. If supplied, the agent records the
        escalation cost on it.
    ledger_dir
        Where to write hunt ledgers. Defaults to ``artifacts/poc_hunts``.
    """

    def __init__(
        self,
        adapter: Any,
        llm_caller: Callable[[str, int], str] | None = None,
        llm_tracker: LLMUsageTracker | None = None,
        ledger_dir: str | Path | None = None,
    ) -> None:
        self.adapter = adapter
        self.llm_caller = llm_caller
        self.llm_tracker = llm_tracker
        self.ledger_dir = Path(ledger_dir) if ledger_dir else Path("artifacts") / "poc_hunts"
        self.ledger_dir.mkdir(parents=True, exist_ok=True)

    def _run_step(self, step: TestStep, time_window: str, query_id: str) -> StepResult:
        terms = _compile_terms(step)
        result = self.adapter.execute_query(
            operation_id="search_text",
            entity=None,
            window=time_window,
            limit=100,
            query_id=query_id,
            search_terms=terms,
        )
        rows = [dict(row) for row in (result.rows or [])]
        return StepResult(
            step_id=step.step_id,
            description=step.description,
            target_field=step.target_field,
            op=step.op.value,
            value=step.value,
            rows=rows,
            row_count=len(rows),
            used_fallback=False,
        )

    def _maybe_escalate(self, poc: PoC, observations: list[dict[str, Any]]) -> tuple[bool, str | None, int, int, float]:
        """Return ``(called, summary, llm_calls, llm_tokens, cost_usd)``.

        Escalation is triggered when:
        - all primary steps returned empty,
        - the PoC declared an escalation hint,
        - and an LLM caller was configured.
        """
        if observations:
            return False, None, 0, 0, 0.0
        if not poc.escalation_hint or self.llm_caller is None:
            return False, None, 0, 0, 0.0

        t0 = time.perf_counter()
        response = self.llm_caller(
            poc.escalation_hint.question,
            poc.escalation_hint.max_tokens,
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if self.llm_tracker is not None:
            self.llm_tracker.record_call(
                component="poc_escalation",
                prompt=poc.escalation_hint.question,
                response=response,
                duration_ms=elapsed_ms,
                model=getattr(self.llm_tracker, "model_name", "stub"),
            )
        return True, response.strip(), 1, len(poc.escalation_hint.question) + len(response), 0.0

    def run(
        self,
        poc_id: str,
        time_window: str = "NOW-14d/NOW",
        request_id: str | None = None,
    ) -> PocHuntResult:
        poc = get_poc(poc_id)
        request_id = request_id or f"poc-{poc_id}-{_now()}"
        started_at = _now()
        t0 = time.perf_counter()

        graph = compile_poc(poc, request_id=request_id, time_window=time_window)
        summary = graph_summary(graph)

        step_results: list[StepResult] = []
        for index, step in enumerate(poc.steps):
            query_id = f"{request_id}-{step.step_id}"
            step_results.append(self._run_step(step, time_window, query_id))

        primary_empty = all(r.row_count == 0 for r in step_results)
        if primary_empty and poc.fallbacks:
            for step in poc.fallbacks:
                query_id = f"{request_id}-{step.step_id}-fallback"
                fb = self._run_step(step, time_window, query_id)
                fb.used_fallback = True
                step_results.append(fb)

        all_observations = [row for r in step_results for row in r.rows]
        matched_step_ids = [r.step_id for r in step_results if r.row_count > 0]

        called, summary_text, llm_calls, llm_tokens, cost_usd = self._maybe_escalate(
            poc, all_observations
        )

        elapsed = round(time.perf_counter() - t0, 4)

        if matched_step_ids:
            verdict = "MATCHED"
            rationale = (
                f"Matched {len(matched_step_ids)} PoC step(s) with "
                f"{len(all_observations)} observation(s)."
            )
        elif called:
            verdict = "ESCALATED"
            rationale = (
                "No local adapter hits. LLM escalation returned a "
                "bounded narrative; treat as LLM-assisted hypothesis, "
                "not evidence."
            )
        else:
            verdict = "EMPTY"
            rationale = "No local adapter hits and no escalation configured."

        result = PocHuntResult(
            poc_id=poc.poc_id,
            poc_name=poc.name,
            request_id=request_id,
            started_at=started_at,
            finished_at=_now(),
            time_window=time_window,
            step_results=step_results,
            matched_step_ids=matched_step_ids,
            total_observations=len(all_observations),
            escalation_called=called,
            escalation_summary=summary_text,
            llm_calls=llm_calls,
            llm_tokens=llm_tokens,
            llm_cost_usd=cost_usd,
            runtime_seconds=elapsed,
            verdict=verdict,
            rationale=rationale,
        )

        ledger_path = self.ledger_dir / f"{request_id}.json"
        ledger_path.write_text(
            json.dumps({"graph": summary, "result": result.to_dict()}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        result.ledger_path = str(ledger_path)
        return result

    def run_chain(
        self,
        poc_ids: list[str],
        time_window: str = "NOW-14d/NOW",
    ) -> list[PocHuntResult]:
        """Run a sequence of PoCs. Useful when an analyst wants to test a
        chain (phishing → powershell → persistence) end-to-end."""
        return [self.run(poc_id, time_window=time_window) for poc_id in poc_ids]


__all__ = [
    "PocAgent",
    "PocHuntResult",
    "StepResult",
    "list_pocs",
    "get_poc",
]
