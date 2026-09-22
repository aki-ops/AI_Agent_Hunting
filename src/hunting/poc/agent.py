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
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from hunting.contracts.entities import Host
from hunting.controller.cost import LLMUsageTracker
from hunting.peak import (
    PrepareError,
    able_drive,
    enforce_max_duration,
    missing_prepare_fields,
    parse_duration,
)
from hunting.poc.compiler import compile_poc, graph_summary
from hunting.poc.library import get_poc, list_pocs
from hunting.poc.models import PoC, TestStep


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _row_text(row: dict[str, Any]) -> str:
    return " ".join(
        f"{k}={v}" for k, v in row.items() if isinstance(v, (str, int, float))
    )


def _cell_equals(value: Any, want: str) -> bool:
    """Exact match with basename fallback for image-like fields.

    ``EQUALS powershell.exe`` must match ``powershell.exe`` and
    ``C:\\...\\powershell.exe`` but NOT ``splunk-powershell.exe``
    (eval 2026-09-21: LIKE-based EQUALS produced 100 FPs on 4.38M rows).
    """
    if value is None:
        return False
    text = str(value).strip()
    if text.lower() == want.lower():
        return True
    base = text.replace("/", "\\").rsplit("\\", 1)[-1]
    return base.lower() == want.lower()


def _cell_contains(value: Any, want: str) -> bool:
    return want.lower() in str(value or "").lower()


def _apply_op(cell: Any, op: str, want: str) -> bool:
    op = op.upper()
    if op == "EQUALS":
        return _cell_equals(cell, want)
    if op == "CONTAINS":
        return _cell_contains(cell, want)
    if op == "STARTS_WITH":
        return str(cell or "").lower().startswith(want.lower())
    if op == "ENDS_WITH":
        return str(cell or "").lower().endswith(want.lower())
    if op == "MATCHES":
        try:
            import re
            return re.search(want, str(cell or "")) is not None
        except Exception:
            return _cell_contains(cell, want)
    if op == "EXISTS":
        return cell not in (None, "")
    return _cell_contains(cell, want)


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
    pass_index: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "description": self.description,
            "target_field": self.target_field,
            "op": self.op,
            "value": self.value,
            "row_count": self.row_count,
            "used_fallback": self.used_fallback,
            "pass_index": self.pass_index,
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
    judgment: Any | None = None  # Judgment or None when --poc-judge disabled
    judgment_llm_calls: int = 0
    judgment_llm_tokens: int = 0
    ledger_path: str | None = None
    refine_log: list[dict[str, Any]] = field(default_factory=list)
    ir_escalated: bool = False
    ir_escalation_path: str | None = None
    scope_note: str = ""

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
            "judgment": (self.judgment.to_dict() if self.judgment is not None else None),
            "judgment_llm_calls": self.judgment_llm_calls,
            "judgment_llm_tokens": self.judgment_llm_tokens,
            "ledger_path": self.ledger_path,
            "refine_log": list(self.refine_log),
            "ir_escalated": self.ir_escalated,
            "ir_escalation_path": self.ir_escalation_path,
            "scope_note": self.scope_note,
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
        judge_caller: Callable[[str, int], str] | None = None,
        enable_judge: bool = False,
    ) -> None:
        self.adapter = adapter
        self.llm_caller = llm_caller
        self.llm_tracker = llm_tracker
        self.ledger_dir = Path(ledger_dir) if ledger_dir else Path("artifacts") / "poc_hunts"
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self.judge_caller = judge_caller or llm_caller
        self.enable_judge = enable_judge

    def _run_step(
        self,
        step: TestStep,
        time_window: str,
        query_id: str,
        *,
        extra_terms: tuple[str, ...] = (),
        host: str | None = None,
        actor: str | None = None,
        pass_index: int = 1,
    ) -> StepResult:
        terms = list(_compile_terms(step))
        for term in extra_terms:
            if term not in terms:
                terms.append(term)
        result = self.adapter.execute_query(
            operation_id="search_text",
            entity=Host(name=host) if host else None,
            window=time_window,
            limit=100,
            query_id=query_id,
            search_terms=terms,
        )
        rows = [dict(row) for row in (result.rows or [])]
        # Post-filter: the adapter is a coarse LIKE retriever; enforce the
        # step's real operator on the target field here so EQUALS is exact
        # and EXISTS with an empty value does not match arbitrary rows.
        if step.op.value == "EXISTS" and not (step.value or "").strip():
            rows = []
        else:
            rows = [r for r in rows if _apply_op(r.get(step.target_field), step.op.value, step.value)]
        if actor:
            needle = actor.lower()
            rows = [r for r in rows if needle in str(r.get("user") or "").lower()]
        if host:
            rows = [r for r in rows if str(r.get("host") or "") == host]
        return StepResult(
            step_id=step.step_id,
            description=step.description,
            target_field=step.target_field,
            op=step.op.value,
            value=step.value,
            rows=rows,
            row_count=len(rows),
            used_fallback=False,
            pass_index=pass_index,
        )

    def _run_steps(
        self,
        steps: list[TestStep],
        time_window: str,
        request_id: str,
        *,
        drive: Any,
        host: str | None,
        fallback: bool,
        pass_index: int,
    ) -> list[StepResult]:
        results: list[StepResult] = []
        for step in steps:
            query_id = f"{request_id}-{step.step_id}"
            if fallback:
                query_id += "-fallback"
            if pass_index > 1:
                query_id += f"-p{pass_index}"
            step_result = self._run_step(
                step,
                time_window,
                query_id,
                extra_terms=drive.observables,
                host=host,
                actor=drive.actor,
                pass_index=pass_index,
            )
            step_result.used_fallback = fallback
            results.append(step_result)
        return results

    def _execute_loop(
        self,
        poc: PoC,
        time_window: str,
        request_id: str,
        *,
        max_refine: int,
        deadline: float | None,
    ) -> tuple[list[StepResult], list[dict[str, Any]]]:
        """Analyze, refine once, and run again. Operators are never widened."""
        drive = able_drive(poc.actor, poc.behavior, poc.location, poc.evidence)
        primary = self._run_steps(
            list(poc.steps), time_window, request_id,
            drive=drive, host=drive.host, fallback=False, pass_index=1,
        )
        log: list[dict[str, Any]] = [{
            "pass": 1,
            "phase": "analyze",
            "matched": [step.step_id for step in primary if step.row_count],
            "missed": [step.step_id for step in primary if not step.row_count],
        }]
        results = list(primary)
        matched = [step for step in primary if step.row_count]
        missed = [step for step in primary if not step.row_count]

        def _over_deadline() -> bool:
            return deadline is not None and time.perf_counter() >= deadline

        if matched and max_refine > 0 and not _over_deadline():
            anchor_hosts: list[str] = []
            for row in matched[0].rows:
                observed = str(row.get("host") or "").strip()
                if observed and observed not in anchor_hosts:
                    anchor_hosts.append(observed)
            other_steps = [step for step in poc.steps if step.step_id != matched[0].step_id]
            if len(anchor_hosts) == 1 and anchor_hosts[0] != (drive.host or "") and other_steps:
                log.append({
                    "pass": 2,
                    "phase": "refine",
                    "reason": f"restrict the remaining steps to observed host {anchor_hosts[0]}",
                })
                pivoted = self._run_steps(
                    other_steps, time_window, request_id,
                    drive=drive, host=anchor_hosts[0], fallback=False, pass_index=2,
                )
                by_id = {step.step_id: step for step in results}
                for step in pivoted:
                    by_id[step.step_id] = step
                order = [step.step_id for step in primary]
                results = [by_id[step_id] for step_id in order if step_id in by_id]
                log.append({"pass": 2, "phase": "stop", "reason": "refine pass finished"})
                return results, log

        if matched and not missed:
            log.append({"pass": 1, "phase": "stop", "reason": "all primary steps matched"})
            return results, log

        if matched and missed:
            log.append({
                "pass": 1,
                "phase": "refine",
                "reason": "partial match; no single new host to pivot onto",
            })

        if not any(step.row_count for step in results) and poc.fallbacks:
            results.extend(self._run_steps(
                list(poc.fallbacks), time_window, request_id,
                drive=drive, host=drive.host, fallback=True, pass_index=1,
            ))
            log.append({"pass": 1, "phase": "refine", "reason": "primary empty; ran declared fallbacks"})

        if not any(step.row_count for step in results) and max_refine > 0:
            if _over_deadline():
                log.append({"phase": "stop", "reason": "max_duration elapsed before the refine pass"})
                return results, log
            log.append({
                "pass": 2,
                "phase": "refine",
                "reason": "empty analysis; re-run original predicates with operators unchanged",
            })
            rerun = self._run_steps(
                list(poc.steps), time_window, request_id,
                drive=drive, host=drive.host, fallback=False, pass_index=2,
            )
            if any(step.row_count for step in rerun):
                results = rerun
            log.append({
                "pass": 2,
                "phase": "stop",
                "reason": "refine pass finished",
                "rerun_rows": sum(step.row_count for step in rerun),
            })
            return results, log

        log.append({"phase": "stop", "reason": "no further safe refinement"})
        return results, log

    def _write_ir(self, request_id: str, payload: dict[str, Any]) -> str:
        ir_dir = self.ledger_dir / "ir"
        ir_dir.mkdir(parents=True, exist_ok=True)
        path = ir_dir / f"{request_id}.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)

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
        *,
        max_refine: int = 1,
        enforce_prepare: bool = False,
    ) -> PocHuntResult:
        poc = get_poc(poc_id)
        if enforce_prepare:
            missing = missing_prepare_fields(poc)
            if missing:
                raise PrepareError(
                    "PEAK Prepare is incomplete (" + ", ".join(missing) + "). "
                    "Pass --hunt-plan or --prepare before the hunt."
                )
        time_window, scope_note = enforce_max_duration(time_window, poc.max_duration)
        request_id = request_id or f"poc-{poc_id}-{_now()}"
        started_at = _now()
        t0 = time.perf_counter()
        duration = parse_duration(poc.max_duration)
        deadline = (t0 + duration.total_seconds()) if duration is not None else None

        graph = compile_poc(
            poc, request_id=request_id, time_window=time_window, scope_note=scope_note,
        )
        summary = graph_summary(graph)

        step_results, refine_log = self._execute_loop(
            poc, time_window, request_id, max_refine=max_refine, deadline=deadline,
        )

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

        ir_escalated = bool(matched_step_ids) or called
        ir_path = None
        if ir_escalated:
            hosts = sorted({str(row.get("host")) for row in all_observations if row.get("host")})
            ir_path = self._write_ir(request_id, {
                "request_id": request_id,
                "poc_id": poc.poc_id,
                "destination": "IR",
                "advisory": not bool(matched_step_ids),
                "verdict": verdict,
                "reason": (
                    "Matched observables are a critical finding."
                    if matched_step_ids
                    else "Local evidence is empty; the LLM narrative is advisory and is filed for IR review."
                ),
                "matched_step_ids": list(matched_step_ids),
                "hosts": hosts,
                "refine_log": refine_log,
                "escalation_summary": summary_text,
            })

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
            judgment=None,
            judgment_llm_calls=0,
            judgment_llm_tokens=0,
            refine_log=refine_log,
            ir_escalated=ir_escalated,
            ir_escalation_path=ir_path,
            scope_note=scope_note,
        )

        # Optional post-hoc LLM judge. Runs only when --poc-judge is set.
        if self.enable_judge and self.judge_caller is not None:
            from hunting.poc.judge import judge_run
            judgment, j_calls, j_tokens = judge_run(
                poc=poc,
                matched_step_ids=matched_step_ids,
                step_results=step_results,
                total_observations=len(all_observations),
                time_window=time_window,
                llm_caller=self.judge_caller,
            )
            result.judgment = judgment
            result.judgment_llm_calls = j_calls
            result.judgment_llm_tokens = j_tokens
            if self.llm_tracker is not None and j_calls > 0:
                t0j = time.perf_counter()
                # capture response was already produced inside judge_run; here
                # we only record the cost envelope.
                self.llm_tracker.record_call(
                    component="poc_judge",
                    prompt="judge",
                    response=str(judgment.to_dict()),
                    duration_ms=round((time.perf_counter() - t0j) * 1000.0, 2),
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
        *,
        max_refine: int = 1,
        enforce_prepare: bool = False,
    ) -> list[PocHuntResult]:
        """Run a sequence of PoCs. Useful when an analyst wants to test a
        chain (phishing → powershell → persistence) end-to-end."""
        return [
            self.run(
                poc_id,
                time_window=time_window,
                max_refine=max_refine,
                enforce_prepare=enforce_prepare,
            )
            for poc_id in poc_ids
        ]


__all__ = [
    "PocAgent",
    "PocHuntResult",
    "StepResult",
    "list_pocs",
    "get_poc",
]
