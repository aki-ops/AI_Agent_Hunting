"""PEAK Prepare phase, delegated to PEAK Assistant (Cisco Talos).

PEAK Assistant's agents do the Prepare work:

* ``able_table``  - turns hypothesis + research + local data into an ABLE table;
* ``plan_hunt``   - planner/critic team that writes the step-by-step hunt plan.

Inputs that PEAK normally gets from the web UI are built here:

* hypothesis         - the PoC's name + summary;
* research document  - the PoC's own research references (optionally replaced by PEAK's
  ``researcher`` team when MCP research servers are configured: ``use_research=True``);
* local data document / data discovery - the adapter's own description of its telemetry
  (replaces the Splunk MCP data-discovery step);
* local context      - how this deployment executes hunts (deterministic literal predicates).

Nothing PEAK writes is evidence. It is advisory context for the human and for the
recommendation layer. If PEAK or the LLM is unavailable the PoC's own ABLE/plan are used
and the result is marked ``used_peak=False`` with the reason.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import logging
from dataclasses import dataclass, field
from typing import Any

from hunting.llm import PeakLlm, retry_async, run_async
from hunting.poc.models import PoC

LOCAL_CONTEXT = (
    "Hunts run through a deterministic executor, not by the LLM. Each PoC step is one literal "
    "predicate (field, operator, value) matched against a telemetry table; operators are EQUALS, "
    "CONTAINS, STARTS_WITH, ENDS_WITH, MATCHES and EXISTS; EQUALS, CONTAINS, STARTS_WITH and ENDS_WITH are case-insensitive. The LLM never creates or edits evidence. "
    "Plan steps must therefore be expressible as field/operator/value predicates over the fields "
    "listed in the local data document, plus pivots on host, user, ip and time. Write any SPL as "
    "an equivalent detection draft only. Say clearly where the available data cannot answer a question."
)


@dataclass
class PrepareResult:
    used_peak: bool
    able_markdown: str = ""
    hunt_plan_markdown: str = ""
    research_markdown: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "used_peak": self.used_peak,
            "able_markdown": self.able_markdown,
            "hunt_plan_markdown": self.hunt_plan_markdown,
            "research_markdown": self.research_markdown,
            "notes": list(self.notes),
        }


def hypothesis_text(poc: PoC) -> str:
    return f"{poc.name}. {poc.summary}".strip()


def research_document(poc: PoC) -> str:
    """Research input built from what the analyst already recorded in the PoC."""
    lines = [f"# {poc.topic or poc.name}", "", poc.summary or poc.name, ""]
    if poc.research_refs:
        lines += ["## Research references", *[f"- {ref}" for ref in poc.research_refs], ""]
    if poc.references:
        lines += ["## MITRE / external references", *[f"- {ref}" for ref in poc.references], ""]
    if poc.expected_chain:
        lines += ["## Expected observable chain", ", ".join(poc.expected_chain), ""]
    lines += [
        "## Candidate detection predicates (analyst-authored)",
        *[f"- {s.description}: `{s.target_field} {s.op.value} {s.value}` ({s.source_kind})" for s in poc.steps],
    ]
    return "\n".join(lines)


def offline_able(poc: PoC) -> str:
    return "\n".join([
        f"# ABLE (from PoC, PEAK Assistant not used): {poc.topic or poc.name}",
        "",
        "| ABLE Element | |",
        "|---|---|",
        f"| Actor | {poc.actor or '(unknown)'} |",
        f"| Behavior | {poc.behavior} |",
        f"| Location | {poc.location} |",
        f"| Evidence | {poc.evidence} |",
    ])


def offline_plan(poc: PoC) -> str:
    steps = "\n".join(
        f"{i}. {s.description}: `{s.target_field} {s.op.value} {s.value}` on {s.source_kind} telemetry"
        for i, s in enumerate(poc.steps, 1)
    )
    return f"## Hunt procedure (from PoC, PEAK Assistant not used)\n\nScope: {poc.scope}\nMax duration: {poc.max_duration}\n\n{steps}\n\nPlan: {poc.plan}"


async def _peak_prepare(
    poc: PoC, data_document: str, timeout: int, use_research: bool, result: PrepareResult,
) -> None:
    from peak_assistant.able_assistant import able_table
    from peak_assistant.planning_assistant import plan_hunt
    from peak_assistant.utils.result_extractors import extract_hunt_plan

    hypothesis = hypothesis_text(poc)
    research = research_document(poc)

    if use_research:
        try:
            from peak_assistant.research_assistant import researcher
            from peak_assistant.utils.result_extractors import extract_research_report

            run = await asyncio.wait_for(researcher(technique=poc.topic or poc.name, local_context=LOCAL_CONTEXT), timeout)
            report = extract_research_report(run)
            if report and "no report generated" not in report.lower():
                research = report
                result.research_markdown = report
                result.notes.append("research: PEAK researcher team")
            else:
                result.notes.append("research: PEAK researcher returned nothing; used PoC references")
        except Exception as exc:  # MCP research servers are optional
            result.notes.append(f"research: PEAK researcher unavailable ({type(exc).__name__}: {exc}); used PoC references")
    else:
        result.research_markdown = research
        result.notes.append("research: PoC references (PEAK researcher not requested)")

    async def _able() -> str:
        text = await asyncio.wait_for(
            able_table(
                hypothesis=hypothesis,
                research_document=research,
                local_data_document=data_document,
                local_context=LOCAL_CONTEXT,
            ),
            timeout,
        )
        if not text or text.startswith("Error while generating"):  # able_table swallows errors into a string
            raise RuntimeError(text or "empty ABLE table")
        return text

    able = await retry_async(_able, label="ABLE", notes=result.notes)
    result.able_markdown = able
    result.notes.append("ABLE: PEAK able_table")

    async def _plan() -> str:
        run = await asyncio.wait_for(
            plan_hunt(
                research_document=research,
                local_data_document=data_document,
                hypothesis=hypothesis,
                able_info=able,
                data_discovery=data_document,
                local_context=LOCAL_CONTEXT,
            ),
            timeout,
        )
        text = extract_hunt_plan(run)
        if not text or "could not create a hunt plan" in text.lower() or text.strip() == "no plan was generated":
            raise RuntimeError(f"PEAK planner produced no usable plan: {(text or '')[:200]}")
        return text

    plan = await retry_async(_plan, label="hunt plan", notes=result.notes)
    result.hunt_plan_markdown = plan
    result.notes.append("plan: PEAK hunt_planner + hunt_plan_critic")


@contextlib.contextmanager
def _quiet_peak():
    """PEAK/autogen print tracebacks for every failed LLM call; failures are reported in the notes instead."""
    names = ("autogen_core", "autogen_agentchat", "autogen_ext")
    loggers = [logging.getLogger(n) for n in names]
    levels = [lg.level for lg in loggers]
    for lg in loggers:
        lg.setLevel(logging.CRITICAL)
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            yield
    finally:
        for lg, level in zip(loggers, levels):
            lg.setLevel(level)


def run_prepare(
    poc: PoC,
    data_document: str,
    llm: PeakLlm | None,
    *,
    timeout: int = 420,
    use_research: bool = False,
    attempts: int = 2,
) -> PrepareResult:
    """Run PEAK Prepare for one PoC; degrade to the PoC's own plan with a recorded reason."""
    result = PrepareResult(used_peak=False)
    if llm is None:
        result.able_markdown, result.hunt_plan_markdown = offline_able(poc), offline_plan(poc)
        result.research_markdown = research_document(poc)
        result.notes.append("PEAK Assistant not used (offline mode or LLM not configured)")
        return result
    for attempt in range(1, attempts + 1):
        attempt_result = PrepareResult(used_peak=False)
        try:
            with _quiet_peak():
                run_async(_peak_prepare(poc, data_document, timeout, use_research, attempt_result))
        except Exception as exc:  # PEAK/LLM failure must never abort the hunt
            result.notes.extend(attempt_result.notes)
            result.notes.append(f"PEAK Prepare attempt {attempt}/{attempts} failed ({type(exc).__name__}: {str(exc)[:300]})")
            continue
        attempt_result.notes = [*result.notes, *attempt_result.notes]
        attempt_result.used_peak = True
        return attempt_result
    result.notes.append("fell back to the PoC's own ABLE/plan")
    result.able_markdown = offline_able(poc)
    result.hunt_plan_markdown = offline_plan(poc)
    result.research_markdown = research_document(poc)
    return result
