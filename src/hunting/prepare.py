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
import hashlib
import io
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
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
    cache: str = "disabled"  # disabled | miss | hit | refresh

    def to_dict(self) -> dict[str, Any]:
        return {
            "used_peak": self.used_peak,
            "able_markdown": self.able_markdown,
            "hunt_plan_markdown": self.hunt_plan_markdown,
            "research_markdown": self.research_markdown,
            "notes": list(self.notes),
            "cache": self.cache,
        }


def _peak_version() -> str:
    try:
        from importlib.metadata import version

        return version("peak-assistant")
    except Exception:  # not installed / no metadata
        return "unknown"


def prepare_cache_key(poc: PoC, data_document: str, model: str, use_research: bool) -> str:
    """Stable key: the PoC content, the data description, the model and PEAK's version decide the output."""
    payload = {
        "poc": poc.render(), "data": data_document, "model": model, "research": use_research,
        "context": LOCAL_CONTEXT, "peak": _peak_version(), "schema": 1,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cache_path(cache_dir: Path, poc: PoC, key: str) -> Path:
    return Path(cache_dir) / "prepare" / f"{poc.poc_id}-{key[:16]}.json"


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
    await _peak_prepare_texts(
        hypothesis=hypothesis_text(poc), research=research_document(poc), data_document=data_document,
        local_context=LOCAL_CONTEXT, technique=poc.topic or poc.name, timeout=timeout,
        use_research=use_research, result=result,
    )


async def _peak_prepare_texts(
    *, hypothesis: str, research: str, data_document: str, local_context: str, technique: str,
    timeout: int, use_research: bool, result: PrepareResult,
) -> None:
    """The PEAK Prepare calls, on plain text inputs (shared by the PoC pipeline and the public-PoC planner)."""
    from peak_assistant.able_assistant import able_table
    from peak_assistant.planning_assistant import plan_hunt
    from peak_assistant.utils.result_extractors import extract_hunt_plan

    if use_research:
        try:
            from peak_assistant.research_assistant import researcher
            from peak_assistant.utils.result_extractors import extract_research_report

            run = await asyncio.wait_for(researcher(technique=technique, local_context=local_context), timeout)
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
                local_context=local_context,
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
                local_context=local_context,
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
    cache_dir: str | Path | None = None,
    refresh: bool = False,
) -> PrepareResult:
    """Run PEAK Prepare for one PoC; degrade to the PoC's own plan with a recorded reason.

    With ``cache_dir`` the successful PEAK output is stored under a key made of the PoC, the data
    description, the model and PEAK's version, so a rerun of the same PoC is instant and reproduces the
    same ABLE/plan text. ``refresh`` ignores a cached entry and overwrites it. Fallback (non-PEAK)
    output is never cached.
    """
    result = PrepareResult(used_peak=False)
    cache_file: Path | None = None
    if llm is not None and cache_dir is not None:
        model = getattr(getattr(llm, "settings", None), "model", "unknown")
        key = prepare_cache_key(poc, data_document, model, use_research)
        cache_file = _cache_path(Path(cache_dir), poc, key)
        result.cache = "refresh" if refresh else "miss"
        if cache_file.exists() and not refresh:
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                hit = PrepareResult(
                    used_peak=True,
                    able_markdown=data["able_markdown"],
                    hunt_plan_markdown=data["hunt_plan_markdown"],
                    research_markdown=data.get("research_markdown", ""),
                    notes=[*data.get("notes", []), f"prepare cache hit ({key[:12]}): PEAK not called; delete the entry or use --refresh-prepare to regenerate"],
                    cache="hit",
                )
                return hit
            except (OSError, ValueError, KeyError):
                result.notes.append("prepare cache entry unreadable; regenerated")
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
            switch = getattr(llm, "switch_model", None)
            if callable(switch) and switch(exc):
                result.notes.append(f"switched to fallback model {llm.settings.model}")
            continue
        attempt_result.notes = [*result.notes, *attempt_result.notes]
        attempt_result.used_peak = True
        attempt_result.cache = result.cache
        if cache_file is not None:
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps({
                    "able_markdown": attempt_result.able_markdown,
                    "hunt_plan_markdown": attempt_result.hunt_plan_markdown,
                    "research_markdown": attempt_result.research_markdown,
                    "notes": attempt_result.notes,
                    "model": getattr(getattr(llm, "settings", None), "model", "unknown"),
                }, ensure_ascii=False, indent=1), encoding="utf-8")
            except OSError as exc:
                attempt_result.notes.append(f"prepare cache not written: {exc}")
        return attempt_result
    result.notes.append("fell back to the PoC's own ABLE/plan")
    result.able_markdown = offline_able(poc)
    result.hunt_plan_markdown = offline_plan(poc)
    result.research_markdown = research_document(poc)
    return result


def run_peak_texts(
    *,
    hypothesis: str,
    research: str,
    data_document: str,
    local_context: str,
    technique: str,
    llm: PeakLlm | None,
    timeout: int = 420,
    attempts: int = 2,
    cache_dir: str | Path | None = None,
    refresh: bool = False,
) -> PrepareResult:
    """PEAK Prepare on plain text (used for public PoCs, where there is no ``PoC`` object).

    Same behaviour as :func:`run_prepare`: cached on success, never raises, and returns ``used_peak=False`` with the
    reason in ``notes`` when PEAK or the LLM is unavailable (the caller then plans without PEAK's text).
    """
    result = PrepareResult(used_peak=False)
    if llm is None:
        result.notes.append("PEAK Assistant not used (offline mode or LLM not configured)")
        return result
    model = getattr(getattr(llm, "settings", None), "model", "unknown")
    key = hashlib.sha256(json.dumps(
        [hypothesis, research, data_document, local_context, model, _peak_version(), "texts-1"], ensure_ascii=False
    ).encode("utf-8")).hexdigest()
    cache_file = Path(cache_dir) / "prepare-texts" / f"{key[:24]}.json" if cache_dir is not None else None
    if cache_file is not None:
        result.cache = "refresh" if refresh else "miss"
        if cache_file.exists() and not refresh:
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                return PrepareResult(
                    used_peak=True, able_markdown=data["able_markdown"], hunt_plan_markdown=data["hunt_plan_markdown"],
                    research_markdown=data.get("research_markdown", ""), cache="hit",
                    notes=[*data.get("notes", []), f"prepare cache hit ({key[:12]}): PEAK not called"],
                )
            except (OSError, ValueError, KeyError):
                result.notes.append("prepare cache entry unreadable; regenerated")
    for attempt in range(1, attempts + 1):
        attempt_result = PrepareResult(used_peak=False)
        try:
            with _quiet_peak():
                run_async(_peak_prepare_texts(
                    hypothesis=hypothesis, research=research, data_document=data_document, local_context=local_context,
                    technique=technique, timeout=timeout, use_research=False, result=attempt_result,
                ))
        except Exception as exc:  # PEAK/LLM failure must never abort planning
            result.notes.extend(attempt_result.notes)
            result.notes.append(f"PEAK Prepare attempt {attempt}/{attempts} failed ({type(exc).__name__}: {str(exc)[:300]})")
            switch = getattr(llm, "switch_model", None)
            if callable(switch) and switch(exc):
                result.notes.append(f"switched to fallback model {llm.settings.model}")
            continue
        attempt_result.notes = [*result.notes, *attempt_result.notes]
        attempt_result.used_peak = True
        attempt_result.cache = result.cache
        if cache_file is not None:
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps({
                    "able_markdown": attempt_result.able_markdown, "hunt_plan_markdown": attempt_result.hunt_plan_markdown,
                    "research_markdown": attempt_result.research_markdown, "notes": attempt_result.notes, "model": model,
                }, ensure_ascii=False, indent=1), encoding="utf-8")
            except OSError as exc:
                attempt_result.notes.append(f"prepare cache not written: {exc}")
        return attempt_result
    result.notes.append("PEAK Prepare failed; planning continues without PEAK's ABLE/plan text")
    return result
