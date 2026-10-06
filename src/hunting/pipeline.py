"""End-to-end run of one PoC: PEAK Prepare -> deterministic Execute -> recommendation."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from hunting.act import commit_act
from hunting.llm import METER, PeakLlm
from hunting.peak import PrepareError, able_drive, missing_prepare_fields
from hunting.poc import PocAgent
from hunting.poc.library import POC_LIBRARY
from hunting.poc.models import PoC
from hunting.poc.reporter import build_poc_act_block
from hunting.prepare import run_prepare
from hunting.recommend import advise, decide, summarize_evidence
from hunting.redact import RedactingAdapter, Redactor
from hunting.report import render_recommendation


def run_poc(
    poc: PoC,
    adapter: Any,
    *,
    window: str,
    out_dir: Path,
    llm: PeakLlm | None,
    data_document: str,
    data_source: str,
    peak_timeout: int = 420,
    use_research: bool = False,
    cache_dir: Path | None = None,
    refresh_prepare: bool = False,
    judge_votes: int = 3,
    token_budget: int | None = None,
    redactor: Redactor | None = None,
) -> dict[str, Any]:
    """Run one PoC and write its recommendation. Returns a summary row."""
    missing = missing_prepare_fields(poc)
    if missing:
        raise PrepareError(f"PoC {poc.poc_id}: PEAK Prepare incomplete ({', '.join(missing)})")
    out_dir.mkdir(parents=True, exist_ok=True)
    METER.begin(token_budget if llm is not None else None)
    switches_before = len(llm.model_switches) if llm is not None else 0
    configured_model = llm.settings.model if llm is not None else None
    if redactor is not None:
        redactor.learn_values("host", [able_drive(poc.actor, poc.behavior, poc.location, poc.evidence).host])
        adapter_for_agent: Any = RedactingAdapter(adapter, redactor)
    else:
        adapter_for_agent = adapter

    # 1) Prepare: PEAK Assistant writes the ABLE table and the hunt plan.
    prepare = run_prepare(
        poc, data_document, llm, timeout=peak_timeout, use_research=use_research,
        cache_dir=cache_dir, refresh=refresh_prepare,
    )
    (out_dir / "peak_able.md").write_text(prepare.able_markdown + "\n", encoding="utf-8")
    (out_dir / "peak_hunt_plan.md").write_text(prepare.hunt_plan_markdown + "\n", encoding="utf-8")

    llm_before = (llm.calls, llm.total_tokens) if llm else (0, 0)

    # 2) Execute: deterministic literal predicates against the adapter (+ advisory judge).
    POC_LIBRARY[poc.poc_id] = poc
    agent = PocAgent(
        adapter=adapter_for_agent,
        ledger_dir=out_dir,
        judge_caller=llm,
        enable_judge=llm is not None,
        judge_votes=judge_votes,
    )
    t0 = time.perf_counter()
    result = agent.run(poc.poc_id, time_window=window, request_id=f"{poc.poc_id}", enforce_prepare=True)
    hunt_seconds = time.perf_counter() - t0

    # 3) Act: recommendation for the human.
    effective_window = result.time_window
    evidence = summarize_evidence(poc, result, adapter, effective_window)
    if evidence.observations == 0 and evidence.scope_empty_sources and not evidence.missing_sources:
        # The ABLE host filter matched no telemetry at all: re-run once without it, so "no data for that host"
        # is not confused with "no such activity anywhere".
        probe = PocAgent(
            adapter=adapter, ledger_dir=out_dir / "unscoped_probe", enable_judge=False, use_able_host=False
        ).run(poc.poc_id, time_window=window, request_id=f"{poc.poc_id}-unscoped", enforce_prepare=True)
        evidence.unscoped_probe = {
            "observations": probe.total_observations,
            "matched_steps": len(probe.matched_step_ids),
            "total_steps": len(poc.steps),
        }
    rec = decide(poc, evidence, result.judgment)
    if redactor is not None:
        for name in ("host", "user", "ip"):
            redactor.learn_values(name, [value for value, _ in evidence.pivots.get(name, [])])
        for hosts in evidence.source_hosts.values():
            redactor.learn_values("host", [value for value, _ in hosts])
    if llm is not None:
        advise(rec, poc, prepare.able_markdown, prepare.hunt_plan_markdown, llm)
    llm_calls = (llm.calls - llm_before[0]) if llm else 0  # judge + advisor (PEAK agents are not metered)
    llm_tokens = (llm.total_tokens - llm_before[1]) if llm else 0

    poc_render = poc.render()
    act_block = build_poc_act_block(result, poc_render)
    commit_act(
        kind="poc", source=poc.poc_id,
        spls=[str(act_block["detection_spl"])],
        backlog=list(act_block["backlog"]), stakeholder=list(act_block["stakeholder"]),
        export_dir=out_dir / "act", backlog_path=out_dir / "act" / "backlog.jsonl",
    )

    meta = {
        "data_source": data_source,
        "used_peak": prepare.used_peak,
        "peak_notes": prepare.notes,
        "able_file": "peak_able.md",
        "plan_file": "peak_hunt_plan.md",
        "llm_calls": llm_calls,
        "llm_tokens": llm_tokens,
        "hunt_seconds": hunt_seconds,
        "ledger_path": result.ledger_path,
    }
    snap = METER.snapshot()
    meta |= {
        "model_configured": configured_model,
        "models_used": snap["by_model"],
        "model_switches": list(llm.model_switches[switches_before:]) if llm is not None else [],
        "llm_all_calls": snap["calls"],
        "llm_all_tokens": snap["total_tokens"],
        "llm_prompt_tokens": snap["prompt_tokens"],
        "llm_completion_tokens": snap["completion_tokens"],
        "llm_unmetered_calls": snap["unmetered_calls"],
        "token_budget": snap["budget"],
        "token_budget_exhausted": bool(snap["budget"]) and snap["total_tokens"] >= snap["budget"],
        "prepare_cache": prepare.cache,
        "redacted": redactor is not None,
        "judge_votes": judge_votes if llm is not None else 0,
        "temperature": llm.settings.temperature if llm is not None else None,
    }
    (out_dir / "recommendation.md").write_text(render_recommendation(rec, meta, act_block), encoding="utf-8")
    payload = rec.to_dict()
    payload["execution"] = {
        "verdict": result.verdict, "window": effective_window, "scope_note": result.scope_note,
        "ir_escalation_path": result.ir_escalation_path,
    }
    payload["peak"] = prepare.to_dict() | {"used_peak": prepare.used_peak}
    payload["meta"] = meta
    (out_dir / "recommendation.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "poc_id": poc.poc_id,
        "verdict": result.verdict,
        "observations": evidence.observations,
        "disposition": rec.disposition,
        "confidence": rec.confidence,
        "used_peak": prepare.used_peak,
        "models": sorted(snap["by_model"]),
        "llm_all_tokens": snap["total_tokens"],
    }
