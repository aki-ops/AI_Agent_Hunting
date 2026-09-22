"""PoC case-file Markdown reporter.

The PoC case-file is what an analyst reads after a hunt. It is not the
machine-readable ledger; that is JSON.
"""
from __future__ import annotations

from hunting.poc.agent import PocHuntResult


def build_poc_act_block(
    result: PocHuntResult,
    poc_render: dict,
    live_checker=None,
) -> dict[str, object]:
    """Assemble the Act block. The live checker is optional and performs no write."""
    from hunting.act import (
        backlog_from_poc,
        spl_from_poc_steps,
        stakeholder_summary,
        validate_spl,
    )

    spl = spl_from_poc_steps(poc_render.get("steps", []))
    validation = validate_spl(spl, live_checker)
    all_ids = [s.get("step_id", "") for s in poc_render.get("steps", [])]
    backlog = backlog_from_poc(poc_render, list(result.matched_step_ids), all_ids)
    judge = f"Judge: {result.judgment.verdict} ({result.judgment.confidence:.2f})." if result.judgment else "No judge."
    stakeholder = stakeholder_summary(
        "poc",
        f"PoC `{result.poc_id}` verdict {result.verdict} over {result.total_observations} observations. {judge}",
        [f"Matched steps: {', '.join(result.matched_step_ids) or '(none)'}."],
    )
    return {
        "detection_spl": spl,
        "backlog": backlog,
        "stakeholder": stakeholder,
        "validation": validation.to_dict(),
    }


def render_poc_report(result: PocHuntResult, poc_render: dict, live_checker=None) -> str:
    act_block = build_poc_act_block(result, poc_render, live_checker=live_checker)
    lines: list[str] = []
    lines.append(f"# PoC Hunt Report — `{result.poc_id}`")
    lines.append("")
    lines.append(f"**PoC Name:** {result.poc_name}")
    lines.append(f"**Request ID:** `{result.request_id}`")
    lines.append(f"**Window:** {result.time_window}")
    lines.append(f"**Started:** {result.started_at}")
    lines.append(f"**Finished:** {result.finished_at}")
    lines.append(f"**Runtime:** {result.runtime_seconds:.4f} s")
    lines.append("")
    lines.append("## Hunt Plan (ABLE)")
    lines.append("")
    if poc_render.get("topic"):
        lines.append(f"- Topic: {poc_render.get('topic')}")
    able = poc_render.get("able") or {}
    lines.append(f"- Actor: {able.get('actor') or '(unknown)'}")
    if able.get("behavior"):
        lines.append(f"- Behavior: {able.get('behavior')}")
    if able.get("location"):
        lines.append(f"- Location: {able.get('location')}")
    if able.get("evidence"):
        lines.append(f"- Evidence: {able.get('evidence')}")
    if poc_render.get("scope"):
        lines.append(f"- Scope: {poc_render.get('scope')}")
    if poc_render.get("max_duration"):
        lines.append(f"- Max duration: {poc_render.get('max_duration')}")
    if poc_render.get("plan"):
        lines.append(f"- Plan: {poc_render.get('plan')}")
    if poc_render.get("research_refs"):
        lines.append(f"- Research: {', '.join(poc_render.get('research_refs'))}")
    lines.append("")
    lines.append(f"## Verdict: **{result.verdict}**")
    lines.append("")
    lines.append(result.rationale)
    lines.append("")
    if getattr(result, "scope_note", ""):
        lines.append(f"Scope enforcement: {result.scope_note}")
        lines.append("")
    lines.append("## Execute (Analyze → Refine)")
    lines.append("")
    for entry in getattr(result, "refine_log", []) or []:
        detail = entry.get("reason")
        if not detail:
            detail = f"matched={entry.get('matched', [])} missed={entry.get('missed', [])}"
        lines.append(f"- pass {entry.get('pass', '-')}: {entry.get('phase')} — {detail}")
    lines.append("")
    lines.append("## IR Escalation")
    lines.append("")
    if getattr(result, "ir_escalated", False):
        lines.append(f"- Filed for IR: `{result.ir_escalation_path}`")
    else:
        lines.append("- Not filed. The pass produced no critical finding.")
    lines.append("")
    if result.judgment is not None:
        lines.append(f"## LLM Judge: **{result.judgment.verdict}** (confidence {result.judgment.confidence:.2f})")
        lines.append("")
        lines.append(result.judgment.rationale)
        if result.judgment.notes:
            lines.append("")
            lines.append("**Notes:**")
            for note in result.judgment.notes:
                lines.append(f"- {note}")
        lines.append("")
        lines.append(f"_Judge cost: {result.judgment_llm_calls} call(s), {result.judgment_llm_tokens} token(s)_")
        lines.append("")
    lines.append("## PoC Definition")
    lines.append("")
    lines.append(f"- Kind: `{poc_render.get('kind')}`")
    lines.append(f"- Summary: {poc_render.get('summary', '')}")
    lines.append(f"- Expected chain: {', '.join(poc_render.get('expected_chain', [])) or '(none)'}")
    lines.append(f"- References: {', '.join(poc_render.get('references', [])) or '(none)'}")
    lines.append("")
    lines.append("### Steps")
    lines.append("")
    for step in poc_render.get("steps", []):
        lines.append(
            f"- `[{step['step_id']}]` {step['description']} "
            f"→ `{step['target_field']} {step['op']} {step['value']}`"
        )
    if poc_render.get("fallbacks"):
        lines.append("")
        lines.append("### Fallbacks")
        for step in poc_render["fallbacks"]:
            lines.append(
                f"- `[{step['step_id']}]` {step['description']} "
                f"→ `{step['target_field']} {step['op']} {step['value']}`"
            )
    lines.append("")
    lines.append("## Step Results")
    lines.append("")
    for step in result.step_results:
        flag = "✓" if step.row_count > 0 else "✗"
        fallback_note = " (fallback)" if step.used_fallback else ""
        lines.append(
            f"- {flag} `[{step.step_id}]{fallback_note}` "
            f"{step.description}: {step.row_count} row(s)"
        )
        for row in step.rows[:5]:
            lines.append(f"  - `{row}`")
        if step.row_count > 5:
            lines.append(f"  - … (+{step.row_count - 5} more)")
    lines.append("")
    lines.append("## LLM Cost")
    lines.append("")
    total_calls = result.llm_calls + result.judgment_llm_calls
    total_tokens = result.llm_tokens + result.judgment_llm_tokens
    lines.append(f"- Calls: {total_calls} (match/escalation={result.llm_calls}, judge={result.judgment_llm_calls})")
    lines.append(f"- Tokens: {total_tokens} (match/escalation={result.llm_tokens}, judge={result.judgment_llm_tokens})")
    lines.append(f"- Cost: ${result.llm_cost_usd:.6f}")
    if result.escalation_called:
        lines.append("")
        lines.append("### Escalation Summary")
        lines.append("")
        lines.append(result.escalation_summary or "(no summary)")
    lines.append("")
    lines.append("## Act (Detection Draft + Backlog)")
    lines.append("")
    validation = act_block.get("validation") or {}
    lines.append("### Detection Draft (SPL)")
    lines.append("")
    lines.append(
        f"Validation: **{validation.get('status', 'DRAFT')}** "
        f"(static_ok={validation.get('static_ok')}, live={validation.get('live_status', 'skipped')})"
    )
    lines.append("")
    lines.append("```spl")
    lines.append(act_block["detection_spl"])
    lines.append("```")
    lines.append("")
    if act_block["backlog"]:
        lines.append("### Backlog")
        lines.append("")
        for item in act_block["backlog"]:
            lines.append(f"- {item}")
        lines.append("")
    lines.append("### Stakeholder Summary")
    lines.append("")
    for bullet in act_block["stakeholder"]:
        lines.append(f"- {bullet}")
    lines.append("")
    lines.append("## Ledger")
    lines.append("")
    lines.append(f"`{result.ledger_path}`")
    lines.append("")
    return "\n".join(lines)


__all__ = ["build_poc_act_block", "render_poc_report"]
