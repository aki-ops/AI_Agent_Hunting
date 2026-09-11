"""PoC case-file Markdown reporter.

The PoC case-file is what an analyst reads after a hunt. It is not the
machine-readable ledger; that is JSON.
"""
from __future__ import annotations

from hunting.poc.agent import PocHuntResult


def render_poc_report(result: PocHuntResult, poc_render: dict) -> str:
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
    lines.append(f"## Verdict: **{result.verdict}**")
    lines.append("")
    lines.append(result.rationale)
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
    lines.append(f"- Calls: {result.llm_calls}")
    lines.append(f"- Tokens: {result.llm_tokens}")
    lines.append(f"- Cost: ${result.llm_cost_usd:.6f}")
    if result.escalation_called:
        lines.append("")
        lines.append("### Escalation Summary")
        lines.append("")
        lines.append(result.escalation_summary or "(no summary)")
    lines.append("")
    lines.append("## Ledger")
    lines.append("")
    lines.append(f"`{result.ledger_path}`")
    lines.append("")
    return "\n".join(lines)


__all__ = ["render_poc_report"]
