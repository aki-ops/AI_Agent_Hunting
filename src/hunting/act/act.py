"""PEAK Act — deterministic post-hunt artifacts, no LLM.

Shared by all three PEAK hunt types (hypothesis PoC, baseline EDA, M-ATH lite).
For every finished run the Act layer derives:

- detection draft: a Splunk SPL search the analyst can paste into
  Splunk / Enterprise Security (marked DRAFT — needs analyst review);
- backlog: follow-up hunt topics discovered during the run;
- stakeholder summary: 3–5 plain-language bullets for SOC lead / manager.

All builders are pure functions over the run's own rows/fields so the
output is reproducible and auditable. Nothing here claims a detection is
production-ready — PEAK Act says "propose, analyst disposes".
"""
from __future__ import annotations

from typing import Any


def _quote(value: str) -> str:
    return value.replace('"', '\\"')


def spl_from_poc_steps(
    steps: list[dict[str, Any]],
    *,
    index: str = "botsv1",
    earliest: str = "-14d",
    latest: str = "now",
) -> str:
    """Build a draft SPL search from PoC TestStep predicates.

    EQUALS -> ``field="value"``; CONTAINS/STARTS_WITH/ENDS_WITH/MATCHES ->
    a case-insensitive ``match()``; EXISTS -> ``NOT field=""``.
    """
    terms: list[str] = []
    for step in steps:
        fld = str(step.get("target_field", "")).strip()
        op = str(step.get("op", "")).upper()
        val = str(step.get("value", ""))
        if not fld:
            continue
        if op == "EQUALS" and val:
            terms.append(f'{fld}="{_quote(val)}"')
        elif op in ("CONTAINS", "STARTS_WITH", "ENDS_WITH", "MATCHES") and val:
            terms.append(f'match({fld}, "(?i){_quote(val)}")')
        elif op == "EXISTS":
            terms.append(f'NOT {fld}=""')
    body = " ".join(terms) if terms else "*"
    return (
        f"search index=\"{index}\" {body} earliest={earliest} latest={latest}\n"
        "| table _time, host, user, image, cmdline, domain, file_path, action"
    )


def spl_from_lead(
    lead: dict[str, Any],
    *,
    index: str = "botsv1",
    earliest: str = "-14d",
    latest: str = "now",
) -> str:
    """Build a draft SPL search from a single M-ATH lead."""
    fld = str(lead.get("field", "")).strip()
    val = str(lead.get("value", ""))
    kind = str(lead.get("kind", ""))
    if kind == "rare_sequence" and "->" in val:
        left, _, right = val.partition("->")
        body = f'"{_quote(left.strip())}" "{_quote(right.strip())}"'
    elif fld and val:
        body = f'{fld}="{_quote(val)}"'
    else:
        body = "*"
    return (
        f"search index=\"{index}\" {body} earliest={earliest} latest={latest}\n"
        "| table _time, host, user, image, cmdline, domain, file_path, action"
    )


def spl_from_outlier(
    outlier: dict[str, Any],
    *,
    index: str = "botsv1",
    earliest: str = "-30d",
    latest: str = "now",
) -> str:
    """Build a draft SPL search from a single baseline outlier."""
    fld = str(outlier.get("field", "")).strip()
    val = str(outlier.get("value", ""))
    body = f'{fld}="{_quote(val)}"' if fld else "*"
    return (
        f"search index=\"{index}\" {body} earliest={earliest} latest={latest}\n"
        "| stats count by host, user, image | sort -count"
    )


def backlog_from_poc(
    poc_render: dict[str, Any],
    matched_step_ids: list[str],
    all_step_ids: list[str],
) -> list[str]:
    """Suggest follow-up hunts from a PoC run."""
    suggestions: list[str] = []
    missed = [s for s in all_step_ids if s not in matched_step_ids]
    able = poc_render.get("able") or {}
    if missed:
        suggestions.append(
            "Refine hunt: steps "
            + ", ".join(f"`{s}`" for s in missed)
            + " had no hits — narrow the value or widen the window (PEAK Refine)."
        )
    if able.get("behavior"):
        suggestions.append(
            f"Sibling TTP hunt: same behavior `{able['behavior']}` on other host groups."
        )
    if poc_render.get("topic"):
        suggestions.append(
            f"New topic candidate: variations of `{poc_render['topic']}` (PEAK Re-Add Topic to Backlog)."
        )
    return suggestions


def backlog_from_baseline(
    outliers: list[dict[str, Any]],
    gaps: list[str],
) -> list[str]:
    suggestions: list[str] = []
    for outlier in outliers[:5]:
        suggestions.append(
            f"Hypothesis candidate: `{outlier.get('field')}={outlier.get('value')}` "
            f"seen {outlier.get('count')}x ({outlier.get('reason')}) — hunt it as a hypothesis."
        )
    for gap in gaps:
        suggestions.append(f"Coverage task: {gap}")
    return suggestions


def backlog_from_math(leads: list[dict[str, Any]]) -> list[str]:
    suggestions: list[str] = []
    for lead in leads[:5]:
        suggestions.append(
            f"Lead follow-up: `{lead.get('lead_id')}` {lead.get('kind')} "
            f"score={lead.get('score')} — adjudicate via PoC hunt or --poc-judge."
        )
    return suggestions


def stakeholder_summary(kind: str, headline: str, facts: list[str]) -> list[str]:
    """Plain-language bullets: what happened, impact, next action."""
    bullets = [headline]
    bullets.extend(facts[:3])
    if kind == "poc":
        bullets.append("Next: analyst reviews the detection draft before production.")
    elif kind == "baseline":
        bullets.append("Next: SOC links this baseline from triage playbooks.")
    elif kind == "math":
        bullets.append("Next: analyst adjudicates top leads (TP/FP) before alerting.")
    return bullets


__all__ = [
    "backlog_from_baseline",
    "backlog_from_math",
    "backlog_from_poc",
    "spl_from_lead",
    "spl_from_outlier",
    "spl_from_poc_steps",
    "stakeholder_summary",
]
