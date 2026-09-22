"""PEAK Act — detection draft, Splunk parse check, backlog, stakeholder export.

Shared by the PoC, baseline-survey and LLM-assisted runs.
For every finished run the Act layer derives:

- detection draft: a Splunk SPL search;
- a static read-only check, plus a live Splunk parser check when a
  checker is attached;
- an append-only backlog store;
- a stakeholder summary written to its own file.

SPL builders stay pure. ``commit_act`` is the only function that writes.
A draft is VALIDATED only after the Splunk parser accepts it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def _quote(value: str) -> str:
    return value.replace('"', '\\"')


_DANGEROUS_SPL = re.compile(
    r"(?i)\|\s*(delete|outputlookup|collect|sendemail|map|script|runshellscript)\b"
)


@dataclass
class SplValidation:
    """Result of checking one detection draft."""

    spl: str
    static_ok: bool
    live_status: str  # skipped | valid | invalid | unreachable
    messages: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.static_ok or self.live_status == "invalid":
            return "INVALID"
        if self.live_status == "valid":
            return "VALIDATED"
        return "DRAFT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "static_ok": self.static_ok,
            "live_status": self.live_status,
            "messages": list(self.messages),
            "spl": self.spl,
        }


def validate_spl_static(spl: str) -> list[str]:
    """Reject drafts that are not a read-only search."""
    text = str(spl or "").strip()
    errors: list[str] = []
    if not text:
        return ["SPL is empty"]
    head = text.splitlines()[0].strip().lower()
    if not (head.startswith("search ") or head.startswith("|")):
        errors.append("SPL must start with 'search' or a generating command")
    if _DANGEROUS_SPL.search(text):
        errors.append("SPL contains a command that writes or shells out")
    if text.count('"') % 2:
        errors.append("SPL has unbalanced double quotes")
    return errors


def validate_spl(
    spl: str,
    live_checker: Callable[[str], dict[str, Any]] | None = None,
) -> SplValidation:
    """Static check, then optional Splunk ``/services/search/parser`` check.

    ``live_checker`` returns ``{"ok": bool, "messages": [str, ...]}``.
    A transport failure is ``unreachable`` and leaves the draft unvalidated.
    """
    errors = validate_spl_static(spl)
    messages = list(errors)
    live = "skipped"
    if not errors and live_checker is not None:
        try:
            result = live_checker(spl) or {}
            live = "valid" if result.get("ok") else "invalid"
            messages.extend(str(item) for item in (result.get("messages") or []) if str(item).strip())
        except Exception as exc:
            live = "unreachable"
            messages.append(f"Splunk parser unreachable: {exc}")
    return SplValidation(spl=spl, static_ok=not errors, live_status=live, messages=messages)


def append_backlog(
    items: list[str],
    *,
    source: str,
    store_path: str | Path = "artifacts/backlog/backlog.jsonl",
) -> str:
    """Append follow-up topics to the backlog store. Returns the store path."""
    path = Path(store_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with path.open("a", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(
                {"ts": stamp, "source": source, "item": item},
                ensure_ascii=False,
            ) + "\n")
    return str(path)


def export_stakeholder(bullets: list[str], path: str | Path, *, title: str) -> str:
    """Write the stakeholder summary as its own Markdown note."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", ""]
    for bullet in bullets:
        lines.append(f"- {bullet}")
    lines.append("")
    file_path.write_text("\n".join(lines), encoding="utf-8")
    return str(file_path)


def commit_act(
    *,
    kind: str,
    source: str,
    spls: list[str],
    backlog: list[str],
    stakeholder: list[str],
    export_dir: str | Path,
    live_checker: Callable[[str], dict[str, Any]] | None = None,
    backlog_path: str | Path = "artifacts/backlog/backlog.jsonl",
) -> dict[str, Any]:
    """Validate drafts, append the backlog, and export the stakeholder note."""
    validations = [validate_spl(spl, live_checker) for spl in spls]
    directory = Path(export_dir)
    directory.mkdir(parents=True, exist_ok=True)
    validation_path = directory / "spl_validation.json"
    validation_path.write_text(
        json.dumps([item.to_dict() for item in validations], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    stored = append_backlog(backlog, source=f"{kind}:{source}", store_path=backlog_path) if backlog else ""
    stakeholder_path = export_stakeholder(
        stakeholder,
        directory / "stakeholder.md",
        title=f"Stakeholder note — {source}",
    )
    return {
        "validations": [item.to_dict() for item in validations],
        "validation_path": str(validation_path),
        "backlog_path": stored,
        "stakeholder_path": stakeholder_path,
    }


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
        bullets.append("Next: analyst adjudicates top API-LLM leads (TP/FP) before alerting.")
    return bullets


__all__ = [
    "SplValidation",
    "append_backlog",
    "backlog_from_baseline",
    "backlog_from_math",
    "backlog_from_poc",
    "commit_act",
    "export_stakeholder",
    "spl_from_lead",
    "spl_from_outlier",
    "spl_from_poc_steps",
    "stakeholder_summary",
    "validate_spl",
    "validate_spl_static",
]
