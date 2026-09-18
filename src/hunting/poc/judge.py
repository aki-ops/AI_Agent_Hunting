"""LLM-as-Judge for PoC runs.

The judge answers one question given the artifact of a hunt:

    "Is the local adapter hit a TRUE_POSITIVE (active threat) or
     FALSE_POSITIVE (operational / legitimate use)?"

Why a separate module
---------------------
The agent already does structured retrieval. The judge is the final
reviewer, not the retrieval itself. It only fires when the analyst asks
for it (``--poc-judge``), keeps token cost bounded, and refuses to answer
without anchored evidence.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


class JudgmentVerdict(str):
    pass


# Verdict is a small enum. We use a plain str + Literal-style values for
# parser friendliness with non-strict LLMs.
TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"
INCONCLUSIVE = "INCONCLUSIVE"
NO_SIGNAL = "NO_SIGNAL"


@dataclass(frozen=True)
class Judgment:
    verdict: str  # TRUE_POSITIVE | FALSE_POSITIVE | INCONCLUSIVE | NO_SIGNAL
    confidence: float  # 0.0–1.0
    rationale: str
    notes: list[str] = field(default_factory=list)
    raw_response: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

JUDGE_PROMPT = """You are a Senior DFIR Reviewer. You are given the
artifact of a PoC-driven hypothesis run. Your job is to decide whether the
adapter hits represent active threat activity or operational noise.

PoC: {poc_name}
PoC summary: {poc_summary}
Time window: {time_window}

Matched steps: {matched_steps}
Total observations: {total_observations}

Evidence rows (up to 10):
{rows}

You must return STRICT JSON only — no markdown, no prose — matching this schema:
{{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "INCONCLUSIVE" | "NO_SIGNAL",
  "confidence": 0.0,
  "rationale": "short evidence-grounded explanation",
  "notes": ["optional short bullet(s)"]
}}

Decision rules
--------------
TRUE_POSITIVE
    A row or set of rows together constitute an active intrusion chain,
    e.g. encoded PowerShell with parent=Outlook, or dns+telemetry to a
    known C2, or persistence created within minutes of the hit.

FALSE_POSITIVE
    The row(s) match the predicates but the surrounding context
    (parent process, owner, signer, scheduled baseline, change-ticket
    metadata, sanctioned IT task) makes the activity consistent with
    legitimate operations or management tooling.

INCONCLUSIVE
    The row(s) exist but the surrounding context is unknown or mixed.
    Not enough to rule in either direction.

NO_SIGNAL
    There were no local hits AND no LLM escalation produced a usable
    narrative. Preserve this as "absence of evidence" rather than
    "evidence of absence".
"""


def build_evidence_brief(poc, matched_step_ids, step_results, total_observations, time_window):
    rows = []
    for step in step_results:
        for row in step.rows[:5]:
            rows.append({
                "step_id": step.step_id,
                "description": step.description,
                "row": _shorten(row),
            })
            if len(rows) >= 10:
                break
        if len(rows) >= 10:
            break

    return {
        "poc_name": poc.name,
        "poc_summary": poc.summary,
        "time_window": time_window,
        "matched_steps": list(matched_step_ids),
        "total_observations": total_observations,
        "rows": rows,
    }


def _shorten(row: dict[str, Any]) -> dict[str, Any]:
    """Trim rows to the fields that matter for analyst review.

    ``parent_image`` is the single most important discriminator for TP/FP
    verdicts, so we always keep it. The other fields are reasonable for
    posture / context.
    """
    keep = [
        "timestamp", "host", "user", "image", "cmdline",
        "parent_image", "ppid", "pid",
        "query", "domain", "site", "uri", "method",
        "file_path", "action",
    ]
    out = {k: row.get(k) for k in keep if row.get(k) not in (None, "")}
    return out


def render_prompt(brief: dict[str, Any], max_tokens: int) -> str:
    body = JUDGE_PROMPT.format(
        poc_name=brief["poc_name"],
        poc_summary=brief["poc_summary"],
        time_window=brief["time_window"],
        matched_steps=", ".join(brief["matched_steps"]) or "(none)",
        total_observations=brief["total_observations"],
        rows=json.dumps(brief["rows"], indent=2, ensure_ascii=False) or "(empty)",
    )
    if max_tokens:
        body += f"\n\nMax tokens for your response: {max_tokens}"
    return body


# ---------------------------------------------------------------------------
# Parser (defensive)
# ---------------------------------------------------------------------------

_VALID_VERDICTS = {TRUE_POSITIVE, FALSE_POSITIVE, INCONCLUSIVE, NO_SIGNAL}


def _extract_json(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object from an LLM response."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None


def parse_judgment(text: str) -> Judgment:
    """Parse an LLM response into a Judgment, falling back to INCONCLUSIVE
    if the response is unparseable. The judge never throws.
    """
    data = _extract_json(text or "")
    if not isinstance(data, dict):
        return Judgment(
            verdict=INCONCLUSIVE,
            confidence=0.0,
            rationale="Judge returned unparseable response; defaulted to INCONCLUSIVE.",
            notes=["parse_failed"],
            raw_response=text or "",
        )

    verdict = str(data.get("verdict", "")).strip().upper()
    if verdict not in _VALID_VERDICTS:
        verdict = INCONCLUSIVE

    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    rationale = str(data.get("rationale", "")).strip()
    notes = [str(n).strip() for n in data.get("notes", []) if str(n).strip()]

    return Judgment(
        verdict=verdict,
        confidence=confidence,
        rationale=rationale,
        notes=notes,
        raw_response=text or "",
    )


# ---------------------------------------------------------------------------
# One-shot judge API
# ---------------------------------------------------------------------------

def judge_run(
    poc,
    matched_step_ids: list[str],
    step_results,
    total_observations: int,
    time_window: str,
    llm_caller,
    max_tokens: int = 2000,
) -> tuple[Judgment, int, int]:
    """Run the LLM judge over a finished PoC run.

    Returns ``(judgment, llm_calls, llm_tokens)``.
    The judge refuses to call the LLM if there is no evidence: empty
    rows AND no escalation summary produces ``NO_SIGNAL`` directly.
    """
    brief = build_evidence_brief(
        poc,
        matched_step_ids,
        step_results,
        total_observations,
        time_window,
    )

    if not matched_step_ids and not any(s.rows for s in step_results):
        return (
            Judgment(
                verdict=NO_SIGNAL,
                confidence=0.0,
                rationale="No adapter hits and no escalation evidence; result is 'absence of evidence', not 'evidence of absence'.",
                notes=["skipped_llm"],
            ),
            0,
            0,
        )

    prompt = render_prompt(brief, max_tokens=max_tokens)
    try:
        response = llm_caller(prompt, max_tokens)
    except Exception as exc:
        return (
            Judgment(
                verdict=INCONCLUSIVE,
                confidence=0.0,
                rationale=f"Judge call failed: {exc}",
                notes=["judge_call_failed"],
            ),
            1,
            0,
        )

    tokens = len(prompt) + len(response or "")
    return parse_judgment(response or ""), 1, tokens


__all__ = [
    "Judgment",
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "INCONCLUSIVE",
    "NO_SIGNAL",
    "judge_run",
    "parse_judgment",
    "build_evidence_brief",
    "render_prompt",
]
