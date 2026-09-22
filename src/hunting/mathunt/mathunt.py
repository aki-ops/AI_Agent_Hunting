"""LLM-assisted lead ranking. The model is the API LLM, not a locally trained model.

PEAK M-ATH asks for a model when simple methods are not enough. Training
a local model costs data, GPU time and a maintenance loop. The endpoint
configured in ``.env`` is already a pretrained model, so this module sends
a bounded row sample to that API and keeps only leads whose value occurs
in the supplied rows.

The stdlib detectors below remain an offline prefilter. They run when no
API caller is attached (tests, ``--llm stub``) or when the API reply cannot
be grounded. They are not a trained model and are not called M-ATH.

Offline prefilter, stdlib only:

- frequency anomaly: rare categorical values via stack counting;
- lexical scoring: suspicious tokens in cmdline/domain/uri;
- sequence rarity: rare ordered pairs (parent -> child, user -> image).

No numpy / sklearn / pandas. Same rows in, same prefilter leads out.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Security-relevant fields weigh more: a rare cmdline matters more than a
# rare port number.
FIELD_WEIGHTS = {
    "cmdline": 3.0,
    "image": 2.5,
    "parent_image": 2.5,
    "domain": 2.5,
    "query": 2.5,
    "site": 2.0,
    "uri": 2.0,
    "file_path": 2.0,
    "user": 1.5,
    "host": 1.0,
    "native_type": 0.5,
    "event_id": 0.5,
}

# Lexical signals mapped to (label, weight). Weights are local heuristics,
# documented here so an analyst can retune them per environment.
LEXICAL_SIGNALS: tuple[tuple[str, float, str], ...] = (
    (r"(?i)-enc(odedcommand)?\b", 3.0, "encoded-powershell"),
    (r"(?i)-w\s+hidden|hidden\b.*powershell|powershell.*hidden", 2.0, "hidden-window"),
    (r"(?i)nop(rofile)?\b", 1.0, "no-profile"),
    (r"(?i)bypass|unrestricted", 1.5, "execution-policy-bypass"),
    (r"(?i)iex\b|invoke-expression|invoke-webrequest|downloadstring|frombase64string", 3.0, "download-cradle"),
    (r"(?i)schtasks(\.exe)?\s+/create", 2.5, "scheduled-task-create"),
    (r"(?i)reg\s+add|run\\\\.*\\\\currentversion\\\\run", 2.0, "run-key-persistence"),
    (r"(?i)mimikatz|sekurlsa|procdump|ntdsutil", 4.0, "credential-tool"),
    (r"(?i)powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32", 0.5, "script-host"),
)

_DGA_VOWELS = set("aeiouAEIOU")


def _lexical_score(text: str) -> tuple[float, list[str]]:
    score = 0.0
    labels: list[str] = []
    for pattern, weight, label in LEXICAL_SIGNALS:
        if re.search(pattern, text):
            score += weight
            labels.append(label)
    return score, labels


def _dga_score(domain: str) -> float:
    """Cheap randomness heuristic: long labels with few vowels look generated."""
    host = domain.split("://")[-1].split("/")[0].split(":")[0]
    labels = [p for p in host.split(".") if p]
    if not labels:
        return 0.0
    longest = max(labels, key=len)
    if len(longest) < 12:
        return 0.0
    vowels = sum(1 for c in longest if c in _DGA_VOWELS)
    ratio = vowels / len(longest)
    digits = sum(1 for c in longest if c.isdigit()) / len(longest)
    if ratio < 0.25 or digits > 0.4:
        return 2.0
    return 0.0


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class Lead:
    lead_id: str
    kind: str  # rare_value | lexical | rare_sequence | dga
    score: float
    field: str
    value: Any
    count: int
    evidence_rows: list[dict[str, Any]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "lead_id": self.lead_id,
            "kind": self.kind,
            "score": round(self.score, 3),
            "field": self.field,
            "value": self.value,
            "count": self.count,
            "reasons": list(self.reasons),
            "evidence_rows": self.evidence_rows,
        }


@dataclass
class MathResult:
    run_id: str
    data_source: str
    time_window: str
    row_count: int
    detectors: list[str]
    leads: list[Lead]
    started_at: str
    finished_at: str
    runtime_seconds: float
    ledger_path: str | None = None
    model_source: str = "heuristic_prefilter"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "data_source": self.data_source,
            "time_window": self.time_window,
            "row_count": self.row_count,
            "detectors": list(self.detectors),
            "leads": [lead.to_dict() for lead in self.leads],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "runtime_seconds": self.runtime_seconds,
            "ledger_path": self.ledger_path,
            "model_source": self.model_source,
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _short_row(row: dict[str, Any]) -> dict[str, Any]:
    keep = ("timestamp", "host", "user", "image", "cmdline", "domain",
            "site", "uri", "file_path", "action", "native_type", "event_id")
    return {k: row.get(k) for k in keep if row.get(k) not in (None, "")}


def _parse_llm_leads(response: str) -> list[dict[str, Any]]:
    text = str(response or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return []
    try:
        payload = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    leads = payload.get("leads") if isinstance(payload, dict) else None
    if not isinstance(leads, list):
        return []
    return [item for item in leads if isinstance(item, dict)]


def _ground_llm_leads(parsed: list[dict[str, Any]], rows: list[dict[str, Any]]) -> list[Lead]:
    """Keep an API lead only when its value occurs in a supplied row."""
    grounded: list[Lead] = []
    for index, item in enumerate(parsed, start=1):
        value = str(item.get("value", "")).strip()
        field_name = str(item.get("field", "")).strip() or "cmdline"
        if not value:
            continue
        evidence = [
            _short_row(row) for row in rows
            if value.lower() in json.dumps(row, ensure_ascii=False).lower()
        ]
        if not evidence:
            continue
        try:
            score = float(item.get("score", 1.0))
        except (TypeError, ValueError):
            score = 1.0
        reasons = [str(reason) for reason in (item.get("reasons") or []) if str(reason).strip()]
        reasons.append("api_llm")
        grounded.append(Lead(
            lead_id=f"llm-{index:03d}",
            kind="api_llm",
            score=score,
            field=field_name,
            value=value,
            count=len(evidence),
            evidence_rows=evidence[:3],
            reasons=reasons,
        ))
    grounded.sort(key=lambda lead: lead.score, reverse=True)
    return grounded


def _llm_prompt(rows: list[dict[str, Any]], prefilter: list[Lead]) -> str:
    sample = [_short_row(row) for row in rows[:30]]
    hints = [
        {"field": lead.field, "value": lead.value, "kind": lead.kind, "score": lead.score}
        for lead in prefilter[:8]
    ]
    return (
        "You are the pretrained model for a threat hunt. Do not invent indicators. "
        "Return JSON only: {\"leads\": [{\"field\": str, \"value\": str, \"score\": number, "
        "\"reasons\": [str]}]}. Every value must be copied from the rows. "
        f"Rows: {json.dumps(sample, ensure_ascii=False)}. "
        f"Prefilter hints (not evidence): {json.dumps(hints, ensure_ascii=False)}."
    )


def run_math(
    rows: list[dict[str, Any]],
    *,
    data_source: str,
    time_window: str,
    run_id: str | None = None,
    detectors: list[str] | None = None,
    rare_threshold: int = 2,
    min_score: float = 2.0,
    max_leads: int = 25,
    ledger_dir: str | Path | None = None,
    llm_caller: Any | None = None,
    llm_max_tokens: int = 2000,
) -> MathResult:
    """Rank leads. An API caller replaces the prefilter when its leads ground."""
    import time

    t0 = time.perf_counter()
    started = _now()
    run_id = run_id or f"math-{_now()}"
    wanted = set(detectors or ["rare_value", "lexical", "rare_sequence", "dga"])
    leads: list[Lead] = []
    seq = 0

    def _add(kind: str, score: float, f: str, v: Any, n: int,
             rows_: list[dict[str, Any]], reasons: list[str]) -> None:
        nonlocal seq
        if score < min_score:
            return
        seq += 1
        leads.append(Lead(
            lead_id=f"lead-{seq:03d}", kind=kind, score=score,
            field=f, value=v, count=n,
            evidence_rows=[_short_row(r) for r in rows_[:3]],
            reasons=reasons,
        ))

    total = max(len(rows), 1)

    # 1) Rare-value anomaly (frequency model over categorical fields).
    if "rare_value" in wanted:
        for fname, weight in FIELD_WEIGHTS.items():
            counts: Counter = Counter()
            by_value: dict[str, list[dict[str, Any]]] = {}
            for r in rows:
                v = r.get(fname)
                if v in (None, ""):
                    continue
                counts[str(v)] += 1
                by_value.setdefault(str(v), []).append(r)
            for value, count in counts.items():
                if count <= rare_threshold:
                    rarity = 1.0 - (count / total)
                    _add("rare_value", round(weight * (1.0 + rarity), 3),
                         fname, value, count, by_value[value],
                         [f"seen {count}x of {len(rows)} rows (stack-counting)"])

    # 2) Lexical scoring over free-text fields.
    if "lexical" in wanted:
        for r in rows:
            text = " ".join(str(r.get(c) or "") for c in ("cmdline", "domain", "site", "uri", "file_path"))
            if not text.strip():
                continue
            score, labels = _lexical_score(text)
            if len(text) > 120:
                ent = _entropy(text)
                if ent > 4.5:
                    score += 1.0
                    labels.append("high-entropy")
            if score >= min_score:
                anchor = r.get("cmdline") or r.get("domain") or r.get("uri") or text[:80]
                _add("lexical", round(score, 3),
                     "cmdline" if r.get("cmdline") else "domain",
                     anchor, 1, [r], labels)

    # 3) Rare-sequence: unusual ordered pairs.
    if "rare_sequence" in wanted:
        pid_to_image: dict[Any, str] = {}
        for r in rows:
            if r.get("pid") is not None and r.get("image"):
                pid_to_image[r.get("pid")] = str(r.get("image"))
        pairs: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            parent = r.get("parent_image")
            if not parent and r.get("ppid") in pid_to_image:
                parent = pid_to_image[r.get("ppid")]
            if parent and r.get("image"):
                pairs.setdefault(f"{parent} -> {r.get('image')}", []).append(r)
            if r.get("user") and r.get("image"):
                pairs.setdefault(f"{r.get('user')} :: {r.get('image')}", []).append(r)
        for pair, members in pairs.items():
            if len(members) <= rare_threshold:
                _add("rare_sequence", round(2.0 + (1.0 - len(members) / total), 3),
                     "sequence", pair, len(members), members,
                     [f"sequence seen {len(members)}x (rare behaviour)"])

    # 4) DGA-ish domains.
    if "dga" in wanted:
        by_domain: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            for col in ("domain", "query", "site"):
                d = r.get(col)
                if d:
                    by_domain.setdefault(str(d), []).append(r)
        for domain, members in by_domain.items():
            score = _dga_score(domain)
            if score >= min_score:
                _add("dga", score, "domain", domain, len(members), members,
                     ["long consonant-heavy label (generated-looking)"])

    leads.sort(key=lambda lead: lead.score, reverse=True)
    leads = leads[:max_leads]
    model_source = "heuristic_prefilter"
    if llm_caller is not None:
        response = llm_caller(_llm_prompt(rows, leads), llm_max_tokens)
        grounded = _ground_llm_leads(_parse_llm_leads(response), rows)
        if grounded:
            leads = grounded[:max_leads]
            model_source = "api_llm"
            wanted.add("api_llm")
        else:
            model_source = "api_llm_ungrounded_fallback"
    elapsed = round(time.perf_counter() - t0, 4)
    result = MathResult(
        run_id=run_id, data_source=data_source, time_window=time_window,
        row_count=len(rows), detectors=sorted(wanted), leads=leads,
        started_at=started, finished_at=_now(), runtime_seconds=elapsed,
        model_source=model_source,
    )
    out_dir = Path(ledger_dir) if ledger_dir else Path("models") / "math_runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = out_dir / f"{run_id}.json"
    ledger_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    result.ledger_path = str(ledger_path)
    return result


def render_math_report(result: MathResult) -> str:
    from hunting.act import backlog_from_math, spl_from_lead, stakeholder_summary

    spls = [spl_from_lead(lead.to_dict()) for lead in result.leads[:3]]
    backlog = backlog_from_math([lead.to_dict() for lead in result.leads])
    model_source = getattr(result, "model_source", "heuristic_prefilter")
    if model_source == "api_llm":
        headline = (
            f"API LLM hunt `{result.run_id}` over {result.row_count} rows: "
            f"{len(result.leads)} grounded leads. No local model was trained."
        )
        title = f"# LLM-Assisted Hunt Report — `{result.data_source}`"
    else:
        headline = (
            f"Offline prefilter `{result.run_id}` over {result.row_count} rows: "
            f"{len(result.leads)} leads. This is not a trained model."
        )
        title = f"# Heuristic Lead Report — `{result.data_source}`"
    stakeholder = stakeholder_summary(
        "math",
        headline,
        [f"Top lead: `{result.leads[0].lead_id}` {result.leads[0].kind} "
         f"score={result.leads[0].score:.2f}."] if result.leads else [],
    )
    act_block = {"detection_spls": spls, "backlog": backlog, "stakeholder": stakeholder}
    lines: list[str] = []
    lines.append(title)
    lines.append("")
    lines.append(f"**Model:** `{model_source}`")
    lines.append("")
    lines.append(f"**Run ID:** `{result.run_id}`")
    lines.append(f"**Window:** {result.time_window}")
    lines.append(f"**Rows:** {result.row_count}")
    lines.append(f"**Detectors:** {', '.join(result.detectors)}")
    lines.append(f"**Leads:** {len(result.leads)}")
    lines.append(f"**Runtime:** {result.runtime_seconds:.4f} s")
    lines.append("")
    lines.append("## Leads (ranked)")
    lines.append("")
    if result.leads:
        for lead in result.leads:
            lines.append(f"### `{lead.lead_id}` — {lead.kind} (score {lead.score:.2f})")
            lines.append("")
            lines.append(f"- Field: `{lead.field}` ×{lead.count}")
            lines.append(f"- Value: `{lead.value}`")
            lines.append(f"- Reasons: {'; '.join(lead.reasons)}")
            lines.append("")
    else:
        lines.append("No leads above threshold. Tune `--math-min-score` or `--math-rare`.")
        lines.append("")
    lines.append("## Act (Detection Drafts + Backlog)")
    lines.append("")
    lines.append("### Detection Drafts (SPL — analyst review required)")
    lines.append("")
    for spl in act_block["detection_spls"][:3]:
        lines.append("```spl")
        lines.append(spl)
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
    lines.append("## Next step (Analyze)")
    lines.append("")
    lines.append("Feed a lead into a PoC hunt or the LLM judge, e.g.:")
    lines.append("")
    lines.append("```bash")
    lines.append("--poc-judge --llm api   # adjudicate matched rows as TP/FP")
    lines.append("```")
    lines.append("")
    lines.append("## Ledger")
    lines.append("")
    lines.append(f"`{result.ledger_path}`")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "FIELD_WEIGHTS",
    "LEXICAL_SIGNALS",
    "Lead",
    "MathResult",
    "render_math_report",
    "run_math",
]
