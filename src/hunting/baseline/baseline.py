"""PEAK Baseline hunting (EDA) — deterministic, no LLM.

Implements the PEAK Baseline flow (Splunk SURGe):

    Prepare: Select Data Source -> Research -> Scope -> Plan
    Execute: Gather -> Data Dictionary -> Review Distributions
             -> Investigate Outliers -> Gap Analysis -> Identify Relationships
    Act:     Preserve -> Document Baseline -> (detections/backlog suggestions)

No model, no LLM. Statistics only: counts, cardinality, stack counting
(least-frequency-first), numeric mean/median/std with z-score outliers.
Results persist to ``baselines/<name>.json`` (Knowledge store) plus a
Markdown report.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@dataclass
class FieldProfile:
    name: str
    kind: str  # textual | numeric | categorical | datetime | boolean
    total: int = 0
    non_null: int = 0
    null_count: int = 0
    distinct: int = 0
    top_values: list[dict[str, Any]] = field(default_factory=list)
    mean: float | None = None
    median: float | None = None
    stdev: float | None = None
    min_value: Any = None
    max_value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "total": self.total,
            "non_null": self.non_null,
            "null_count": self.null_count,
            "distinct": self.distinct,
            "top_values": self.top_values,
            "mean": self.mean,
            "median": self.median,
            "stdev": self.stdev,
            "min_value": self.min_value,
            "max_value": self.max_value,
        }


@dataclass
class Outlier:
    field: str
    value: Any
    count: int
    reason: str  # rare_value | zscore

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "value": self.value, "count": self.count, "reason": self.reason}


@dataclass
class BaselineResult:
    baseline_id: str
    data_source: str
    time_window: str
    row_count: int
    fields: list[FieldProfile]
    outliers: list[Outlier]
    gaps: list[str]
    relationships: list[dict[str, Any]]
    started_at: str
    finished_at: str
    runtime_seconds: float
    ledger_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "data_source": self.data_source,
            "time_window": self.time_window,
            "row_count": self.row_count,
            "fields": [f.to_dict() for f in self.fields],
            "outliers": [o.to_dict() for o in self.outliers],
            "gaps": list(self.gaps),
            "relationships": list(self.relationships),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "runtime_seconds": self.runtime_seconds,
            "ledger_path": self.ledger_path,
        }


_KNOWN_COLUMNS = (
    "timestamp", "event_id", "native_type", "host", "user",
    "pid", "ppid", "cmdline", "image", "ip", "port",
    "domain", "file_path", "action", "status", "raw_ref",
)

_SECURITY_FIELDS = (
    "native_type", "host", "user", "image", "cmdline",
    "domain", "ip", "file_path", "action", "status", "event_id",
)


def _classify_kind(name: str, values: list[Any]) -> str:
    if name == "timestamp":
        return "datetime"
    sample = [v for v in values if v is not None][:50]
    if not sample:
        return "textual"
    if all(isinstance(v, bool) for v in sample):
        return "boolean"
    if all(_is_number(v) for v in sample):
        return "numeric"
    if all(isinstance(v, (int, float, bool)) or v is None for v in values[:200]):
        return "numeric"
    if len({str(v) for v in sample}) <= 20:
        return "categorical"
    return "textual"


def _profile_field(name: str, values: list[Any]) -> FieldProfile:
    total = len(values)
    non_null_vals = [v for v in values if v not in (None, "")]
    null_count = total - len(non_null_vals)
    kind = _classify_kind(name, values)
    counts: dict[str, int] = {}
    for v in non_null_vals:
        key = str(v)
        counts[key] = counts.get(key, 0) + 1
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    profile = FieldProfile(
        name=name,
        kind=kind,
        total=total,
        non_null=len(non_null_vals),
        null_count=null_count,
        distinct=len(counts),
        top_values=[{"value": k, "count": c} for k, c in top],
    )
    nums = [float(v) for v in non_null_vals if _is_number(v)]
    if nums:
        nums.sort()
        profile.mean = sum(nums) / len(nums)
        mid = len(nums) // 2
        profile.median = nums[mid] if len(nums) % 2 else (nums[mid - 1] + nums[mid]) / 2
        if len(nums) > 1:
            var = sum((x - profile.mean) ** 2 for x in nums) / len(nums)
            profile.stdev = math.sqrt(var)
        profile.min_value = nums[0]
        profile.max_value = nums[-1]
    return profile


def run_baseline(
    rows: list[dict[str, Any]],
    *,
    data_source: str,
    time_window: str,
    baseline_id: str | None = None,
    fields: list[str] | None = None,
    rare_threshold: int = 2,
    zscore_threshold: float = 3.0,
    ledger_dir: str | Path | None = None,
) -> BaselineResult:
    """Run the deterministic EDA baseline over in-memory rows."""
    import time

    t0 = time.perf_counter()
    started = _now()
    baseline_id = baseline_id or f"baseline-{data_source}-{started}"
    field_names = fields or [c for c in _SECURITY_FIELDS if any(c in r for r in rows)]
    if not field_names:
        field_names = list(_KNOWN_COLUMNS)

    profiles: list[FieldProfile] = []
    for name in field_names:
        profiles.append(_profile_field(name, [r.get(name) for r in rows]))

    # Stack counting (LFO): rare categorical/textual values are outliers.
    outliers: list[Outlier] = []
    for profile in profiles:
        if profile.kind not in ("categorical", "textual"):
            continue
        for entry in profile.top_values:
            if entry["count"] <= rare_threshold:
                outliers.append(Outlier(
                    field=profile.name, value=entry["value"],
                    count=entry["count"], reason="rare_value",
                ))
    # Z-score outliers for numeric fields.
    for profile in profiles:
        if profile.kind != "numeric" or not profile.stdev:
            continue
        for entry in profile.top_values:
            try:
                z = abs(float(entry["value"]) - (profile.mean or 0.0)) / profile.stdev
            except (TypeError, ValueError):
                continue
            if z >= zscore_threshold:
                outliers.append(Outlier(
                    field=profile.name, value=entry["value"],
                    count=entry["count"], reason="zscore",
                ))

    # Gap analysis: columns never populated, missing hosts/users.
    gaps: list[str] = []
    for profile in profiles:
        if profile.non_null == 0:
            gaps.append(f"field '{profile.name}' has no values in window (all null/empty)")
    if rows:
        if not any(r.get("host") for r in rows):
            gaps.append("no host attribution in window — host-scoped hunts not possible")
        if not any(r.get("user") for r in rows):
            gaps.append("no user attribution in window — identity hunts not possible")

    # Relationships: top co-occurrence pairs for (host, image), (user, image), (host, native_type).
    relationships: list[dict[str, Any]] = []
    for left, right in (("host", "image"), ("user", "image"), ("host", "native_type")):
        pair_counts: dict[str, int] = {}
        for r in rows:
            a, b = r.get(left), r.get(right)
            if a and b:
                pair_counts[f"{a} :: {b}"] = pair_counts.get(f"{a} :: {b}", 0) + 1
        top_pairs = sorted(pair_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        if top_pairs:
            relationships.append({
                "fields": [left, right],
                "top_pairs": [{"pair": k, "count": c} for k, c in top_pairs],
            })

    elapsed = round(time.perf_counter() - t0, 4)
    result = BaselineResult(
        baseline_id=baseline_id,
        data_source=data_source,
        time_window=time_window,
        row_count=len(rows),
        fields=profiles,
        outliers=outliers,
        gaps=gaps,
        relationships=relationships,
        started_at=started,
        finished_at=_now(),
        runtime_seconds=elapsed,
    )
    out_dir = Path(ledger_dir) if ledger_dir else Path("baselines")
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = out_dir / f"{baseline_id}.json"
    ledger_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    result.ledger_path = str(ledger_path)
    return result


def render_baseline_report(result: BaselineResult) -> str:
    from hunting.act import backlog_from_baseline, spl_from_outlier, stakeholder_summary

    spls = [spl_from_outlier(o.to_dict()) for o in result.outliers[:3]]
    backlog = backlog_from_baseline([o.to_dict() for o in result.outliers], result.gaps)
    stakeholder = stakeholder_summary(
        "baseline",
        f"Baseline `{result.data_source}` over {result.row_count} rows: "
        f"{len(result.outliers)} outliers, {len(result.gaps)} gaps.",
        [f"Top outlier: `{result.outliers[0].field}={result.outliers[0].value}`."] if result.outliers else [],
    )
    act_block = {"detection_spls": spls, "backlog": backlog, "stakeholder": stakeholder}
    lines: list[str] = []
    lines.append(f"# Baseline Report — `{result.data_source}`")
    lines.append("")
    lines.append(f"**Baseline ID:** `{result.baseline_id}`")
    lines.append(f"**Window:** {result.time_window}")
    lines.append(f"**Rows:** {result.row_count}")
    lines.append(f"**Runtime:** {result.runtime_seconds:.4f} s")
    lines.append("")
    lines.append("## Data Dictionary")
    lines.append("")
    lines.append("| Field | Kind | Non-null | Distinct | Top value |")
    lines.append("|---|---|---|---|---|")
    for f in result.fields:
        top = f.top_values[0] if f.top_values else {"value": "(none)", "count": 0}
        lines.append(
            f"| `{f.name}` | {f.kind} | {f.non_null}/{f.total} "
            f"| {f.distinct} | `{top['value']}` ({top['count']}) |"
        )
    lines.append("")
    lines.append("## Distributions")
    lines.append("")
    for f in result.fields:
        if f.kind == "numeric" and f.mean is not None:
            lines.append(
                f"- `{f.name}`: mean={f.mean:.2f} median={f.median} "
                f"stdev={f.stdev} min={f.min_value} max={f.max_value}"
            )
        else:
            tops = ", ".join(f"`{t['value']}` ({t['count']})" for t in f.top_values[:5])
            lines.append(f"- `{f.name}`: {tops or '(empty)'}")
    lines.append("")
    lines.append("## Outliers")
    lines.append("")
    if result.outliers:
        for o in result.outliers[:20]:
            lines.append(f"- `{o.field}={o.value}` ×{o.count} _({o.reason})_")
        if len(result.outliers) > 20:
            lines.append(f"- … (+{len(result.outliers) - 20} more)")
    else:
        lines.append("No outliers under current thresholds.")
    lines.append("")
    lines.append("## PEAK Act")
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
    lines.append("## Gap Analysis")
    lines.append("")
    if result.gaps:
        for g in result.gaps:
            lines.append(f"- {g}")
    else:
        lines.append("No coverage gaps detected.")
    lines.append("")
    lines.append("## Relationships")
    lines.append("")
    if result.relationships:
        for rel in result.relationships:
            pairs = ", ".join(f"`{p['pair']}` ({p['count']})" for p in rel["top_pairs"])
            lines.append(f"- `{','.join(rel['fields'])}`: {pairs}")
    else:
        lines.append("No co-occurrence relationships found.")
    lines.append("")
    lines.append("## Ledger")
    lines.append("")
    lines.append(f"`{result.ledger_path}`")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "BaselineResult",
    "FieldProfile",
    "Outlier",
    "render_baseline_report",
    "run_baseline",
]
