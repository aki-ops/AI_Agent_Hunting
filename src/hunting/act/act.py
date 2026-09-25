"""PEAK Act artifacts for a finished free-text hunt.

SPL builders stay pure. ``commit_act`` is the only function that writes.
A draft is VALIDATED only after a live parser accepts it. This module does
not import the hunt kernel.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

_DANGEROUS_SPL = re.compile(
    r"(?i)\|\s*(delete|outputlookup|collect|sendemail|map|script|runshellscript)\b"
)
DETECTION_TIERS = frozenset({"report", "dashboard", "code", "rule"})


@dataclass
class SplValidation:
    spl: str
    static_ok: bool
    live_status: str
    messages: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.static_ok or self.live_status == "invalid":
            return "INVALID"
        if self.live_status == "valid":
            return "VALIDATED"
        return "DRAFT"


def validate_spl_static(spl: str) -> list[str]:
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


def validate_spl(spl: str, live_checker: Callable[[str], dict[str, Any]] | None = None) -> SplValidation:
    errors = validate_spl_static(spl)
    live_status = "skipped"
    if not errors and live_checker is not None:
        try:
            result = live_checker(spl)
        except Exception as exc:
            result = {"valid": False, "messages": [str(exc)]}
        live_status = "valid" if result.get("valid") else "invalid"
        errors.extend(str(item) for item in result.get("messages") or [])
    return SplValidation(spl=spl, static_ok=not validate_spl_static(spl), live_status=live_status, messages=errors)


def append_backlog(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: list[dict[str, Any]] = []
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8") or "[]")
    existing.extend(items)
    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")


def export_stakeholder(bullets: list[str], path: Path, *, title: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", ""]
    lines.extend(f"- {bullet}" for bullet in bullets)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def commit_act(
    *,
    source: str,
    spls: list[str],
    backlog: list[dict[str, Any]],
    stakeholder: list[str],
    detection_tier: str,
    export_dir: Path,
    gaps: list[str] | None = None,
    live_checker: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if detection_tier not in DETECTION_TIERS:
        raise ValueError(f"detection tier must be one of {sorted(DETECTION_TIERS)}")
    export_dir.mkdir(parents=True, exist_ok=True)
    validations = [validate_spl(spl, live_checker) for spl in spls]
    (export_dir / "detections.json").write_text(
        json.dumps(
            {
                "tier": detection_tier,
                "validations": [
                    {"status": item.status, "messages": item.messages, "spl": item.spl}
                    for item in validations
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    backlog_path = export_dir / "backlog.json"
    stamped = [
        {
            **item,
            "source": source,
            "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        for item in [*backlog, *({"kind": "gap", "text": gap} for gap in (gaps or []))]
    ]
    append_backlog(backlog_path, stamped)
    stakeholder_path = export_dir / "stakeholder.md"
    export_stakeholder(stakeholder, stakeholder_path, title=f"Stakeholder note {source}")
    return {
        "stakeholder_path": str(stakeholder_path),
        "backlog_path": str(backlog_path),
        "validations": [item.status for item in validations],
        "detection_tier": detection_tier,
    }
