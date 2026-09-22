"""PEAK process gate: Prepare, Execute/Refine, and IR escalation.

PEAK (Prepare, Execute, Act with Knowledge) is Splunk SURGe's hunting
process. This module is the deterministic part of that process:

- Prepare checks topic, research, ABLE, scope, max duration and plan.
- ABLE contributes only concrete observables (host, account, file name,
  flag, IP, quoted literal). Prose stays a hypothesis label.
- Execute records analyze → one refine → stop, and says when a finding
  goes to IR.

The PoC agent re-runs queries. The hypothesis engine records the same
decision without opening a second unbounded query budget.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


class PrepareError(ValueError):
    """A hunt started without a complete PEAK Prepare plan."""


_DURATION = re.compile(r"^(\d+)\s*([mhdw])$", re.IGNORECASE)
_FILENAME = re.compile(r"(?i)\b[\w.-]+\.(?:exe|dll|ps1|bat|js|vbs|hta)\b")
_FLAG = re.compile(r"(?:^|\s)(-{1,2}[A-Za-z][\w-]{1,20})\b")
_ACCOUNT = re.compile(r"\b[\w.-]+\\[\w.-]+\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_QUOTED = re.compile(r'"([^"]{2,80})"')
_HOST = re.compile(r"\b([A-Za-z][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*)\b")
_TECHNIQUE = re.compile(r"^T\d+(?:\.\d+)?$", re.IGNORECASE)
_FIELD = re.compile(
    r"(?i)\b(cmdline|parent_image|image|file_path|domain|query|uri|url|src_ip|client_ip|host|user)\b"
)

_SOURCE_WORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("process", ("process_creation", "process", "sysmon", "cmdline")),
    ("dns", ("dns",)),
    ("web", ("web_request", "web", "http", "proxy")),
    ("file", ("filesystem", "file")),
    ("authentication", ("authentication", "logon", "4624", "4625")),
)

_REQUIRED = (
    ("topic", "topic"),
    ("behavior", "able.behavior"),
    ("location", "able.location"),
    ("evidence", "able.evidence"),
    ("scope", "scope"),
    ("max_duration", "max_duration"),
    ("plan", "plan"),
)


@dataclass(frozen=True)
class AbleDrive:
    """Concrete ABLE filters. Empty fields mean 'do not add a predicate'."""

    host: str | None = None
    actor: str | None = None
    observables: tuple[str, ...] = ()
    evidence_fields: tuple[str, ...] = ()
    source_kinds: tuple[str, ...] = ()


def missing_prepare_fields(poc: Any) -> list[str]:
    """Return Prepare fields that must be filled before a hunt runs.

    Actor may be empty: PEAK allows an unknown actor.
    """
    missing: list[str] = []
    for attr, label in _REQUIRED:
        if not str(getattr(poc, attr, "") or "").strip():
            missing.append(label)
    refs = getattr(poc, "research_refs", None) or []
    if not list(refs):
        missing.append("research_refs")
    return missing


def parse_duration(text: str) -> timedelta | None:
    match = _DURATION.match(str(text or "").strip())
    if not match:
        return None
    count = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "m":
        return timedelta(minutes=count)
    if unit == "h":
        return timedelta(hours=count)
    if unit == "w":
        return timedelta(weeks=count)
    return timedelta(days=count)


def _fmt(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enforce_max_duration(window: str, max_duration: str) -> tuple[str, str]:
    """Clamp a telemetry window to the trailing ``max_duration``.

    PEAK's max duration is also a hunt deadline. Callers compare the
    returned duration with wall-clock time and stop the refine loop.
    A window that already fits is returned unchanged.
    """
    raw = str(max_duration or "").strip()
    if not raw:
        return window, ""
    duration = parse_duration(raw)
    if duration is None:
        return window, (
            f"max_duration {raw!r} is not a duration (use 30m, 12h, 3d or 2w); window unchanged"
        )
    from hunting.m5_adapter.allowlist import validate_time_window_format

    start, end = validate_time_window_format(window)
    span = end - start
    if span <= duration:
        return window, f"window within max_duration {raw}"
    clamped_start = end - duration
    clamped = f"{_fmt(clamped_start)}/{_fmt(end)}"
    return clamped, f"window exceeded max_duration {raw}; clamped to the trailing edge {clamped}"


def _dedupe(items: list[str]) -> tuple[str, ...]:
    seen: list[str] = []
    for item in items:
        text = str(item).strip().strip('"')
        if text and text not in seen and not _TECHNIQUE.match(text):
            seen.append(text)
    return tuple(seen)


def concrete_observables(*texts: str) -> tuple[str, ...]:
    """Pull literals a query can AND without turning prose into a predicate."""
    found: list[str] = []
    for text in texts:
        blob = str(text or "")
        found.extend(_FILENAME.findall(blob))
        found.extend(_FLAG.findall(blob))
        found.extend(_IP.findall(blob))
        found.extend(_QUOTED.findall(blob))
    return _dedupe(found)


def _host_token(location: str) -> str | None:
    for token in _HOST.findall(str(location or "")):
        if _TECHNIQUE.match(token):
            continue
        return token
    return None


def _actor_token(actor: str) -> str | None:
    text = str(actor or "").strip()
    if not text or " " in text:
        return None
    if _ACCOUNT.fullmatch(text) or _ACCOUNT.search(text):
        return text
    return None


def infer_source_kinds(evidence: str) -> tuple[str, ...]:
    text = str(evidence or "").lower()
    found: list[str] = []
    for kind, words in _SOURCE_WORDS:
        if any(word in text for word in words):
            found.append(kind)
    return tuple(found)


def able_drive(actor: str = "", behavior: str = "", location: str = "", evidence: str = "") -> AbleDrive:
    """Build the query filters ABLE is allowed to add."""
    fields = _dedupe(_FIELD.findall(str(evidence or "")))
    return AbleDrive(
        host=_host_token(location),
        actor=_actor_token(actor),
        observables=concrete_observables(behavior, evidence),
        evidence_fields=fields,
        source_kinds=infer_source_kinds(evidence),
    )


def load_hunt_plan(path: str | Path) -> dict[str, Any]:
    """Load a YAML or JSON hunt plan into the Prepare field names."""
    file_path = Path(path)
    # utf-8-sig tolerates an optional BOM (editors and PowerShell often add one)
    # while still decoding plain UTF-8.
    text = file_path.read_text(encoding="utf-8-sig")
    if file_path.suffix.lower() in {".yaml", ".yml"}:
        import yaml

        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise PrepareError(f"Hunt plan {file_path} must be a mapping")
    able = data.get("able") if isinstance(data.get("able"), dict) else {}
    refs = data.get("research_refs") or data.get("research") or []
    if isinstance(refs, str):
        refs = [part.strip() for part in refs.split(",") if part.strip()]
    return {
        "topic": str(data.get("topic", "") or ""),
        "actor": str(able.get("actor", data.get("actor", "")) or ""),
        "behavior": str(able.get("behavior", data.get("behavior", "")) or ""),
        "location": str(able.get("location", data.get("location", "")) or ""),
        "evidence": str(able.get("evidence", data.get("evidence", "")) or ""),
        "research_refs": [str(item) for item in refs if str(item).strip()],
        "scope": str(data.get("scope", "") or ""),
        "max_duration": str(data.get("max_duration", "") or ""),
        "plan": str(data.get("plan", "") or ""),
    }


def missing_prepare_fields_from_plan(plan: dict[str, Any]) -> list[str]:
    """Return the PEAK Prepare fields missing from a plan dict.

    Mirrors :func:`missing_prepare_fields` but works on the plan mapping
    produced by :func:`load_hunt_plan` / :func:`derive_prepare_plan` rather
    than a PoC object, so the non-PoC entrypoints (hypothesis engine,
    baseline, M-ATH) can share the same PEAK Prepare contract. Actor may be
    empty: PEAK allows an unknown actor.
    """
    missing: list[str] = []
    for attr, label in _REQUIRED:
        if not str((plan or {}).get(attr, "") or "").strip():
            missing.append(label)
    refs = (plan or {}).get("research_refs") or []
    if not list(refs):
        missing.append("research_refs")
    return missing


def derive_prepare_plan(
    *,
    hunt_kind: str,
    content: str,
    scope: str = "",
    time_window: str = "",
    evidence_hint: str = "",
    location_hint: str = "",
    actor: str = "",
    research_refs: list[str] | None = None,
) -> dict[str, Any]:
    """Build a minimal but complete PEAK Prepare plan from hunt inputs.

    The non-PoC entrypoints (``--hypothesis``/``--cve``/``--ttp``/``--ioc``/
    ``--query``, ``--baseline`` and ``--math``) still owe PEAK a Prepare
    plan. Rather than block a legitimate hunt that supplies its objective
    inline, this derives the ABLE/scope/plan skeleton from what the caller
    already gave. The result is deterministic and auditable — it is printed
    and, for hypothesis hunts, recorded alongside the run.

    A field the caller did not supply is filled with an explicit, generic
    placeholder so the plan is complete and the analyst can see exactly what
    was assumed. If ``content`` itself is empty the plan stays incomplete and
    the gate will block, because a hunt with no objective is not a PEAK hunt.
    """
    kind = str(hunt_kind or "hunt").strip() or "hunt"
    goal = str(content or "").strip()
    topic = goal if goal else ""
    behavior = goal if goal else ""
    location = str(location_hint or "").strip() or (
        f"telemetry in scope {scope}" if str(scope or "").strip() else "in-scope telemetry"
    )
    evidence = str(evidence_hint or "").strip() or (
        f"telemetry records consistent with '{goal}'" if goal else ""
    )
    scope_val = str(scope or "").strip() or (
        f"{kind} over the selected window {time_window}".strip()
        if str(time_window or "").strip()
        else f"{kind} over the selected telemetry"
    )
    # PEAK max duration doubles as the hunt deadline. Default to the window
    # span when the caller gave one; otherwise a conservative trailing bound.
    max_duration = ""
    win = str(time_window or "").strip()
    if win and "/" in win:
        try:
            from hunting.m5_adapter.allowlist import validate_time_window_format

            start, end = validate_time_window_format(win)
            days = max(1, (end - start).days or 1)
            max_duration = f"{days}d"
        except Exception:
            max_duration = "14d"
    if not max_duration:
        max_duration = "14d"
    plan_text = (
        f"PEAK {kind} hunt: search in-scope telemetry for evidence of '{goal}', "
        "analyze hits, allow one refine pass, then Act (detection draft + backlog)."
        if goal
        else ""
    )
    refs = [str(r) for r in (research_refs or []) if str(r).strip()]
    if not refs:
        refs = ["Splunk SURGe PEAK hypothesis-driven hunting"]
    return {
        "topic": topic,
        "actor": str(actor or ""),
        "behavior": behavior,
        "location": location,
        "evidence": evidence,
        "research_refs": refs,
        "scope": scope_val,
        "max_duration": max_duration,
        "plan": plan_text,
    }


def dump_hunt_plan(plan: dict[str, Any], path: str | Path) -> str:
    import yaml

    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "topic": plan.get("topic", ""),
        "research_refs": list(plan.get("research_refs") or []),
        "able": {
            "actor": plan.get("actor", ""),
            "behavior": plan.get("behavior", ""),
            "location": plan.get("location", ""),
            "evidence": plan.get("evidence", ""),
        },
        "scope": plan.get("scope", ""),
        "max_duration": plan.get("max_duration", ""),
        "plan": plan.get("plan", ""),
    }
    file_path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return str(file_path)


def interactive_prepare(
    defaults: dict[str, Any] | None = None,
    read_line: Callable[[], str] | None = None,
    write: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Ask topic → research → ABLE → scope → plan. Blank keeps the default."""
    current = dict(defaults or {})
    read = read_line or input
    emit = write or (lambda line: print(line, end=""))

    def ask(label: str, value: str) -> str:
        suffix = f" [{value}]" if value else ""
        emit(f"[Prepare] {label}{suffix}: ")
        try:
            entered = read()
        except EOFError as exc:
            raise PrepareError("Prepare wizard closed before the plan was complete") from exc
        text = str(entered or "").strip()
        return text if text else value

    emit("[Prepare] topic → research → ABLE → scope → plan\n")
    topic = ask("Topic", str(current.get("topic", "")))
    research_raw = ask(
        "Research refs (comma-separated)",
        ", ".join(current.get("research_refs") or []),
    )
    actor = ask("ABLE Actor (empty if unknown)", str(current.get("actor", "")))
    behavior = ask("ABLE Behavior", str(current.get("behavior", "")))
    location = ask("ABLE Location", str(current.get("location", "")))
    evidence = ask("ABLE Evidence (source and what a hit looks like)", str(current.get("evidence", "")))
    scope = ask("Scope", str(current.get("scope", "")))
    max_duration = ask("Max duration (30m, 12h, 3d, 2w)", str(current.get("max_duration", "")))
    plan = ask("Plan", str(current.get("plan", "")))
    refs = [part.strip() for part in research_raw.split(",") if part.strip()]
    return {
        "topic": topic,
        "research_refs": refs,
        "actor": actor,
        "behavior": behavior,
        "location": location,
        "evidence": evidence,
        "scope": scope,
        "max_duration": max_duration,
        "plan": plan,
    }


def apply_plan_to_poc(poc: Any, plan: dict[str, Any]) -> Any:
    """Return a copy of ``poc`` with Prepare fields overwritten by ``plan``."""
    from dataclasses import replace

    def pick(name: str, current: Any) -> Any:
        incoming = plan.get(name)
        if incoming in (None, "", []):
            return current
        return incoming

    return replace(
        poc,
        topic=str(pick("topic", poc.topic)),
        actor=str(pick("actor", poc.actor)),
        behavior=str(pick("behavior", poc.behavior)),
        location=str(pick("location", poc.location)),
        evidence=str(pick("evidence", poc.evidence)),
        research_refs=list(pick("research_refs", list(poc.research_refs))),
        scope=str(pick("scope", poc.scope)),
        max_duration=str(pick("max_duration", poc.max_duration)),
        plan=str(pick("plan", poc.plan)),
    )


def peak_execute_cycle(*, observation_count: int) -> list[dict[str, Any]]:
    """Analyze, allow one refine, and flag IR. Does not run a query itself."""
    analyze = {"phase": "analyze", "observations": int(observation_count)}
    if observation_count > 0:
        return [
            analyze,
            {
                "phase": "stop",
                "action": "escalate_ir",
                "reason": "observations are a finding; hand them to IR",
                "ir_escalate": True,
            },
        ]
    return [
        analyze,
        {
            "phase": "refine",
            "action": "rerun",
            "reason": "no observations; one refine pass is allowed without widening operators",
            "ir_escalate": False,
        },
        {
            "phase": "stop",
            "action": "stop",
            "reason": "refine budget is one pass; the PoC agent performs the rerun",
            "ir_escalate": False,
        },
    ]


__all__ = [
    "AbleDrive",
    "PrepareError",
    "able_drive",
    "apply_plan_to_poc",
    "concrete_observables",
    "derive_prepare_plan",
    "dump_hunt_plan",
    "enforce_max_duration",
    "infer_source_kinds",
    "interactive_prepare",
    "load_hunt_plan",
    "missing_prepare_fields",
    "missing_prepare_fields_from_plan",
    "parse_duration",
    "peak_execute_cycle",
]
