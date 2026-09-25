"""PEAK Prepare plan for a free-text hypothesis.

This module does not import the hunt kernel. A plan is derived from the
hypothesis first. A user override replaces only the fields it supplies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_DURATION = re.compile(r"^(\d+)\s*([mhdw])$", re.IGNORECASE)
_BEHAVIOR_MARKERS = (
    "bị dùng",
    "lạm dụng",
    "interactive",
    "tương tác",
    "service account",
    "tài khoản dịch vụ",
    "logon",
    "đăng nhập",
    "rdp",
    "console",
)


class PrepareError(ValueError):
    """A free-text hunt started without a complete Prepare plan."""


@dataclass(frozen=True)
class DecisionCriteria:
    """Thresholds that license confirm or refute. Derived first, then editable."""

    confirm_when: str
    min_coverage_to_refute: float
    expected_magnitude: str
    source: str = "derived"

    def __post_init__(self) -> None:
        if not str(self.confirm_when).strip():
            raise PrepareError("decision_criteria.confirm_when is required")
        coverage = float(self.min_coverage_to_refute)
        if coverage < 0 or coverage > 1:
            raise PrepareError("decision_criteria.min_coverage_to_refute must be between 0 and 1")
        object.__setattr__(self, "min_coverage_to_refute", coverage)
        if not str(self.expected_magnitude).strip():
            raise PrepareError("decision_criteria.expected_magnitude is required")
        if self.source not in {"derived", "user"}:
            raise PrepareError("decision_criteria.source must be derived or user")


@dataclass(frozen=True)
class PreparePlan:
    """Checklist that must exist before a free-text hypothesis touches a provider."""

    topic: str
    behavior: str
    location: str
    evidence: str
    scope: str
    max_duration: str
    plan: str
    research_refs: tuple[str, ...]
    decision_criteria: DecisionCriteria
    actor: str = ""
    location_override: tuple[str, ...] = ()
    location_source: str = "derived"

    def to_dict(self) -> dict:
        criteria = self.decision_criteria
        if self.location_source not in {"derived", "user", "fallback_probe"}:
            raise PrepareError("location_source must be derived, user, or fallback_probe")
        return {
            "topic": self.topic,
            "actor": self.actor,
            "behavior": self.behavior,
            "location": self.location,
            "location_override": list(self.location_override),
            "location_source": self.location_source,
            "evidence": self.evidence,
            "scope": self.scope,
            "max_duration": self.max_duration,
            "plan": self.plan,
            "research_refs": list(self.research_refs),
            "decision_criteria": {
                "confirm_when": criteria.confirm_when,
                "min_coverage_to_refute": criteria.min_coverage_to_refute,
                "expected_magnitude": criteria.expected_magnitude,
                "source": criteria.source,
            },
        }


def missing_prepare_fields(plan: PreparePlan) -> list[str]:
    """Actor may be unknown. Every other checklist field and all three thresholds are required."""
    missing: list[str] = []
    for name in ("topic", "behavior", "location", "evidence", "scope", "max_duration", "plan"):
        if not str(getattr(plan, name) or "").strip():
            missing.append(name)
    if not tuple(plan.research_refs):
        missing.append("research_refs")
    criteria = plan.decision_criteria
    if not str(criteria.confirm_when).strip():
        missing.append("decision_criteria.confirm_when")
    if criteria.min_coverage_to_refute is None:
        missing.append("decision_criteria.min_coverage_to_refute")
    if not str(criteria.expected_magnitude).strip():
        missing.append("decision_criteria.expected_magnitude")
    return missing


def _duration_from_window(time_window: str) -> str:
    text = str(time_window or "").strip()
    if _DURATION.match(text):
        return text.replace(" ", "")
    if text.upper().startswith("NOW-") and text.upper().endswith("/NOW"):
        span = text[4:-4]
        if _DURATION.match(span):
            return span.replace(" ", "")
    return "14d"


def _magnitude(content: str) -> str:
    lowered = content.casefold()
    if any(marker in lowered for marker in _BEHAVIOR_MARKERS):
        return "small"
    return "population"


def derive_prepare_plan(
    content: str,
    *,
    time_window: str = "",
    entities: tuple[str, ...] = (),
    research_refs: tuple[str, ...] = (),
) -> PreparePlan:
    """Build a complete plan from the hypothesis. Every derived field is explicit."""
    text = str(content or "").strip()
    if not text:
        raise PrepareError("A free-text hypothesis is required to derive Prepare")
    topic = text.splitlines()[0][:120]
    location = ", ".join(item for item in entities if str(item).strip()) or "population in the hunt window"
    refs = tuple(item.strip() for item in research_refs if str(item).strip()) or ("analyst-hypothesis",)
    criteria = DecisionCriteria(
        confirm_when=text,
        min_coverage_to_refute=0.8,
        expected_magnitude=_magnitude(text),
        source="derived",
    )
    plan = PreparePlan(
        topic=topic,
        actor="",
        behavior=text,
        location=location,
        evidence="observations that satisfy the hypothesis predicates inside the scope",
        scope=location,
        max_duration=_duration_from_window(time_window),
        plan="derive thresholds, compile the hypothesis, size the match set, then confirm or refute",
        research_refs=refs,
        decision_criteria=criteria,
    )
    missing = missing_prepare_fields(plan)
    if missing:
        raise PrepareError("derived Prepare is incomplete: " + ", ".join(missing))
    return plan


def apply_user_overrides(plan: PreparePlan, overrides: dict | None) -> PreparePlan:
    """Replace only fields the user supplied. Untouched thresholds stay derived."""
    if not overrides:
        return plan
    data = plan.to_dict()
    criteria = dict(data["decision_criteria"])
    user_criteria = overrides.get("decision_criteria") or {}
    criteria_touched = False
    for key in ("confirm_when", "min_coverage_to_refute", "expected_magnitude"):
        if key in user_criteria and user_criteria[key] not in (None, ""):
            criteria[key] = user_criteria[key]
            criteria_touched = True
    if criteria_touched:
        criteria["source"] = "user"
    data["decision_criteria"] = criteria
    for key in (
        "topic",
        "actor",
        "behavior",
        "location",
        "evidence",
        "scope",
        "max_duration",
        "plan",
    ):
        if key in overrides and overrides[key] not in (None, ""):
            data[key] = overrides[key]
    if "research_refs" in overrides and overrides["research_refs"]:
        data["research_refs"] = list(overrides["research_refs"])
    if "location_override" in overrides and overrides["location_override"]:
        data["location_override"] = tuple(str(x) for x in overrides["location_override"])
        data["location_source"] = "user"
    updated = PreparePlan(
        topic=str(data["topic"]),
        actor=str(data.get("actor") or ""),
        behavior=str(data["behavior"]),
        location=str(data["location"]),
        location_override=tuple(data.get("location_override", ())),
        location_source=str(data.get("location_source", "derived")),
        evidence=str(data["evidence"]),
        scope=str(data["scope"]),
        max_duration=str(data["max_duration"]),
        plan=str(data["plan"]),
        research_refs=tuple(str(item) for item in data["research_refs"]),
        decision_criteria=DecisionCriteria(
            confirm_when=str(criteria["confirm_when"]),
            min_coverage_to_refute=float(criteria["min_coverage_to_refute"]),
            expected_magnitude=str(criteria["expected_magnitude"]),
            source=str(criteria["source"]),
        ),
    )
    missing = missing_prepare_fields(updated)
    if missing:
        raise PrepareError("user Prepare is incomplete: " + ", ".join(missing))
    return updated


def load_prepare_overrides(path: str) -> dict:
    """Load a YAML or JSON hunt plan. Only supplied fields override the derived plan."""
    import json
    from pathlib import Path

    file_path = Path(path)
    if not file_path.is_file():
        raise PrepareError(f"Hunt plan not found: {file_path}")
    raw = file_path.read_text(encoding="utf-8")
    if file_path.suffix.lower() == ".json":
        data = json.loads(raw)
    else:
        import yaml
        data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise PrepareError("Hunt plan must be a mapping")
    return data


def prompt_threshold_override(plan: PreparePlan, reader) -> PreparePlan:
    """Ask for one threshold. Empty input keeps the derived value."""
    raw = str(reader(
        f"min_coverage_to_refute [{plan.decision_criteria.min_coverage_to_refute}]: "
    ) or "").strip()
    if not raw:
        return plan
    return apply_user_overrides(plan, {"decision_criteria": {"min_coverage_to_refute": float(raw)}})
