"""Digests that tie approvals and results to one exact plan.

``core_digest``  covers only what code built from the intel; it does not change with the LLM (or its absence).
``plan_digest``  covers everything a reviewer approves (core + accepted-or-not LLM suggestions + runbook); the executing
                 team copies it into the results, and ``verify`` refuses results that quote another one.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from hunting.plan.schema import HuntPlan


def _canon(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _sha(payload: Any) -> str:
    return hashlib.sha256(_canon(payload).encode("utf-8")).hexdigest()[:32]


def core_digest(plan: HuntPlan) -> str:
    return _sha({
        "title": plan.title, "hypothesis": plan.hypothesis, "applicability": plan.applicability.model_dump(mode="json"),
        "stages": [s.model_dump(mode="json") for s in plan.stages if s.origin == "core"],
        "probes": [q.model_dump(mode="json") for q in plan.coverage_probes if q.origin == "core"],
        "limits": plan.limits.model_dump(mode="json"), "manual_todo": plan.manual_todo,
    })


def plan_digest(plan: HuntPlan) -> str:
    body = plan.model_dump(mode="json", exclude={"provenance", "dropped", "peak", "intel", "verification"})
    return _sha(body)


def stamp(plan: HuntPlan) -> HuntPlan:
    """Fill in both digests (the plan digest is computed last, over the finished plan)."""
    plan.provenance.core_digest = core_digest(plan)
    plan.provenance.plan_digest = plan_digest(plan)
    return plan
