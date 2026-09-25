"""Map a finished hunt account onto the kernel-free Act input."""
from __future__ import annotations

from typing import Any


def account_to_act_input(account: Any, prepare: dict | None = None) -> dict[str, Any]:
    """Collect plan, queries, citations, gaps, and one detection draft."""
    decision = getattr(getattr(account, "stopping_decision", None), "value", None)
    decision = decision or str(getattr(account, "stopping_decision", "") or "")
    gaps = []
    for items in (getattr(account, "gap_breakdown", None) or {}).values():
        gaps.extend(str(item) for item in items or [])
    for note in (getattr(account, "semantic_analysis", {}) or {}).get("escalations") or []:
        gaps.append(str(note))
    hypotheses = []
    for hypothesis in getattr(account, "hypotheses", ()) or ():
        hypotheses.append({
            "id": hypothesis.id,
            "statement": hypothesis.statement,
            "status": getattr(getattr(hypothesis, "status", ""), "value", str(hypothesis.status)),
        })
    queries = list(getattr(account, "queries", ()) or ())
    analysis = getattr(account, "semantic_analysis", {}) or {}
    runtime_caps = list(getattr(account, "runtime_capabilities", ()) or [])
    data_locations = [
        {
            "relation": cap.get("relation"),
            "source_id": cap.get("source_id"),
            "probe_query_id": cap.get("probe_query_id"),
        }
        for cap in runtime_caps
        if isinstance(cap, dict) and cap.get("source_id")
    ]
    spls = []
    for source in (queries, analysis.get("behavior_queries") or []):
        for query in source:
            if not isinstance(query, dict):
                continue
            text = str(query.get("native_query") or "").strip()
            if text and text not in spls:
                spls.append(text)
    tier = "rule" if decision in {"STOP_RESOLVED", "STOP_REFUTED"} else "report"
    return {
        "source": str(getattr(account, "request_id", "") or "hunt"),
        "spls": spls,
        "backlog": [{"kind": "hypothesis", "text": item["statement"]} for item in hypotheses],
        "stakeholder": [
            f"Stopping decision: {decision or 'unspecified'}.",
            f"Hypotheses: {len(hypotheses)}.",
            f"Citations: {len(getattr(account, 'observation_citations', ()) or ())}.",
        ],
        "detection_tier": tier,
        "gaps": gaps,
        "prepare": prepare or {},
        "queries": queries,
        "hypotheses": hypotheses,
        "data_locations": data_locations,
    }
