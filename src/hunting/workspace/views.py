"""Structured investigation views reconstructed from the machine run account.

These records are for analysts and future UI.  They never grant proof and they
do not require an analyst to hand-edit JSON.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.lifecycle import BindingReview, WorkspaceSnapshot


def _as_dict(item: Any) -> dict[str, Any]:
    if item is None:
        return {}
    if isinstance(item, dict):
        return dict(item)
    if hasattr(item, "to_dict"):
        return dict(item.to_dict())
    return {}


def _account_payload(account: Any) -> dict[str, Any]:
    if isinstance(account, dict):
        return dict(account)
    payload = _as_dict(account)
    payload.setdefault("request_id", getattr(account, "request_id", ""))
    payload.setdefault("observations", list(getattr(account, "observations", []) or []))
    payload.setdefault("queries", list(getattr(account, "queries", []) or []))
    payload.setdefault("query_results", list(getattr(getattr(account, "state", None), "query_results", []) or []))
    payload.setdefault("proof_results", list(getattr(account, "proof_results", []) or []))
    payload.setdefault("candidate_sets", getattr(account, "candidate_sets", {}) or {})
    payload.setdefault("semantic_analysis", dict(getattr(account, "semantic_analysis", {}) or {}))
    payload.setdefault("semantic_goal_graph", getattr(account, "semantic_goal_graph", None))
    payload.setdefault("stopping_decision", getattr(account, "stopping_decision", None))
    payload.setdefault("residuals", list(getattr(account, "residuals", []) or []))
    payload.setdefault("limitations", list(getattr(account, "limitations", []) or []))
    payload.setdefault("coverage_bound", getattr(account, "coverage_bound", None))
    payload.setdefault("coverage_gaps", list(getattr(account, "coverage_gaps", []) or []))
    payload.setdefault("workspace_snapshot", getattr(account, "workspace_snapshot", None))
    payload.setdefault("llm_usage", dict(getattr(account, "llm_usage", {}) or {}))
    if not payload.get("observations") and hasattr(account, "observation_citations"):
        payload["observation_ids"] = list(getattr(account, "observation_citations", []) or [])
    return payload


def _observation_records(source: Any) -> list[dict[str, Any]]:
    records = []
    observations = getattr(source, "observations", None)
    if observations is None and isinstance(source, dict):
        observations = source.get("observations") or []
    for obs in observations or []:
        payload = _as_dict(obs)
        if not payload:
            payload = {
                "id": getattr(obs, "id", ""),
                "timestamp": getattr(obs, "timestamp", ""),
                "fields": dict(getattr(obs, "fields", {}) or {}),
                "native_fields": dict(getattr(obs, "native_fields", {}) or getattr(obs, "fields", {}) or {}),
                "query_id": getattr(obs, "query_id", ""),
                "entities": [
                    item.to_dict() if hasattr(item, "to_dict") else {"value": str(item)}
                    for item in getattr(obs, "entities", []) or []
                ],
            }
        records.append(payload)
    return records


def build_timeline(source: Any) -> tuple[dict[str, Any], ...]:
    records = _observation_records(source)
    records.sort(key=lambda item: str(item.get("timestamp", "")))
    return tuple(
        {
            "observation_id": item.get("id") or item.get("observation_id"),
            "timestamp": item.get("timestamp", ""),
            "query_id": item.get("query_id", ""),
            "fields": dict(item.get("fields") or {}),
            "native_fields": dict(item.get("native_fields") or item.get("fields") or {}),
        }
        for item in records
    )


def build_entity_pivot(source: Any) -> tuple[dict[str, Any], ...]:
    pivot: dict[tuple[str, str], dict[str, Any]] = {}
    for item in _observation_records(source):
        obs_id = str(item.get("id") or item.get("observation_id") or "")
        entities = item.get("entities") or []
        if entities:
            for entity in entities:
                payload = entity if isinstance(entity, dict) else _as_dict(entity)
                key = (str(payload.get("type") or payload.get("entity_type") or "entity"), str(payload.get("value") or payload.get("id") or ""))
                if not key[1]:
                    continue
                bucket = pivot.setdefault(key, {"entity_type": key[0], "value": key[1], "observation_ids": [], "query_ids": []})
                if obs_id:
                    bucket["observation_ids"].append(obs_id)
                if item.get("query_id"):
                    bucket["query_ids"].append(str(item["query_id"]))
            continue
        for role, value in dict(item.get("fields") or {}).items():
            if value in (None, ""):
                continue
            key = (str(role), str(value))
            bucket = pivot.setdefault(key, {"entity_type": key[0], "value": key[1], "observation_ids": [], "query_ids": []})
            if obs_id:
                bucket["observation_ids"].append(obs_id)
            if item.get("query_id"):
                bucket["query_ids"].append(str(item["query_id"]))
    return tuple(pivot[key] for key in sorted(pivot))


def build_native_events(source: Any) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "observation_id": item.get("id") or item.get("observation_id"),
            "timestamp": item.get("timestamp", ""),
            "query_id": item.get("query_id", ""),
            "native_fields": dict(item.get("native_fields") or item.get("fields") or {}),
            "raw_event": dict(item.get("raw_event") or {}),
        }
        for item in build_timeline(source)
    )


def _query_records(source: Any) -> list[Any]:
    queries = getattr(source, "queries", None)
    if queries is None and isinstance(source, dict):
        queries = source.get("queries") or []
    return list(queries or [])


def build_query_audit(source: Any) -> tuple[dict[str, Any], ...]:
    analysis = dict(getattr(source, "semantic_analysis", {}) or {})
    if not analysis and isinstance(source, dict):
        analysis = dict(source.get("semantic_analysis") or {})
    step_actions = {
        str(item.get("step_id")): str(item.get("next_action_reason") or "")
        for item in analysis.get("step_actions") or []
        if isinstance(item, dict)
    }
    results_by_id = {}
    for result in getattr(source, "query_results", None) or (
        source.get("query_results") if isinstance(source, dict) else []
    ) or []:
        results_by_id[str(getattr(result, "query_id", "") or (result.get("query_id") if isinstance(result, dict) else ""))] = result
    audit = []
    for query in _query_records(source):
        if isinstance(query, dict):
            query_id = str(query.get("id") or query.get("query_id") or "")
            operation_id = str(query.get("operation_id") or "")
            params = dict(query.get("parameters") or {})
            goal_ids = list(params.get("advances_goal_ids") or query.get("advances_goal_ids") or [])
        else:
            query_id = str(getattr(query, "id", "") or "")
            operation_id = str(getattr(query, "operation_id", "") or "")
            params = dict(getattr(query, "parameters", {}) or {})
            goal_ids = list(params.get("advances_goal_ids") or [])
        result = results_by_id.get(query_id)
        complete = getattr(result, "complete", None)
        if complete is None and isinstance(result, dict):
            complete = result.get("complete")
        reason = (
            step_actions.get(str(params.get("logical_plan_id") or ""), "")
            or f"advances goals {goal_ids or ['unspecified']} via operation {operation_id or 'undeclared'}"
        )
        audit.append({
            "query_id": query_id,
            "operation_id": operation_id,
            "c3_invoked": bool(params.get("c3_invoked")),
            "advances_goal_ids": goal_ids,
            "relation": params.get("relation", ""),
            "reason": reason,
            "complete": complete,
            "retrieval_stage": params.get("retrieval_stage", ""),
        })
    return tuple(audit)


def build_proof_obligations(source: Any) -> tuple[dict[str, Any], ...]:
    obligations = []
    analysis = dict(getattr(source, "semantic_analysis", {}) or {})
    if not analysis and isinstance(source, dict):
        analysis = dict(source.get("semantic_analysis") or {})
    verdicts = list(analysis.get("goal_verdicts") or [])
    if verdicts:
        for verdict in verdicts:
            if not isinstance(verdict, dict):
                continue
            proofs = list(verdict.get("proof_results") or [])
            missing: list[str] = list(verdict.get("unverified_restrictions") or [])
            satisfied: list[str] = []
            citations: list[str] = []
            contract_id = verdict.get("proof_method_id")
            for proof in proofs:
                payload = proof if isinstance(proof, dict) else _as_dict(proof)
                missing.extend(str(item) for item in payload.get("missing_obligations") or ())
                satisfied.extend(str(item) for item in payload.get("satisfied_obligations") or ())
                citations.extend(str(item) for item in payload.get("citations") or ())
                contract_id = contract_id or payload.get("contract_id")
            obligations.append({
                "goal_id": verdict.get("goal_id"),
                "relation": verdict.get("relation"),
                "status": verdict.get("status"),
                "contract_id": contract_id,
                "verified": str(verdict.get("status", "")).upper() in {"VERIFIED", "PROVEN", "SUPPORTED"},
                "satisfied_obligations": list(dict.fromkeys(satisfied)),
                "missing_obligations": list(dict.fromkeys(missing)),
                "citations": list(dict.fromkeys(citations)),
                "query_ids": list(verdict.get("query_ids") or []),
            })
        return tuple(obligations)
    for proof in getattr(source, "proof_results", None) or (
        source.get("proof_results") if isinstance(source, dict) else []
    ) or []:
        payload = proof if isinstance(proof, dict) else _as_dict(proof)
        obligations.append({
            "goal_id": payload.get("goal_id") or payload.get("contract_id"),
            "relation": payload.get("relation"),
            "status": payload.get("status") or payload.get("verdict"),
            "contract_id": payload.get("contract_id"),
            "verified": bool(payload.get("verified")),
            "satisfied_obligations": list(payload.get("satisfied_obligations") or ()),
            "missing_obligations": list(payload.get("missing_obligations") or ()),
            "citations": list(payload.get("citations") or ()),
            "query_ids": list(payload.get("query_ids") or ()),
        })
    return tuple(obligations)


def build_stop_explanation(source: Any) -> dict[str, Any]:
    decision = getattr(source, "stopping_decision", None)
    if decision is None and isinstance(source, dict):
        decision = source.get("stopping_decision")
    analysis = dict(getattr(source, "semantic_analysis", {}) or {})
    if not analysis and isinstance(source, dict):
        analysis = dict(source.get("semantic_analysis") or {})
    residuals = list(getattr(source, "residuals", None) or (
        source.get("residuals") if isinstance(source, dict) else []
    ) or [])
    return {
        "decision": getattr(decision, "value", None) or str(decision or ""),
        "taxonomy": str(getattr(decision, "to_taxonomy_state", lambda: "")() or ""),
        "unresolved_reasons": dict(analysis.get("unresolved_reasons") or {}),
        "needs_user_decision": bool(analysis.get("needs_user_decision")),
        "residuals": residuals,
        "query_count": len(_query_records(source)),
        "llm_calls": dict(getattr(source, "llm_usage", {}) or analysis.get("llm_usage") or {}),
    }


def build_coverage_view(source: Any) -> dict[str, Any]:
    bound = getattr(source, "coverage_bound", None)
    if bound is None and isinstance(source, dict):
        bound = source.get("coverage_bound")
    gaps = list(getattr(source, "coverage_gaps", None) or (
        source.get("coverage_gaps") if isinstance(source, dict) else []
    ) or [])
    return {
        "coverage_bound": _as_dict(bound),
        "coverage_gaps": [item if isinstance(item, dict) else {"gap": str(item)} for item in gaps],
        "unexamined_routes": list(getattr(source, "unexamined_routes", None) or []),
        "query_completeness": [
            {"query_id": item.get("query_id"), "complete": item.get("complete")}
            for item in build_query_audit(source)
        ],
    }


def reconstruct_from_run_account(account: Any) -> WorkspaceSnapshot:
    """Rebuild workspace views from the machine run account, not a hand-edited dump."""
    payload = _account_payload(account)
    existing = payload.get("workspace_snapshot")
    if isinstance(existing, WorkspaceSnapshot):
        snap = existing
    elif isinstance(existing, dict) and existing:
        snap = WorkspaceSnapshot(
            run_id=str(existing.get("run_id") or payload.get("request_id") or ""),
            observation_ids=tuple(existing.get("observation_ids") or ()),
            evidence_graph=dict(existing.get("evidence_graph") or {}),
            goal_graph=dict(existing.get("goal_graph") or {}),
            query_audit=tuple(dict(item) for item in existing.get("query_audit") or ()),
            unexamined_routes=tuple(existing.get("unexamined_routes") or ()),
            limitations=tuple(existing.get("limitations") or ()),
            timeline=tuple(dict(item) for item in existing.get("timeline") or ()),
            tags=tuple(existing.get("tags") or ()),
            comments=tuple(dict(item) for item in existing.get("comments") or ()),
            saved_searches=tuple(dict(item) for item in existing.get("saved_searches") or ()),
            analyst_decisions=tuple(existing.get("analyst_decisions") or ()),
        )
    else:
        snap = WorkspaceSnapshot(run_id=str(payload.get("request_id") or ""))
    graph = payload.get("semantic_goal_graph")
    goal_graph = snap.goal_graph or (_as_dict(graph) if graph is not None else {})
    source = account if not isinstance(account, dict) else payload
    observations = _observation_records(source)
    observation_ids = snap.observation_ids or tuple(
        str(item.get("id") or item.get("observation_id") or "")
        for item in observations
        if item.get("id") or item.get("observation_id")
    ) or tuple(payload.get("observation_ids") or payload.get("observation_citations") or ())
    reviews = []
    for item in getattr(snap, "binding_reviews", ()) or payload.get("binding_reviews") or ():
        if isinstance(item, BindingReview):
            reviews.append(item)
        elif isinstance(item, dict):
            reviews.append(BindingReview(
                id=str(item.get("id") or ""),
                run_id=str(item.get("run_id") or snap.run_id),
                actor=str(item.get("actor") or "analyst"),
                variable_id=str(item.get("variable_id") or ""),
                selected_values=tuple(item.get("selected_values") or ()),
                citations=tuple(item.get("citations") or ()),
                rejected_values=tuple(item.get("rejected_values") or ()),
                timestamp=str(item.get("timestamp") or ""),
                rationale=str(item.get("rationale") or ""),
            ))
    return WorkspaceSnapshot(
        run_id=snap.run_id or str(payload.get("request_id") or ""),
        observation_ids=observation_ids,
        evidence_graph=snap.evidence_graph or {"observation_ids": list(observation_ids), "proof": False},
        goal_graph=goal_graph,
        query_audit=snap.query_audit or build_query_audit(source),
        unexamined_routes=snap.unexamined_routes,
        limitations=snap.limitations or tuple(payload.get("limitations") or payload.get("residuals") or ()),
        timeline=snap.timeline or build_timeline(source),
        tags=snap.tags,
        comments=snap.comments,
        saved_searches=snap.saved_searches,
        analyst_decisions=snap.analyst_decisions,
        entity_pivot=snap.entity_pivot or build_entity_pivot(source),
        native_events=snap.native_events or build_native_events(source),
        proof_obligations=snap.proof_obligations or build_proof_obligations(source),
        stop_explanation=snap.stop_explanation or build_stop_explanation(source),
        coverage_view=snap.coverage_view or build_coverage_view(source),
        binding_reviews=tuple(reviews),
    )


__all__ = [
    "build_coverage_view",
    "build_entity_pivot",
    "build_native_events",
    "build_proof_obligations",
    "build_query_audit",
    "build_stop_explanation",
    "build_timeline",
    "reconstruct_from_run_account",
]
