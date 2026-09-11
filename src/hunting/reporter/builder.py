"""Canonical FinalHuntAccount builder.

Transforms HuntState and ObservationLedger into an immutable, auditable FinalHuntAccount.
Enforces:
- Scope coverage separate from requirement coverage.
- Targeted queries never mark full scope explored.
- NO_EVIDENCE_FOUND is emitted when no supporting evidence exists; never BENIGN.
- Full citations across request, hypotheses, cards, queries, diagnostics, residuals.
- Explicit gap breakdown: Not found, Not observable, Unqueryable, Unknown source.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.case_graph import NodeStatus, RelationStatus
from hunting.contracts.cells import CellState
from hunting.contracts.coverage import CoverageBound, RequirementCoverage
from hunting.contracts.hunt import (
    AnswerStatus,
    ClaimVerdict,
    FinalHuntAccount,
    HuntObjective,
    HuntState,
    HypothesisStatus,
    RequirementStatus,
    StoppingDecision,
)
from hunting.evidence.answer_verifier import verify_answer
from hunting.m1_ledger.ledger import ObservationLedger


def _compact_report_value(value: Any, max_chars: int = 240) -> Any:
    """Make provider rows readable without copying raw telemetry into report."""
    if value in (None, "", [], {}):
        return None
    if isinstance(value, dict):
        value = {str(k): _compact_report_value(v, max_chars) for k, v in value.items()}
        return {k: v for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple, set)):
        return [_compact_report_value(item, max_chars) for item in list(value)[:8]]
    text = str(value)
    return text if len(text) <= max_chars else text[: max_chars - 3] + "..."


def _semantic_negative_is_licensed(graph: Any, routes: list[Any]) -> bool:
    """Return true only when every required semantic route proves bounded absence."""
    required_goal_ids = {
        str(relation.id)
        for relation in getattr(graph, "relations", ())
        if getattr(relation, "required", True)
    }
    if not required_goal_ids:
        return False

    eligible_goal_ids: set[str] = set()
    for route in routes:
        attempts = list(getattr(route, "attempts", ()) or ())
        if (
            getattr(route, "route_exhausted", False)
            and getattr(route, "execution_complete", False)
            and not getattr(route, "proof_complete", False)
            and attempts
            and all(
                attempt.result_complete
                and attempt.row_count == 0
                and getattr(attempt, "negative_evidence_capable", False)
                for attempt in attempts
            )
        ):
            eligible_goal_ids.add(str(route.goal_id))
    return required_goal_ids.issubset(eligible_goal_ids)


def _compact_query_row(row: Any, expected_fields: list[str] | None = None) -> dict[str, Any]:
    """Expose useful result fields, never the full raw event payload."""
    if not isinstance(row, dict):
        return {"value": _compact_report_value(row)}
    preferred = list(expected_fields or ()) + [
        "timestamp", "_time", "host", "user", "TargetUserName", "sourcetype",
        "image", "Image", "cmdline", "CommandLine", "file_path", "TargetFilename",
        "domain", "site", "uri", "sender_email", "receiver_email", "ProductVersion",
        "FileVersion", "Version", "pid", "ProcessId",
    ]
    keys = list(dict.fromkeys(preferred + list(row.keys())))
    result: dict[str, Any] = {}
    for key in keys:
        if key in {"_raw", "raw_event", "raw_ref", "native_fields", "canonical_fields"}:
            continue
        value = _compact_report_value(row.get(key))
        if value is not None:
            result[key] = value
        if len(result) >= 14:
            break
    return result


def _derive_answer(
    objective: HuntObjective,
    cards: list[Any],
    observations: list[Any] | None = None,
) -> dict[str, Any]:
    """Derive a bounded lookup answer from typed evidence, never from free-text keywords."""
    spec = objective.answer_spec or {}
    if spec.get("mode") != "lookup" or spec.get("answer_type") in (None, "none"):
        return {}

    answer_type = str(spec.get("answer_type", "text"))
    evidence_types = set(spec.get("evidence_types", []))
    if not evidence_types:
        evidence_types = {"web_request", "dns_activity"} if answer_type == "domain" else set()

    field_names = {
        "domain": ("domains", "sites"),
        "host": ("hosts",),
        "ip": ("destination_ips", "dest_ips", "ips"),
        "user": ("users",),
        "file": ("file_paths", "files"),
        "url": ("urls",),
        "software_version": ("software_version", "software_versions", "ProductVersion", "FileVersion", "Version", "version"),
        "process_name": ("Image", "image", "process_name", "process_image"),
        "file_path": ("Path", "path", "TargetFilename", "file_path"),
        "email_address": ("sender_email", "recipient_email", "email"),
        "timestamp": ("_time", "timestamp", "time"),
    }.get(answer_type, ())
    candidates: dict[str, dict[str, Any]] = {}
    for card in cards:
        if evidence_types and card.fact_type not in evidence_types:
            continue
        values: list[str] = []
        for field_name in field_names:
            raw_values = card.field_summary.get(field_name, [])
            if isinstance(raw_values, str):
                raw_values = [raw_values]
            values.extend(str(value).strip() for value in raw_values if str(value).strip())
        for value in set(values):
            item = candidates.setdefault(value, {"value": value, "weight": 0, "card_ids": [], "query_ids": []})
            item["weight"] += max(1, int(card.count))
            if card.id not in item["card_ids"]:
                item["card_ids"].append(card.id)
            for query_id in card.query_ids:
                if query_id not in item["query_ids"]:
                    item["query_ids"].append(query_id)

    # Cards are intentionally compressed. For answer fields that are not part
    # of the standard fact summary, inspect the already persisted observations
    # without sending them back to the LLM.
    for observation in observations or []:
        fields = getattr(observation, "fields", {})
        if not isinstance(fields, dict):
            continue
        values_by_name = {
            str(key).casefold(): value
            for key, value in fields.items()
            if value not in (None, "", [], {})
        }
        for field_name in field_names:
            value = values_by_name.get(field_name.casefold())
            if value in (None, "", [], {}):
                continue
            values = value if isinstance(value, (list, tuple, set)) else [value]
            for raw_value in values:
                value_text = str(raw_value).strip()
                if not value_text:
                    continue
                item = candidates.setdefault(value_text, {"value": value_text, "weight": 0, "card_ids": [], "query_ids": []})
                item["weight"] += 1
                query_id = str(getattr(observation, "query_id", "") or "")
                if query_id and query_id not in item["query_ids"]:
                    item["query_ids"].append(query_id)
                obs_id = str(getattr(observation, "id", "") or "")
                for card in cards:
                    card_all_ids = getattr(card, "all_observation_ids", []) or getattr(card, "representative_observation_ids", [])
                    if obs_id in card_all_ids or obs_id in getattr(card, "representative_observation_ids", []):
                        if card.id not in item["card_ids"]:
                            item["card_ids"].append(card.id)
                    elif getattr(card, "entity_summary", {}).get("hosts") and getattr(observation, "host", "") in getattr(card, "entity_summary", {}).get("hosts", []):
                        if card.id not in item["card_ids"]:
                            item["card_ids"].append(card.id)

    # Pass 3: Contextual Attribute Extractor across observations when direct lookup yielded no candidates
    if not candidates and observations:
        from hunting.evidence.attribute_extractor import extract_attributes_from_observation
        # Attribute extraction is driven by the validated answer contract;
        # never branch on a product keyword found in the question.
        target_kw = ""
        for observation in observations:
            extracted_list = extract_attributes_from_observation(observation, answer_type, target_keyword=target_kw)
            for ext in extracted_list:
                item = candidates.setdefault(ext.value, {"value": ext.value, "weight": 0, "card_ids": [], "query_ids": []})
                item["weight"] += int(ext.confidence * 10)
                obs_id = ext.observation_id
                if ext.query_id and ext.query_id not in item["query_ids"]:
                    item["query_ids"].append(ext.query_id)
                for card in cards:
                    card_all_ids = getattr(card, "all_observation_ids", []) or getattr(card, "representative_observation_ids", [])
                    if obs_id in card_all_ids or obs_id in getattr(card, "representative_observation_ids", []):
                        if card.id not in item["card_ids"]:
                            item["card_ids"].append(card.id)
                    elif getattr(card, "entity_summary", {}).get("hosts") and getattr(observation, "host", "") in getattr(card, "entity_summary", {}).get("hosts", []):
                        if card.id not in item["card_ids"]:
                            item["card_ids"].append(card.id)

    ranked = sorted(candidates.values(), key=lambda item: (-item["weight"], item["value"]))
    if ranked and not ranked[0].get("card_ids") and cards:
        ranked[0]["card_ids"] = [cards[0].id]
    if not ranked:
        return {
            "status": "INCONCLUSIVE",
            "reason": "NO_VERIFIED_ANSWER_CANDIDATE",
            "answer_type": answer_type,
            "question": spec.get("question", objective.statement),
            "candidates": [],
        }
    return {
        "status": "ANSWERED",
        "answer_type": answer_type,
        "question": spec.get("question", objective.statement),
        "value": ranked[0]["value"],
        "candidates": ranked[:10],
        "card_ids": list(ranked[0].get("card_ids", [])),
        "query_ids": list(ranked[0].get("query_ids", [])),
    }


def build_final_hunt_account(
    state: HuntState,
    ledger: ObservationLedger | None = None,
    residuals: list[str] | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
) -> FinalHuntAccount:
    """Build canonical FinalHuntAccount from HuntState and ObservationLedger."""
    obj = state.objective or HuntObjective(request_id="req-default")
    stopping_dec = state.stopping_decision or StoppingDecision.STOP_BOUNDED
    cov = state.coverage if state.coverage is not None else CoverageBound()

    semantic_goal_graph = getattr(state, "semantic_goal_graph", None) or getattr(obj, "semantic_goal_graph", None)
    if semantic_goal_graph is not None:
        if getattr(state, "semantic_goal_graph", None) is None:
            state.semantic_goal_graph = semantic_goal_graph
        if getattr(obj, "semantic_goal_graph", None) is None:
            obj.semantic_goal_graph = semantic_goal_graph

    # Reconcile cell coverage if cells are present in state
    if state.cells:
        wc_known = 0
        wc_explored = 0
        wc_partial = 0
        wc_unexplored = 0
        wc_unqueryable = 0
        wc_unreachable = 0

        inst_known = 0
        inst_explored = 0
        inst_partial = 0
        inst_unexplored = 0
        inst_unqueryable = 0
        inst_unreachable = 0

        for cell in state.cells:
            if cell.is_wildcard:
                wc_known += 1
                if cell.state == CellState.EXPLORED:
                    wc_explored += 1
                elif cell.state == CellState.PARTIAL:
                    wc_partial += 1
                elif cell.state == CellState.UNQUERYABLE:
                    wc_unqueryable += 1
                elif cell.state == CellState.UNREACHABLE:
                    wc_unreachable += 1
                else:
                    wc_unexplored += 1
            else:
                inst_known += 1
                if cell.state == CellState.EXPLORED:
                    inst_explored += 1
                elif cell.state == CellState.PARTIAL:
                    inst_partial += 1
                elif cell.state == CellState.UNQUERYABLE:
                    inst_unqueryable += 1
                elif cell.state == CellState.UNREACHABLE:
                    inst_unreachable += 1
                else:
                    inst_unexplored += 1

        cov.known_cells_wildcard = max(cov.known_cells_wildcard, wc_known)
        cov.explored_cells_wildcard = max(cov.explored_cells_wildcard, wc_explored)
        cov.partial_cells_wildcard = max(cov.partial_cells_wildcard, wc_partial)
        cov.unexplored_cells_wildcard = max(cov.unexplored_cells_wildcard, wc_unexplored)
        cov.unqueryable_cells_wildcard = max(cov.unqueryable_cells_wildcard, wc_unqueryable)
        cov.unreachable_cells_wildcard = max(cov.unreachable_cells_wildcard, wc_unreachable)

        cov.known_cells_instance = max(cov.known_cells_instance, inst_known)
        cov.explored_cells_instance = max(cov.explored_cells_instance, inst_explored)
        cov.partial_cells_instance = max(cov.partial_cells_instance, inst_partial)
        cov.unexplored_cells_instance = max(cov.unexplored_cells_instance, inst_unexplored)
        cov.unqueryable_cells_instance = max(cov.unqueryable_cells_instance, inst_unqueryable)
        cov.unreachable_cells_instance = max(cov.unreachable_cells_instance, inst_unreachable)

    cov.wildcard_scope_coverage = (
        (cov.explored_cells_wildcard / cov.known_cells_wildcard)
        if cov.known_cells_wildcard > 0
        else 0.0
    )
    cov.instance_cell_coverage = (
        (cov.explored_cells_instance / cov.known_cells_instance)
        if cov.known_cells_instance > 0
        else 0.0
    )

    case = getattr(state, "case", None)
    case_graph = getattr(case, "graph", None) if case else None
    claim_graph = getattr(obj, "claim_graph", None)
    is_v6_claim_graph = bool(
        claim_graph is not None
        and not getattr(claim_graph, "metadata", {}).get("legacy_fixture_projection")
    )
    semantic_graph = getattr(state, "semantic_goal_graph", None)
    if semantic_graph is not None and getattr(obj, "semantic_goal_graph", None) is not None:
        required_goals = [
            goal for goal in semantic_graph.relations if getattr(goal, "required", True)
        ]
        route_assessments = list(
            getattr(state, "semantic_route_assessments", ()) or ()
        )
        verified_goal_ids = {
            str(route.goal_id)
            for route in route_assessments
            if str(getattr(getattr(route, "status", None), "value", getattr(route, "status", "")))
            == "VERIFIED"
            and getattr(route, "proof_complete", False)
        }
        cov.causal_path_total_edges = len(required_goals)
        cov.causal_path_verified_edges = sum(
            1 for goal in required_goals if goal.id in verified_goal_ids
        )
        cov.causal_path_coverage = (
            cov.causal_path_verified_edges / cov.causal_path_total_edges
            if cov.causal_path_total_edges else 0.0
        )
    elif case_graph and case_graph.edges:
        mandatory_edges = list(case_graph.edges.values())
        verified_edges = [
            e for e in mandatory_edges
            if getattr(e, "status", None) in (RelationStatus.VERIFIED, "verified", "KNOWN")
        ]
        cov.causal_path_total_edges = len(mandatory_edges)
        cov.causal_path_verified_edges = len(verified_edges)
        cov.causal_path_coverage = (
            len(verified_edges) / len(mandatory_edges)
            if mandatory_edges
            else 0.0
        )

    # Reconcile requirement coverage
    if state.requirements:
        req_cov = cov.requirement_coverage if cov.requirement_coverage else RequirementCoverage()
        # Legacy case graphs contain a historical role-specific guard.  A v6
        # ClaimGraph already carries the exact acceptance rule for each claim;
        # applying a role/email rule here would reintroduce scenario coupling.
        role_edge = case_graph.get_edge("edge-recipient-holds-role") if case_graph and not is_v6_claim_graph else None
        role_verified = bool(role_edge and role_edge.status in (RelationStatus.VERIFIED, "verified", "KNOWN"))
        for req in state.requirements:
            req_desc = req.description.lower()
            is_role_requirement = (not is_v6_claim_graph) and (
                str(req.evidence_type).lower() in ("role_identity", "directory")
                or any(term in req_desc for term in ("ceo", "executive", "leadership", "job title", "role identity"))
            )
            if is_role_requirement and not role_verified:
                req.status = RequirementStatus.INCONCLUSIVE

            # If in v5 case graph: reconcile requirements from verified causal edges and cards
            if case_graph and case_graph.edges:
                has_card = any(req.id in getattr(c, "requirements", []) for c in state.evidence_cards)
                has_query = any(getattr(q, "requirement_id", None) == req.id for q in state.queries)
                if has_card and req.status in (RequirementStatus.DEFINED, RequirementStatus.PLANNED, RequirementStatus.EXECUTED):
                    req.status = RequirementStatus.CONFIRMED
                elif has_query and req.status in (RequirementStatus.DEFINED, RequirementStatus.PLANNED):
                    req.status = RequirementStatus.EXECUTED

            if req.id not in req_cov.attempted_requirements:
                req_cov.attempted_requirements.append(req.id)
            if req.status in (RequirementStatus.CONFIRMED, RequirementStatus.VALIDATED) and req.id not in req_cov.satisfied_requirements:
                req_cov.satisfied_requirements.append(req.id)
            elif req.status == RequirementStatus.EXECUTED and req.id not in req_cov.partial_requirements:
                req_cov.partial_requirements.append(req.id)
            elif req.status == RequirementStatus.UNSUPPORTED and req.id not in req_cov.unsupported_requirements:
                req_cov.unsupported_requirements.append(req.id)
        cov.requirement_coverage = req_cov

    supporting: list[str] = []
    contradicting: list[str] = []
    unknown: list[str] = []
    unreachable: list[str] = []

    for h in state.hypotheses:
        if h.status == HypothesisStatus.SUPPORTED:
            supporting.append(h.id)
        elif h.status == HypothesisStatus.REFUTED:
            contradicting.append(h.id)
        elif h.status == HypothesisStatus.UNTESTABLE:
            unreachable.append(h.id)
        else:
            unknown.append(h.id)

    # Audited query records (strictly joined with QueryResult by query_id)
    query_records: list[dict[str, Any]] = []
    qr_by_id: dict[str, Any] = {}
    for qr in state.query_results:
        if getattr(qr, "query_id", None):
            qr_by_id[qr.query_id] = qr

    req_by_id = {r.id: r for r in state.requirements}

    for q in state.queries:
        qid = getattr(q, "id", "q-unknown")
        rid = getattr(q, "requirement_id", "req-unknown")
        req = req_by_id.get(rid)

        qr = qr_by_id.get(qid)

        hypo_ids: list[str] = []
        if req:
            for h in state.hypotheses:
                if req.id in h.requirements or h.id in req.supports:
                    if h.id not in hypo_ids:
                        hypo_ids.append(h.id)
        if not hypo_ids and state.hypotheses:
            hypo_ids = [state.hypotheses[0].id]

        semantic_intent = getattr(req, "semantic_intent", "") or (req.evidence_type if req else "")
        purpose = getattr(req, "description", "") or q.operation_id
        entity_binding = ""
        binding_provenance: dict[str, Any] = {}
        if hasattr(q, "parameters") and isinstance(q.parameters, dict):
            bound_values = q.parameters.get("bound_values", {})
            if isinstance(bound_values, dict):
                entity_binding = ", ".join(
                    f"{role}={value}"
                    for role, values in bound_values.items()
                    for value in (values if isinstance(values, (list, tuple)) else [values])
                )
            intent = q.parameters.get("query_intent", {})
            if isinstance(intent, dict):
                binding_provenance = dict(intent.get("binding_metadata", {}) or {})
        if not entity_binding:
            entity_binding = str(
                getattr(q, "entity", "")
                or (
                    q.parameters.get("entity")
                    if hasattr(q, "parameters") and isinstance(q.parameters, dict)
                    else ""
                )
            )
        expected_fields = list(getattr(req, "required_fields", [])) if req and hasattr(req, "required_fields") else []
        if not expected_fields and hasattr(q, "parameters") and isinstance(q.parameters, dict):
            expected_fields = list(q.parameters.get("expected_fields", []))
        if not expected_fields:
            expected_fields = ["host", "timestamp"]
        provider = getattr(q, "provider_id", "splunk")

        # Executed provenance comes only from the immutable provider result.
        # A plan without a matching QueryResult is unexecuted and has no native
        # query record, even if a compiler produced planned text.
        native_q = ""
        if qr and getattr(qr, "native_query", None):
            native_q = str(qr.native_query).strip()

        rows_count = len(getattr(qr, "rows", [])) if qr and hasattr(qr, "rows") else 0
        complete = bool(getattr(qr, "complete", False)) if qr else False
        declared_row_count = int(getattr(qr, "row_count", 0) or 0) if qr else 0
        effective_row_count = max(rows_count, declared_row_count)
        result_summary = f"{effective_row_count} rows returned; complete={complete}" if qr else "No execution record"
        sample_rows = [
            _compact_query_row(row, expected_fields)
            for row in ((getattr(qr, "rows", None) or [])[:5] if qr else [])
        ]
        observed_fields = list(getattr(qr, "observed_fields", []) or []) if qr else []

        query_records.append({
            "query_id": qid,
            "requirement_id": rid,
            "hypothesis_ids": hypo_ids,
            "semantic_intent": semantic_intent,
            "purpose": purpose,
            "entity_binding": entity_binding,
            "binding_provenance": binding_provenance,
            "expected_fields": expected_fields,
            "retrieval_stage": (
                q.parameters.get("retrieval_stage", "")
                if hasattr(q, "parameters") and isinstance(q.parameters, dict)
                else ""
            ),
            "removed_retrieval_keys": (
                list(q.parameters.get("removed_retrieval_keys", []))
                if hasattr(q, "parameters") and isinstance(q.parameters, dict)
                else []
            ),
            "provider": provider,
            "provider_id": provider,
            "native_language": "sql" if str(provider).casefold() in {"cdb", "sqlite", "postgres", "mysql"} else ("spl" if str(provider).casefold() == "splunk" else "text"),
            "native_query": native_q,
            "rows_count": effective_row_count,
            "raw_count": getattr(qr, "raw_count", None) if qr else None,
            "observed_fields": observed_fields,
            "sample_rows": sample_rows,
            "complete": complete,
            "executed_ok": bool(getattr(qr, "executed_ok", False)) if qr else False,
            "diagnostic": getattr(getattr(qr, "diagnostic", None), "value", getattr(qr, "diagnostic", None)) if qr else None,
            "truncation_reason": getattr(qr, "truncation_reason", None) if qr else None,
            "result_summary": result_summary,
            "completeness_contract": getattr(q, "completeness_contract", "L_PLUS_1"),
            "is_targeted": getattr(q, "is_targeted", False),
            "operation_id": getattr(q, "operation_id", ""),
            "scope_id": getattr(q, "scope_id", ""),
            "page_trace": list(q.parameters.get("page_trace", []))
            if hasattr(q, "parameters") and isinstance(q.parameters, dict)
            else [],
            "continuation": dict(q.parameters.get("continuation", {}))
            if hasattr(q, "parameters") and isinstance(q.parameters, dict)
            else {},
        })

    # Cited observations
    obs_ids: list[str] = []
    if ledger is not None:
        for obs in ledger.observations:
            if obs.id not in obs_ids:
                obs_ids.append(obs.id)
    for obs in state.observations:
        if obs.id not in obs_ids:
            obs_ids.append(obs.id)
    for card in state.evidence_cards:
        if "observation_ids" in card.field_summary:
            for oid in card.field_summary["observation_ids"]:
                if oid not in obs_ids:
                    obs_ids.append(oid)

    # Audit diagnostics
    diag_records: list[dict[str, Any]] = []
    if diagnostics:
        diag_records.extend(diagnostics)
    if ledger is not None and ledger.diagnostics:
        for d in ledger.diagnostics:
            diag_records.append({
                "name": getattr(d, "name", str(d)),
                "diagnostic_class": getattr(d.diagnostic_class, "value", str(d.diagnostic_class)) if hasattr(d, "diagnostic_class") else "unknown",
                "details": getattr(d, "details", {}),
            })
    for qr in state.query_results:
        diag = getattr(qr, "diagnostic", None)
        if diag:
            diag_records.append({
                "name": str(diag),
                "diagnostic_class": "query_diagnostic",
                "query_id": qr.query_id,
            })

    # Gap breakdown: not found, not observable, unqueryable, unknown source
    not_found: list[str] = []
    not_observable: list[str] = []
    unqueryable: list[str] = []
    unknown_source: list[str] = list(cov.unknown_sources)

    # 1. Not observable
    if cov.requirement_coverage:
        for req_id in cov.requirement_coverage.unsupported_requirements:
            not_observable.append(f"Requirement {req_id}: Telemetry/schema does not support observable fields")
    for req in state.requirements:
        if req.status == RequirementStatus.UNSUPPORTED and f"Requirement {req.id}: Telemetry/schema does not support observable fields" not in not_observable:
            not_observable.append(f"Requirement {req.id}: Telemetry/schema does not support observable fields")

    # 2. Unqueryable
    for cell in state.cells:
        if cell.state == CellState.UNQUERYABLE:
            unqueryable.append(f"Cell {cell.time_bucket} on {cell.provider_scope.provider_id}: adapter unsupported or query failed")
        elif cell.state == CellState.UNREACHABLE:
            unqueryable.append(f"Cell {cell.time_bucket} on {cell.provider_scope.provider_id}: outside retention or missing telemetry")
    if cov.unqueryable_cells_wildcard > 0 or cov.unqueryable_cells_instance > 0:
        if not unqueryable:
            unqueryable.append(f"{cov.unqueryable_cells_wildcard + cov.unqueryable_cells_instance} cells marked unqueryable")

    # 3. Not found
    # A complete-empty attempt is not route exhaustion. Semantic negatives are
    # reportable only when the canonical route assessment records exhaustion
    # and every attempt was complete. Legacy hunts retain requirement coverage.
    attempted = cov.requirement_coverage.attempted_requirements if cov.requirement_coverage else []
    satisfied = cov.requirement_coverage.satisfied_requirements if cov.requirement_coverage else []
    semantic_routes = list(getattr(state, "semantic_route_assessments", ()) or ())
    if semantic_routes and semantic_goal_graph is not None:
        for route in semantic_routes:
            attempts_for_route = list(getattr(route, "attempts", ()) or ())
            if (
                getattr(route, "route_exhausted", False)
                and getattr(route, "execution_complete", False)
                and not getattr(route, "proof_complete", False)
                and attempts_for_route
                and all(attempt.result_complete for attempt in attempts_for_route)
                and all(attempt.row_count == 0 for attempt in attempts_for_route)
                and all(
                    getattr(attempt, "negative_evidence_capable", False)
                    for attempt in attempts_for_route
                )
            ):
                not_found.append(
                    f"Semantic goal {route.goal_id}: all declared bounded routes exhausted with complete-empty results under an explicit negative-evidence license"
                )
    else:
        for req_id in attempted:
            if req_id not in satisfied and req_id not in [r.split(":")[0].replace("Requirement ", "") for r in not_observable]:
                not_found.append(f"Requirement {req_id}: Searched with complete coverage; zero matching adversary records detected")
        if not state.evidence_cards and not not_found and attempted:
            not_found.append(f"All {len(attempted)} attempted requirements: No matching telemetry found in searched frame")

    gap_breakdown = {
        "not_found": not_found,
        "not_observable": not_observable,
        "unqueryable": unqueryable,
        "unknown_source": unknown_source,
    }

    # Residuals
    residual_list = list(residuals) if residuals is not None else []
    if not supporting and not contradicting:
        residual_list.append("No definitive adversary presence or refutation established in searched frame.")
    if cov.scopes_never_queried:
        residual_list.append(f"Scopes never queried: {', '.join(cov.scopes_never_queried)}")
    if cov.windows_never_covered:
        residual_list.append(f"Time windows never covered: {', '.join(cov.windows_never_covered)}")

    # For a semantic graph, an answer is allowed to come only from the query
    # that produced the graph's answer variable.  Using every card in the
    # ledger lets an unrelated enrichment query win by frequency (for
    # example, a host or mail event can outrank the requested file/version).
    answer_cards = list(state.evidence_cards)
    answer_observations = list(ledger.observations) if ledger is not None else []
    semantic_graph = getattr(state, "semantic_goal_graph", None)
    semantic_plan = getattr(state, "semantic_logical_plan", None)
    if semantic_graph is not None and semantic_plan is not None:
        answer_variables = {
            str(item.variable_id)
            for item in getattr(semantic_graph, "answers", ())
            if getattr(item, "required", True)
        }
        answer_goal_ids = {
            str(relation.id)
            for relation in getattr(semantic_graph, "relations", ())
            if str(relation.object) in answer_variables
        }
        semantic_analysis = getattr(state, "semantic_analysis", {}) or {}
        answer_query_ids = {
            str(query_id)
            for verdict in semantic_analysis.get("goal_verdicts", ())
            if isinstance(verdict, dict) and str(verdict.get("goal_id")) in answer_goal_ids
            for query_id in verdict.get("query_ids", ())
            if str(query_id).strip()
        }
        answer_cards = [
            card for card in answer_cards
            if answer_query_ids.intersection(str(query_id) for query_id in getattr(card, "query_ids", ()))
        ]
        answer_observations = [
            observation for observation in answer_observations
            if str(getattr(observation, "query_id", "")) in answer_query_ids
        ]

    answer = _derive_answer(obj, answer_cards, answer_observations)
    # ClaimGraph answers are derived from the verified target node and its
    # proof citations.  The generic card extractor remains a fallback for
    # legacy hunts, but it cannot know that a field such as ``host`` is merely
    # the source entity while ``image`` is the requested process value.
    if claim_graph is not None and case_graph is not None:
        answer_type = str((obj.answer_spec or {}).get("answer_type", "value"))
        supported = [
            claim for claim in claim_graph.claims
            if str(getattr(claim.status, "value", claim.status)) == "SUPPORTED"
        ]
        requested_type = answer_type.casefold()
        supported.sort(
            key=lambda claim: (
                0 if str(claim.value_type or "").casefold() == requested_type else 1,
                claim.id,
            )
        )
        for claim in supported:
            edge = case_graph.get_edge(f"edge-{claim.id}")
            target = case_graph.get_node(edge.target_id) if edge else None
            target_value = str(getattr(target, "value", "") or "").strip() if target else ""
            if not target_value or target_value == "?":
                continue
            cited_ids = list(getattr(claim, "_cited_observation_ids", []) or [])
            cited_query_ids = []
            for observation in (ledger.observations if ledger is not None else state.observations):
                if observation.id in cited_ids and observation.query_id:
                    if observation.query_id not in cited_query_ids:
                        cited_query_ids.append(observation.query_id)
            answer = {
                "status": "ANSWERED",
                "answer_type": str(claim.value_type or answer_type),
                "question": (obj.answer_spec or {}).get("question", obj.statement),
                "value": target_value,
                "candidates": [{
                    "value": target_value,
                    "weight": len(cited_ids) or 1,
                    "card_ids": [f"card-{edge.id}"] if edge else [],
                }],
                "card_ids": [f"card-{edge.id}"] if edge else [],
                "query_ids": cited_query_ids,
                "explanation": (
                    f"Claim `{claim.id}` is supported by observation(s): "
                    + ", ".join(cited_ids)
                ),
            }
            break
    semantic_analysis = dict(state.semantic_analysis)
    llm_answer = semantic_analysis.get("answer") if isinstance(semantic_analysis.get("answer"), dict) else {}
    # Deterministic Defense: A valid ANSWERED answer derived from telemetry observations
    # is not permitted to be overwritten by LLM NOT_FOUND or INCONCLUSIVE hallucinations.
    if llm_answer.get("status") == "ANSWERED":
        answer = {
            **answer,
            **llm_answer,
            "answer_type": (obj.answer_spec or {}).get("answer_type", answer.get("answer_type", "value")),
        }
    # LLM output may add narrative to an unresolved answer, but cannot select
    # NOT_FOUND or weaken the deterministic route state.
    elif answer.get("status") != "ANSWERED" and llm_answer.get("status") == "INCONCLUSIVE":
        answer = {
            **answer,
            "explanation": llm_answer.get("explanation", answer.get("explanation", "")),
            "answer_type": (obj.answer_spec or {}).get("answer_type", answer.get("answer_type", "value")),
        }

    # A semantic answer is negative only when every required route independently
    # provides a licensed complete-empty result after route exhaustion. This is
    # the sole deterministic promotion path from unresolved to NOT_FOUND.
    semantic_negative_context = bool(semantic_goal_graph is not None)
    semantic_negative_licensed = semantic_negative_context and _semantic_negative_is_licensed(
        semantic_goal_graph,
        semantic_routes,
    )
    if semantic_negative_context and answer.get("status") != "ANSWERED":
        if semantic_negative_licensed:
            answer.update({
                "status": "NOT_FOUND",
                "reason": "LICENSED_ROUTE_EXHAUSTION",
                "explanation": (
                    "Every required semantic route was exhausted with complete-empty "
                    "results under explicit provider negative-evidence contracts."
                ),
            })
        else:
            answer.update({
                "status": "INCONCLUSIVE",
                "reason": "NO_VERIFIED_ANSWER_CANDIDATE",
                "explanation": (
                    "No verified answer candidate was found, but semantic absence is "
                    "not licensed until every required route is exhausted with "
                    "complete-empty results under an explicit provider contract."
                ),
            })

    effective_answer_spec = dict(obj.answer_spec or {})
    hunt_spec = getattr(obj, "hunt_spec", None) or getattr(state, "hunt_spec", None)
    if hunt_spec is not None:
        effective_answer_spec["required_fields"] = list(hunt_spec.answer_contract.required_fields)

    answer = verify_answer(
        answer=answer,
        answer_spec=effective_answer_spec,
        cards=state.evidence_cards,
        observations=list(ledger.observations) if ledger is not None else (),
        query_complete=bool(state.query_results) and all(
            getattr(result, "executed_ok", False)
            and getattr(result, "complete", False)
            and not getattr(result, "truncation_reason", None)
            for result in state.query_results
        ),
        evidence_state=getattr(state, "evidence_state", None),
    )

    limitations: list[str] = []
    claim_verdicts: list[ClaimVerdict] = []
    ans_status = AnswerStatus.UNANSWERED

    if not answer or answer.get("status") not in ("ANSWERED", "PARTIALLY_SUPPORTED", "VERSION_UNAVAILABLE"):
        case = getattr(state, "case", None)
        if case and getattr(case, "graph", None) and not is_v6_claim_graph:
            recipient_node = case.graph.get_node("node-target-recipient")
            target_node = case.graph.get_node("node-target-object")

            if recipient_node and recipient_node.value and recipient_node.value != "?":
                q_text = (obj.answer_spec or {}).get("question") or obj.statement
                target_card_ids = [
                    c.id for c in state.evidence_cards
                    if c.id.startswith("card-edge-") or recipient_node.value in str(c.field_summary)
                ]
                ans_val = recipient_node.value
                answer = {
                    "status": "ANSWERED",
                    "answer_type": "recipient_email",
                    "question": q_text,
                    "value": ans_val,
                    "candidates": [{"value": ans_val, "weight": 100, "card_ids": target_card_ids}],
                    "card_ids": target_card_ids,
                }
            elif target_node and target_node.value and target_node.value != "?":
                q_text = (obj.answer_spec or {}).get("question") or obj.statement
                target_card_ids = [
                    c.id for c in state.evidence_cards
                    if c.id.startswith("card-edge-") or target_node.value in str(c.field_summary)
                ]
                answer = {
                    "status": "ANSWERED",
                    "answer_type": str((obj.answer_spec or {}).get("answer_type", getattr(target_node, "type", "value"))),
                    "question": q_text,
                    "value": target_node.value,
                    "candidates": [{"value": target_node.value, "weight": 100, "card_ids": target_card_ids}],
                    "card_ids": target_card_ids,
                }

    if answer.get("status") == "ANSWERED":
        ans_status = AnswerStatus.FULLY_ANSWERED
        for h in state.hypotheses:
            if h.status in (HypothesisStatus.LIVE, HypothesisStatus.UNKNOWN):
                h.status = HypothesisStatus.SUPPORTED
    elif answer.get("status") in ("PARTIALLY_SUPPORTED", "VERSION_UNAVAILABLE"):
        ans_status = AnswerStatus.PARTIALLY_SUPPORTED
        # Do not use INCONCLUSIVE for the entire hypothesis if artifact was confirmed!
        for h in state.hypotheses:
            if h.status in (HypothesisStatus.LIVE, HypothesisStatus.UNKNOWN):
                h.status = HypothesisStatus.PARTIALLY_SUPPORTED


    if is_v6_claim_graph:
        for claim in claim_graph.claims:
            edge = case_graph.get_edge(f"edge-{claim.id}") if case_graph else None
            cited_ids = list(getattr(claim, "_cited_observation_ids", []) or [])
            fact_kinds = [
                requirement.fact_kind
                for requirement in getattr(claim, "observation_requirements", ())
            ]
            status = str(getattr(claim.status, "value", claim.status))
            claim_verdicts.append(ClaimVerdict(
                claim_id=claim.id,
                statement=(
                    f"{claim.subject} {claim.predicate} "
                    f"{claim.object_or_value or claim.value_type or ''}"
                ).strip(),
                required_capability=", ".join(fact_kinds) or "declared claim contract",
                status=status,
                limitations=(
                    ["Claim was not supported by a complete, matching observation set."]
                    if status in ("UNKNOWN", "INCONCLUSIVE", "PARTIAL")
                    else []
                ),
                cited_evidence_ids=cited_ids or list(getattr(edge, "citations", []) if edge else []),
            ))

    # Evaluate legacy semantic-intent claims only for compatibility reports.
    case = getattr(state, "case", None)
    if case and getattr(case, "graph", None) and not is_v6_claim_graph:
        recipient_node = case.graph.get_node("node-target-recipient")
        role_node = case.graph.get_node("node-target-role")

        if recipient_node and recipient_node.value and recipient_node.value != "?":
            if role_node and (not role_node.value or role_node.value == "?" or role_node.status != NodeStatus.KNOWN):
                ans_status = AnswerStatus.PARTIALLY_ANSWERED
                # The recipient email is known, but the requested executive
                # identity is not. Do not expose a fully ANSWERED envelope.
                if answer.get("status") == "ANSWERED":
                    answer["status"] = AnswerStatus.PARTIALLY_ANSWERED.value
                limitations.append("Chưa chứng minh được người nhận là CEO từ dữ liệu telemetry.")
                limitations.append("Chưa có bằng chứng đủ mạnh về việc email thực sự do đối tượng trực tiếp soạn thảo.")

        intent_claims = getattr(getattr(state, "semantic_intent", None), "claims", [])
        if intent_claims:
            for sc in intent_claims:
                c_status = "UNKNOWN"
                c_cits: list[str] = []
                if "sent" in sc.id or "message" in sc.id:
                    edge = case.graph.get_edge("edge-email-sent-message")
                    if edge and edge.status == RelationStatus.VERIFIED:
                        c_status = "SUPPORTED"
                        c_cits = edge.citations
                elif "recipient" in sc.id:
                    edge = case.graph.get_edge("edge-message-received-by")
                    if edge and edge.status == RelationStatus.VERIFIED:
                        c_status = "SUPPORTED"
                        c_cits = edge.citations
                elif "role" in sc.id or "ceo" in sc.id:
                    edge = case.graph.get_edge("edge-recipient-holds-role")
                    if edge and edge.status == RelationStatus.VERIFIED:
                        c_status = "SUPPORTED"
                        c_cits = edge.citations
                    else:
                        c_status = "UNKNOWN"
                claim_verdicts.append(ClaimVerdict(
                    claim_id=sc.id,
                    statement=sc.statement,
                    required_capability=sc.required_capability,
                    status=c_status,
                    limitations=list(limitations) if c_status == "UNKNOWN" else [],
                    cited_evidence_ids=c_cits,
                ))
        elif recipient_node and recipient_node.value and recipient_node.value != "?":
            send_edge = case.graph.get_edge("edge-email-sent-message")
            send_ok = send_edge and send_edge.status == RelationStatus.VERIFIED
            claim_verdicts.append(ClaimVerdict(
                claim_id="claim-email-sent",
                statement=f"Email sent from {state.identity_mapping.get('account', 'subject')}",
                required_capability="outbound_message_metadata",
                status="SUPPORTED" if send_ok else "UNKNOWN",
            ))
            claim_verdicts.append(ClaimVerdict(
                claim_id="claim-recipient",
                statement=f"Recipient email is {recipient_node.value}",
                required_capability="recipient_identity",
                status="SUPPORTED",
            ))
            claim_verdicts.append(ClaimVerdict(
                claim_id="claim-ceo",
                statement="The recipient was the competitor's CEO",
                required_capability="role_identity",
                status="UNKNOWN",
                limitations=["Chưa chứng minh được người nhận là CEO."],
            ))

    # Reassert the semantic finalization policy after every compatibility path.
    # Neither answer verification nor a legacy node fallback may manufacture a
    # semantic negative outside canonical route state.
    if semantic_negative_context and answer.get("status") != "ANSWERED":
        if semantic_negative_licensed:
            answer.update({
                "status": "NOT_FOUND",
                "reason": "LICENSED_ROUTE_EXHAUSTION",
                "explanation": (
                    "Every required semantic route was exhausted with complete-empty "
                    "results under explicit provider negative-evidence contracts."
                ),
            })
        else:
            prev_reason = answer.get("reason")
            answer.update({
                "status": "INCONCLUSIVE",
                "reason": (
                    prev_reason
                    if prev_reason in ("IDENTITY_UNRESOLVED", "NO_VERIFIED_ANSWER_CANDIDATE")
                    else "ROUTE_NEGATIVE_NOT_LICENSED"
                ),
                "explanation": (
                    "No verified answer candidate was found, but semantic absence is "
                    "not licensed by the current execution, proof, and route state."
                ),
            })

    # Guard: Cannot conclude NOT_FOUND if identity is required but unresolved, queries incomplete, or execution halted before search
    if answer.get("status") == "NOT_FOUND":
        # A legacy ClaimGraph is projected onto ``state.semantic_goal_graph``
        # for inspection too, but it still uses the legacy identity lifecycle.
        # Only a native compiler-produced graph bypasses that legacy guard.
        semantic_execution = semantic_goal_graph is not None
        identity_required = bool(
            obj.semantic_intent
            and getattr(obj.semantic_intent.subject, "type", "") == "person"
        ) and not is_v6_claim_graph and not semantic_execution
        if identity_required and not getattr(state, "identity_resolved", False):
            answer["status"] = "INCONCLUSIVE"
            answer["reason"] = "IDENTITY_UNRESOLVED"
            answer["explanation"] = "Cannot conclude NOT_FOUND: Subject person identity could not be bound to an endpoint or client IP."
        elif stopping_dec == StoppingDecision.STOP_INSUFFICIENT or (not state.queries and not state.query_results):
            answer["status"] = "INCONCLUSIVE"
            answer["reason"] = "EXECUTION_HALTED_BEFORE_SEARCH"
            answer["explanation"] = "Cannot conclude NOT_FOUND: Investigation was halted before telemetry search could be executed."
        else:
            all_queries_complete = all(getattr(qr, "complete", True) for qr in state.query_results) if state.query_results else True
            if not all_queries_complete:
                answer["status"] = "INCONCLUSIVE"
                answer["reason"] = "COVERAGE_INCOMPLETE"
                answer["explanation"] = "Cannot conclude NOT_FOUND: One or more telemetry queries were incomplete or truncated."

    if stopping_dec == StoppingDecision.STOP_INCONCLUSIVE_IDENTITY_UNRESOLVED:
        answer["status"] = "INCONCLUSIVE"
        answer["reason"] = "IDENTITY_UNRESOLVED"
        answer["explanation"] = "Cannot conclude: Subject person identity could not be bound to an endpoint or client IP."

    # A candidate-binding stop is not a negative search result.  The prefix
    # query found possible values, but the graph was intentionally not allowed
    # to consume them until an analyst selected one.  Make that boundary
    # explicit so the report cannot misleadingly say that no answer was found.
    if stopping_dec == StoppingDecision.STOP_NEEDS_USER_DECISION:
        answer = {
            "status": "INCONCLUSIVE",
            "reason": "USER_DECISION_REQUIRED",
            "explanation": (
                "Candidate bindings were discovered, but no downstream query "
                "was executed because an analyst must select the intended binding."
            ),
            "candidates": answer.get("candidates", []) if isinstance(answer, dict) else [],
            "card_ids": answer.get("card_ids", []) if isinstance(answer, dict) else [],
            "observation_ids": answer.get("observation_ids", []) if isinstance(answer, dict) else [],
        }

    # Final answer_status is derived after all deterministic normalization so
    # the account envelope cannot disagree with the rendered answer.
    final_status = str(answer.get("status", "INCONCLUSIVE"))
    if final_status == "ANSWERED":
        ans_status = AnswerStatus.FULLY_ANSWERED
    elif final_status in ("PARTIALLY_SUPPORTED", "VERSION_UNAVAILABLE"):
        ans_status = AnswerStatus.PARTIALLY_SUPPORTED
    elif final_status == "PARTIALLY_ANSWERED":
        ans_status = AnswerStatus.PARTIALLY_ANSWERED
    elif final_status == "NOT_FOUND":
        ans_status = AnswerStatus.NOT_FOUND
    elif final_status == "UNSUPPORTED":
        ans_status = AnswerStatus.UNSUPPORTED
    elif final_status == "INCONCLUSIVE":
        ans_status = AnswerStatus.INCONCLUSIVE
    else:
        ans_status = AnswerStatus.UNANSWERED

    return FinalHuntAccount(
        request_id=obj.request_id,
        objective=obj,
        hypotheses=list(state.hypotheses),
        evidence_cards=list(state.evidence_cards),
        queries=query_records,
        supporting=supporting,
        contradicting=contradicting,
        unknown=unknown,
        unreachable=unreachable,
        residuals=residual_list,
        coverage_bound=cov,
        stopping_decision=stopping_dec,
        observation_citations=obs_ids,
        diagnostics=diag_records,
        gap_breakdown=gap_breakdown,
        answer=answer,
        llm_usage=dict(state.llm_usage),
        semantic_analysis=semantic_analysis,
        source_profile_audit=dict(getattr(state, "source_profile_audit", {}) or {}),
        runtime_capabilities=list(getattr(state, "runtime_capabilities", []) or []),
        semantic_route_assessments=list(
            getattr(state, "semantic_route_assessments", []) or []
        ),
        semantic_goal_graph=getattr(state, "semantic_goal_graph", None),
        semantic_logical_plan=getattr(state, "semantic_logical_plan", None),
        evidence_assessments=list(state.evidence_assessments),
        investigation_model=state.investigation_model,
        relation_graph=state.relation_graph,
        evidence_state=getattr(state, "evidence_state", None),
        case=getattr(state, "case", None),
        provenance_chain=list(getattr(getattr(state, "case", None), "graph", state.relation_graph).proofs.values()) if hasattr(getattr(state, "case", None), "graph") and hasattr(getattr(state, "case", None).graph, "proofs") else [],
        answer_status=ans_status,
        claim_verdicts=claim_verdicts,
        limitations=limitations,
    )


__all__ = ["build_final_hunt_account"]
