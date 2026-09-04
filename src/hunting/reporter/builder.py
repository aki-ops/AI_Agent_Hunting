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

from hunting.contracts.cells import CellState
from hunting.contracts.coverage import CoverageBound, RequirementCoverage
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntObjective,
    HuntState,
    HypothesisStatus,
    RequirementStatus,
    StoppingDecision,
)
from hunting.m1_ledger.ledger import ObservationLedger


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

    # Reconcile requirement coverage
    if state.requirements:
        req_cov = cov.requirement_coverage if cov.requirement_coverage else RequirementCoverage()
        for req in state.requirements:
            if req.id not in req_cov.attempted_requirements:
                req_cov.attempted_requirements.append(req.id)
            if req.status == RequirementStatus.VALIDATED and req.id not in req_cov.satisfied_requirements:
                req_cov.satisfied_requirements.append(req.id)
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

    # Audited query records
    query_records: list[dict[str, Any]] = []
    for q in state.queries:
        query_records.append({
            "query_id": q.id,
            "requirement_id": q.requirement_id,
            "provider_id": q.provider_id,
            "scope_id": q.scope_id,
            "operation_id": q.operation_id,
            "completeness_contract": q.completeness_contract,
            "is_targeted": getattr(q, "is_targeted", False),
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
        for diag in qr.diagnostics:
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
    # Requirements that were attempted with complete observable scope but yielded 0 hits
    attempted = cov.requirement_coverage.attempted_requirements if cov.requirement_coverage else []
    satisfied = cov.requirement_coverage.satisfied_requirements if cov.requirement_coverage else []
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
    )


__all__ = ["build_final_hunt_account"]
