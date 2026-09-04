"""Canonical Threat Hunting Markdown Report Renderer.

Pure rendering of FinalHuntAccount into an immutable, auditable markdown document.
Enforces:
- Strict separation of Scope Coverage and Requirement Coverage.
- Targeted queries never imply full scope coverage.
- NO_EVIDENCE_FOUND is emitted when no supporting evidence exists; NEVER rendered as BENIGN.
- Cites request, hypotheses, evidence cards, cited observations, queries, diagnostics, residuals.
- Explicit gap breakdown: Not found, Not observable, Unqueryable, Unknown source.
"""
from __future__ import annotations

from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntOutcome,
    HypothesisStatus,
)


def render_final_hunt_account(account: FinalHuntAccount) -> str:
    """Render canonical Markdown report from FinalHuntAccount.

    Pure function: Never mutates account, dispositions, or hypotheses.
    """
    # Determine top-level outcome headline
    if account.supporting:
        outcome_str = HuntOutcome.SUPPORTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Adversary Activity Detected)"
    elif account.contradicting and not account.supporting:
        outcome_str = HuntOutcome.CONTRADICTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Hypothesis Refuted by Negative Evidence)"
    elif account.unreachable and not account.supporting:
        outcome_str = HuntOutcome.UNREACHABLE.value
        verdict_banner = "**Investigation Outcome:** `NO_EVIDENCE_FOUND` (Target Scopes Unreachable)"
    else:
        outcome_str = "NO_EVIDENCE_FOUND"
        verdict_banner = "**Investigation Outcome:** `NO_EVIDENCE_FOUND`"

    cb = account.coverage_bound
    req_cov = cb.requirement_coverage

    obj = account.objective
    kind_val = getattr(obj, "kind", None)
    if kind_val is not None:
        kind_str = kind_val.value if hasattr(kind_val, "value") else str(kind_val)
    else:
        kind_str = "HUNT"

    stmt_str = getattr(obj, "statement", "") or (f"Investigate {', '.join(obj.target_hypotheses)}" if getattr(obj, "target_hypotheses", None) else "Proactive hunt")

    tp = getattr(obj, "time_policy", None)
    if tp is not None and (tp.start or tp.end):
        time_frame_str = f"`{tp.start or 'N/A'}` to `{tp.end or 'N/A'}`"
    elif getattr(obj, "time_window", ""):
        time_frame_str = f"`{obj.time_window}`"
    else:
        time_frame_str = "`N/A`"

    entities = getattr(obj, "entities", [])
    if entities:
        ent_strs = [f"{type(e).__name__}({getattr(e, 'name', getattr(e, 'address', str(e)))})" for e in entities]
        entity_str = ", ".join(ent_strs)
    else:
        entity_str = "`POPULATION / ANY`"

    lines: list[str] = [
        "# Threat Hunting Investigation Final Account",
        "",
        verdict_banner,
        f"- **Request ID:** `{account.request_id}`",
        f"- **Stopping Decision:** `{account.stopping_decision.value}`",
        f"- **Hunt Kind:** `{kind_str}`",
        f"- **Objective Statement:** {stmt_str}",
        f"- **Searched Time Window:** {time_frame_str}",
        f"- **Target Entities:** {entity_str}",
    ]

    # Epistemic notice when no evidence is found
    if not account.supporting:
        lines.extend([
            "",
            "> [!IMPORTANT]",
            "> **Epistemic Notice:** `NO_EVIDENCE_FOUND` represents the bounded absence of detected adversary activity",
            "> within the queried telemetry frame. This result is strictly **NOT** a finding of `BENIGN` and does not imply",
            "> absence of compromise outside the observed scope or telemetry capabilities.",
        ])

    # 1. Coverage Accounting (Separate Scope vs Requirement)
    lines.extend([
        "",
        "---",
        "## 1. Coverage Accounting",
        "",
        "> Scope coverage (spatial-temporal telemetry partition cells) is strictly accounted separately",
        "> from requirement coverage (behavioral TTPs). Targeted queries on specific entities do NOT",
        "> mark wildcard broadsweep cells as explored.",
        "",
        "### Scope Coverage (Spatial-Temporal Partition Cells)",
        "",
        "#### Wildcard Cells (BroadSweep / Population):",
        f"- Known: {cb.known_cells_wildcard}",
        f"- Explored: {cb.explored_cells_wildcard}",
        f"- Partial (truncated / split): {cb.partial_cells_wildcard}",
        f"- Unexplored: {cb.unexplored_cells_wildcard}",
        f"- Unqueryable (syntax / permissions / unsupported adapter): {cb.unqueryable_cells_wildcard}",
        f"- Unreachable (retention expired / missing telemetry): {cb.unreachable_cells_wildcard}",
        "",
        "#### Instance Cells (Discovered Concrete Entities):",
        f"- Known: {cb.known_cells_instance}",
        f"- Explored: {cb.explored_cells_instance}",
        f"- Partial: {cb.partial_cells_instance}",
        f"- Unexplored: {cb.unexplored_cells_instance}",
        f"- Unqueryable: {cb.unqueryable_cells_instance}",
        f"- Unreachable: {cb.unreachable_cells_instance}",
    ])

    scope_denom = cb.scope_coverage_denominator
    total_explored = cb.explored_cells_wildcard + cb.explored_cells_instance
    if scope_denom > 0:
        ratio_pct = (total_explored / scope_denom) * 100.0
        lines.append(f"\n**Active Scope Coverage Ratio:** {total_explored} / {scope_denom} active cells ({ratio_pct:.1f}%)")
    else:
        lines.append("\n**Active Scope Coverage Ratio:** 0 / 0 active cells (0.0%)")

    # Requirement Coverage
    lines.extend([
        "",
        "### Requirement Coverage (Behavioral TTPs)",
    ])
    if req_cov and req_cov.attempted_requirements:
        attempted_cnt = len(req_cov.attempted_requirements)
        satisfied_cnt = len(req_cov.satisfied_requirements)
        partial_cnt = len(req_cov.partial_requirements)
        unsupported_cnt = len(req_cov.unsupported_requirements)
        sat_pct = (satisfied_cnt / attempted_cnt * 100.0) if attempted_cnt > 0 else 0.0

        lines.extend([
            f"- **Attempted Requirements ({attempted_cnt}):** {list(req_cov.attempted_requirements)}",
            f"- **Satisfied Requirements ({satisfied_cnt}):** {list(req_cov.satisfied_requirements)}",
            f"- **Partial Requirements ({partial_cnt}):** {list(req_cov.partial_requirements)}",
            f"- **Unsupported Requirements ({unsupported_cnt}):** {list(req_cov.unsupported_requirements)}",
            f"- **Requirement Satisfaction Ratio:** {satisfied_cnt} / {attempted_cnt} attempted requirements ({sat_pct:.1f}%)",
        ])
    else:
        lines.extend([
            "- **Attempted Requirements (0):** []",
            "- **Satisfied Requirements (0):** []",
            "- **Partial Requirements (0):** []",
            "- **Unsupported Requirements (0):** []",
            "- **Requirement Satisfaction Ratio:** 0 / 0 attempted requirements (0.0%)",
        ])

    # Unmapped and Unknown Sources
    lines.extend([
        "",
        f"- **Unmapped Observations:** {cb.unmapped_observations}",
        f"- **Unknown Sources (excluded from coverage denominator):** {list(cb.unknown_sources) if cb.unknown_sources else '[]'}",
    ])

    # 2. Hypotheses Evaluation
    lines.extend([
        "",
        "---",
        "## 2. Hypotheses Evaluation",
        "",
        "| Hypothesis ID | Statement | Origin | Status | Requirements | Source Refs |",
        "|---|---|---|---|---|---|",
    ])
    for h in account.hypotheses:
        origin_str = h.origin.value if hasattr(h.origin, "value") else str(h.origin)
        status_str = h.status.value if hasattr(h.status, "value") else str(h.status)
        reqs_str = ", ".join(h.requirements) if h.requirements else "None"
        refs_str = ", ".join(h.source_refs) if h.source_refs else "None"
        stmt_clean = h.statement.replace("|", "\\|")
        lines.append(f"| `{h.id}` | {stmt_clean} | `{origin_str}` | **`{status_str}`** | {reqs_str} | {refs_str} |")

    # Competing Hypotheses Summary
    competing_live = [h.id for h in account.hypotheses if h.status == HypothesisStatus.LIVE]
    competing_supp = [h.id for h in account.hypotheses if h.status == HypothesisStatus.SUPPORTED]
    competing_ref = [h.id for h in account.hypotheses if h.status == HypothesisStatus.REFUTED]
    lines.extend([
        "",
        f"- **Supported Hypotheses:** {competing_supp if competing_supp else '[]'}",
        f"- **Competing Viable (Live) Hypotheses:** {competing_live if competing_live else '[]'}",
        f"- **Refuted Hypotheses:** {competing_ref if competing_ref else '[]'}",
    ])

    # 3. Evidence Cards & Cited Observations
    lines.extend([
        "",
        "---",
        "## 3. Evidence Cards & Cited Observations",
        "",
    ])
    if account.evidence_cards:
        lines.extend([
            "### Evidence Cards",
            "| Card ID | Fingerprint | Fact Type | Count | Completeness | Entity Summary |",
            "|---|---|---|---|---|---|",
        ])
        for card in account.evidence_cards:
            ent_summary_str = ", ".join(f"{k}={v}" for k, v in card.entity_summary.items()) if card.entity_summary else "N/A"
            lines.append(f"| `{card.id}` | `{card.fingerprint[:16]}...` | `{card.fact_type}` | {card.count} | `{card.completeness}` | {ent_summary_str} |")
    else:
        lines.append("*No evidence cards generated.*")

    lines.extend([
        "",
        "### Cited Observations (Audit Trail)",
    ])
    if account.observation_citations:
        for obs_id in sorted(account.observation_citations):
            lines.append(f"- `{obs_id}`")
    else:
        lines.append("- None")

    # 4. Query Audit Trail & Diagnostics
    lines.extend([
        "",
        "---",
        "## 4. Query Audit Trail & Diagnostics",
        "",
    ])
    if account.queries:
        lines.extend([
            "| Query ID | Req ID | Provider | Scope | Operation | Completeness | Targeted? |",
            "|---|---|---|---|---|---|---|",
        ])
        for q in account.queries:
            qid = q.get("query_id", "N/A")
            rid = q.get("requirement_id", "N/A")
            pid = q.get("provider_id", "N/A")
            sid = q.get("scope_id", "N/A")
            opid = q.get("operation_id", "N/A")
            cc = q.get("completeness_contract", "N/A")
            targeted = "YES" if q.get("is_targeted") else "NO (Broad)"
            lines.append(f"| `{qid}` | `{rid}` | `{pid}` | `{sid}` | `{opid}` | `{cc}` | `{targeted}` |")
    else:
        lines.append("*No queries executed.*")

    lines.extend([
        "",
        "### Diagnostics & Warnings",
    ])
    if account.diagnostics:
        for d in account.diagnostics:
            name = d.get("name", "Unknown")
            diag_class = d.get("diagnostic_class", "Info")
            details = d.get("details", "")
            lines.append(f"- **{name}** (`{diag_class}`): {details}")
    else:
        lines.append("- Clean: No query diagnostics or execution warnings recorded.")

    # 5. Visibility and Gap Breakdown (Not found, Not observable, Unqueryable, Unknown source)
    lines.extend([
        "",
        "---",
        "## 5. Visibility & Gap Breakdown",
        "",
    ])
    gaps = account.gap_breakdown

    not_found = gaps.get("not_found", [])
    not_observable = gaps.get("not_observable", [])
    unqueryable = gaps.get("unqueryable", [])
    unknown_source = gaps.get("unknown_source", [])

    lines.extend([
        "### 1. Not Found (Queried with Complete Coverage, Zero Findings)",
    ])
    if not_found:
        for item in not_found:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### 2. Not Observable (Telemetry Lacks Required Behavioral Fields)",
    ])
    if not_observable:
        for item in not_observable:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### 3. Unqueryable (Adapter Unsupported, Permission Denied, or Syntax Error)",
    ])
    if unqueryable:
        for item in unqueryable:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### 4. Unknown Source (Unmapped / Unregistered Telemetry, Excluded from Denominator)",
    ])
    if unknown_source:
        for item in unknown_source:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    # 6. Residual Uncertainty
    lines.extend([
        "",
        "---",
        "## 6. Residual Uncertainty & Investigation Boundaries",
        "",
    ])
    if account.residuals:
        for r in account.residuals:
            lines.append(f"> - {r}")
    else:
        lines.append("> - No residual uncertainty documented.")

    return "\n".join(lines)


__all__ = ["render_final_hunt_account"]
