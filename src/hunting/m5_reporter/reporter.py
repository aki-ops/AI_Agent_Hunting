"""M5 Reporter — Pure rendering of the Final Account and Investigation State.

Enforces:
  - Disposition is computed purely by M4; M5 only renders and cannot mutate or recompute it.
  - Cites observation IDs, query IDs, diagnostics, coverage bound, and confirmation status.
"""
from __future__ import annotations

from hunting.contracts.state import FinalAccount, InvestigationState
from hunting.m1_ledger.ledger import ObservationLedger


def render_investigation_report(
    account: FinalAccount,
    state: InvestigationState,
    ledger: ObservationLedger,
) -> str:
    """Render structured human-readable markdown report.

    Pure function: Never mutates state or disposition.
    """
    cb = account.coverage_bound
    lines: list[str] = [
        "# Threat Investigation Final Report",
        "",
        f"**Disposition:** `{account.disposition.value}`",
        f"**Terminal State:** `{account.terminal_state.value}`",
        f"**Human Confirmed:** `{'YES' if account.human_confirmed else 'NO'}`",
        "",
        "## 1. Coverage Accounting",
        "",
        "### Scope Coverage (Wildcard Cells)",
        f"- Known: {cb.known_cells_wildcard}",
        f"- Explored: {cb.explored_cells_wildcard}",
        f"- Partial (truncated/split): {cb.partial_cells_wildcard}",
        f"- Unexplored: {cb.unexplored_cells_wildcard}",
        f"- Unqueryable (no adapter): {cb.unqueryable_cells_wildcard}",
        f"- Unreachable (expired/gap): {cb.unreachable_cells_wildcard}",
        "",
        "### Instance Coverage (Discovered Entities)",
        f"- Known: {cb.known_cells_instance}",
        f"- Explored: {cb.explored_cells_instance}",
        f"- Partial: {cb.partial_cells_instance}",
        f"- Unexplored: {cb.unexplored_cells_instance}",
        f"- Unreachable: {cb.unreachable_cells_instance}",
        "",
        "### Requirement Coverage",
    ]

    if cb.requirement_coverage:
        lines.append(f"- Attempted: {list(cb.requirement_coverage.attempted_requirements)}")
        lines.append(f"- Satisfied: {list(cb.requirement_coverage.satisfied_requirements)}")
    else:
        lines.append("- Attempted: []")
        lines.append("- Satisfied: []")

    lines.extend([
        f"- Unmapped Observations: {cb.unmapped_observations}",
        f"- Unknown Sources: {list(cb.unknown_sources)}",
        "",
        "## 2. Cited Observations",
    ])

    cited_ids: set[str] = set()
    for expl in state.explanations:
        for attr in expl.attributions:
            cited_ids.add(attr.observation_id)

    if cited_ids:
        for oid in sorted(cited_ids):
            lines.append(f"- `{oid}`")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## 3. Query Diagnostics & Audit Trail",
    ])

    if ledger.diagnostics:
        for diag in ledger.diagnostics:
            lines.append(f"- `{diag.name}` ({diag.diagnostic_class.value})")
    else:
        lines.append("- Clean: No query diagnostics recorded")

    if account.residual:
        lines.extend([
            "",
            "## 4. Residual Uncertainty",
            f"> {account.residual}",
        ])

    return "\n".join(lines)


__all__ = ["render_investigation_report"]
