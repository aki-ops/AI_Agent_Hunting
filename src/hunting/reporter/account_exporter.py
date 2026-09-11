"""Machine run account exporter, cost accounting, and 6-part human report generation."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hunting.contracts.hunt import FinalHuntAccount, StoppingTaxonomyState
from hunting.contracts.step_trace import StepTrace


@dataclass
class RunCostAccounting:
    """Financial cost accounting model enforcing C_run = C_llm + C_splunk + C_control + C_analyst."""
    llm_cost_usd: float = 0.0
    splunk_cost_usd: float = 0.0
    control_cost_usd: float = 0.0
    analyst_cost_usd: float = 0.0
    waste_cost_usd: float = 0.0

    @property
    def total_cost_usd(self) -> float:
        return round(self.llm_cost_usd + self.splunk_cost_usd + self.control_cost_usd + self.analyst_cost_usd, 6)

    @property
    def waste_ratio(self) -> float:
        return round(self.waste_cost_usd / self.total_cost_usd, 4) if self.total_cost_usd > 0 else 0.0

    @classmethod
    def from_account(
        cls,
        account: FinalHuntAccount,
        analyst_time_seconds: float = 0.0,
        analyst_rate_per_second: float = 60.0 / 3600.0,
    ) -> RunCostAccounting:
        # LLM cost from account.llm_usage
        llm_cost = float(account.llm_usage.get("estimated_cost_usd", 0.0))

        # Splunk cost: query base overhead + scanned events
        splunk_queries = len(account.queries)
        scanned_events = sum(int(q.get("scan_count") or q.get("scanned_events") or 0) for q in account.queries)
        splunk_cost = round(splunk_queries * 0.001 + scanned_events * 0.000001, 6)

        # Control plane cost: probe execution and capability compilation
        control_items = len(account.runtime_capabilities) + len(account.diagnostics)
        control_cost = round(control_items * 0.0005, 6)

        # Analyst cost: human clarification / review
        analyst_cost = round(analyst_time_seconds * analyst_rate_per_second, 6)

        # Waste cost: queries with 0 results or rejected candidates
        waste_queries = sum(1 for q in account.queries if q.get("executed_ok") is False or q.get("row_count") == 0)
        waste_cost = round(waste_queries * 0.001, 6)

        return cls(
            llm_cost_usd=llm_cost,
            splunk_cost_usd=splunk_cost,
            control_cost_usd=control_cost,
            analyst_cost_usd=analyst_cost,
            waste_cost_usd=waste_cost,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formula": "C_run = C_llm + C_splunk + C_control + C_analyst",
            "llm_cost_usd": self.llm_cost_usd,
            "splunk_cost_usd": self.splunk_cost_usd,
            "control_cost_usd": self.control_cost_usd,
            "analyst_cost_usd": self.analyst_cost_usd,
            "total_cost_usd": self.total_cost_usd,
            "waste_cost_usd": self.waste_cost_usd,
            "waste_ratio": self.waste_ratio,
        }


def emit_machine_run_account(
    account: FinalHuntAccount,
    cost: RunCostAccounting | None = None,
    step_trace: StepTrace | None = None,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Emit comprehensive run_account.json capturing complete telemetry, LLM metrics, and ledger."""
    cost_accounting = cost or RunCostAccounting.from_account(account)
    trace_dict = step_trace.to_dict() if step_trace is not None else {"request_id": account.request_id, "steps": []}

    run_dict: dict[str, Any] = {
        "schema_version": "v8",
        "request_id": account.request_id,
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stopping_taxonomy_state": account.taxonomy_state.value,
        "stopping_decision": account.stopping_decision.value if hasattr(account.stopping_decision, "value") else str(account.stopping_decision),
        "outcome": account.outcome.value if hasattr(account.outcome, "value") else str(account.outcome),
        "answer_contract": account.answer,
        "llm_raw_proposal": account.llm_raw_proposal,
        "validated_graph": account.validated_graph,
        "validation_diagnostics": account.validation_diagnostics,
        "evidence_ledger": {
            "citations": list(account.observation_citations),
            "evidence_cards": [c.id for c in account.evidence_cards],
            "supporting_hypotheses": list(account.supporting),
            "contradicting_hypotheses": list(account.contradicting),
        },
        "executed_queries": account.queries,
        "coverage_manifest": {
            "bound": str(account.coverage_bound),
            "gap_breakdown": account.gap_breakdown,
            "limitations": list(account.limitations),
        },
        "llm_metrics": account.llm_usage,
        "cost_accounting": cost_accounting.to_dict(),
        "step_trace": trace_dict,
    }

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(run_dict, indent=2, ensure_ascii=False), encoding="utf-8")

    return run_dict


def emit_aborted_run_account(
    request_id: str,
    reason: str,
    stopping_state: StoppingTaxonomyState = StoppingTaxonomyState.ABORTED_BY_USER,
    cost: RunCostAccounting | None = None,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Emit failure artifact specifically tied to the active request ID for aborted runs."""
    cost_dict = cost.to_dict() if cost else RunCostAccounting().to_dict()
    aborted_dict = {
        "schema_version": "v8",
        "request_id": request_id,
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "ABORTED",
        "stopping_taxonomy_state": stopping_state.value,
        "reason": reason,
        "cost_accounting": cost_dict,
    }
    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(aborted_dict, indent=2, ensure_ascii=False), encoding="utf-8")
    return aborted_dict


def render_six_part_report(
    account: FinalHuntAccount,
    cost: RunCostAccounting | None = None,
    step_trace: StepTrace | None = None,
) -> str:
    """Render canonical 6-part human markdown report matching 01 / 08."""
    cost_acc = cost or RunCostAccounting.from_account(account)
    obj = account.objective
    statement = getattr(obj, "statement", "") or account.request_id

    lines = [
        f"# Threat Hunt Investigation Report: `{account.request_id}`",
        "",
        "## 1. Executive Verdict & Answer Contract",
        f"- **Terminal Stopping State:** `{account.taxonomy_state.value}`",
        f"- **Investigation Outcome:** `{account.outcome.value}`",
        f"- **User Request / Objective:** {statement}",
        f"- **Answer Value:** `{account.answer.get('value', 'NOT_FOUND')}`",
        f"- **Answer Status:** `{account.answer.get('status', 'INCONCLUSIVE')}`",
        f"- **Explanation:** {account.answer.get('explanation', 'No detailed explanation provided.')}",
        "",
        "## 2. Investigation Plan & Obligation Graph",
        f"- **Goal Graph Status:** `{'VALIDATED' if account.validated_graph else 'INFERRED'}`",
        f"- **Atomic Obligations:** {len(getattr(account.semantic_goal_graph, 'goals', [])) if hasattr(account.semantic_goal_graph, 'goals') else 0} nodes",
        f"- **Runtime Capabilities Materialized:** {len(account.runtime_capabilities)}",
        f"- **Hypotheses Evaluated:** {len(account.hypotheses)}",
        "",
        "## 3. Evidence Ledger & Proof Chain",
        f"- **Observation Citations:** {len(account.observation_citations)}",
        f"- **Evidence Cards Summary:** {len(account.evidence_cards)} cards",
        f"- **Provenance Chain Length:** {len(account.provenance_chain)}",
        "",
        "## 4. Executed Queries & Execution Telemetry",
        f"- **Total Queries Dispatched:** {len(account.queries)}",
    ]
    for i, q in enumerate(account.queries, 1):
        lines.append(f"  {i}. `[{q.get('query_id', 'q')}]` {q.get('native_query', 'N/A')[:80]}... (rows: {q.get('row_count', 0)}, scan: {q.get('scan_count', 0)})")

    lines.extend([
        "",
        "## 5. Coverage & Uncertainty Manifest",
        f"- **Coverage Bound:** {account.coverage_bound}",
        f"- **Active Limitations:** {', '.join(account.limitations) if account.limitations else 'None declared'}",
        f"- **Validation Diagnostics:** {', '.join(account.validation_diagnostics) if account.validation_diagnostics else 'None'}",
        "",
        "## 6. Resource & Financial Cost Accounting",
        f"- **Formula:** `${cost_acc.to_dict()['formula']}$",
        f"- **LLM Cost ($C_{{llm}}$):** ${cost_acc.llm_cost_usd:.6f}",
        f"- **Splunk Cost ($C_{{splunk}}$):** ${cost_acc.splunk_cost_usd:.6f}",
        f"- **Control Plane Cost ($C_{{control}}$):** ${cost_acc.control_cost_usd:.6f}",
        f"- **Analyst Cost ($C_{{analyst}}$):** ${cost_acc.analyst_cost_usd:.6f}",
        f"- **Total Run Cost ($C_{{run}}$):** ${cost_acc.total_cost_usd:.6f}",
        f"- **Waste Ratio:** {cost_acc.waste_ratio:.2%}",
    ])

    return "\n".join(lines) + "\n"


__all__ = [
    "RunCostAccounting",
    "emit_machine_run_account",
    "emit_aborted_run_account",
    "render_six_part_report",
]
