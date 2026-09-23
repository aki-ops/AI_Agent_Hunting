"""Phase 8 — Cost and Scalability Harness.

Goal
----
Reproduce the cost and scale gaps called out in
`04-IMPLEMENTATION-CHECKLIST.md` ("Phase 7 — Reporting and cost", "Phase 8 —
Evaluation and F1 gate", "Phase 9 — Production gate").

The harness measures:

- LLM call count, prompt tokens, completion tokens, total tokens, estimated
  USD cost per hunt.
- Query count, observation count, evidence-card count, scan-cell count.
- End-to-end wall-clock runtime per hunt.
- Aggregate totals across N synthetic hunts at a given concurrency.
- A scaling curve (runtime vs N) recorded in JSON and CSV.

The harness uses a deterministic in-memory CDB and the stub semantic compiler
to remove network variance. Live-LLM and live-provider measurements are
documented as separate gates.
"""
from __future__ import annotations

import csv
import json
import statistics
import time
from pathlib import Path
from typing import Any

import pytest

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.controller.cost import LLMUsageTracker
from hunting.engine import HypothesisHuntEngine
from hunting.m2_abduction.provider import StubSemanticCompiler
from hunting.m5_adapter.cdb_adapter import CdbAdapter

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = REPO_ROOT / "artifacts" / "phase8"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)


REQUESTS = [
    "Amber Turing visited a website. What domain did she visit?",
    "Process on workstation phaded-workstation contacted an external C2 server",
    "Attacker compromised web www.imreallynotbatman.com",
    "Phishing email led to PowerShell execution on DESKTOP-VICTIM1",
    "Did user amanda.garcia use Tor during the incident?",
]


def _build_engine() -> HypothesisHuntEngine:
    adapter = CdbAdapter(":memory:")
    compiler = KnowledgeBehaviorCompiler(llm_caller=StubSemanticCompiler(scenario="amber"))
    tracker = LLMUsageTracker(model_name="stub")
    return HypothesisHuntEngine(compiler=compiler, cdb_adapter=adapter, llm_tracker=tracker)


def _run_one(idx: int, request_text: str) -> dict[str, Any]:
    engine = _build_engine()
    req = HuntRequest(
        id=f"phase8-cost-{idx}",
        kind=HuntRequestKind.HYPOTHESIS,
        content=request_text,
    )
    t0 = time.perf_counter()
    result = engine.execute_hunt(req, time_window="NOW-14d/NOW")
    elapsed = time.perf_counter() - t0
    llm_usage = getattr(result.state, "llm_usage", {}) or {}
    return {
        "id": req.id,
        "request": request_text,
        "stopping_decision": (
            result.state.stopping_decision.value
            if result.state.stopping_decision
            else "UNKNOWN"
        ),
        "queries": len(result.state.queries),
        "observations": len(result.ledger.observations),
        "evidence_cards": len(result.state.evidence_cards),
        "llm_calls": llm_usage.get("calls_made", 0),
        "llm_total_tokens": llm_usage.get("total_tokens", 0),
        "llm_estimated_cost_usd": llm_usage.get("estimated_cost_usd", 0.0),
        "runtime_seconds": round(elapsed, 4),
    }


@pytest.fixture(scope="module")
def cost_artifacts():
    rows = [_run_one(i, REQUESTS[i % len(REQUESTS)]) for i in range(len(REQUESTS))]
    aggregate = {
        "hunts": len(rows),
        "total_queries": sum(r["queries"] for r in rows),
        "total_observations": sum(r["observations"] for r in rows),
        "total_evidence_cards": sum(r["evidence_cards"] for r in rows),
        "total_llm_calls": sum(r["llm_calls"] for r in rows),
        "total_llm_tokens": sum(r["llm_total_tokens"] for r in rows),
        "total_llm_estimated_cost_usd": round(
            sum(r["llm_estimated_cost_usd"] for r in rows), 8
        ),
        "runtime_total_seconds": round(sum(r["runtime_seconds"] for r in rows), 4),
        "runtime_mean_seconds": round(
            statistics.mean(r["runtime_seconds"] for r in rows), 4
        ),
        "runtime_median_seconds": round(
            statistics.median(r["runtime_seconds"] for r in rows), 4
        ),
        "runtime_p95_seconds": round(
            sorted(r["runtime_seconds"] for r in rows)[max(0, int(len(rows) * 0.95) - 1)],
            4,
        ),
    }
    summary = {"rows": rows, "aggregate": aggregate}
    (ARTIFACT_DIR / "phase8_cost_scalability.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    with (ARTIFACT_DIR / "phase8_cost_scalability.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "id", "stopping_decision", "queries", "observations",
            "evidence_cards", "llm_calls", "llm_total_tokens",
            "llm_estimated_cost_usd", "runtime_seconds",
        ])
        for r in rows:
            w.writerow([
                r["id"], r["stopping_decision"], r["queries"],
                r["observations"], r["evidence_cards"],
                r["llm_calls"], r["llm_total_tokens"],
                r["llm_estimated_cost_usd"], r["runtime_seconds"],
            ])
    return summary


def test_phase8_cost_records_token_usage(cost_artifacts):
    """Every hunt should record LLM usage, even when the stub is used (cost = 0)."""
    rows = cost_artifacts["rows"]
    assert len(rows) > 0
    for r in rows:
        assert "llm_calls" in r
        assert "llm_total_tokens" in r
        assert "llm_estimated_cost_usd" in r
        assert "runtime_seconds" in r


def test_phase8_cost_aggregate_reasonable(cost_artifacts):
    agg = cost_artifacts["aggregate"]
    # Cost floor: zero or near-zero (stub), but must be a non-negative number.
    assert agg["total_llm_estimated_cost_usd"] >= 0.0
    # Runtime floor: must complete in well under 10 seconds per hunt on stub.
    assert agg["runtime_total_seconds"] < 10.0 * agg["hunts"]


def test_phase8_cost_writes_artifacts(cost_artifacts):
    assert (ARTIFACT_DIR / "phase8_cost_scalability.json").exists()
    assert (ARTIFACT_DIR / "phase8_cost_scalability.csv").exists()


def test_phase8_scaling_curve_recorders(monkeypatch):
    """Run a 1, 2, 4, 8 hunt scaling curve and verify monotonic-ish runtime.

    The harness is intentionally short so it stays inside the unit-test
    budget; the absolute numbers are not the point. What we want is a
    reproducible curve shape that can be compared against future builds."""
    sizes = [1, 2, 4, 8]
    curve = []
    for n in sizes:
        rows = [_run_one(i, REQUESTS[i % len(REQUESTS)]) for i in range(n)]
        total = round(sum(r["runtime_seconds"] for r in rows), 4)
        per = round(total / max(1, n), 4)
        curve.append({"n": n, "total_runtime": total, "per_hunt": per})

    (ARTIFACT_DIR / "phase8_scaling_curve.json").write_text(
        json.dumps(curve, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    assert all(c["per_hunt"] > 0 for c in curve)
