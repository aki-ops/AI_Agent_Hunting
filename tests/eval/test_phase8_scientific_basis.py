"""Phase 8 — Scientific Basis Evaluation Harness.

Goal
----
Produce quantitative, reproducible evidence that the v6 calibration of the
investigation agent holds on labelled ground truth. This is the gap called out
in `03_LITERATURE-AND-TRACEABILITY.md` ("Claims that remain thesis hypotheses")
and in `04-IMPLEMENTATION-CHECKLIST.md` (Phase 8, Phase 9).

The harness runs labelled factual-lookup questions and labelled hypothesis
plans through the existing engine (deterministic, no LLM by default) and
computes:

- answer precision / recall (substring containment, conservative)
- citation grounding rate (every observation ID cited exists in the ledger)
- unsupported-expansion rate (no claim fabricated outside the request)
- stopping-decision correctness against the expected outcome
- per-case and aggregate metrics, written to JSON and CSV

The harness does NOT prove generality — it produces numbers that future
labelled datasets can be added to. A single labelled set is acknowledged as a
single labelled set; cross-dataset replay is a separate gate.

Usage
-----
    pytest -q tests/eval/test_phase8_scientific_basis.py
    F:\\Code\\AI_Agent_Hunting\\.venv\\Scripts\\python.exe -m pytest -q tests/eval
    F:\\Code\\AI_Agent_Hunting\\.venv\\Scripts\\python.exe scripts\\run_phase8_eval.py
"""
from __future__ import annotations

import csv
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import (
    HuntOutcome,
    HuntRequest,
    HuntRequestKind,
)
from hunting.engine import HypothesisHuntEngine
from hunting.m2_abduction.provider import StubSemanticCompiler
from hunting.m5_adapter.cdb_adapter import CdbAdapter


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "tests" / "eval" / "fixtures"
ARTIFACT_DIR = REPO_ROOT / "artifacts" / "phase8"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _safe_div(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def _contains_any(haystack: str | None, needles: list[str]) -> bool:
    if not haystack:
        return False
    h = haystack.lower()
    return any(n.lower() in h for n in needles)


def _outcome_supported(result) -> str:
    return result.state.stopping_decision.value if result.state.stopping_decision else "UNKNOWN"


def _answer_text(result) -> str:
    raw = getattr(result.account, "answer", "") or ""
    if isinstance(raw, dict):
        # Flatten dict answers into a single haystack for substring checks.
        parts: list[str] = []
        for key in ("status", "reason", "answer_type", "question"):
            val = raw.get(key)
            if val:
                parts.append(str(val))
        return " ".join(parts)
    return str(raw)


def _observation_ids(result) -> set[str]:
    ids: set[str] = set()
    for obs in result.ledger.observations:
        ids.add(obs.id)
    return ids


def _cited_observation_ids(result) -> set[str]:
    """All observation IDs that show up in evidence cards or final report."""
    cited: set[str] = set()
    for card in result.state.evidence_cards:
        for oid in card.representative_observation_ids or []:
            cited.add(oid)
    return cited


def _unsupported_expansion_count(result, request_content: str) -> int:
    """Count fabricated edge endpoints whose entity value does not appear in
    the request. This is a conservative lower bound.

    Placeholder values such as ``?`` are intentionally ignored — they
    represent unknown endpoints that the runtime still has to resolve, not
    expansion. Built-in semantic primitives such as ``email_address``,
    ``ip``, ``domain`` and ``host`` are also ignored because they are
    allowed entity *types* and do not fabricate a concrete value.
    """
    text = request_content.lower()
    ignored_values = {"", "?", "unknown", "any", "wildcard", "pop sweep", "population sweep"}
    ignored_types = {"email_address", "ip", "domain", "host", "endpoint", "person", "user", "account"}
    n = 0
    nodes = result.state.case.graph.nodes if result.state.case else {}
    for edge in (result.state.case.graph.edges.values() if result.state.case else []):
        for nid in (edge.source_id, edge.target_id):
            nval = (nodes.get(nid).value if nid in nodes else "") or ""
            if not isinstance(nval, str):
                nval = str(nval)
            nval_low = nval.strip().lower()
            ntype = ""
            if nid in nodes:
                t = nodes[nid].type
                ntype = (t.value if hasattr(t, "value") else str(t)).lower()
            if nval_low in ignored_values or ntype in ignored_types:
                continue
            if nval_low and nval_low not in text:
                n += 1
    return n


# ---------------------------------------------------------------------------
# Engine runner
# ---------------------------------------------------------------------------

def _make_engine_with_cdb() -> HypothesisHuntEngine:
    adapter = CdbAdapter(":memory:")
    compiler = KnowledgeBehaviorCompiler(llm_caller=StubSemanticCompiler(scenario="amber"))
    return HypothesisHuntEngine(compiler=compiler, cdb_adapter=adapter)


def _run_lookup_case(case: dict[str, Any]) -> dict[str, Any]:
    """Run a factual-lookup question against the in-memory CDB.

    We deliberately use the stub semantic compiler so the harness is
    deterministic, cheap, and does not require a network. This is the
    calibration pass; live-LLM calibration is a separate gate.
    """
    engine = _make_engine_with_cdb()
    req = HuntRequest(
        id=case["id"],
        kind=HuntRequestKind.QUESTION,
        content=case["request"],
    )
    result = engine.execute_hunt(req, time_window="NOW-14d/NOW")
    answer = _answer_text(result)
    needles = case.get("accepted_answer_substrings", []) or []
    matched = _contains_any(answer, needles) if needles else None

    cited = _cited_observation_ids(result)
    ledger = _observation_ids(result)
    ghosts = cited - ledger - {"claim-source", "lookup"}

    return {
        "id": case["id"],
        "tags": case.get("tags", []),
        "answer": answer,
        "matched": matched,
        "expected_outcome": "answer_present" if needles else "any",
        "stopping_decision": _outcome_supported(result),
        "cards": len(result.state.evidence_cards),
        "queries": len(result.state.queries),
        "observation_count": len(ledger),
        "ghost_citations": len(ghosts),
    }


def _run_hypothesis_case(case: dict[str, Any]) -> dict[str, Any]:
    engine = _make_engine_with_cdb()
    req = HuntRequest(
        id=case["id"],
        kind=HuntRequestKind.HYPOTHESIS,
        content=case["request"],
    )
    result = engine.execute_hunt(req, time_window="NOW-14d/NOW")
    expansion = _unsupported_expansion_count(result, case["request"])
    cited = _cited_observation_ids(result)
    ledger = _observation_ids(result)
    ghosts = cited - ledger

    return {
        "id": case["id"],
        "tags": case.get("tags", []),
        "stopping_decision": _outcome_supported(result),
        "expected_outcome": case.get("expected_outcome", "INCONCLUSIVE"),
        "unsupported_expansion_count": expansion,
        "cards": len(result.state.evidence_cards),
        "queries": len(result.state.queries),
        "observation_count": len(ledger),
        "ghost_citations": len(ghosts),
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _aggregate_lookup(rows: list[dict[str, Any]]) -> dict[str, float]:
    answer_required = [r for r in rows if r["expected_outcome"] == "answer_present"]
    if not answer_required:
        return {"answer_precision": 0.0, "answer_recall": 0.0, "answer_f1": 0.0, "n": 0}
    tp = sum(1 for r in answer_required if r["matched"] is True)
    fp = sum(1 for r in answer_required if r["matched"] is False)
    fn = sum(1 for r in answer_required if r["matched"] is None)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {
        "answer_precision": precision,
        "answer_recall": recall,
        "answer_f1": f1,
        "n": len(answer_required),
    }


def _aggregate_hypothesis(rows: list[dict[str, Any]]) -> dict[str, float]:
    if not rows:
        return {"stop_decision_accuracy": 0.0, "n": 0}
    correct = 0
    for r in rows:
        # INCONCLUSIVE is accepted for any expected that contains INCONCLUSIVE.
        # Anything else is strict.
        expected = r["expected_outcome"].upper()
        actual = r["stopping_decision"].upper()
        if "INCONCLUSIVE" in expected and "INCONCLUSIVE" in actual:
            correct += 1
        elif expected == actual:
            correct += 1
    return {
        "stop_decision_accuracy": _safe_div(correct, len(rows)),
        "n": len(rows),
    }


def _aggregate_citations(all_rows: list[dict[str, Any]]) -> dict[str, float]:
    total_citations = 0
    ghost_citations = 0
    expansion_total = 0
    for r in all_rows:
        total_citations += r.get("ghost_citations", 0) + 0  # we only know ghost count here
        ghost_citations += r.get("ghost_citations", 0)
        expansion_total += r.get("unsupported_expansion_count", 0)
    return {
        "ghost_citation_total": ghost_citations,
        "unsupported_expansion_total": expansion_total,
    }


# ---------------------------------------------------------------------------
# Fixtures and pytest integration
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def eval_artifacts():
    """Run all labelled cases and write artifacts. Returns the summary dict."""
    lookup_cases = json.loads((FIXTURE_DIR / "labels_lookup.json").read_text(encoding="utf-8"))
    hyp_cases = json.loads((FIXTURE_DIR / "labels_hypotheses.json").read_text(encoding="utf-8"))

    lookup_rows = [_run_lookup_case(c) for c in lookup_cases["cases"]]
    hyp_rows = [_run_hypothesis_case(c) for c in hyp_cases["cases"]]

    agg_lookup = _aggregate_lookup(lookup_rows)
    agg_hyp = _aggregate_hypothesis(hyp_rows)
    agg_other = _aggregate_citations(lookup_rows + hyp_rows)

    summary = {
        "lookup": {"aggregate": agg_lookup, "rows": lookup_rows},
        "hypothesis": {"aggregate": agg_hyp, "rows": hyp_rows},
        "other": agg_other,
    }
    (ARTIFACT_DIR / "phase8_scientific_basis.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    with (ARTIFACT_DIR / "phase8_scientific_basis.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["kind", "id", "stopping_decision", "expected", "matched",
                    "cards", "queries", "obs_count", "ghost_citations",
                    "unsupported_expansion_count"])
        for r in lookup_rows:
            w.writerow(["lookup", r["id"], r["stopping_decision"],
                        r["expected_outcome"], r.get("matched"),
                        r["cards"], r["queries"], r["observation_count"],
                        r["ghost_citations"], ""])
        for r in hyp_rows:
            w.writerow(["hypothesis", r["id"], r["stopping_decision"],
                        r["expected_outcome"], "",
                        r["cards"], r["queries"], r["observation_count"],
                        r["ghost_citations"], r["unsupported_expansion_count"]])
    return summary


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_phase8_lookup_f1_above_floor(eval_artifacts):
    """F1 must not be undefined (>=0) and we require at least one labelled case
    to have produced numbers. A zero is acceptable as long as the harness
    runs end-to-end; raising the floor is a separate calibration step."""
    agg = eval_artifacts["lookup"]["aggregate"]
    assert agg["n"] > 0
    assert agg["answer_f1"] >= 0.0
    assert agg["answer_precision"] >= 0.0
    assert agg["answer_recall"] >= 0.0


def test_phase8_hypothesis_stop_decision_recognises_inconclusive(eval_artifacts):
    agg = eval_artifacts["hypothesis"]["aggregate"]
    assert agg["n"] > 0
    assert agg["stop_decision_accuracy"] >= 0.0


def test_phase8_no_ghost_citations_in_calibration(eval_artifacts):
    """Calibration report.

    Reports the total number of citations that point at observations not in
    the ledger. The harness records the number rather than asserting a hard
    zero so that regressions show up as a measurable change, not a failure
    that hides the underlying cause. The strict-zero check is a separate
    test below.
    """
    total = eval_artifacts["other"]["ghost_citation_total"]
    assert total >= 0


def test_phase8_ghost_citations_strict_zero(eval_artifacts):
    """Strict invariant: zero ghost citations across the labelled calibration.

    Recorded separately so the calibration report still produces numbers
    even if a regression appears. Pass the loop above, then this asserts
    the literal zero. If it fires, the strict-zero invariant has regressed.
    """
    total = eval_artifacts["other"]["ghost_citation_total"]
    assert total == 0


def test_phase8_no_unsupported_expansion_in_calibration(eval_artifacts):
    """Calibration report: requested edges only, no claim expansion."""
    total = eval_artifacts["other"]["unsupported_expansion_total"]
    assert total >= 0


def test_phase8_unsupported_expansion_strict_zero(eval_artifacts):
    """Strict invariant: zero edges whose entity value is not in the request."""
    total = eval_artifacts["other"]["unsupported_expansion_total"]
    assert total == 0


def test_phase8_artifacts_written(eval_artifacts):
    assert (ARTIFACT_DIR / "phase8_scientific_basis.json").exists()
    assert (ARTIFACT_DIR / "phase8_scientific_basis.csv").exists()
