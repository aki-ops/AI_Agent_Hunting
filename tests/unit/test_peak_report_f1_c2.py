"""Pha 0: report phải phân biệt F1 đã lọc và C2 profiler hỏng."""
from hunting.reporter.renderer import render_analyst_report
from hunting.contracts.hunt import FinalHuntAccount, HuntObjective, StoppingDecision
from hunting.contracts.coverage import CoverageBound


def _account():
    obj = HuntObjective(request_id="req-zip", statement="zip")
    return FinalHuntAccount(
        request_id="req-zip",
        objective=obj,
        hypotheses=[],
        evidence_cards=[],
        queries=[],
        supporting=[],
        contradicting=[],
        unknown=[],
        unreachable=[],
        residuals=[],
        coverage_bound=CoverageBound(),
        stopping_decision=StoppingDecision.STOP_INCONCLUSIVE,
        source_profile_audit={
            "status": "PROVIDER_UNAVAILABLE",
            "proposals": [],
            "rejected": [],
            "coverage_manifests": {
                "goal-1": {
                    "total_sources": 2920,
                    "considered_source_ids": ["s%d" % i for i in range(8)],
                    "examined_source_ids": ["s%d" % i for i in range(8)],
                    "unexamined_source_ids": ["u%d" % i for i in range(92)],
                    "rejected_source_ids": {},
                }
            },
            "retrieval": [
                {
                    "relation": "sent_message",
                    "stage": "F1_METADATA",
                    "hits": [{"a": 1}] * 8,
                    "total_documents": 2920,
                    "unexamined_ids": ["u"] * 92,
                }
            ],
            "relation_calls": [
                {"relation": "sent_message", "status": "PROVIDER_UNAVAILABLE"}
            ],
        },
    )


def test_report_shows_f1_hits_not_batches_zero():
    text = render_analyst_report(_account())
    assert "F1 hits=`8`" in text
    assert "total=`2920`" in text
    assert "batches=`0`" not in text
    assert "status=`PROVIDER_UNAVAILABLE`" in text
    assert "F1 filtering vs C2 proposal are separate" in text
