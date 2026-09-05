import json
import sys
from dataclasses import asdict
from pathlib import Path

# Add src to sys.path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "src"))

import urllib3  # noqa: E402

from hunting.contracts.hunt import HuntRequest, HuntRequestKind  # noqa: E402
from hunting.engine import HypothesisHuntEngine  # noqa: E402
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter  # noqa: E402

urllib3.disable_warnings()


def json_serial(obj):
    if hasattr(obj, "value"):
        return obj.value
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def main():
    out_dir = repo_root / "artifacts" / "botsv1_web_compromise"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Exporting artifacts to {out_dir}...")

    adapter = SplunkLiveAdapter(
        splunk_url="https://localhost:8089",
        auth=("admin", "12345678"),
        index="botsv1",
        manifest_path=str(repo_root / "configs" / "splunk_botsv1.yaml"),
        verify_ssl=False,
    )

    req = HuntRequest(
        id="hunt-botsv1-web-01",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker compromised web www.imreallynotbatman.com",
        entities=[],
    )

    engine = HypothesisHuntEngine()
    result = engine.execute_hunt(
        request=req,
        adapter=adapter,
        time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
    )

    # 1. request.json
    req_data = {
        "id": req.id,
        "kind": req.kind.value,
        "content": req.content,
        "entities": [json_serial(e) for e in req.entities],
        "time_policy": asdict(req.time_policy) if req.time_policy else None,
        "provider_hints": req.provider_hints,
    }
    with open(out_dir / "request.json", "w", encoding="utf-8") as f:
        json.dump(req_data, f, indent=2, default=json_serial)
    print("1. Wrote request.json")

    # 2. compiler_output.json
    comp_data = {
        "hypotheses": [asdict(h) for h in result.state.hypotheses],
        "requirements": [asdict(r) for r in result.state.requirements],
    }
    with open(out_dir / "compiler_output.json", "w", encoding="utf-8") as f:
        json.dump(comp_data, f, indent=2, default=json_serial)
    print("2. Wrote compiler_output.json")

    # 3. capability_catalog.json
    cat_data = asdict(result.state.capability_catalog) if result.state.capability_catalog else {}
    with open(out_dir / "capability_catalog.json", "w", encoding="utf-8") as f:
        json.dump(cat_data, f, indent=2, default=json_serial)
    print("3. Wrote capability_catalog.json")

    # 4. logical_query_plans.json
    lqp_data = [asdict(p) for p in result.state.logical_query_plans]
    with open(out_dir / "logical_query_plans.json", "w", encoding="utf-8") as f:
        json.dump(lqp_data, f, indent=2, default=json_serial)
    print("4. Wrote logical_query_plans.json")

    # 5. native_spl_queries.json
    nsp_data = [asdict(p) for p in result.state.native_query_plans]
    with open(out_dir / "native_spl_queries.json", "w", encoding="utf-8") as f:
        json.dump(nsp_data, f, indent=2, default=json_serial)
    print("5. Wrote native_spl_queries.json")

    # 6. query_results_metadata.json
    qrm_data = [
        {
            "query_id": qr.query_id,
            "logical_plan_id": qr.logical_plan_id,
            "provider": qr.provider,
            "index": qr.index,
            "sourcetype": qr.sourcetype,
            "native_query": qr.native_query,
            "executed_ok": qr.executed_ok,
            "outcome": qr.outcome.value if qr.outcome else None,
            "row_count": len(qr.rows) if qr.rows else qr.row_count,
            "execution_time_ms": qr.execution_time_ms,
            "observed_fields": qr.observed_fields,
            "columns": list(qr.rows[0].keys()) if qr.rows else [],
            "sample_rows": qr.rows[:3] if qr.rows else [],
        }
        for qr in result.state.query_results
    ]
    with open(out_dir / "query_results_metadata.json", "w", encoding="utf-8") as f:
        json.dump(qrm_data, f, indent=2, default=json_serial)
    print("6. Wrote query_results_metadata.json")

    # 7. evidence_cards.json
    ec_data = [asdict(c) for c in result.state.evidence_cards]
    with open(out_dir / "evidence_cards.json", "w", encoding="utf-8") as f:
        json.dump(ec_data, f, indent=2, default=json_serial)
    print("7. Wrote evidence_cards.json")

    # 8. hypothesis_assessment.json
    ha_data = {
        "stopping_decision": result.state.stopping_decision.value,
        "hunt_outcome": result.account.outcome.value,
        "hypotheses": [
            {
                "id": h.id,
                "statement": h.statement,
                "origin": h.origin.value if hasattr(h.origin, "value") else str(h.origin),
                "status": h.status.value,
                "source_refs": h.source_refs,
                "requirements": h.requirements,
            }
            for h in result.state.hypotheses
        ],
        "evidence_assessments": [asdict(a) for a in result.state.evidence_assessments],
        "expectations": [
            {
                "id": e.id,
                "owner_explanation_id": e.owner_explanation_id,
                "evidence_requirement": e.evidence_requirement.value,
                "test_status": e.test_status.value,
                "predicted_observation": e.predicted_observation,
                "falsification_condition": e.falsification_condition,
            }
            for e in result.state.expectations
        ],
    }
    with open(out_dir / "hypothesis_assessment.json", "w", encoding="utf-8") as f:
        json.dump(ha_data, f, indent=2, default=json_serial)
    print("8. Wrote hypothesis_assessment.json")

    # 9. llm_usage.json
    with open(out_dir / "llm_usage.json", "w", encoding="utf-8") as f:
        json.dump(result.state.llm_usage, f, indent=2, default=json_serial)
    print("9. Wrote llm_usage.json")

    # 10. final_report.md
    with open(out_dir / "final_report.md", "w", encoding="utf-8") as f:
        f.write(result.report)
    print("10. Wrote final_report.md")

    print("\nAll 10 artifacts exported successfully!")


if __name__ == "__main__":
    main()
