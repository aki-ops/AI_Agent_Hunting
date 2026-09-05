import socket

import pytest
import urllib3

from hunting.contracts.entities import Host
from hunting.contracts.hunt import HuntRequest, HuntRequestKind, StoppingDecision
from hunting.engine import HypothesisHuntEngine
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter


def is_splunk_available(host: str = "localhost", port: int = 8089, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not is_splunk_available(), reason="Splunk not available at localhost:8089")
def test_botsv1_web_compromise_live_replay():
    urllib3.disable_warnings()

    adapter = SplunkLiveAdapter(
        splunk_url="https://localhost:8089",
        auth=("admin", "12345678"),
        index="botsv1",
        manifest_path="configs/splunk_botsv1.yaml",
        verify_ssl=False,
    )

    req = HuntRequest(
        id="hunt-botsv1-web-01",
        kind=HuntRequestKind.HYPOTHESIS,
        content="Attacker compromised web www.imreallynotbatman.com",
        entities=[Host(name="we1149srv")],
    )

    from hunting.compiler.compiler import KnowledgeBehaviorCompiler
    from hunting.m2_abduction.provider import StubSemanticCompiler
    engine = HypothesisHuntEngine(compiler=KnowledgeBehaviorCompiler(llm_caller=StubSemanticCompiler(scenario="web")))
    result = engine.execute_hunt(
        request=req,
        adapter=adapter,
        time_window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
    )

    # 1. Capability Catalog Online
    assert result.state.capability_catalog is not None
    assert result.state.capability_catalog.status == "ONLINE"
    assert "web_request" in result.state.capability_catalog.supported_evidence_types

    # 2. Query Plans (Logical and Native)
    assert len(result.state.logical_query_plans) >= 3
    assert len(result.state.native_query_plans) >= 3
    assert len(result.state.query_results) >= 3

    for qr in result.state.query_results:
        assert qr.logical_plan_id is not None
        assert qr.native_query is not None
        assert len(qr.native_query) > 0

    # 3. Evidence Cards & Assessments
    assert len(result.state.evidence_cards) >= 1
    assert len(result.state.evidence_assessments) >= 1

    # 4. LLM Tracker bounded
    assert result.state.llm_usage is not None
    assert result.state.llm_usage.get("total_calls", 0) <= 3

    # 5. Strict Epistemic Stopping Guard
    assert result.state.stopping_decision in (
        StoppingDecision.STOP_RESOLVED,
        StoppingDecision.STOP_BOUNDED,
        StoppingDecision.STOP_EXHAUSTED_BY_BUDGET,
    )
    assert result.account is not None
    assert result.report is not None
    assert len(result.report) > 0

    # 6. Domain Extraction and SPL Query Filtering
    web_queries = [qr.native_query for qr in result.state.query_results if qr.native_query and "stream:http" in qr.native_query]
    assert len(web_queries) >= 1
    assert any("imreallynotbatman.com" in wq for wq in web_queries)

    # 7. Timeline reflects dynamic requirements and cost in llm_usage
    assert "web_request" in result.report
    assert "estimated_cost_usd" in result.state.llm_usage
