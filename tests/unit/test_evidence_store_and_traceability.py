"""Unit tests for Phase 1: ObservationStore, raw event persistence, and bi-directional traceability."""
from __future__ import annotations

from pathlib import Path

from hunting.contracts.cells import ProviderScope
from hunting.contracts.hunt import (
    EvidenceCard,
    EvidenceRequirementV4,
    Hypothesis,
    HypothesisStatus,
    NativeQueryPlan,
    QueryPlan,
    QueryResult,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import QueryOutcome
from hunting.m1_ledger.store import ObservationStore


def test_observation_store_records_and_retrieves_raw_event():
    """ObservationStore preserves raw provider record and indexes by observation_id."""
    store = ObservationStore()
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})

    raw_payload = {
        "_time": "2026-09-01T12:00:00Z",
        "_raw": "2026-09-01 12:00:00 POST /joomla/bin/evil.php - 80 - 192.168.1.50 Mozilla/5.0 - 200",
        "custom_waf_tag": "SUSPICIOUS_PAYLOAD",
        "nested_meta": {"cluster": "us-east", "sensor_id": 99},
    }

    obs = Observation(
        id="obs-splunk-001",
        provider_scope=scope,
        cell_id="2026-09-01/P1D",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="iis:access",
        fields={"host": "we1149srv", "uri": "/joomla/bin/evil.php"},
        raw_event=raw_payload,
        query_id="q-web-01",
    )
    store.add_observation(obs)

    retrieved = store.get_observation("obs-splunk-001")
    assert retrieved is not None
    assert retrieved.id == "obs-splunk-001"

    raw_out = store.get_raw_event("obs-splunk-001")
    assert raw_out is not None
    assert raw_out["custom_waf_tag"] == "SUSPICIOUS_PAYLOAD"
    assert raw_out["nested_meta"]["cluster"] == "us-east"

    # Query lookup
    by_query = store.get_by_query("q-web-01")
    assert len(by_query) == 1
    assert by_query[0].id == "obs-splunk-001"


def test_full_bidirectional_traceability():
    """Trace observation_id -> EvidenceCard -> EvidenceRequirement -> Hypothesis -> QueryResult -> native query -> raw event."""
    store = ObservationStore()
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})

    obs = Observation(
        id="obs-trace-1",
        provider_scope=scope,
        cell_id="2026-09-01/P1D",
        timestamp="2026-09-01T12:05:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="WinEventLog:Security",
        fields={"host": "we1149srv", "image": "cmd.exe", "parent_image": "php-cgi.exe"},
        raw_event={"EventCode": 4688, "CommandLine": "cmd.exe /c whoami"},
        query_id="q-proc-101",
    )
    store.add_observation(obs)

    card = EvidenceCard(
        id="card-proc-01",
        fingerprint="fp-cmd",
        summary="php-cgi.exe spawned cmd.exe on we1149srv",
        why_it_matters="High-fidelity web shell indicator",
        hypotheses=["hyp-web-compromise"],
        requirements=["req-server-exec"],
        query_ids=["q-proc-101"],
        representative_observation_ids=["obs-trace-1"],
    )
    store.link_card(card.id, ["obs-trace-1"])

    # Mock state for full resolution
    class MockState:
        evidence_cards = [card]
        hypotheses = [
            Hypothesis(
                id="hyp-web-compromise",
                statement="Adversary compromised web server via webshell",
                status=HypothesisStatus.SUPPORTED,
                requirements=["req-server-exec"],
            )
        ]
        requirements = [
            EvidenceRequirementV4(
                id="req-server-exec",
                description="Server-side process execution under web worker",
                evidence_type="process_execution",
            )
        ]
        queries = [
            QueryPlan(
                id="q-proc-101",
                requirement_id="req-server-exec",
                provider_id="splunk",
                scope_id="botsv1",
                operation_id="cdb_process_lineage",
            )
        ]
        native_query_plans = [
            NativeQueryPlan(
                id="q-proc-101",
                logical_plan_id="q-proc-101",
                provider="splunk",
                native_query='search index=botsv1 sourcetype="*WinEventLog*" "php-cgi.exe" | head 100',
            )
        ]
        query_results = [
            QueryResult(
                query_id="q-proc-101",
                outcome=QueryOutcome.ROWS,
                logical_plan_id="q-proc-101",
                executed_ok=True,
                complete=True,
                native_query='search index=botsv1 sourcetype="*WinEventLog*" "php-cgi.exe" | head 100',
            )
        ]

    trace = store.get_trace("obs-trace-1", state=MockState())

    # Full chain verified
    assert trace["observation_id"] == "obs-trace-1"
    assert trace["card_id"] == "card-proc-01"
    assert trace["evidence_card"]["summary"] == "php-cgi.exe spawned cmd.exe on we1149srv"
    assert "req-server-exec" in trace["requirements"]
    assert "hyp-web-compromise" in trace["hypotheses"]
    assert trace["query_id"] == "q-proc-101"
    assert "index=botsv1" in trace["native_query"]
    assert trace["raw_event"]["CommandLine"] == "cmd.exe /c whoami"


def test_jsonl_export_and_load_preserves_raw_events_and_utf8(tmp_path: Path):
    """ObservationStore export_jsonl and load_jsonl preserve raw_event and Unicode without mojibake."""
    store = ObservationStore()
    scope = ProviderScope(provider_id="cdb", native_partition={"table": "events"})

    obs = Observation(
        id="obs-vn-1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="custom_audit",
        fields={"host": "máy-chủ-web-01", "action": "tải tệp lên"},
        raw_event={"mô_tả": "Hacker tải tệp mã độc webshell.php lên hệ thống", "mã_lỗi": 0},
        query_id="q-vn-1",
    )
    store.add_observation(obs)

    jsonl_path = tmp_path / "observations.jsonl"
    store.export_jsonl(jsonl_path)

    assert jsonl_path.exists()
    records = ObservationStore.load_jsonl(jsonl_path)
    assert len(records) == 1
    rec = records[0]
    assert rec["observation_id"] == "obs-vn-1"
    assert rec["fields"]["host"] == "máy-chủ-web-01"
    assert rec["raw_event"]["mô_tả"] == "Hacker tải tệp mã độc webshell.php lên hệ thống"
    # Verify no ascii escapes in raw file
    raw_content = jsonl_path.read_text(encoding="utf-8")
    assert "Hacker tải tệp mã độc" in raw_content
    assert "\\u" not in raw_content
