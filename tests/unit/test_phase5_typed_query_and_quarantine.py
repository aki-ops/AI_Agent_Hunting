"""Unit tests for Phase 5: Typed Query & Native-Query Quarantine.

Covers:
- QueryIntentMode (EXPLORE, DISCRIMINATE, PROVE)
- NativeQueryGate broad wildcard query rejection (index=* | head, search * | head)
- NativeQueryGate unknown source and field rejection
- NativeQueryGate duplicate query signature loop blocking
- SplunkLiveAdapter backend SID cancellation on timeout
- SplunkLiveAdapter cancel_search_job REST call
- SplunkLiveAdapter telemetry capture (sid, scan_count, execution_time_ms, row_count)
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from hunting.contracts.entities import Host
from hunting.contracts.native_query import NativeQueryCandidate
from hunting.contracts.queries import Diagnostic
from hunting.contracts.query_intent import QueryIntentMode, QueryIntentSpec, QueryPredicateSpec
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter
from hunting.query_safety.native_query_gate import NativeQueryGate, compute_query_signature


def test_query_intent_modes_and_epistemic_authority() -> None:
    """Verify QueryIntentMode values and default/explicit assignment on QueryIntentSpec."""
    assert QueryIntentMode.EXPLORE.value == "EXPLORE"
    assert QueryIntentMode.DISCRIMINATE.value == "DISCRIMINATE"
    assert QueryIntentMode.PROVE.value == "PROVE"

    # Default mode is PROVE
    intent_prove = QueryIntentSpec(
        goal_id="g-01",
        operation_id="op-auth",
        source_id="src-ad",
        relation="authenticates",
        predicates=(QueryPredicateSpec(key="user", operator="equals", value="Alice"),),
        time_window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
    )
    assert intent_prove.mode == QueryIntentMode.PROVE.value
    assert intent_prove.to_dict()["mode"] == "PROVE"

    # Explicit EXPLORE mode
    intent_explore = QueryIntentSpec(
        goal_id="g-02",
        operation_id="op-scan",
        source_id="src-logs",
        relation="observed",
        mode=QueryIntentMode.EXPLORE.value,
        time_window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
    )
    assert intent_explore.mode == QueryIntentMode.EXPLORE.value
    assert intent_explore.to_dict()["mode"] == "EXPLORE"

    # Explicit DISCRIMINATE mode
    intent_discrim = QueryIntentSpec(
        goal_id="g-03",
        operation_id="op-diff",
        source_id="src-hosts",
        relation="resolves",
        mode=QueryIntentMode.DISCRIMINATE.value,
        time_window="2026-08-18T00:00:00Z/2026-08-19T00:00:00Z",
    )
    assert intent_discrim.mode == QueryIntentMode.DISCRIMINATE.value
    assert intent_discrim.to_dict()["mode"] == "DISCRIMINATE"


def test_gate_rejects_broad_wildcard_query() -> None:
    """Gate verification: broad queries like index=* | head or search * | head are rejected."""
    gate = NativeQueryGate()
    time_win = "2026-08-18T00:00:00Z/2026-08-19T00:00:00Z"

    # 1. Broad wildcard index query: index=* | head 10
    cand_wild_idx = NativeQueryCandidate(
        provider="splunk",
        query_text="search index=* | head 10",
        time_window=time_win,
        max_rows=10,
    )
    res_wild_idx = gate.validate(
        cand_wild_idx,
        known_sources=["main", "botsv2"],
        known_fields=["host", "user"],
    )
    assert not res_wild_idx.accepted
    assert "broad_wildcard_query_rejected" in res_wild_idx.reasons

    # 2. Broad search with wildcard: search * | head 10
    cand_wild_search = NativeQueryCandidate(
        provider="splunk",
        query_text="search * | head 10",
        time_window=time_win,
        max_rows=10,
    )
    res_wild_search = gate.validate(
        cand_wild_search,
        known_sources=["main"],
        known_fields=["host", "user"],
    )
    assert not res_wild_search.accepted
    assert "broad_wildcard_query_rejected" in res_wild_search.reasons

    # 3. Search index=main * without field constraints: search index=main * | head 10
    cand_unconstrained = NativeQueryCandidate(
        provider="splunk",
        query_text="search index=main * | head 10",
        time_window=time_win,
        max_rows=10,
    )
    res_unconstrained = gate.validate(
        cand_unconstrained,
        known_sources=["main"],
        known_fields=["host", "user"],
    )
    assert not res_unconstrained.accepted
    assert "broad_wildcard_query_rejected" in res_unconstrained.reasons

    # 4. Valid constrained query is accepted
    cand_valid = NativeQueryCandidate(
        provider="splunk",
        query_text='search index="main" user="Alice" | head 10',
        time_window=time_win,
        expected_fields=("user",),
        max_rows=10,
    )
    res_valid = gate.validate(
        cand_valid,
        known_sources=["main"],
        known_fields=["user"],
    )
    assert res_valid.accepted, res_valid.reasons


def test_gate_rejects_unknown_fields_and_sources() -> None:
    """Gate verification: unknown sources and fields not in census are rejected."""
    gate = NativeQueryGate()
    time_win = "2026-08-18T00:00:00Z/2026-08-19T00:00:00Z"

    # Unknown source / index
    cand_bad_source = NativeQueryCandidate(
        provider="splunk",
        query_text='search index="secret_internal" user="Alice" | head 10',
        time_window=time_win,
        max_rows=10,
    )
    res_bad_source = gate.validate(
        cand_bad_source,
        known_sources=["main"],
        known_fields=["user"],
    )
    assert not res_bad_source.accepted
    assert "index_not_in_census" in res_bad_source.reasons

    # Unknown field
    cand_bad_field = NativeQueryCandidate(
        provider="splunk",
        query_text='search index="main" non_existent_secret_field="xyz" | head 10',
        time_window=time_win,
        max_rows=10,
    )
    res_bad_field = gate.validate(
        cand_bad_field,
        known_sources=["main"],
        known_fields=["user", "host"],
    )
    assert not res_bad_field.accepted
    assert "field_not_in_census:non_existent_secret_field" in res_bad_field.reasons


def test_gate_blocks_duplicate_query_signature_from_looping() -> None:
    """Gate verification: query with identical semantic signature is blocked from looping."""
    gate = NativeQueryGate()
    query_text = 'search index="main" user="Alice" | head 10'
    time_win = "2026-08-18T00:00:00Z/2026-08-19T00:00:00Z"

    sig = compute_query_signature(query_text, time_win)
    assert sig and isinstance(sig, str)

    cand = NativeQueryCandidate(
        provider="splunk",
        query_text=query_text,
        time_window=time_win,
        expected_fields=("user",),
        max_rows=10,
    )

    # First run: no executed signatures -> accepted
    res1 = gate.validate(
        cand,
        known_sources=["main"],
        known_fields=["user"],
        executed_query_signatures=(),
    )
    assert res1.accepted
    assert res1.query_signature == sig

    # Second run: identical signature already executed -> blocked
    res2 = gate.validate(
        cand,
        known_sources=["main"],
        known_fields=["user"],
        executed_query_signatures=(sig,),
    )
    assert not res2.accepted
    assert "duplicate_query_signature_blocked" in res2.reasons


def test_adapter_backend_sid_cancellation_on_timeout() -> None:
    """Gate verification: client-side timeout cancels backend SID and records failure."""
    with patch.object(SplunkLiveAdapter, "_discover_capabilities"):
        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            auth=("user", "pass"),
            index="test_idx",
            manifest_path=None,
            verify_ssl=False,
        )

    with patch.object(adapter, "cancel_search_job", return_value=True) as mock_cancel, \
         patch("requests.post", side_effect=requests.exceptions.Timeout("Read timeout")):
        qr = adapter.execute_query(
            operation_id="cdb_process_lineage",
            entity=Host(name="h1"),
            window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
            parameters={"sid": "test_sid_cancel_01"},
        )
        assert qr.executed_ok is False
        assert qr.diagnostic == Diagnostic.QUERY_FAILED
        assert "client_timeout_cancelled_sid:test_sid_cancel_01" in qr.truncation_reason
        assert qr.sid == "test_sid_cancel_01"
        # Verify backend SID cancellation was invoked
        mock_cancel.assert_called_once_with("test_sid_cancel_01")


def test_adapter_cancel_search_job_rest_call() -> None:
    """Verify cancel_search_job issues POST to /services/search/jobs/{sid}/control."""
    with patch.object(SplunkLiveAdapter, "_discover_capabilities"):
        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            auth=("user", "pass"),
            index="test_idx",
            manifest_path=None,
            verify_ssl=False,
        )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("requests.post", return_value=mock_resp) as mock_post:
        cancelled = adapter.cancel_search_job("sid_test_999")
        assert cancelled is True
        mock_post.assert_called_once_with(
            "https://mock-splunk:8089/services/search/jobs/sid_test_999/control",
            data={"action": "cancel"},
            auth=("user", "pass"),
            verify=False,
            timeout=5,
        )


def test_adapter_telemetry_capture() -> None:
    """Verify dispatch.max_time is dispatched and telemetry (sid, scan_count, row_count) is captured."""
    with patch.object(SplunkLiveAdapter, "_discover_capabilities"):
        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            auth=("user", "pass"),
            index="test_idx",
            manifest_path=None,
            verify_ssl=False,
        )

    mock_results = [
        {"_time": "2016-08-24T18:00:00.000Z", "host": "h1", "Image": "calc.exe"},
        {"_time": "2016-08-24T18:00:01.000Z", "host": "h1", "Image": "cmd.exe"},
    ]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"X-Splunk-ScanCount": "150"}
    mock_resp.json.return_value = {"results": mock_results}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        qr = adapter.execute_query(
            operation_id="cdb_process_lineage",
            entity=Host(name="h1"),
            window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
            parameters={"sid": "test_sid_telemetry", "dispatch_max_time": 45},
        )
        assert qr.executed_ok is True
        assert qr.row_count == 2
        assert qr.sid == "test_sid_telemetry"
        assert qr.scan_count == 150
        assert qr.execution_time_ms >= 0.0

        # Verify dispatch.max_time and id in post call
        call_args = mock_post.call_args
        post_data = call_args[1]["data"]
        assert post_data["id"] == "test_sid_telemetry"
        assert post_data["dispatch.max_time"] == "45"
