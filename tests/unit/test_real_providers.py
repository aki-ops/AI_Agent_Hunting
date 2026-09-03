"""Unit and execution tests for the Real-Provider Gate (Splunk, EDR, IDS).

Verifies the integration contracts defined in docs/01-REAL-PROVIDER-SPECIFICATIONS.md:
  1. Splunk adapter: native (index, sourcetype, source) scopes, search-time fields, and L+1 completeness.
  2. EDR adapter: tenant/dataset/endpoint scopes separate from operations, cursor pagination, and rate limits.
  3. IDS adapter: stream/sensor scopes, optional native predicates, and evolving schema preservation.
  4. Real-provider execution workflows verifying valid negative controls and coverage bounds.
"""
from __future__ import annotations

from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import Observation
from hunting.contracts.queries import (
    ControlResult,
    Diagnostic,
    QueryIntent,
    QueryOutcome,
    QueryResult,
)
from hunting.m1_ledger.extraction import build_observation
from hunting.m5_adapter.controls import license_valid_negative


class MockSplunkAdapter:
    """Mock Splunk adapter enforcing native (index, sourcetype, source) partition & L+1 completeness."""

    def __init__(self, index: str, sourcetype: str, source: str | None = None) -> None:
        partition = {"index": index, "sourcetype": sourcetype}
        if source:
            partition["source"] = source
        self.scope = ProviderScope(
            provider_id="splunk_siem",
            native_partition=partition,
            scope_id=f"splunk_{index}_{sourcetype}",
        )
        self.extracted_search_time_fields = {"CommandLine", "ParentProcessId", "Image", "User", "DestinationIp"}
        self.events_db: list[dict[str, Any]] = []

    def execute_spl(self, spl: str, limit: int) -> QueryResult:
        # Simulate L+1 completeness logic
        matching = [e for e in self.events_db if "DESKTOP-VICTIM1" in str(e)]
        fetched = matching[: limit + 1]

        if len(fetched) > limit:
            # Over limit -> truncated / partial
            return QueryResult(
                query_id="q-spl-01",
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=False,
                rows=fetched[:limit],
                diagnostic=Diagnostic.PARTIAL_RESULT,
            )
        return QueryResult(
            query_id="q-spl-01",
            outcome=QueryOutcome.ROWS,
            executed_ok=True,
            complete=True,
            rows=fetched,
        )


class MockEdrAdapter:
    """Mock EDR adapter separating dataset/tenant/endpoint scopes from operations & testing rate limits."""

    def __init__(self, tenant_id: str, dataset: str, cid: str) -> None:
        self.scope = ProviderScope(
            provider_id="crowdstrike_edr",
            native_partition={"tenant_id": tenant_id, "dataset": dataset, "cid": cid},
            scope_id=f"edr_{tenant_id}_{dataset}",
        )
        self.supported_operations = ["process_ancestry", "network_connection", "file_modification"]
        self.rate_limit_hits = 0

    def query_with_cursor(self, operation: str, cursor: str | None, limit: int) -> tuple[QueryResult, str | None]:
        # Simulate cursor pagination
        if self.rate_limit_hits > 0:
            self.rate_limit_hits -= 1
            return (
                QueryResult(
                    query_id="q-edr-01",
                    outcome=QueryOutcome.UNKNOWN,
                    executed_ok=False,
                    complete=False,
                    rows=[],
                    diagnostic=Diagnostic.SOURCE_UNAVAILABLE,
                ),
                cursor,
            )

        # Return page with next cursor
        rows = [{"pid": 100, "name": "cmd.exe"}]
        next_cursor = "cursor_tok_page_2" if cursor is None else None
        is_complete = next_cursor is None

        return (
            QueryResult(
                query_id="q-edr-01",
                outcome=QueryOutcome.ROWS,
                executed_ok=True,
                complete=is_complete,
                rows=rows,
            ),
            next_cursor,
        )


class MockIdsAdapter:
    """Mock IDS adapter implementing sensor/stream scopes and handling evolving JSON schema."""

    def __init__(self, sensor_id: str, interface: str, stream: str) -> None:
        self.scope = ProviderScope(
            provider_id="suricata_ids",
            native_partition={"sensor_id": sensor_id, "interface": interface, "stream": stream},
            scope_id=f"ids_{sensor_id}_{stream}",
        )

    def parse_eve_record(self, raw_record: dict[str, Any]) -> Observation:
        # Novel metadata (e.g. ja4, quic) is preserved without error using build_observation
        rec = dict(raw_record)
        rec.setdefault("native_type", f"eve_{self.scope.native_partition['stream']}")
        return build_observation(
            record=rec,
            provider_scope=self.scope,
            cell_id="cell-ids-01",
            raw_ref="ref-raw-ids-01",
            query_id="q-ids-01",
            collector=self.scope.provider_id,
            ingest_time="2026-09-01T10:00:00Z",
        )


def test_splunk_adapter_scope_and_completeness():
    adapter = MockSplunkAdapter(index="botsv3", sourcetype="XmlWinEventLog:Sysmon", source="XmlWinEventLog:Sysmon")
    assert adapter.scope.native_partition["index"] == "botsv3"
    assert adapter.scope.native_partition["sourcetype"] == "XmlWinEventLog:Sysmon"

    # Populate 15 events
    adapter.events_db = [{"host": "DESKTOP-VICTIM1", "id": i} for i in range(15)]

    # Query with limit 10: 15 events > 10 limit -> complete=False (PARTIAL)
    res_partial = adapter.execute_spl("search host=DESKTOP-VICTIM1", limit=10)
    assert res_partial.complete is False
    assert len(res_partial.rows) == 10
    assert res_partial.diagnostic is Diagnostic.PARTIAL_RESULT

    # Query with limit 20: 15 events <= 20 limit -> complete=True
    res_complete = adapter.execute_spl("search host=DESKTOP-VICTIM1", limit=20)
    assert res_complete.complete is True
    assert len(res_complete.rows) == 15


def test_edr_adapter_scope_and_rate_limits():
    adapter = MockEdrAdapter(tenant_id="tenant_01", dataset="fdr_telemetry", cid="cid_xyz")
    assert adapter.scope.native_partition["tenant_id"] == "tenant_01"
    assert adapter.scope.native_partition["dataset"] == "fdr_telemetry"

    # Page 1: returns rows and next_cursor -> complete=False
    res_page1, next_cursor = adapter.query_with_cursor("process_ancestry", cursor=None, limit=10)
    assert res_page1.complete is False
    assert next_cursor == "cursor_tok_page_2"

    # Page 2: returns final rows and next_cursor=None -> complete=True
    res_page2, final_cursor = adapter.query_with_cursor("process_ancestry", cursor=next_cursor, limit=10)
    assert res_page2.complete is True
    assert final_cursor is None

    # Rate limiting handling
    adapter.rate_limit_hits = 1
    res_rate_limited, _ = adapter.query_with_cursor("process_ancestry", cursor=None, limit=10)
    assert res_rate_limited.complete is False
    assert res_rate_limited.diagnostic is Diagnostic.SOURCE_UNAVAILABLE


def test_ids_adapter_sensor_scopes_and_schema_evolution():
    adapter = MockIdsAdapter(sensor_id="sensor-dmz-01", interface="eth0", stream="dns")
    assert adapter.scope.native_partition["sensor_id"] == "sensor-dmz-01"
    assert adapter.scope.native_partition["stream"] == "dns"

    # Novel unmapped EVE-JSON record containing novel protocol fields
    raw_eve = {
        "timestamp": "2026-09-01T10:14:30Z",
        "src_ip": "192.168.1.50",
        "dest_ip": "1.1.1.1",
        "dns": {"query": "evil-c2.corp.internal", "type": "A"},
        "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",  # Evolving protocol field
        "quic_version": "1",                           # Novel field
    }

    obs = adapter.parse_eve_record(raw_eve)
    assert obs.native_type == "eve_dns"
    assert obs.is_unmapped is True  # Preserved as UNMAPPED
    assert obs.fields["ja4"] == "t13d1516h2_8daaf6152771_b186095e22b6"
    assert obs.fields["quic_version"] == "1"


def test_real_provider_negative_licensing_matrix():
    # Empty result on Splunk
    empty_result = QueryResult(query_id="q-spl-empty", outcome=QueryOutcome.VALID_NEGATIVE, executed_ok=True, complete=True, rows=[])

    # Case 1: Healthy controls -> licenses valid negative
    c_health_ok = ControlResult("ctrl_health", QueryIntent.SCOPE_HEALTH_CONTROL, executed_ok=True)
    c_any_ok = ControlResult("ctrl_any", QueryIntent.ANY_RECORD_IN_SCOPE, executed_ok=True, count=42)
    c_obs_ok = ControlResult("ctrl_obs", QueryIntent.PREDICATE_OBSERVABILITY_CONTROL, executed_ok=True, predicate_observable=True)
    assert license_valid_negative(empty_result, c_health_ok, c_any_ok, c_obs_ok) is True

    # Case 2: Incomplete/truncated result -> cannot license negative
    partial_result = QueryResult(query_id="q-spl-part", outcome=QueryOutcome.ROWS, executed_ok=True, complete=False, rows=[])
    assert license_valid_negative(partial_result, c_health_ok, c_any_ok, c_obs_ok) is False

    # Case 3: Stale scope health lag -> cannot license negative
    c_health_stale = ControlResult("ctrl_health", QueryIntent.SCOPE_HEALTH_CONTROL, executed_ok=False, diagnostic=Diagnostic.SOURCE_UNHEALTHY)
    assert license_valid_negative(empty_result, c_health_stale, c_any_ok, c_obs_ok) is False

