"""Unit tests for SplunkLiveAdapter, Dual Binding Modes, and Completeness Semantics."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from hunting.contracts.entities import Host
from hunting.contracts.expectations import EvidenceRequirement, FieldOp, FieldPredicate
from hunting.contracts.queries import QueryOutcome
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter


def is_splunk_live() -> bool:
    """Check if local Splunk REST API is live and responsive."""
    try:
        resp = requests.get(
            "https://localhost:8089/services/server/info",
            params={"output_mode": "json"},
            auth=("admin", "12345678"),
            verify=False,
            timeout=2,
        )
        return resp.status_code == 200
    except Exception:
        return False


SPLUNK_AVAILABLE = is_splunk_live()


class TestSplunkLiveAdapterUnit:
    """Mock-based unit tests for SplunkLiveAdapter logic and invariants."""

    def test_mode2_manifest_loading(self, tmp_path: Path) -> None:
        """Verify Mode 2 properly loads declarative YAML manifest."""
        manifest_file = tmp_path / "test_manifest.yaml"
        manifest_file.write_text("""
index: "test_index"
provider_id: "splunk"
bindings:
  process_ancestry:
    sourcetype: "Sysmon"
    event_filter: "EventID=1"
    extractions:
      cmdline: "<Data Name='CommandLine'>(?<cmdline>[^<]+)</Data>"
        """, encoding="utf-8")

        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            auth=("user", "pass"),
            index="test_index",
            manifest_path=manifest_file,
            verify_ssl=False,
        )
        assert adapter.binding_mode == "manifest"
        assert adapter.manifest is not None
        assert adapter.manifest["index"] == "test_index"
        assert adapter.scope.provider_id == "splunk"

    def test_mode1_auto_discovery_fallback(self) -> None:
        """Verify Mode 1 initializes with discovery mode when no manifest is provided."""
        with patch.object(SplunkLiveAdapter, "_discover_capabilities"):
            adapter = SplunkLiveAdapter(
                splunk_url="https://mock-splunk:8089",
                auth=("user", "pass"),
                index="custom_idx",
                manifest_path=None,
                verify_ssl=False,
            )
            assert adapter.binding_mode == "discovery"
            assert adapter.index == "custom_idx"

    def test_l_plus_1_completeness_truncation(self) -> None:
        """Verify the L+1 rule: when rows > limit, results are truncated and complete=False."""
        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            index="test_idx",
            manifest_path=None,
        )

        mock_results = [
            {"_time": f"2016-08-24T18:00:0{i}.000Z", "host": "h1", "Image": "calc.exe"}
            for i in range(5)  # 5 rows returned when limit is 4
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": mock_results}

        with patch("requests.post", return_value=mock_resp):
            qr = adapter.execute_query(
                operation_id="cdb_process_lineage",
                entity=Host(name="h1"),
                window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
                limit=4,
            )
            assert qr.executed_ok is True
            assert qr.complete is False  # Truncated because 5 > 4
            assert len(qr.rows) == 4
            assert qr.cursor == "4"

    def test_l_plus_1_completeness_eof(self) -> None:
        """Verify the L+1 rule: when rows <= limit, complete=True (EOF reached)."""
        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            index="test_idx",
            manifest_path=None,
        )

        mock_results = [
            {"_time": f"2016-08-24T18:00:0{i}.000Z", "host": "h1", "Image": "calc.exe"}
            for i in range(3)  # 3 rows returned when limit is 5
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"results": mock_results}

        with patch("requests.post", return_value=mock_resp):
            qr = adapter.execute_query(
                operation_id="cdb_process_lineage",
                entity=Host(name="h1"),
                window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
                limit=5,
            )
            assert qr.executed_ok is True
            assert qr.complete is True  # EOF reached
            assert len(qr.rows) == 3
            assert qr.cursor is None

    def test_invalid_index_preflight_validation(self) -> None:
        """Verify validate_index raises clear diagnostic when index is not found."""
        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            index="nonexistent_index",
        )
        with patch.object(adapter, "list_indexes", return_value=[{"name": "botsv1", "disabled": False}]):
            with pytest.raises(ValueError) as excinfo:
                adapter.validate_index()
            assert "nonexistent_index" in str(excinfo.value)
            assert "botsv1" in str(excinfo.value)

    def test_predicate_observability_control(self) -> None:
        """Verify PredicateObservabilityControl against allowlisted fields."""
        adapter = SplunkLiveAdapter(
            splunk_url="https://mock-splunk:8089",
            index="botsv1",
        )
        pred_valid = FieldPredicate(field="image", op=FieldOp.CONTAINS, value="powershell")
        res_valid = adapter.control_observability(EvidenceRequirement.PROCESS_ANCESTRY, pred_valid)
        assert res_valid.executed_ok is True
        assert res_valid.predicate_observable is True

        pred_invalid = FieldPredicate(field="non_existent_telemetry_field", op=FieldOp.EQUALS, value="xyz")
        res_invalid = adapter.control_observability(EvidenceRequirement.PROCESS_ANCESTRY, pred_invalid)
        assert res_invalid.predicate_observable is False


@pytest.mark.skipif(not SPLUNK_AVAILABLE, reason="Splunk Docker container is not reachable on localhost:8089")
class TestSplunkLiveAdapterIntegration:
    """Live integration tests executing queries against running Splunk Docker container with BOTSv1."""

    @pytest.fixture
    def live_adapter(self) -> SplunkLiveAdapter:
        adapter = SplunkLiveAdapter(
            splunk_url="https://localhost:8089",
            auth=("admin", "12345678"),
            index="botsv1",
            manifest_path="configs/splunk_botsv1.yaml",
            verify_ssl=False,
        )
        adapter.validate_index()
        return adapter

    def test_live_list_indexes(self, live_adapter: SplunkLiveAdapter) -> None:
        """Verify list_indexes returns active botsv1 index."""
        indexes = live_adapter.list_indexes()
        assert len(indexes) > 0
        botsv1_entry = next((i for i in indexes if i["name"] == "botsv1"), None)
        assert botsv1_entry is not None
        assert botsv1_entry["total_events"] > 30_000_000
        assert botsv1_entry["disabled"] is False

    def test_live_process_ancestry_query(self, live_adapter: SplunkLiveAdapter) -> None:
        """Verify live Sysmon process execution query on we1149srv returns normalized fields."""
        qr = live_adapter.execute_query(
            operation_id="cdb_process_lineage",
            entity=Host(name="we1149srv"),
            window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
            limit=5,
        )
        assert qr.executed_ok is True
        assert qr.outcome == QueryOutcome.ROWS
        assert len(qr.rows) > 0
        assert len(qr.rows) <= 5

        # Verify normalized field names exist in returned rows
        first = qr.rows[0]
        assert "timestamp" in first
        assert "host" in first
        assert "image" in first
        assert first["host"].lower() == "we1149srv"

    def test_live_network_connection_query(self, live_adapter: SplunkLiveAdapter) -> None:
        """Verify live Sysmon network connection query returns destination_ip."""
        qr = live_adapter.execute_query(
            operation_id="cdb_network_connections",
            entity=Host(name="we1149srv"),
            window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
            limit=5,
        )
        assert qr.executed_ok is True
        assert qr.outcome == QueryOutcome.ROWS
        assert len(qr.rows) > 0
        first = qr.rows[0]
        assert "destination_ip" in first or "destination_port" in first

    def test_live_negative_controls(self, live_adapter: SplunkLiveAdapter) -> None:
        """Verify live negative controls evaluate correctly."""
        window = "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z"
        ctrl_health = live_adapter.control_health(window)
        assert ctrl_health.executed_ok is True

        ctrl_any = live_adapter.control_any_record(window)
        assert ctrl_any.executed_ok is True
        assert (ctrl_any.count or 0) > 0

        ctrl_pred = live_adapter.control_observability(
            EvidenceRequirement.PROCESS_ANCESTRY,
            FieldPredicate(field="cmdline", op=FieldOp.CONTAINS, value="whoami"),
        )
        assert ctrl_pred.executed_ok is True
        assert ctrl_pred.predicate_observable is True

    def test_live_is_available(self) -> None:
        """Verify is_available returns True for responsive Splunk endpoint."""
        assert SplunkLiveAdapter.is_available("https://localhost:8089", verify_ssl=False) is True
        assert SplunkLiveAdapter.is_available("https://localhost:9999", timeout=1) is False

    def test_live_auto_select_index(self) -> None:
        """Verify auto_select_index discovers botsv1 as the primary telemetry index."""
        selected = SplunkLiveAdapter.auto_select_index("https://localhost:8089", verify_ssl=False)
        assert selected["name"] == "botsv1"
        assert selected["total_events"] > 1000000
        assert "min_time" in selected and "max_time" in selected

    def test_live_discover_full_capabilities(self, live_adapter: SplunkLiveAdapter) -> None:
        """Verify discover_full_capabilities returns ProviderCapabilityCatalog."""
        catalog = live_adapter.discover_full_capabilities()
        assert catalog.provider_id == "splunk"
        assert catalog.status == "ONLINE"
        assert "botsv1" in catalog.indices
        assert "process_ancestry" in catalog.supported_evidence_types
        assert "web_request" in catalog.supported_evidence_types
        assert "file_modification" in catalog.supported_evidence_types

    def test_live_web_request_query(self, live_adapter: SplunkLiveAdapter) -> None:
        """Verify live web_request query fetches stream:http data."""
        qr = live_adapter.execute_query(
            operation_id="cdb_web_requests",
            entity=None,
            window="2016-08-01T00:00:00Z/2016-08-29T23:59:59Z",
            limit=5,
        )
        assert qr.executed_ok is True
        assert qr.outcome == QueryOutcome.ROWS
        assert qr.row_count > 0
        assert qr.native_query is not None
        assert qr.execution_time_ms > 0


