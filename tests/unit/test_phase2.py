"""Unit and integration tests for Phase 2 (M1 Observation Ledger)."""
from pathlib import Path

import pytest

from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import ANY, Host
from hunting.contracts.observations import TaintLabel
from hunting.contracts.queries import Diagnostic, DiagnosticClass, QueryIntent, QueryOutcome, QueryResult
from hunting.m1_ledger import (
    ObservationLedger,
    ProtectedRawStore,
    RawReference,
    build_observation,
    label_field_taint,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Test 1 & Acceptance 1: Raw loaders, protected references, parse failures
# ---------------------------------------------------------------------------

def test_protected_raw_store_and_parse_failure_diagnostic():
    store = ProtectedRawStore()

    # Valid JSON
    valid_raw = '{"event_id": 4688, "host": "HOST-01", "cmdline": "whoami"}'
    res_valid = store.parse_and_store(valid_raw)
    assert res_valid.is_ok is True
    assert res_valid.data["event_id"] == 4688
    assert isinstance(res_valid.raw_ref, RawReference)
    assert len(res_valid.raw_ref.sha256_digest) == 64

    # Invalid JSON — must produce typed Diagnostic.PARSE_FAILED, NO silent drop
    corrupt_raw = '{"event_id": 4688, corrupt_json...'
    res_corrupt = store.parse_and_store(corrupt_raw)
    assert res_corrupt.is_ok is False
    assert res_corrupt.data is None
    assert res_corrupt.diagnostic is Diagnostic.PARSE_FAILED
    assert res_corrupt.diagnostic_class is DiagnosticClass.PERMANENT
    assert res_corrupt.raw_ref is not None  # Raw reference is still preserved in protected store!


# ---------------------------------------------------------------------------
# Test 2 & Acceptance 2 & 3: Preserved native records, unknown types, taint, provenance
# ---------------------------------------------------------------------------

def test_unknown_event_without_event_code_remains_valid_observation():
    scope = ProviderScope("edr_sensor", {"dataset": "process_tree"}, "scope-01")

    # Record with NO event code, and novel fields
    record = {
        "timestamp": "2026-09-01T10:14:00Z",
        "host": "DESKTOP-TEST",
        "arbitrary_vendor_field": "some_value",
        "cmdline": "powershell -enc AAAA",
    }

    obs = build_observation(
        record=record,
        provider_scope=scope,
        cell_id="c-001",
        raw_ref="raw-001",
        query_id="q-001",
        collector="edr_collector",
        ingest_time="2026-09-01T10:15:00Z",
        semantic_type=None,
    )

    # Acceptance: Every observation has scope, provenance, raw reference and field taint
    assert obs.provider_scope == scope
    assert obs.provenance is not None
    assert obs.provenance.query_id == "q-001"
    assert obs.raw_ref == "raw-001"
    assert "cmdline" in obs.taint
    assert obs.taint["cmdline"] == TaintLabel.ATTACKER_INFLUENCED
    assert obs.taint["timestamp"] == TaintLabel.STRUCTURAL

    # Acceptance: Unknown event without event code remains a valid observation (native_type is None)
    assert obs.native_type is None
    assert obs.is_unmapped is True
    assert obs.is_unexplained is True
    assert obs.fields["arbitrary_vendor_field"] == "some_value"


def test_deterministic_taint_labelling():
    assert label_field_taint("cmdline") == TaintLabel.ATTACKER_INFLUENCED
    assert label_field_taint("image_path") == TaintLabel.ATTACKER_INFLUENCED
    assert label_field_taint("domain") == TaintLabel.ATTACKER_INFLUENCED
    assert label_field_taint("timestamp") == TaintLabel.STRUCTURAL
    assert label_field_taint("pid") == TaintLabel.STRUCTURAL
    assert label_field_taint("src_port") == TaintLabel.STRUCTURAL

    # Unknown field defaults conservatively to ATTACKER_INFLUENCED
    assert label_field_taint("mysterious_custom_tag") == TaintLabel.ATTACKER_INFLUENCED


# ---------------------------------------------------------------------------
# Test 3: Append-only ledger, observed_fields recording
# ---------------------------------------------------------------------------

def test_ledger_append_only_and_observed_fields():
    ledger = ObservationLedger()
    scope = ProviderScope("winsec", {"table": "events"}, "scope-sec")

    obs1 = build_observation(
        record={"timestamp": "2026-09-01T10:00:00Z", "event_id": "4688", "NewProcessName": "cmd.exe", "host": "HOST1"},
        provider_scope=scope,
        cell_id="c1",
        raw_ref="r1",
        query_id="q1",
        collector="col",
        ingest_time="2026-09-01T10:05:00Z",
    )
    obs2 = build_observation(
        record={"timestamp": "2026-09-01T10:01:00Z", "event_id": "4688", "CommandLine": "cmd.exe /c whoami", "host": "HOST1"},
        provider_scope=scope,
        cell_id="c1",
        raw_ref="r2",
        query_id="q1",
        collector="col",
        ingest_time="2026-09-01T10:05:00Z",
    )

    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    # Cannot overwrite existing observation (append-only)
    with pytest.raises(ValueError, match="already exists"):
        ledger.add_observation(obs1)

    assert len(ledger.observations) == 2

    # Observed fields recorded per (scope_id, native_type)
    fields_recorded = ledger.observed_fields_for("scope-sec", "4688")
    assert "NewProcessName" in fields_recorded
    assert "CommandLine" in fields_recorded
    assert "timestamp" in fields_recorded


# ---------------------------------------------------------------------------
# Test 4: Unattributed and UNMAPPED observations maintained
# ---------------------------------------------------------------------------

def test_unattributed_and_unmapped_tracking():
    ledger = ObservationLedger()
    scope = ProviderScope("ids", {"stream": "eve.json"}, "sensor-01")

    # Unmapped observation (semantic_type=None)
    obs_unmapped = build_observation(
        record={"timestamp": "2026-09-01T10:00:00Z", "event_type": "custom_proto", "host": "HOST1"},
        provider_scope=scope,
        cell_id="c1",
        raw_ref="r1",
        query_id="q1",
        collector="col",
        ingest_time="2026-09-01T10:05:00Z",
        semantic_type=None,
    )
    ledger.add_observation(obs_unmapped)

    assert len(ledger.unattributed_observations) == 1
    assert len(ledger.unmapped_observations) == 1

    # When attributed, it leaves unattributed_observations but remains in unmapped_observations
    ledger.mark_attributed(obs_unmapped.id, "explanation-01")
    assert len(ledger.unattributed_observations) == 0
    assert len(ledger.unmapped_observations) == 1


# ---------------------------------------------------------------------------
# Test 5: Wildcard and instance cells tracked separately & split parents excluded
# ---------------------------------------------------------------------------

def test_wildcard_and_instance_cells_and_split_parents():
    ledger = ObservationLedger()
    scope = ProviderScope("cdb", {"table": "events"}, "cdb_sec")

    wildcard_cell = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T12:00:00Z")
    instance_cell = Cell(scope, Host(name="HOST-01"), "2026-09-01T10:00:00Z/2026-09-01T12:00:00Z")

    ledger.register_cell(wildcard_cell)
    ledger.register_cell(instance_cell)

    cb_initial = ledger.build_coverage_bound()
    assert cb_initial.known_cells_wildcard == 1
    assert cb_initial.known_cells_instance == 1

    # Split a partial wildcard cell
    left_child = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")
    right_child = Cell(scope, ANY, "2026-09-01T11:00:00Z/2026-09-01T12:00:00Z")

    ledger.record_split_parent(wildcard_cell, left_child, right_child)

    cb_split = ledger.build_coverage_bound()
    # Active wildcard cells: left and right children (2 cells). Split parent is not active.
    assert cb_split.known_cells_wildcard == 2
    # Partial count tracks the split parent for audit
    assert cb_split.partial_cells_wildcard == 1


# ---------------------------------------------------------------------------
# Acceptance Criterion 4: Complete scope scan vs targeted evidence query
# ---------------------------------------------------------------------------

def test_complete_scope_scan_vs_targeted_query_coverage():
    ledger = ObservationLedger()
    scope = ProviderScope("cdb", {"table": "events"}, "cdb_sec")

    wildcard_cell = Cell(scope, ANY, "window")
    instance_cell = Cell(scope, Host(name="HOST-01"), "window")

    ledger.register_cell(wildcard_cell)
    ledger.register_cell(instance_cell)

    # 1. Targeted query (e.g. ProcessLineage for HOST-01) completes
    targeted_result = QueryResult(
        query_id="q-target",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
    )
    ledger.record_query_outcome(QueryIntent.PROCESS_LINEAGE, instance_cell, targeted_result)

    # Acceptance: Targeted query marks ONLY the instance cell explored
    assert instance_cell.state is CellState.EXPLORED
    # The whole provider scope wildcard cell CANNOT be marked explored by a targeted query!
    assert wildcard_cell.state is CellState.UNEXPLORED

    # 2. Complete scope scan (BroadSweep) completes
    sweep_result = QueryResult(
        query_id="q-sweep",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
    )
    ledger.record_query_outcome(QueryIntent.BROAD_SWEEP, wildcard_cell, sweep_result)

    # Acceptance: Complete scope scan marks scope coverage explored
    assert wildcard_cell.state is CellState.EXPLORED


# ---------------------------------------------------------------------------
# Regression tests for coverage edge cases
# ---------------------------------------------------------------------------

def test_targeted_intent_on_wildcard_cell_cannot_mark_it_explored():
    """Regression 1: Targeted query (e.g. DNS_QUERIES) on a wildcard cell MUST NOT mark it EXPLORED."""
    ledger = ObservationLedger()
    scope = ProviderScope("cdb", {"table": "events"}, "cdb_sec")

    wildcard_cell = Cell(scope, ANY, "window")
    ledger.register_cell(wildcard_cell)

    # Issue targeted query (DNS_QUERIES) with complete=True against wildcard cell
    res_targeted = QueryResult(
        query_id="q-dns-wildcard",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
    )
    ledger.record_query_outcome(QueryIntent.DNS_QUERIES, wildcard_cell, res_targeted)

    # Contract invariant: Wildcard cell CANNOT become EXPLORED via a targeted intent!
    assert wildcard_cell.state is CellState.UNEXPLORED

    # Now issue BroadSweep (complete scope scan) with complete=True
    res_sweep = QueryResult(
        query_id="q-broad-sweep",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
    )
    ledger.record_query_outcome(QueryIntent.BROAD_SWEEP, wildcard_cell, res_sweep)

    # BroadSweep successfully explores the scope
    assert wildcard_cell.state is CellState.EXPLORED


def test_instance_split_parents_counted_in_instance_partial_not_wildcard():
    """Regression 2: Split parents must be partitioned by wildcard vs instance in CoverageBound."""
    ledger = ObservationLedger()
    scope = ProviderScope("cdb", {"table": "events"}, "cdb_sec")

    # Instance cell split
    instance_cell = Cell(scope, Host(name="HOST-01"), "2026-09-01T10:00:00Z/2026-09-01T12:00:00Z")
    ledger.register_cell(instance_cell)

    i_left = Cell(scope, Host(name="HOST-01"), "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")
    i_right = Cell(scope, Host(name="HOST-01"), "2026-09-01T11:00:00Z/2026-09-01T12:00:00Z")
    ledger.record_split_parent(instance_cell, i_left, i_right)

    cb1 = ledger.build_coverage_bound()
    # Must increment partial_cells_instance, NEVER partial_cells_wildcard!
    assert cb1.partial_cells_instance == 1
    assert cb1.partial_cells_wildcard == 0

    # Wildcard cell split
    wildcard_cell = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T12:00:00Z")
    ledger.register_cell(wildcard_cell)

    w_left = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")
    w_right = Cell(scope, ANY, "2026-09-01T11:00:00Z/2026-09-01T12:00:00Z")
    ledger.record_split_parent(wildcard_cell, w_left, w_right)

    cb2 = ledger.build_coverage_bound()
    # Both counts must accurately reflect their respective split parents
    assert cb2.partial_cells_instance == 1
    assert cb2.partial_cells_wildcard == 1
