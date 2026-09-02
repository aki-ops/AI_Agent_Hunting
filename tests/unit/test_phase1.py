"""Unit and integration tests for Phase 1 (Discovery, input, normalization and bootstrapping)."""
import json
from pathlib import Path

from hunting.bootstrap import bootstrap_investigation
from hunting.contracts.cells import CellState
from hunting.contracts.entities import ANY, Account, Domain, Host, IPAddress, Process
from hunting.contracts.observations import EpistemicType, Observation, Provenance
from hunting.contracts.state import Alert
from hunting.normalization import (
    assign_stable_scope_id,
    normalize_account,
    normalize_domain,
    normalize_file,
    normalize_host,
    normalize_ip,
    normalize_process,
    normalize_time_window,
)
from hunting.registry import load_registry

FIXTURES = Path(__file__).parent.parent / "fixtures"


def load_alert_fixture(name: str) -> Alert:
    path = FIXTURES / name
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return Alert(
        id=data["id"],
        raw=data["raw"],
        source=data["source"],
        received_at=data["received_at"],
        fields=data.get("fields", {}),
    )


# ---------------------------------------------------------------------------
# Normalization tests
# ---------------------------------------------------------------------------

def test_normalization_rules():
    assert normalize_host("domain\\desktop-01.corp.internal").name == "DESKTOP-01"
    assert normalize_account("CORP\\alice").username == "alice"
    assert normalize_domain("EVIL.COM.").name == "evil.com"
    assert normalize_ip(" 10.0.0.1 ").address == "10.0.0.1"

    proc = normalize_process("DESKTOP-01", 1234, "2026-09-01T10:00:00Z")
    assert proc.host == "DESKTOP-01"
    assert proc.pid == 1234

    file_ent = normalize_file("DESKTOP-01", "C:/Windows/System32/calc.exe")
    assert file_ent.host == "DESKTOP-01"
    assert file_ent.path == "c:\\windows\\system32\\calc.exe"

    window = normalize_time_window("2026-09-01T12:00:00Z", radius_seconds=3600)
    assert window == "2026-09-01T11:00:00Z/2026-09-01T13:00:00Z"


def test_assign_stable_scope_id():
    stable = assign_stable_scope_id("splunk", {"sourcetype": "xmlwineventlog", "index": "security"})
    assert stable == "splunk_index-security_sourcetype-xmlwineventlog"

    # Preserves explicit ID if provided
    assert assign_stable_scope_id("splunk", {"index": "sec"}, current_id="my_scope") == "my_scope"


# ---------------------------------------------------------------------------
# Acceptance Criterion 1: Entity-bearing alert creates instance candidates
# ---------------------------------------------------------------------------

def test_entity_bearing_alert_creates_instance_candidates():
    alert = load_alert_fixture("alert_entity_bearing.json")
    registry = load_registry(FIXTURES / "registry_cdb.yaml")

    result = bootstrap_investigation(alert, registry)

    assert len(result.seed.entities) > 0
    assert result.has_instance_candidates is True
    assert len(result.instance_cells) > 0

    # Verify extracted entity types
    entity_types = {type(e) for e in result.seed.entities}
    assert Host in entity_types
    assert Account in entity_types
    assert Process in entity_types
    assert IPAddress in entity_types
    assert Domain in entity_types

    # Ensure wildcard cells also exist for the scope
    assert len(result.wildcard_cells) == 1
    assert result.wildcard_cells[0].entity is ANY


# ---------------------------------------------------------------------------
# Acceptance Criterion 2: Entity-free alert creates finite wildcard frame alone
# ---------------------------------------------------------------------------

def test_entity_free_alert_creates_finite_wildcard_frame_alone():
    alert = load_alert_fixture("alert_entity_free.json")
    registry = load_registry(FIXTURES / "registry_cdb.yaml")

    result = bootstrap_investigation(alert, registry)

    # Must produce empty seed entities
    assert len(result.seed.entities) == 0
    # Must have NO instance candidates
    assert result.has_instance_candidates is False
    assert len(result.instance_cells) == 0
    # Finite wildcard frame from known scopes alone
    assert len(result.wildcard_cells) == 1
    assert result.wildcard_cells[0].is_wildcard is True
    assert result.wildcard_cells[0].entity is ANY
    assert result.wildcard_cells[0].state is CellState.UNEXPLORED


# ---------------------------------------------------------------------------
# Acceptance Criterion 3: Retention-expired / known-gap cells are never selected
# ---------------------------------------------------------------------------

def test_coverage_end_in_past_makes_cells_unreachable():
    alert = load_alert_fixture("alert_entity_bearing.json")
    # stale_scope coverage_end is in 2025; alert is in 2026
    stale_registry = load_registry(FIXTURES / "fixture_stale_scope.yaml")

    result = bootstrap_investigation(alert, stale_registry)

    for cell in result.all_cells:
        assert cell.state is CellState.UNREACHABLE

    # Selectable cells must exclude UNREACHABLE
    assert len(result.selectable_cells) == 0


def test_retention_days_expiration_with_null_coverage_end():
    """Verify that retention_days actually prunes rolling logs even when coverage_end is null."""
    alert = load_alert_fixture("alert_entity_bearing.json")  # Alert is at 2026-09-01T10:15:00Z
    retention_registry = load_registry(FIXTURES / "fixture_retention_expired.yaml")  # retention_days = 10, coverage_end = null

    from datetime import datetime, timezone

    # Case 1: Investigation run 34 days later (2026-10-05) -> retention cutoff is 2026-09-25.
    # Alert window (2026-09-01) has rolled off retention -> UNREACHABLE.
    as_of_expired = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
    result_expired = bootstrap_investigation(alert, retention_registry, as_of=as_of_expired)

    for cell in result_expired.all_cells:
        assert cell.state is CellState.UNREACHABLE
    assert len(result_expired.selectable_cells) == 0

    # Case 2: Investigation run 2 days later (2026-09-03) -> retention cutoff is 2026-08-24.
    # Alert window (2026-09-01) is safely inside retention -> UNEXPLORED and selectable!
    as_of_fresh = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
    result_fresh = bootstrap_investigation(alert, retention_registry, as_of=as_of_fresh)

    for cell in result_fresh.all_cells:
        assert cell.state is CellState.UNEXPLORED
    assert len(result_fresh.selectable_cells) > 0


def test_known_gap_cells_are_unreachable_and_never_selectable():
    alert = load_alert_fixture("alert_entity_bearing.json")
    # gap declared 10:00 to 12:00; alert is at 10:15
    gap_registry = load_registry(FIXTURES / "fixture_known_gap.yaml")

    result = bootstrap_investigation(alert, gap_registry)

    for cell in result.all_cells:
        assert cell.state is CellState.UNREACHABLE

    assert len(result.selectable_cells) == 0


# ---------------------------------------------------------------------------
# Acceptance Criterion 4: Scope with no operation is UNQUERYABLE
# ---------------------------------------------------------------------------

def test_scope_with_no_operation_is_unqueryable_not_silently_omitted():
    alert = load_alert_fixture("alert_entity_free.json")
    hybrid_registry = load_registry(FIXTURES / "fixture_no_adapter_scope.yaml")

    result = bootstrap_investigation(alert, hybrid_registry)

    # 2 scopes in hybrid_provider: covered_scope and unqueryable_scope
    scope_states = {c.provider_scope.scope_id: c.state for c in result.wildcard_cells}

    assert "covered_scope" in scope_states
    assert scope_states["covered_scope"] is CellState.UNEXPLORED

    # The unqueryable scope is present in the cells (not omitted) and typed UNQUERYABLE
    assert "unqueryable_scope" in scope_states
    assert scope_states["unqueryable_scope"] is CellState.UNQUERYABLE

    # It must NOT be in selectable cells
    selectable_scope_ids = [c.provider_scope.scope_id for c in result.selectable_cells]
    assert "unqueryable_scope" not in selectable_scope_ids
    assert "covered_scope" in selectable_scope_ids


# ---------------------------------------------------------------------------
# Native partition identity in provenance & unknown native records
# ---------------------------------------------------------------------------

def test_native_partition_preserved_in_provenance():
    with (FIXTURES / "record_unknown_native.json").open(encoding="utf-8") as f:
        record = json.load(f)

    registry = load_registry(FIXTURES / "registry_cdb.yaml")
    scope = registry.sources[0].scopes[0]

    prov = Provenance(
        query_id="q-001",
        collector="ids-collector",
        ingest_time="2026-09-01T10:15:00Z",
        native_partition=record["native_partition"],
    )
    obs = Observation(
        id="obs-native-001",
        provider_scope=scope,  # type: ignore
        cell_id="cell-001",
        timestamp=record["timestamp"],
        epistemic_type=EpistemicType.OBSERVED,
        native_type=record["native_type"],
        provenance=prov,
        fields=record["fields"],
    )

    assert obs.native_type == "quic_unparsed_flow_frame"
    assert obs.is_unmapped is True
    assert obs.provenance.native_partition == {"stream": "eve.json", "sensor": "sensor-west-01"}
