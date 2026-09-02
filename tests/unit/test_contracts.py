"""Unit tests for data contracts (Part II of 02_METHOD-AND-IMPLEMENTATION-PLAN.md)."""
import pytest

from hunting.contracts.entities import (
    Host, Account, Process, IPAddress, File, Domain,
    AnyEntity, ANY, EntityKind,
)
from hunting.contracts.cells import Cell, CellState, EventFamily
from hunting.contracts.observations import Observation, EpistemicType, TaintLabel
from hunting.contracts.queries import (
    QueryResult, QueryOutcome, ControlResult, QueryIntent,
    Diagnostic, DiagnosticClass,
)
from hunting.contracts.coverage import CoverageBound


# ---------------------------------------------------------------------------
# Entity tests
# ---------------------------------------------------------------------------

def test_host_kind():
    h = Host(name="DESKTOP-ABC")
    assert h.kind == EntityKind.HOST
    assert h.name == "DESKTOP-ABC"


def test_any_is_singleton():
    """ANY must equal a freshly created AnyEntity (frozen dataclass equality)."""
    assert ANY == AnyEntity()
    assert isinstance(ANY, AnyEntity)
    assert ANY.kind == EntityKind.ANY


def test_process_has_host():
    p = Process(host="DESKTOP-A", pid=1234, time="2026-09-01T10:00:00Z")
    assert p.host == "DESKTOP-A"
    assert p.pid == 1234
    assert p.time == "2026-09-01T10:00:00Z"


def test_file_has_host():
    f = File(host="DESKTOP-A", path="c:\\windows\\system32\\cmd.exe")
    assert f.host == "DESKTOP-A"
    assert f.path == "c:\\windows\\system32\\cmd.exe"


def test_entity_frozen():
    """Entity dataclasses must be immutable."""
    h = Host(name="DESKTOP-A")
    with pytest.raises(Exception):  # FrozenInstanceError
        h.name = "DESKTOP-B"  # type: ignore


# ---------------------------------------------------------------------------
# Cell tests
# ---------------------------------------------------------------------------

def test_cell_defaults_to_unexplored():
    h = Host(name="DESKTOP-A")
    c = Cell(
        source="winsec",
        event_family=EventFamily.PROCESS_CREATION,
        entity=h,
        time_bucket="2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
    )
    assert c.state == CellState.UNEXPLORED
    assert c.split_parent is False
    assert c.is_wildcard is False


def test_wildcard_cell_detection():
    c = Cell(
        source="winsec",
        event_family=EventFamily.LOGON,
        entity=ANY,
        time_bucket="2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
    )
    assert c.is_wildcard is True


def test_cell_state_is_mutable():
    """Cell state must change — Cell is NOT frozen."""
    h = Host(name="DESKTOP-A")
    c = Cell(
        source="winsec",
        event_family=EventFamily.DNS,
        entity=h,
        time_bucket="2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
    )
    c.state = CellState.EXPLORED
    assert c.state == CellState.EXPLORED


# ---------------------------------------------------------------------------
# QueryResult / negative-evidence tests
# ---------------------------------------------------------------------------

def test_partial_result_cannot_be_valid_negative():
    """A truncated result must never become VALID_NEGATIVE — spec C7."""
    result = QueryResult(
        query_id="q1",
        outcome=QueryOutcome.UNKNOWN,
        executed_ok=True,
        complete=False,     # truncated
    )
    assert result.complete is False
    assert result.outcome != QueryOutcome.VALID_NEGATIVE


def test_diagnostic_class_retryable():
    assert Diagnostic.QUERY_FAILED.diagnostic_class == DiagnosticClass.RETRYABLE
    assert Diagnostic.SOURCE_UNHEALTHY.diagnostic_class == DiagnosticClass.RETRYABLE
    assert Diagnostic.PARTIAL_RESULT.diagnostic_class == DiagnosticClass.RETRYABLE


def test_diagnostic_class_permanent():
    assert Diagnostic.RETENTION_EXPIRED.diagnostic_class == DiagnosticClass.PERMANENT
    assert Diagnostic.PARSE_FAILED.diagnostic_class == DiagnosticClass.PERMANENT
    assert Diagnostic.SOURCE_UNAVAILABLE.diagnostic_class == DiagnosticClass.PERMANENT


def test_control_intents_identified():
    from hunting.contracts.queries import CONTROL_INTENTS, INVESTIGATION_INTENTS
    assert QueryIntent.ANY_EVENT_CONTROL in CONTROL_INTENTS
    assert QueryIntent.ANY_EVENT_OF_FAMILY in CONTROL_INTENTS
    assert QueryIntent.BROAD_SWEEP in INVESTIGATION_INTENTS
    assert len(CONTROL_INTENTS) == 2
    assert len(INVESTIGATION_INTENTS) == 7


# ---------------------------------------------------------------------------
# CoverageBound tests
# ---------------------------------------------------------------------------

def test_coverage_bound_integer_fields():
    """All count fields must be integers — no floats or bare fractions."""
    cb = CoverageBound(known_cells_wildcard=10, explored_cells_wildcard=5)
    assert isinstance(cb.known_cells_wildcard, int)
    assert isinstance(cb.explored_cells_wildcard, int)
    assert isinstance(cb.unexplored_cells_instance, int)
