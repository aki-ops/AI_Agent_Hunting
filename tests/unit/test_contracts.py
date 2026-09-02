import pytest

from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.entities import ANY, AnyEntity, EntityKind, Host
from hunting.contracts.expectations import EvidenceRequirement, Expectation
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import (
    CONTROL_INTENTS,
    INVESTIGATION_INTENTS,
    Diagnostic,
    DiagnosticClass,
    QueryIntent,
    QueryOutcome,
    QueryResult,
)


def test_entity_and_any_contracts():
    host = Host(name="DESKTOP-ABC")
    assert host.kind == EntityKind.HOST
    assert ANY == AnyEntity()
    assert isinstance(ANY, AnyEntity)


def test_cell_uses_provider_scope_and_has_no_event_family():
    scope = ProviderScope("cdb", {"database": "cdb.sqlite", "table": "events"}, "cdb_security")
    cell = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")

    assert cell.provider_scope == scope
    assert cell.is_wildcard
    assert cell.state is CellState.UNEXPLORED
    assert not hasattr(cell, "event_family")


def test_cell_state_is_mutable():
    scope = ProviderScope("cdb", {"table": "events"}, "scope")
    cell = Cell(scope, Host(name="DESKTOP-A"), "window")
    cell.state = CellState.EXPLORED
    assert cell.state is CellState.EXPLORED


def test_observation_preserves_unknown_native_type():
    scope = ProviderScope("ids", {"stream": "eve.json"}, "sensor-01")
    observation = Observation(
        id="o1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="vendor_new_type",
        semantic_type=None,
    )
    assert observation.native_type == "vendor_new_type"
    assert observation.semantic_type is None


def test_any_is_not_allowed_in_expectation_or_observation_entities():
    with pytest.raises(ValueError):
        Expectation("e", "x", EvidenceRequirement.DNS_ACTIVITY, "dns", ANY, None, None, "window", "not found")

    scope = ProviderScope("ids", {"stream": "eve.json"}, "sensor")
    with pytest.raises(ValueError):
        Observation("o", scope, "c", "timestamp", EpistemicType.OBSERVED, entities=[ANY])


def test_query_controls_are_not_event_family_controls():
    assert CONTROL_INTENTS == {
        QueryIntent.SCOPE_HEALTH_CONTROL,
        QueryIntent.ANY_RECORD_IN_SCOPE,
        QueryIntent.PREDICATE_OBSERVABILITY_CONTROL,
    }
    assert QueryIntent.BROAD_SWEEP in INVESTIGATION_INTENTS
    assert len(CONTROL_INTENTS) == 3
    assert len(INVESTIGATION_INTENTS) == 7


def test_partial_result_cannot_be_valid_negative():
    result = QueryResult("q1", QueryOutcome.UNKNOWN, True, complete=False)
    assert result.outcome is not QueryOutcome.VALID_NEGATIVE


def test_diagnostic_classes():
    assert Diagnostic.QUERY_FAILED.diagnostic_class is DiagnosticClass.RETRYABLE
    assert Diagnostic.PARTIAL_RESULT.diagnostic_class is DiagnosticClass.RETRYABLE
    assert Diagnostic.UNQUERYABLE.diagnostic_class is DiagnosticClass.PERMANENT
