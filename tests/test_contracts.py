from hunting.contracts.cells import Cell, ProviderScope
from hunting.contracts.entities import ANY, Host


def test_cell_is_addressed_by_provider_scope_not_event_family():
    scope = ProviderScope("splunk-prod", {"index": "security", "sourcetype": "wineventlog"})
    cell = Cell(scope, ANY, "2026-01-01T00:00Z/2026-01-01T01:00Z")

    assert cell.provider_scope is scope
    assert cell.entity is ANY
    assert not hasattr(cell, "event_family")


def test_any_and_concrete_entities_are_valid_cell_entities():
    scope = ProviderScope("edr-prod", {"dataset": "endpoint-events"})

    assert Cell(scope, ANY, "window")
    assert Cell(scope, Host(name="host-01"), "window")
