"""Unit tests for registry loading and validation (C1 — Telemetry Discovery)."""
import pytest
from pathlib import Path

from hunting.registry import load_registry
from hunting.registry.schema import Registry

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_load_cdb_registry():
    reg = load_registry(FIXTURES / "registry_cdb.yaml")
    assert isinstance(reg, Registry)
    assert len(reg.sources) == 1
    src = reg.sources[0]
    assert src.id == "winsec"
    assert src.backend == "cdb_sqlite"
    assert "process_creation" in src.event_families
    assert "dns" in src.event_families
    assert src.retention_days == 90
    assert src.coverage_end is None


def test_all_seven_families_present():
    reg = load_registry(FIXTURES / "registry_cdb.yaml")
    families = set(reg.sources[0].event_families)
    expected = {
        "process_creation", "logon", "network_bind", "file_write",
        "registry", "dns", "scheduled_task",
    }
    assert expected == families


def test_supports_family_true():
    reg = load_registry(FIXTURES / "registry_cdb.yaml")
    assert reg.supports_family("winsec", "process_creation") is True


def test_supports_family_unknown():
    reg = load_registry(FIXTURES / "registry_cdb.yaml")
    assert reg.supports_family("winsec", "wmi_activity") is False


def test_supports_family_unknown_source():
    reg = load_registry(FIXTURES / "registry_cdb.yaml")
    assert reg.supports_family("nonexistent", "process_creation") is False


def test_indexes_entity_type():
    reg = load_registry(FIXTURES / "registry_cdb.yaml")
    assert reg.indexes_entity_type("winsec", "host") is True
    assert reg.indexes_entity_type("winsec", "process") is True
    assert reg.indexes_entity_type("winsec", "domain") is False  # not in fixture


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_registry("/nonexistent/registry.yaml")


def test_missing_sources_key_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("foo: bar\n")
    with pytest.raises(ValueError, match="sources"):
        load_registry(f)


def test_empty_sources_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("sources: []\n")
    with pytest.raises(ValueError):
        load_registry(f)


def test_unknown_backend_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("""
sources:
  - id: test
    backend: elasticsearch
    event_families: [process_creation]
    indexed_entity_types: [host]
    retention_days: 30
    coverage_start: "2026-01-01T00:00:00Z"
""")
    with pytest.raises(ValueError, match="backend"):
        load_registry(f)


def test_unknown_event_family_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("""
sources:
  - id: test
    backend: cdb_sqlite
    event_families: [process_creation, wmi_activity]
    indexed_entity_types: [host]
    retention_days: 30
    coverage_start: "2026-01-01T00:00:00Z"
""")
    with pytest.raises(ValueError, match="event_family"):
        load_registry(f)


def test_empty_event_families_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("""
sources:
  - id: test
    backend: cdb_sqlite
    event_families: []
    indexed_entity_types: [host]
    retention_days: 30
    coverage_start: "2026-01-01T00:00:00Z"
""")
    with pytest.raises(ValueError):
        load_registry(f)


def test_negative_retention_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("""
sources:
  - id: test
    backend: cdb_sqlite
    event_families: [process_creation]
    indexed_entity_types: [host]
    retention_days: -5
    coverage_start: "2026-01-01T00:00:00Z"
""")
    with pytest.raises(ValueError):
        load_registry(f)


def test_missing_required_field_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    # Missing retention_days
    f.write_text("""
sources:
  - id: test
    backend: cdb_sqlite
    event_families: [process_creation]
    indexed_entity_types: [host]
    coverage_start: "2026-01-01T00:00:00Z"
""")
    with pytest.raises(ValueError, match="retention_days"):
        load_registry(f)
