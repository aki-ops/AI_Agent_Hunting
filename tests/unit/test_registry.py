from pathlib import Path

import pytest

from hunting.registry import Registry, load_registry

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_load_provider_scope_manifest():
    registry = load_registry(FIXTURES / "registry_cdb.yaml")
    assert isinstance(registry, Registry)
    assert registry.all_source_ids() == ["cdb"]
    assert registry.all_scope_ids() == ["cdb_security"]
    assert registry.scope_by_id("cdb_security").native_partition["table"] == "events"
    assert registry.operation_by_id("cdb_scope_scan").scope_ids == ("cdb_security",)


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_registry("/nonexistent/registry.yaml")


def test_missing_providers_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("foo: bar\n")
    with pytest.raises(ValueError, match="providers"):
        load_registry(path)


def test_unknown_backend_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("""
providers:
  - id: test
    backend: elasticsearch
    scopes:
      - id: scope
        native_partition: {dataset: events}
        retention_days: 30
        coverage_start: "2026-01-01T00:00:00Z"
    operations:
      - id: search
        scope_ids: [scope]
""")
    with pytest.raises(ValueError, match="backend"):
        load_registry(path)


def test_empty_scopes_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("""
providers:
  - id: test
    backend: cdb_sqlite
    scopes: []
    operations:
      - id: search
        scope_ids: [scope]
""")
    with pytest.raises(ValueError, match="scopes"):
        load_registry(path)


def test_operation_unknown_scope_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("""
providers:
  - id: test
    backend: cdb_sqlite
    scopes:
      - id: scope
        native_partition: {dataset: events}
        retention_days: 30
        coverage_start: "2026-01-01T00:00:00Z"
    operations:
      - id: search
        scope_ids: [missing]
""")
    with pytest.raises(ValueError, match="unknown scopes"):
        load_registry(path)


def test_invalid_retention_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("""
providers:
  - id: test
    backend: cdb_sqlite
    scopes:
      - id: scope
        native_partition: {dataset: events}
        retention_days: 0
        coverage_start: "2026-01-01T00:00:00Z"
    operations:
      - id: search
        scope_ids: [scope]
""")
    with pytest.raises(ValueError, match="retention_days"):
        load_registry(path)
