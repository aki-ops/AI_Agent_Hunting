"""Unit and integration tests for InvestigationOrchestrator."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hunting import InvestigationOrchestrator, InvestigationResult
from hunting.contracts.expectations import FieldOp, FieldPredicate
from hunting.contracts.state import Alert, Disposition, TerminalState
from hunting.m4_controller import BudgetLedger
from hunting.m5_adapter import CdbAdapter
from hunting.orchestrator import evaluate_field_predicate
from hunting.registry.loader import load_registry


@pytest.fixture
def test_registry():
    fixture_path = Path(__file__).parent.parent / "fixtures" / "registry_cdb.yaml"
    return load_registry(fixture_path)


@pytest.fixture
def cdb_adapter():
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:00Z",
            "event_id": "4688",
            "native_type": "process_creation",
            "host": "HOST-01",
            "user": "alice",
            "pid": 1001,
            "ppid": 500,
            "cmdline": "powershell.exe -enc JABhID0A...",
            "image": "C:\\Windows\\System32\\powershell.exe",
        },
        {
            "timestamp": "2026-09-01T10:15:00Z",
            "event_id": "3",
            "native_type": "net_connect",
            "host": "HOST-01",
            "ip": "10.0.0.99",
            "port": 443,
        },
    ])
    return adapter


def test_evaluate_field_predicate():
    rows = [
        {"cmdline": "powershell.exe -enc abc", "user": "alice", "port": 443},
        {"cmdline": "cmd.exe /c dir", "user": "bob"},
    ]

    # EQUALS
    assert evaluate_field_predicate(FieldPredicate("user", FieldOp.EQUALS, "alice"), rows) is True
    assert evaluate_field_predicate(FieldPredicate("user", FieldOp.EQUALS, "charlie"), rows) is False

    # CONTAINS
    assert evaluate_field_predicate(FieldPredicate("cmdline", FieldOp.CONTAINS, "powershell"), rows) is True
    assert evaluate_field_predicate(FieldPredicate("cmdline", FieldOp.CONTAINS, "mimikatz"), rows) is False

    # EXISTS
    assert evaluate_field_predicate(FieldPredicate("port", FieldOp.EXISTS), rows) is True
    assert evaluate_field_predicate(FieldPredicate("nonexistent", FieldOp.EXISTS), rows) is False

    # ABSENT
    assert evaluate_field_predicate(FieldPredicate("nonexistent", FieldOp.ABSENT), rows) is True


def test_orchestrator_entity_bearing_investigation(test_registry, cdb_adapter):
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": cdb_adapter},
        auto_confirm_analyst=True,
    )

    alert = Alert(
        id="alt-host-01",
        raw="Suspicious PowerShell Activity",
        source="EDR-Sysmon",
        received_at="2026-09-01T10:14:00Z",
        fields={"host": "HOST-01", "user": "alice"},
    )

    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = orchestrator.investigate(alert, as_of=as_of)

    assert isinstance(result, InvestigationResult)
    assert result.account is not None
    assert result.account.terminal_state in {TerminalState.STOP_RESOLVED, TerminalState.STOP_BOUNDED}
    assert result.account.disposition in {Disposition.MALICIOUS, Disposition.BENIGN, Disposition.UNKNOWN, Disposition.INSUFFICIENT_EVIDENCE}

    # Coverage bound is accurately built
    assert result.account.coverage_bound.known_cells_wildcard > 0
    assert result.account.coverage_bound.known_cells_instance > 0

    # Report is rendered in Markdown
    assert "# Threat Investigation Final Report" in result.report
    assert "## 1. Coverage Accounting" in result.report

    # Observations were ingested into ledger
    assert len(result.ledger.observations) > 0


def test_orchestrator_entity_free_investigation(test_registry, cdb_adapter):
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": cdb_adapter},
        auto_confirm_analyst=True,
    )

    # Entity-free alert (no host, no ip, no user)
    alert = Alert(
        id="alt-broad-01",
        raw="Anomaly detected across environment",
        source="Threat-Intel",
        received_at="2026-09-01T10:14:00Z",
        fields={"description": "General anomaly scan"},
    )

    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = orchestrator.investigate(alert, as_of=as_of)

    assert isinstance(result, InvestigationResult)
    assert result.account is not None
    # Wildcard cells were sampled and explored
    assert result.account.coverage_bound.known_cells_wildcard > 0
    assert result.account.coverage_bound.explored_cells_wildcard > 0

    # Instance entities were discovered during broad sweep
    assert result.account.coverage_bound.known_cells_instance > 0


def test_orchestrator_budget_exhaustion_stops_bounded(test_registry, cdb_adapter):
    # Set tight budget: t_max=1, q_max=1
    tight_budgets = BudgetLedger(t_max=1, q_max=1)
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": cdb_adapter},
        budgets=tight_budgets,
        auto_confirm_analyst=True,
    )

    alert = Alert(
        id="alt-tight-01",
        raw="Testing budget boundary",
        source="EDR",
        received_at="2026-09-01T10:14:00Z",
        fields={"host": "HOST-01"},
    )

    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = orchestrator.investigate(alert, as_of=as_of)

    assert result.account.terminal_state is TerminalState.STOP_BOUNDED
    assert any("budget" in b.lower() for b in result.account.residual.splitlines() if b) or result.account.disposition is Disposition.INSUFFICIENT_EVIDENCE


def test_orchestrator_mandatory_analyst_confirmation_enforced(test_registry, cdb_adapter):
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": cdb_adapter},
        auto_confirm_analyst=False,  # Human confirmation NOT given
    )

    alert = Alert(
        id="alt-conf-01",
        raw="Suspicious Activity",
        source="EDR",
        received_at="2026-09-01T10:14:00Z",
        fields={"host": "HOST-01"},
    )

    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    # When confirmation is required (e.g. MALICIOUS or STOP_BOUNDED) and human_confirmed=False, must raise PermissionError
    with pytest.raises(PermissionError, match="Mandatory analyst confirmation required"):
        orchestrator.investigate(alert, as_of=as_of, analyst_confirmed=False)


def test_orchestrator_query_audit_unique_ids_and_coverage(test_registry, cdb_adapter):
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": cdb_adapter},
        auto_confirm_analyst=True,
    )

    alert = Alert(
        id="alt-audit-01",
        raw="Suspicious Host Activity",
        source="EDR",
        received_at="2026-09-01T10:14:00Z",
        fields={"host": "HOST-01"},
    )

    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = orchestrator.investigate(alert, as_of=as_of)

    # 1. state.queries must be populated
    assert len(result.state.queries) > 0
    assert len(result.state.queries) == len(result.state.query_results)

    # 2. Query IDs must be unique
    query_ids = [q.id for q in result.state.queries]
    assert len(query_ids) == len(set(query_ids))
    assert all(qid.startswith("q-") for qid in query_ids)

    # 3. Requirement coverage attempted_requirements must not be empty
    attempted = result.account.coverage_bound.requirement_coverage.attempted_requirements
    assert len(attempted) > 0
    assert set(attempted) == {q.operation_id for q in result.state.queries}

    # 4. Attributed observations must be marked in ledger
    for obs in result.ledger.observations:
        if obs.attributed_by:
            assert obs not in result.ledger.unattributed_observations


