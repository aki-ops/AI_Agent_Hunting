"""Unit and integration tests for Phase 4 (M5 Adapter and Controls)."""
from datetime import datetime, timezone

import pytest

from hunting.contracts.entities import ANY, Account, Domain, Host, IPAddress
from hunting.contracts.expectations import EvidenceRequirement, FieldOp, FieldPredicate
from hunting.contracts.queries import QueryOutcome, QueryResult
from hunting.m1_ledger import ObservationLedger
from hunting.m5_adapter import (
    CdbAdapter,
    execute_any_record_in_scope,
    license_valid_negative,
    validate_field_name,
    validate_operation_id,
    validate_query_params,
)


@pytest.fixture
def cdb_adapter() -> CdbAdapter:
    """Fixture providing an in-memory CDB SQLite adapter seeded with sample events."""
    adapter = CdbAdapter(":memory:")
    events = [
        # Process event
        {
            "timestamp": "2026-09-01T10:14:00Z",
            "event_id": "4688",
            "native_type": "process_creation",
            "host": "HOST-01",
            "user": "alice",
            "pid": 1001,
            "ppid": 500,
            "cmdline": "powershell.exe -enc AAAA",
            "image": "C:\\Windows\\System32\\powershell.exe",
        },
        # Auth event
        {
            "timestamp": "2026-09-01T10:10:00Z",
            "event_id": "4624",
            "native_type": "logon_success",
            "host": "HOST-01",
            "user": "alice",
            "status": "success",
        },
        # Network event
        {
            "timestamp": "2026-09-01T10:15:00Z",
            "event_id": "3",
            "native_type": "net_connect",
            "host": "HOST-01",
            "ip": "192.168.1.100",
            "port": 443,
        },
        # Persistence event
        {
            "timestamp": "2026-09-01T10:16:00Z",
            "event_id": "13",
            "native_type": "registry_mod",
            "host": "HOST-01",
            "file_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\bad",
            "action": "set_value",
        },
        # File write event
        {
            "timestamp": "2026-09-01T10:17:00Z",
            "event_id": "11",
            "native_type": "file_create",
            "host": "HOST-01",
            "file_path": "C:\\temp\\malware.exe",
        },
        # DNS event
        {
            "timestamp": "2026-09-01T10:18:00Z",
            "event_id": "22",
            "native_type": "dns_query",
            "host": "HOST-01",
            "domain": "evil-c2.corp.internal",
        },
    ]
    adapter.insert_events(events)
    return adapter


# ---------------------------------------------------------------------------
# Acceptance 1: Seven workflows execute on the CDB adapter
# ---------------------------------------------------------------------------

def test_seven_workflows_execute_on_cdb_adapter(cdb_adapter: CdbAdapter):
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"
    host1 = Host(name="HOST-01")

    # 1. ProcessLineage -> process_ancestry
    res_proc = cdb_adapter.execute_query("cdb_process_search", host1, window)
    assert res_proc.executed_ok is True
    assert len(res_proc.rows) >= 1
    assert res_proc.complete is True

    # 2. LogonHistory -> authentication_activity
    res_auth = cdb_adapter.execute_query("cdb_auth_search", Account(username="alice"), window)
    assert res_auth.executed_ok is True
    assert len(res_auth.rows) >= 1

    # 3. NetworkConnections -> network_connection
    res_net = cdb_adapter.execute_query("cdb_net_search", IPAddress(address="192.168.1.100"), window)
    assert res_net.executed_ok is True
    assert len(res_net.rows) >= 1

    # 4. PersistenceArtifacts -> persistence_change
    res_pers = cdb_adapter.execute_query("cdb_persistence_search", host1, window)
    assert res_pers.executed_ok is True
    assert len(res_pers.rows) >= 1

    # 5. FileWrites -> file_modification
    res_file = cdb_adapter.execute_query("cdb_file_search", host1, window)
    assert res_file.executed_ok is True
    assert len(res_file.rows) >= 1

    # 6. DNSQueries -> dns_activity
    res_dns = cdb_adapter.execute_query("cdb_dns_search", Domain(name="evil-c2.corp.internal"), window)
    assert res_dns.executed_ok is True
    assert len(res_dns.rows) >= 1

    # 7. BroadSweep -> scope_records (on a wildcard Cell)
    res_sweep = cdb_adapter.execute_query("cdb_scope_scan", ANY, window)
    assert res_sweep.executed_ok is True
    assert len(res_sweep.rows) == 6  # All 6 events returned
    assert res_sweep.complete is True


# ---------------------------------------------------------------------------
# Acceptance 2: Three controls execute without entering the observation ledger
# ---------------------------------------------------------------------------

def test_three_controls_execute_without_entering_observation_ledger(cdb_adapter: CdbAdapter):
    ledger = ObservationLedger()
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"
    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 1. ScopeHealthControl
    ctrl_health = cdb_adapter.control_health(window, as_of=as_of)
    assert ctrl_health.executed_ok is True
    ledger.record_control_result(ctrl_health)

    # 2. AnyRecordInScope
    ctrl_any = cdb_adapter.control_any_record(window)
    assert ctrl_any.executed_ok is True
    assert (ctrl_any.count or 0) > 0
    ledger.record_control_result(ctrl_any)

    # 3. PredicateObservabilityControl
    pred = FieldPredicate(field="cmdline", op=FieldOp.CONTAINS, value="powershell")
    ctrl_obs = cdb_adapter.control_observability(EvidenceRequirement.PROCESS_ANCESTRY, pred)
    assert ctrl_obs.executed_ok is True
    assert ctrl_obs.predicate_observable is True
    ledger.record_control_result(ctrl_obs)

    # Inviolable rule: Controls NEVER mint observations in the ledger!
    assert len(ledger.observations) == 0


# ---------------------------------------------------------------------------
# Acceptance 3: Exactly-limit and cursor-more results remain incomplete
# ---------------------------------------------------------------------------

def test_exactly_limit_and_more_results_remain_incomplete(cdb_adapter: CdbAdapter):
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"

    # Limit = 2 (there are 6 events in DB). Fetches limit+1=3 rows internally.
    # Returns 2 rows, complete must be False!
    res_partial = cdb_adapter.execute_query("cdb_scope_scan", ANY, window, limit=2)
    assert len(res_partial.rows) == 2
    assert res_partial.complete is False
    assert res_partial.cursor == "2"

    # Second page with offset=2, limit=2
    res_page2 = cdb_adapter.execute_query("cdb_scope_scan", ANY, window, limit=2, offset=2)
    assert len(res_page2.rows) == 2
    assert res_page2.complete is False
    assert res_page2.cursor == "4"

    # Third page with offset=4, limit=2 (remaining 2 rows).
    # Since total events = 6, offset 4 with limit 2 returns exactly 2 rows and EOF is established!
    res_page3 = cdb_adapter.execute_query("cdb_scope_scan", ANY, window, limit=2, offset=4)
    assert len(res_page3.rows) == 2
    assert res_page3.complete is True
    assert res_page3.cursor is None


# ---------------------------------------------------------------------------
# Acceptance 4: Negative evidence licensing & failures
# ---------------------------------------------------------------------------

def test_license_valid_negative_and_blockers(cdb_adapter: CdbAdapter):
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"
    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Empty target query for a non-existent host
    non_existent_host = Host(name="HOST-GHOST")
    target_res = cdb_adapter.execute_query("cdb_process_search", non_existent_host, window)
    assert target_res.executed_ok is True
    assert target_res.complete is True
    assert len(target_res.rows) == 0

    ctrl_health = cdb_adapter.control_health(window, as_of=as_of)
    ctrl_any = cdb_adapter.control_any_record(window)
    pred = FieldPredicate(field="cmdline", op=FieldOp.EQUALS, value="whoami")
    ctrl_pred = cdb_adapter.control_observability(EvidenceRequirement.PROCESS_ANCESTRY, pred)

    # All controls pass -> licenses VALID_NEGATIVE
    assert license_valid_negative(target_res, ctrl_health, ctrl_any, ctrl_pred) is True

    # Failure Case A: Incomplete / truncated query cannot license negative
    incomplete_res = QueryResult("q", QueryOutcome.UNKNOWN, executed_ok=True, complete=False, rows=[])
    assert license_valid_negative(incomplete_res, ctrl_health, ctrl_any, ctrl_pred) is False

    # Failure Case B: Stale scope / Ingestion lag violation
    stale_as_of = datetime(2026, 9, 1, 10, 5, 0, tzinfo=timezone.utc)  # window ends at 11:00 > as_of - lag
    stale_health = cdb_adapter.control_health(window, as_of=stale_as_of)
    assert stale_health.executed_ok is False
    assert license_valid_negative(target_res, stale_health, ctrl_any, ctrl_pred) is False

    # Failure Case C: Field absent / not observable
    unobservable_pred = FieldPredicate(field="non_existent_proprietary_tag", op=FieldOp.EXISTS)
    failed_pred_ctrl = cdb_adapter.control_observability(
        EvidenceRequirement.PROCESS_ANCESTRY,
        unobservable_pred,
        observed_fields={"timestamp", "host"},
    )
    assert failed_pred_ctrl.predicate_observable is False
    assert license_valid_negative(target_res, ctrl_health, ctrl_any, failed_pred_ctrl) is False

    # Failure Case D: Zero records in scope (telemetry pipeline unverified)
    empty_any_ctrl = execute_any_record_in_scope(cdb_adapter.scope, record_count=0)
    assert license_valid_negative(target_res, ctrl_health, empty_any_ctrl, ctrl_pred) is False


# ---------------------------------------------------------------------------
# Allowlist validation
# ---------------------------------------------------------------------------

def test_adapter_allowlist_validation():
    # Valid operation and params
    validate_query_params("cdb_scope_scan", {"window": "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z", "limit": 50})

    # Disallowed operation raises ValueError
    with pytest.raises(ValueError, match="Disallowed operation"):
        validate_operation_id("drop_database_table")

    # Disallowed field raises ValueError
    with pytest.raises(ValueError, match="Disallowed field"):
        validate_field_name("attacker_injected_column; DROP TABLE events--")

    # Malformed time window
    with pytest.raises(ValueError, match="Invalid window"):
        validate_query_params("cdb_scope_scan", {"window": "invalid_window"})
