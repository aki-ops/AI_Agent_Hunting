"""Unit tests for the CDB (SQLite) provider adapter: relation-first operations, completeness, scoping."""
from __future__ import annotations

from hunting.adapters.cdb_adapter import CdbAdapter
from hunting.contracts.entities import Account, IPAddress


def test_cdb_adapter_relation_operations():
    """Verify CdbAdapter registers and executes relation operations over SQLite."""
    adapter = CdbAdapter()
    desc = adapter.get_capability_descriptor()
    op_ids = {op.id for op in desc.operations}

    assert "resolve_person_to_account" in op_ids
    assert "resolve_account_to_endpoint" in op_ids
    endpoint = next(op for op in desc.operations if op.id == "resolve_account_to_endpoint")
    assert endpoint.output_value_bindings["object"] == ("ComputerName", "host")
    assert "resolve_endpoint_to_client_ip" in op_ids
    assert "find_web_activity_from_client_ip" in op_ids

    # Insert test events
    events = [
        {
            "timestamp": "2026-09-01T08:00:00Z",
            "event_id": "4624",
            "native_type": "WinEventLog:Security",
            "host": "wrk-amber",
            "user": "amber.turing",
            "ip": "10.0.1.25",
            "action": "logon",
            "status": "success",
        },
        {
            "timestamp": "2026-09-01T09:00:00Z",
            "event_id": "http-1",
            "native_type": "stream:http",
            "host": "wrk-amber",
            "ip": "10.0.1.25",
            "domain": "competitor-beer.com",
            "action": "GET",
            "status": "200",
        },
    ]
    adapter.insert_events(events)

    # 1. Test resolve_person_to_account / logon
    res1 = adapter.execute_query(
        operation_id="resolve_person_to_account",
        entity=Account("amber.turing"),
        window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
    )
    assert res1.executed_ok is True
    assert len(res1.rows) == 1
    assert res1.rows[0]["user"] == "amber.turing"
    assert res1.rows[0]["host"] == "wrk-amber"

    # 2. Test find_web_activity_from_client_ip
    res2 = adapter.execute_query(
        operation_id="find_web_activity_from_client_ip",
        entity=IPAddress("10.0.1.25"),
        window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
    )
    assert res2.executed_ok is True
    assert len(res2.rows) == 1
    assert res2.rows[0]["domain"] == "competitor-beer.com"


def test_cdb_person_seed_is_filtered_and_each_result_keeps_own_sql():
    adapter = CdbAdapter()
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T08:00:00Z", "event_id": "1",
            "native_type": "identity", "host": "mallory-mac", "user": "mallory",
        },
        {
            "timestamp": "2026-09-01T09:00:00Z", "event_id": "2",
            "native_type": "identity", "host": "alice-pc", "user": "alice",
        },
    ])
    result = adapter.execute_query(
        operation_id="resolve_person_to_account", entity="Mallory",
        window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
    )
    assert [row["user"] for row in result.rows] == ["mallory"]
    assert result.native_query is not None
    assert "raw_ref LIKE" in result.native_query
    assert "host = ?" not in result.native_query
    assert result.provider == "cdb"
