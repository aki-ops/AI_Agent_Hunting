"""Unit tests for v5 Provider Adapters (Splunk & CDB).

Verifies:
1. SplunkLiveAdapter registers relation-first operations.
2. SplunkLiveAdapter validates field roles against sourcetypes (blocks client_ip on dest_ip, blocks endpoint_host on IIS).
3. SplunkLiveAdapter builds safe parameterized SPL for relation operations.
4. CdbAdapter registers and executes relation-first operations over SQLite with EOF completeness.
"""
from __future__ import annotations

from hunting.contracts.entities import Account, Host, IPAddress
from hunting.contracts.expectations import FieldOp, FieldPredicate
from hunting.m5_adapter.cdb_adapter import CdbAdapter
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter


def test_splunk_adapter_field_role_validation():
    """Verify SplunkLiveAdapter validates field roles against sourcetypes strictly."""
    # 1. client_ip role must NEVER match dest_ip, destination_ip, or server_ip
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("client_ip", "src_ip", "stream:http") is True
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("client_ip", "c_ip", "iis") is True
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("client_ip", "dest_ip", "stream:http") is False
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("client_ip", "destination_ip", "pan:traffic") is False
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("client_ip", "server_ip", "stream:http") is False

    # 2. endpoint_host role must NEVER match IIS web servers or domain fields
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("endpoint_host", "host", "WinEventLog:Security") is True
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("endpoint_host", "ComputerName", "WinEventLog:Security") is True
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("endpoint_host", "host", "iis") is False
    assert SplunkLiveAdapter.validate_field_role_against_sourcetype("endpoint_host", "site", "stream:http") is False


def test_splunk_adapter_registers_relation_operations():
    """Verify SplunkLiveAdapter capability descriptor advertises the 7 relation operations."""
    adapter = SplunkLiveAdapter(index="botsv2")
    desc = adapter.get_capability_descriptor()
    op_ids = {op.id for op in desc.operations}

    expected_ops = {
        "resolve_person_to_account",
        "resolve_account_to_endpoint",
        "resolve_endpoint_to_client_ip",
        "find_web_activity_from_client_ip",
        "find_dns_activity_from_client_ip",
        "find_process_from_endpoint",
        "find_file_change_from_process",
    }
    for op in expected_ops:
        assert op in op_ids


def test_splunk_adapter_builds_relation_spl():
    """Verify SplunkLiveAdapter builds safe parameterized SPL for relation operations."""
    adapter = SplunkLiveAdapter(index="botsv2")

    # Person -> Account
    spl, _, _ = adapter._build_spl("resolve_person_to_account", Account(username="Amber Turing"), "2026-09-01T00:00:00Z/2026-09-02T00:00:00Z", None, 100)
    assert 'index="botsv2"' in spl
    assert 'TargetUserName="*Amber*"' in spl
    assert "WinEventLog:Security" in spl

    # Endpoint -> IP
    spl_ip, _, _ = adapter._build_spl("resolve_endpoint_to_client_ip", Host("wrk-amber"), "2026-09-01T00:00:00Z/2026-09-02T00:00:00Z", None, 100)
    assert 'host="*wrk-amber*"' in spl_ip

    # IP -> Web
    spl_web, _, _ = adapter._build_spl(
        "find_web_activity_from_client_ip",
        IPAddress("10.0.1.25"),
        "2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
        FieldPredicate(field="site", op=FieldOp.CONTAINS, value="competitor-beer.com"),
        100,
    )
    assert 'src_ip="10.0.1.25"' in spl_web
    assert "competitor-beer.com" in spl_web


def test_cdb_adapter_relation_operations():
    """Verify CdbAdapter registers and executes relation operations over SQLite."""
    adapter = CdbAdapter()
    desc = adapter.get_capability_descriptor()
    op_ids = {op.id for op in desc.operations}

    assert "resolve_person_to_account" in op_ids
    assert "resolve_account_to_endpoint" in op_ids
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
