"""CDB (Common Database Benchmark) SQLite Adapter.

Implements the executable M5 adapter vertical slice for replayable testing:
  - Supports the 7 investigation workflows (mint observations):
      1. ProcessLineage -> process_ancestry
      2. LogonHistory -> authentication_activity
      3. NetworkConnections -> network_connection
      4. PersistenceArtifacts -> persistence_change
      5. FileWrites -> file_modification
      6. DNSQueries -> dns_activity
      7. BroadSweep -> scope_records (only operation licensed to mark scope coverage)
  - Supports the 3 control operations (never mint observations):
      1. ScopeHealthControl
      2. AnyRecordInScope
      3. PredicateObservabilityControl
  - Strict completeness contract: queries fetch limit + 1 internally to verify EOF.
  - Generates published CapabilityDescriptor and executes safe parameterized SQL.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any

from hunting.contracts.capabilities import CapabilityDescriptor
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import ANY, Account, Domain, EntityRef, File, Host, IPAddress, Process
from hunting.contracts.expectations import EvidenceRequirement, FieldOp, FieldPredicate
from hunting.contracts.queries import (
    CapabilityBinding,
    ControlResult,
    Diagnostic,
    ProviderOperation,
    QueryOutcome,
    QueryResult,
)
from hunting.m5_adapter.allowlist import validate_query_params, validate_time_window_format
from hunting.m5_adapter.controls import (
    execute_any_record_in_scope,
    execute_predicate_observability_control,
    execute_scope_health_control,
)


class CdbAdapter:
    """SQLite-backed provider adapter for CDB telemetry."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

        self.provider_id = "cdb"
        self.scope = ProviderScope(
            provider_id="cdb",
            native_partition={"database": "cdb.sqlite", "table": "events"},
            scope_id="cdb_security",
        )

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_id TEXT,
                    native_type TEXT,
                    host TEXT,
                    user TEXT,
                    pid INTEGER,
                    ppid INTEGER,
                    cmdline TEXT,
                    image TEXT,
                    ip TEXT,
                    port INTEGER,
                    domain TEXT,
                    file_path TEXT,
                    action TEXT,
                    status TEXT,
                    raw_ref TEXT
                )
            """)

    def insert_events(self, events: list[dict[str, Any]]) -> None:
        """Insert test fixture records into SQLite."""
        cols = [
            "timestamp", "event_id", "native_type", "host", "user",
            "pid", "ppid", "cmdline", "image", "ip", "port",
            "domain", "file_path", "action", "status", "raw_ref"
        ]
        placeholders = ", ".join("?" for _ in cols)
        col_names = ", ".join(cols)
        sql = f"INSERT INTO events ({col_names}) VALUES ({placeholders})"

        with self._conn:
            for ev in events:
                vals = [ev.get(col) for col in cols]
                self._conn.execute(sql, vals)

    def get_capability_descriptor(self) -> CapabilityDescriptor:
        """Publish the machine-readable capability descriptor for CDB."""
        op_scope_ids = (self.scope.scope_id,)

        operations = (
            ProviderOperation("cdb_scope_scan", "cdb", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_process_search", "cdb", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_auth_search", "cdb", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_net_search", "cdb", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_persistence_search", "cdb", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_file_search", "cdb", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
            ProviderOperation("cdb_dns_search", "cdb", op_scope_ids, pagination="offset", limit_semantics="eof_required"),
        )

        bindings = (
            CapabilityBinding(EvidenceRequirement.SCOPE_RECORDS, "cdb", "cdb_scope_scan", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.PROCESS_ANCESTRY, "cdb", "cdb_process_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.AUTHENTICATION_ACTIVITY, "cdb", "cdb_auth_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.NETWORK_CONNECTION, "cdb", "cdb_net_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.PERSISTENCE_CHANGE, "cdb", "cdb_persistence_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.FILE_MODIFICATION, "cdb", "cdb_file_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.DNS_ACTIVITY, "cdb", "cdb_dns_search", confidence="EXACT"),
        )

        return CapabilityDescriptor(
            provider_id="cdb",
            scopes=(self.scope,),
            operations=operations,
            bindings=bindings,
        )

    def execute_query(
        self,
        operation_id: str,
        entity: EntityRef | None,
        window: str,
        predicate: FieldPredicate | None = None,
        limit: int = 100,
        offset: int = 0,
        query_id: str = "q-001",
    ) -> QueryResult:
        """Execute a parameterized query over SQLite events table with EOF completeness check."""
        params = {"window": window, "limit": limit}
        validate_query_params(operation_id, params)

        start_dt, end_dt = validate_time_window_format(window)
        start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        conditions: list[str] = ["timestamp >= ?", "timestamp <= ?"]
        sql_params: list[Any] = [start_iso, end_iso]

        # Entity filtering
        if entity and entity != ANY:
            if isinstance(entity, Host):
                conditions.append("host = ?")
                sql_params.append(entity.name)
            elif isinstance(entity, Account):
                conditions.append("user = ?")
                sql_params.append(entity.username)
            elif isinstance(entity, Process):
                conditions.append("host = ? AND pid = ?")
                sql_params.extend([entity.host, entity.pid])
            elif isinstance(entity, IPAddress):
                conditions.append("ip = ?")
                sql_params.append(entity.address)
            elif isinstance(entity, Domain):
                conditions.append("domain = ?")
                sql_params.append(entity.name)
            elif isinstance(entity, File):
                conditions.append("host = ? AND file_path = ?")
                sql_params.extend([entity.host, entity.path])

        # Predicate filtering
        if predicate:
            fn = predicate.field.strip().lower()
            if predicate.op == FieldOp.EQUALS:
                conditions.append(f"{fn} = ?")
                sql_params.append(predicate.value)
            elif predicate.op == FieldOp.CONTAINS:
                conditions.append(f"{fn} LIKE ?")
                sql_params.append(f"%{predicate.value}%")
            elif predicate.op == FieldOp.EXISTS:
                conditions.append(f"{fn} IS NOT NULL AND {fn} != ''")
            elif predicate.op == FieldOp.ABSENT:
                conditions.append(f"({fn} IS NULL OR {fn} = '')")

        # Specific operation constraints
        if operation_id == "cdb_process_search":
            conditions.append("(pid IS NOT NULL OR image IS NOT NULL OR cmdline IS NOT NULL)")
        elif operation_id == "cdb_auth_search":
            conditions.append("(user IS NOT NULL OR event_id = '4624' OR event_id = '4625')")
        elif operation_id == "cdb_net_search":
            conditions.append("(ip IS NOT NULL OR port IS NOT NULL)")
        elif operation_id == "cdb_file_search":
            conditions.append("file_path IS NOT NULL")
        elif operation_id == "cdb_dns_search":
            conditions.append("domain IS NOT NULL")

        where_clause = " AND ".join(conditions)
        # Fetch limit + 1 to establish EOF rigorously
        sql = f"SELECT * FROM events WHERE {where_clause} ORDER BY timestamp ASC LIMIT ? OFFSET ?"
        sql_params.extend([limit + 1, offset])

        try:
            cur = self._conn.execute(sql, sql_params)
            rows = [dict(r) for r in cur.fetchall()]
        except Exception as err:
            return QueryResult(
                query_id=query_id,
                outcome=QueryOutcome.UNKNOWN,
                executed_ok=False,
                complete=False,
                diagnostic=Diagnostic.QUERY_FAILED,
                truncation_reason=str(err),
            )

        if len(rows) > limit:
            # More rows exist beyond limit -> incomplete!
            return_rows = rows[:limit]
            complete = False
            cursor = str(offset + limit)
        else:
            # Reached true EOF -> complete!
            return_rows = rows
            complete = True
            cursor = None

        outcome = QueryOutcome.ROWS if return_rows else QueryOutcome.UNKNOWN
        observed_fields = list({k for r in return_rows for k in r.keys()})
        native_types = list({str(r["native_type"]) for r in return_rows if r.get("native_type")})

        return QueryResult(
            query_id=query_id,
            outcome=outcome,
            executed_ok=True,
            complete=complete,
            rows=return_rows,
            observed_fields=observed_fields,
            native_types=native_types,
            cursor=cursor,
        )

    # -----------------------------------------------------------------------
    # Negative Evidence Controls (never mint observations)
    # -----------------------------------------------------------------------

    def control_health(self, window: str, as_of: datetime | None = None) -> ControlResult:
        """Run ScopeHealthControl."""
        return execute_scope_health_control(self.scope, window, as_of=as_of)

    def control_any_record(self, window: str) -> ControlResult:
        """Run AnyRecordInScope check."""
        start_dt, end_dt = validate_time_window_format(window)
        start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        cur = self._conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp <= ?",
            [start_iso, end_iso],
        )
        count = cur.fetchone()[0]
        return execute_any_record_in_scope(self.scope, record_count=count)

    def control_observability(
        self,
        requirement: EvidenceRequirement,
        predicate: FieldPredicate | None,
        observed_fields: set[str] | None = None,
    ) -> ControlResult:
        """Run PredicateObservabilityControl."""
        fields = observed_fields if observed_fields is not None else {
            "timestamp", "event_id", "host", "user", "pid", "ppid",
            "cmdline", "image", "ip", "port", "domain", "file_path",
        }
        return execute_predicate_observability_control(self.scope, requirement, predicate, fields)


__all__ = ["CdbAdapter"]
