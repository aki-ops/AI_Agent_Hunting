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

import re
import sqlite3
from datetime import datetime
from typing import Any

from hunting.contracts.capabilities import CapabilityDescriptor, ProviderCapabilityCatalog
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
from hunting.contracts.source_profile import ProbeSpec, TelemetrySourceProfile
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

    def discover_full_capabilities(self) -> ProviderCapabilityCatalog:
        """Return the runtime census catalog for the SQLite deployment."""
        descriptor = self.get_capability_descriptor()
        table_fields = [
            "id", "timestamp", "event_id", "native_type", "host", "user",
            "pid", "ppid", "cmdline", "image", "ip", "port", "domain",
            "file_path", "action", "status", "raw_ref",
        ]
        return ProviderCapabilityCatalog(
            provider_id=self.provider_id,
            status="ONLINE",
            supported_evidence_types=sorted(
                {binding.evidence_requirement.value for binding in descriptor.bindings}
            ),
            observable_fields=table_fields,
            retention_days=self.scope.retention_days or 4000,
            details={"database": self.db_path, "table": "events"},
            operations=list(descriptor.operations),
            permissions=["read_sqlite"],
            completeness_semantics="complete only on EOF; limit+1 detects pagination",
            partitions={
                self.scope.scope_id: {
                    "native_partition": dict(self.scope.native_partition),
                    "coverage_start": self.scope.coverage_start,
                    "coverage_end": self.scope.coverage_end,
                    "retention_days": self.scope.retention_days,
                    "known_gaps": [dict(value) for value in self.scope.known_gaps],
                }
            },
            schemas={"events": {"fields": table_fields}},
            aliases={
                "client_ip": ("ip",),
                "endpoint_host": ("host",),
                "account_name": ("user",),
                "domain_name": ("domain",),
                "process_name": ("image",),
            },
        )

    def execute_capability_probe(
        self,
        *,
        profile: TelemetrySourceProfile,
        probe: ProbeSpec,
        time_window: str | None = None,
        query_id: str = "probe-001",
    ) -> QueryResult:
        """Run a bounded schema/co-occurrence probe for the CDB source.

        Column identifiers are resolved from the already-censused profile and
        checked against SQLite metadata before interpolation. This probe
        establishes observability only; it never promotes a hunt claim.
        """
        if profile.provider_id != self.provider_id or profile.source_id != "cdb:source:events":
            return QueryResult(
                query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                complete=False, diagnostic=Diagnostic.UNSUPPORTED_REQUIREMENT,
                truncation_reason="profile does not belong to this CDB source",
                provider=self.provider_id, index=self.db_path,
            )
        valid_columns = {
            str(row[1])
            for row in self._conn.execute("PRAGMA table_info(events)").fetchall()
        }
        selected: list[str] = []
        for field_id in probe.field_ids:
            field = profile.field(field_id)
            if field is None or field.name not in valid_columns:
                return QueryResult(
                    query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                    complete=False, diagnostic=Diagnostic.PARSE_FAILED,
                    truncation_reason=f"probe field is not a CDB column: {field_id}",
                    provider=self.provider_id, index=self.db_path,
                )
            selected.append(field.name)
        if not selected:
            selected = ["timestamp", "native_type"]

        where = ""
        params: list[Any] = []
        if time_window:
            start, end = validate_time_window_format(time_window)
            where = " WHERE timestamp >= ? AND timestamp <= ?"
            params.extend([start.isoformat(), end.isoformat()])
        quoted = ", ".join('"' + name.replace('"', '""') + '"' for name in selected)
        sql = f"SELECT {quoted} FROM events{where} LIMIT ?"
        params.append(probe.max_rows + 1)
        try:
            rows = [dict(row) for row in self._conn.execute(sql, params).fetchall()]
        except Exception as error:
            return QueryResult(
                query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                complete=False, diagnostic=Diagnostic.QUERY_FAILED,
                truncation_reason=str(error), native_query=sql,
                provider=self.provider_id, index=self.db_path,
            )
        complete = len(rows) <= probe.max_rows
        returned = rows[:probe.max_rows]
        return QueryResult(
            query_id=query_id,
            outcome=QueryOutcome.ROWS if returned else QueryOutcome.UNKNOWN,
            executed_ok=True,
            complete=complete,
            rows=returned,
            observed_fields=selected,
            native_query=sql,
            provider=self.provider_id,
            index=self.db_path,
            row_count=len(returned),
            cursor=None if complete else str(probe.max_rows),
            truncation_reason=None if complete else "probe_limit_exceeded",
        )

    def get_capability_descriptor(self) -> CapabilityDescriptor:
        """Publish the machine-readable capability descriptor for CDB."""
        op_scope_ids = (self.scope.scope_id,)

        def operation(
            operation_id: str,
            fact_kinds: tuple[str, ...],
            input_kinds: tuple[str, ...],
            output_fields: tuple[str, ...],
            params_schema: dict[str, Any] | None = None,
            *,
            input_roles: tuple[str, ...] = (),
            output_roles: tuple[str, ...] = (),
            output_entity_kinds: tuple[str, ...] = (),
            native_field_bindings: dict[str, tuple[str, ...]] | None = None,
            guaranteed_relations: tuple[str, ...] = (),
            output_value_bindings: dict[str, tuple[str, ...]] | None = None,
            output_binding_entity_kinds: dict[str, str] | None = None,
            supported_constraints: tuple[str, ...] = (),
            searchable_constraints: tuple[str, ...] = (),
            query_builder: str = "",
        ) -> ProviderOperation:
            relation_by_fact = {
                "identity_binding": "associated_with",
                "web_request": "visited",
                "web_request_activity": "visited",
                "web_navigation": "visited",
                "dns_activity": "resolved",
                "network_connection": "communicated_with",
                "process_ancestry": "executed",
                "server_side_execution": "executed",
                "file_modification": "modified",
                "file_artifact": "modified",
                "authentication_activity": "authenticated",
                "remote_authentication": "authenticated",
                "persistence_change": "persisted",
                "software_version": "has_version",
            }
            declared_relations = guaranteed_relations or tuple(dict.fromkeys(
                relation_by_fact[fact] for fact in fact_kinds if fact in relation_by_fact
            ))
            value_fields = tuple(
                field_name for field_name in output_fields
                if field_name.casefold() not in {"timestamp", "host", "user", "native_type", "sourcetype"}
            )
            derived_output_kinds = tuple(dict.fromkeys(
                kind for field_name in output_fields
                for kind, markers in {
                    "account": ("user", "username"),
                    "host": ("host", "computer"),
                    "ip": ("ip", "client_ip", "server_ip", "source_ip", "destination_ip"),
                    "domain": ("domain", "site", "query", "cs_host"),
                    "process": ("image", "process", "cmdline"),
                    "file": ("file_path", "path", "targetfilename"),
                    "version": ("version", "productversion", "fileversion"),
                }.items() if field_name.casefold() in {marker.casefold() for marker in markers}
            ))
            if operation_id == "resolve_person_to_account" and output_value_bindings is None:
                output_value_bindings = {"object": ("user",)}
            return ProviderOperation(
                operation_id,
                "cdb",
                op_scope_ids,
                params_schema=params_schema or {"window": "interval"},
                pagination="offset",
                limit_semantics="complete only on EOF",
                input_entity_kinds=input_kinds,
                output_entity_kinds=output_entity_kinds or derived_output_kinds,
                output_fields=output_fields,
                output_fact_kinds=fact_kinds,
                input_roles=input_roles,
                output_roles=output_roles,
                native_field_bindings=native_field_bindings or {},
                guaranteed_relations=declared_relations,
                output_value_bindings=output_value_bindings or ({"object": value_fields} if value_fields else {}),
                output_binding_entity_kinds=output_binding_entity_kinds or {},
                supported_constraints=supported_constraints,
                searchable_constraints=searchable_constraints,
                query_builder=query_builder,
                completeness="limit+1 EOF proof",
            )

        operations = (
            operation("cdb_scope_scan", ("scope_records", "operational_baseline"), ("ANY",), ("native_type", "timestamp")),
            operation("search_text", ("scope_records", "operational_baseline"), ("ANY",), ("raw_ref", "native_type"), {"terms": "list[string]", "window": "interval"}),
            operation("cdb_process_search", ("process_ancestry", "server_side_execution"), ("host", "account", "process"), ("host", "user", "pid", "ppid", "cmdline", "image")),
            operation("cdb_auth_search", ("authentication_activity", "remote_authentication"), ("host", "account"), ("host", "user", "event_id", "status")),
            operation("cdb_net_search", ("network_connection",), ("host", "ip", "process"), ("host", "ip", "port")),
            operation("cdb_persistence_search", ("persistence_change",), ("host", "account"), ("host", "action", "file_path")),
            operation("cdb_file_search", ("file_modification", "file_artifact"), ("host", "process", "file"), ("host", "image", "file_path", "action")),
            operation("cdb_dns_search", ("dns_activity",), ("host", "ip", "domain"), ("host", "ip", "domain")),
            operation("cdb_web_requests", ("web_request", "web_request_activity", "web_navigation"), ("host", "ip", "domain"), ("host", "ip", "domain", "native_type")),
            operation("cdb_web_search", ("web_request", "web_request_activity", "web_navigation"), ("host", "ip", "domain"), ("host", "ip", "domain", "native_type")),
            operation("resolve_person_to_account", ("identity_binding",), ("person",), ("user",), output_roles=("subject_identity", "account_identity"), native_field_bindings={"subject_identity": ("user",), "account_identity": ("user",)}, query_builder="cdb.identity.person_to_account.v1"),
            operation(
                "resolve_account_to_endpoint", ("identity_binding",), ("account",),
                ("user", "host", "ComputerName", "WorkstationName"),
                output_entity_kinds=("host",),
                # WorkstationName is the client workstation in Windows logon
                # telemetry, not the endpoint that owns the event.  Binding
                # it first caused an identity pivot to an unrelated host.
                output_value_bindings={"object": ("ComputerName", "host")},
                output_binding_entity_kinds={"object": "host"},
                guaranteed_relations=("associated_with",),
            ),
            operation("resolve_endpoint_to_client_ip", ("identity_binding",), ("host",), ("host", "ip")),
            operation("find_web_activity_from_client_ip", ("web_request", "web_request_activity", "web_navigation"), ("ip",), ("ip", "domain", "native_type")),
            operation("find_dns_activity_from_client_ip", ("dns_activity",), ("ip",), ("ip", "domain")),
            operation("find_web_activity_from_endpoint", ("web_request", "web_request_activity", "web_navigation"), ("host",), ("host", "domain", "native_type")),
            operation("find_process_from_endpoint", ("process_ancestry", "server_side_execution"), ("host",), ("host", "pid", "ppid", "image", "cmdline")),
            operation("find_file_change_from_endpoint", ("file_modification", "file_artifact"), ("host",), ("host", "file_path", "action")),
            operation("find_file_change_from_process", ("file_modification", "file_artifact"), ("process",), ("host", "image", "file_path", "action")),
        )

        bindings = (
            CapabilityBinding(EvidenceRequirement.SCOPE_RECORDS, "cdb", "cdb_scope_scan", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.PROCESS_ANCESTRY, "cdb", "cdb_process_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.AUTHENTICATION_ACTIVITY, "cdb", "cdb_auth_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.NETWORK_CONNECTION, "cdb", "cdb_net_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.PERSISTENCE_CHANGE, "cdb", "cdb_persistence_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.FILE_MODIFICATION, "cdb", "cdb_file_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.DNS_ACTIVITY, "cdb", "cdb_dns_search", confidence="EXACT"),
            CapabilityBinding(EvidenceRequirement.WEB_REQUEST, "cdb", "cdb_web_requests", confidence="EXACT"),
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
        native_query: str | None = None,
        search_terms: list[str] | tuple[str, ...] | None = None,
        parameters: dict[str, Any] | None = None,
        query_intent: dict[str, Any] | None = None,
    ) -> QueryResult:
        """Execute a parameterized query over SQLite events table with EOF completeness check."""
        parameters = dict(parameters or {})
        params = {"window": window, "limit": limit}
        validate_query_params(operation_id, params)

        if operation_id.startswith("runtime:") and isinstance(parameters.get("runtime_capability"), dict):
            return self._execute_runtime_capability(
                parameters["runtime_capability"], entity, window, limit, offset, query_id
            )

        start_dt, end_dt = validate_time_window_format(window)
        start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        conditions: list[str] = ["timestamp >= ?", "timestamp <= ?"]
        sql_params: list[Any] = [start_iso, end_iso]

        if operation_id == "search_text":
            terms = [str(t).strip() for t in (search_terms or []) if str(t).strip()]
            text_cols = ("raw_ref", "cmdline", "image", "file_path", "domain", "user", "host", "native_type")
            for term in terms:
                conditions.append("(" + " OR ".join(f"COALESCE({col}, '') LIKE ?" for col in text_cols) + ")")
                sql_params.extend([f"%{term}%"] * len(text_cols))

        # A person is a semantic search seed, not a provider entity type.  It
        # must still constrain identity resolution; otherwise the operation
        # returns the first arbitrary users in the database and the next
        # graph step can silently pivot from Mallory to Alice.
        if operation_id == "resolve_person_to_account" and isinstance(entity, str):
            person = entity.strip()
            if person:
                conditions.append("(user LIKE ? OR raw_ref LIKE ?)")
                sql_params.extend([f"%{person}%", f"%{person}%"])

        # Entity filtering
        if entity and entity != ANY:
            if isinstance(entity, Host):
                h = entity.name or (str(entity.kind) if str(entity.kind) != "host" else "")
                conditions.append("host = ?")
                sql_params.append(h)
            elif isinstance(entity, Account):
                u = entity.username or (str(entity.kind) if str(entity.kind) != "account" else "")
                conditions.append("user = ?")
                sql_params.append(u)
            elif isinstance(entity, Process):
                conditions.append("host = ? AND pid = ?")
                sql_params.extend([entity.host, entity.pid])
            elif isinstance(entity, IPAddress):
                ip_val = entity.address or (str(entity.kind) if str(entity.kind) != "ip" else "")
                conditions.append("ip = ?")
                sql_params.append(ip_val)
            elif isinstance(entity, Domain):
                domain_val = entity.name or (str(entity.kind) if str(entity.kind) != "domain" else "")
                conditions.append("domain = ?")
                sql_params.append(domain_val)
            elif isinstance(entity, File):
                conditions.append("host = ? AND file_path = ?")
                sql_params.extend([entity.host, entity.path])

        # Predicate filtering
        if predicate:
            fn = predicate.field.strip().lower()
            field_map = {
                "destination_port": "port",
                "source_port": "port",
                "destination_ip": "ip",
                "source_ip": "ip",
                "command_line": "cmdline",
                "process_id": "pid",
                "parent_process_id": "ppid",
            }
            fn = field_map.get(fn, fn)
            valid_cols = {
                "id", "timestamp", "event_id", "native_type", "host", "user",
                "pid", "ppid", "cmdline", "image", "ip", "port",
                "domain", "file_path", "action", "status", "raw_ref",
            }
            if fn in valid_cols:
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
        if operation_id in ("cdb_process_search", "cdb_process_lineage"):
            conditions.append("(pid IS NOT NULL OR image IS NOT NULL OR cmdline IS NOT NULL)")
        elif operation_id in ("cdb_auth_search", "cdb_logon_history"):
            conditions.append("(user IS NOT NULL OR event_id = '4624' OR event_id = '4625')")
        elif operation_id in ("cdb_net_search", "cdb_network_connections"):
            conditions.append("(ip IS NOT NULL OR port IS NOT NULL)")
        elif operation_id in ("cdb_file_search", "cdb_file_writes"):
            conditions.append("file_path IS NOT NULL")
        elif operation_id in ("cdb_dns_search", "cdb_dns_queries"):
            conditions.append("domain IS NOT NULL")
        elif operation_id in ("cdb_web_search", "cdb_web_requests"):
            conditions.append("(domain IS NOT NULL OR native_type LIKE '%http%' OR native_type LIKE '%web%')")
        elif operation_id in ("resolve_person_to_account", "resolve_account_to_endpoint"):
            conditions.append("(user IS NOT NULL OR event_id IN ('4624', '4625') OR action = 'logon')")
        elif operation_id == "resolve_endpoint_to_client_ip":
            conditions.append("(host IS NOT NULL AND ip IS NOT NULL)")
        elif operation_id == "find_web_activity_from_client_ip":
            conditions.append("(domain IS NOT NULL OR native_type LIKE '%http%' OR native_type LIKE '%web%')")
        elif operation_id == "find_dns_activity_from_client_ip":
            conditions.append("(domain IS NOT NULL OR native_type LIKE '%dns%')")
        elif operation_id == "find_web_activity_from_endpoint":
            conditions.append("(domain IS NOT NULL OR native_type LIKE '%http%' OR native_type LIKE '%web%')")
        elif operation_id == "find_process_from_endpoint":
            conditions.append("(pid IS NOT NULL OR image IS NOT NULL OR cmdline IS NOT NULL)")
        elif operation_id == "find_file_change_from_endpoint":
            conditions.append("(file_path IS NOT NULL OR action LIKE '%write%' OR action LIKE '%create%')")
        elif operation_id == "find_file_change_from_process":
            conditions.append("(file_path IS NOT NULL OR action LIKE '%write%' OR action LIKE '%create%')")
        elif operation_id == "custom_operation" and native_query:
            import re
            for col in ("cmdline", "image", "user", "ip", "port", "domain", "file_path", "site", "uri"):
                m = re.search(rf"\b{col}\b\s*(?:=|LIKE)\s*['\"]?([^'\",\)]+)['\"]?", native_query, re.IGNORECASE)
                if m:
                    val = m.group(1).strip("%").strip("*")
                    conditions.append(f"{col} LIKE ?")
                    sql_params.append(f"%{val}%")

        where_clause = " AND ".join(conditions)
        # Fetch limit + 1 to establish EOF rigorously
        sql = f"SELECT * FROM events WHERE {where_clause} ORDER BY timestamp ASC LIMIT ? OFFSET ?"
        sql_params.extend([limit + 1, offset])
        self.last_query_text = sql

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
                native_query=sql,
                provider=self.provider_id,
                index=self.db_path,
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
            native_query=sql,
            provider=self.provider_id,
            index=self.db_path,
        )

    def _execute_runtime_capability(
        self,
        runtime_capability: dict[str, Any],
        entity: EntityRef | None,
        window: str,
        limit: int,
        offset: int,
        query_id: str,
    ) -> QueryResult:
        """Execute a probed source mapping without semantic name heuristics."""
        if runtime_capability.get("source_id") != "cdb:source:events":
            return QueryResult(
                query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                complete=False, diagnostic=Diagnostic.UNSUPPORTED_REQUIREMENT,
                truncation_reason="runtime source is not the CDB events source",
                provider=self.provider_id, index=self.db_path,
            )
        columns = {
            str(row[1])
            for row in self._conn.execute("PRAGMA table_info(events)").fetchall()
        }
        field_groups = runtime_capability.get("native_field_bindings", {})
        output_groups = runtime_capability.get("output_value_bindings", {})
        requested = [
            str(name)
            for values in (*field_groups.values(), *output_groups.values())
            if isinstance(values, (list, tuple))
            for name in values
        ]
        requested = list(dict.fromkeys(requested))
        if not requested or any(
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) or name not in columns
            for name in requested
        ):
            return QueryResult(
                query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                complete=False, diagnostic=Diagnostic.PARSE_FAILED,
                truncation_reason="runtime fields are not valid CDB columns",
                provider=self.provider_id, index=self.db_path,
            )

        start_dt, end_dt = validate_time_window_format(window)
        start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        selected = list(dict.fromkeys(["id", "timestamp", "native_type", *requested]))
        conditions = ["timestamp >= ?", "timestamp <= ?"]
        values: list[Any] = [start_iso, end_iso]
        if entity is not None and entity != ANY:
            if isinstance(entity, Account):
                value = entity.username
            elif isinstance(entity, Host):
                value = entity.name
            elif isinstance(entity, IPAddress):
                value = entity.address
            elif isinstance(entity, Domain):
                value = entity.name
            elif isinstance(entity, File):
                value = entity.path
            elif isinstance(entity, Process):
                value = str(entity.pid)
            else:
                value = str(entity)
            input_fields = [
                str(name)
                for names in field_groups.values()
                if isinstance(names, (list, tuple))
                for name in names
                if str(name) in columns
            ]
            if value and input_fields:
                conditions.append("(" + " OR ".join(f"{name} = ?" for name in input_fields) + ")")
                values.extend([str(value)] * len(input_fields))
        sql = (
            f"SELECT {', '.join(selected)} FROM events WHERE {' AND '.join(conditions)} "
            f"ORDER BY timestamp ASC LIMIT ? OFFSET ?"
        )
        values.extend([limit + 1, offset])
        self.last_query_text = sql
        try:
            rows = [dict(row) for row in self._conn.execute(sql, values).fetchall()]
        except Exception as error:
            return QueryResult(
                query_id=query_id, outcome=QueryOutcome.UNKNOWN, executed_ok=False,
                complete=False, diagnostic=Diagnostic.QUERY_FAILED,
                truncation_reason=str(error), native_query=sql,
                provider=self.provider_id, index=self.db_path,
            )
        complete = len(rows) <= limit
        returned = rows[:limit]
        return QueryResult(
            query_id=query_id,
            outcome=QueryOutcome.ROWS if returned else QueryOutcome.UNKNOWN,
            executed_ok=True,
            complete=complete,
            rows=returned,
            observed_fields=list(dict.fromkeys(key for row in returned for key in row)),
            native_query=sql,
            provider=self.provider_id,
            index=self.db_path,
            cursor=None if complete else str(offset + limit),
            row_count=len(returned),
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
