# Real-Provider Specifications (v4.1)

This document describes the provider boundary used by the current code and
the extension contract for providers that are not implemented yet.

## 1. Common provider contract

Every provider must expose, directly or through an adapter:

```text
ProviderScope
  → capability/catalog discovery
  → ProviderOperation/CapabilityBinding
  → QueryResult(executed_ok, complete, rows, diagnostics)
```

Provider-native partitions belong in `ProviderScope`; operations are not Cell
dimensions. Native fields and native record types are preserved during
normalization. Unknown records must survive ingestion.

The current code has two executable providers:

- `CdbAdapter` for local SQLite replay;
- `SplunkLiveAdapter` for live Splunk REST searches.

EDR and IDS sections below are planned adapter contracts, not implemented live
integrations.

## 2. Splunk — implemented

### 2.1 Scope and discovery

The adapter uses the native Splunk index as its primary partition and can also
retain manifest scope metadata such as sourcetype/source. The BOTSv1 test
configuration is `configs/splunk_botsv1.yaml`.

`discover_full_capabilities()` queries Splunk indexes and sourcetypes, then
returns a `ProviderCapabilityCatalog` with status, supported evidence types,
observable fields, retention and discovery details. A manifest can provide
explicit bindings; otherwise the adapter derives supported categories from
discovered sourcetypes.

### 2.2 Query execution

The adapter builds parameterized SPL for the canonical operations:

```text
cdb_scope_scan / cdb_broad_sweep
cdb_process_lineage / cdb_process_search
cdb_logon_history / cdb_auth_search
cdb_network_connections / cdb_net_search
cdb_file_writes / cdb_file_search
cdb_dns_queries / cdb_dns_search
cdb_persistence_artifacts / cdb_persistence_search
cdb_web_requests / splunk_search_web
```

Queries are submitted to `/services/search/jobs` in oneshot mode. Provider
fields are normalized into the engine vocabulary while the original
`native_type` and a bounded `raw_ref` are retained.

The native query compiler and adapter accept entity/predicate constraints only
after provider validation. Custom LLM-generated query text is allowed only
through the planner parser, operation/field allowlist and dry-run validation.

### 2.3 Completeness

The adapter requests one more row than the consumer limit. If more than the
limit is returned, it returns the bounded rows with `complete=False` and a
continuation cursor. If the returned count is within the limit, it returns
`complete=True`.

`complete=False` is not a negative result. The engine records the partial
diagnostic and may continue through bounded time/entity expansion.

### 2.4 Negative controls

Splunk control methods are:

1. `control_health`: checks Splunk reachability and scope health;
2. `control_any_record`: checks that the target index/window has telemetry;
3. `control_observability`: checks whether the requirement predicate is
   observable in the adapter’s field catalog.

Controls do not mint observations. A zero-row query is usable as negative
evidence only when execution is complete and the relevant controls pass.

## 3. EDR — extension contract, not yet implemented

An EDR adapter should use a native scope such as:

```python
ProviderScope(
    provider_id="edr",
    native_partition={"tenant_id": "...", "dataset": "..."},
    scope_id="edr-primary",
)
```

Operations should expose process lineage, authentication, network, file and
registry/persistence capabilities. Opaque cursor pagination, rate-limit
backoff, sensor health and policy observability must be represented in
`QueryResult`/diagnostics. These requirements are design targets; the current
repo has mock contract tests only.

## 4. IDS — extension contract, not yet implemented

An IDS adapter should preserve native sensor/interface/stream partitions, for
example:

```python
ProviderScope(
    provider_id="ids",
    native_partition={"sensor_id": "...", "interface": "eth1", "stream": "dns"},
    scope_id="ids-dmz-dns",
)
```

Suricata/Zeek records should retain their complete native JSON/tabular fields,
including new protocol metadata. Capture drops, parser state, sensor health
and stream availability must block unjustified negative evidence. No live
Suricata/Zeek adapter currently exists in this repository.

## 5. Provider gate status

| Provider | Current state | Required before production claim |
|---|---|---|
| CDB/SQLite | implemented and replay-tested | maintain contract/replay tests |
| Splunk | implemented; BOTSv1 live replay passes | deployment-specific manifest, credentials and completeness evidence |
| EDR | mock contract only | implement adapter, cursor/rate-limit/health tests, then live test |
| IDS | mock contract only | implement adapter, capture/parser health tests, then live test |

All providers must integrate through `ProviderScope`, capability descriptors,
`ProviderOperation`, `CapabilityBinding`, `QueryPlan` and `QueryResult` without
adding `event_family` to `Cell`.
