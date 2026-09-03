# Real-Provider Gate: Technical Specifications & Adapter Architecture

This document specifies the integration contracts, native partition boundaries, query generation, pagination, completeness semantics, and negative control verification for enterprise production backends: **Splunk (SIEM)**, **CrowdStrike/Defender (EDR)**, and **Suricata/Zeek (IDS)**.

---

## 1. Splunk Adapter Specification

### 1.1 Native Partition Scopes
In Splunk, data addressability is defined by the native tuple `(index, sourcetype[, source])`. A universal `event_code` is explicitly rejected.

```python
ProviderScope(
    provider_id="splunk_prod",
    native_partition={
        "index": "botsv3",
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    },
    scope_id="splunk_sysmon_prod"
)
```

- **Search-Time Field Extraction**: Unlike index-time fields (`_time`, `host`, `source`, `sourcetype`, `index`), fields such as `CommandLine`, `ParentProcessId`, `DestinationIp`, and `User` are extracted search-time via props.conf / transforms.conf.
- **Search-Time Field Integrity**: If a field is not extracted or missing from props, the adapter must not fabricate a query; it reports a `FieldAbsentDiagnostic` and flags the field in `observed_fields[(scope, native_type)]`.

### 1.2 Query Generation & Allowlist
SPL generation must use parameterized templates restricted to an explicit allowlist to prevent SPL injection (e.g. `| eval`, `| script`, `| outputlookup`):

```spl
search index="botsv3" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
       earliest="2026-09-01T08:00:00Z" latest="2026-09-01T12:00:00Z"
       host="DESKTOP-VICTIM1" EventCode=1
| table _time, host, user, ProcessId, ParentProcessId, Image, CommandLine
| head 101
```

### 1.3 Pagination and Completeness Semantics
Splunk Search Jobs API (`/services/search/jobs/{sid}/results`) returns search job statistics:
- **`is_done` vs `is_preview`**: A query result is only complete when `job["isDone"] == True`. Preview results are strictly marked `complete=False` (`PARTIAL`).
- **The $L+1$ Rule**: When querying with limit $L$, request `offset=0, count=L+1`:
  - If `len(events) <= L`, all matching events within the time window have been retrieved $\rightarrow$ `complete = True`.
  - If `len(events) > L`, results were truncated by the budget limit $\rightarrow$ `complete = False` (`PARTIAL`), triggering time-split cursor fallback.
- **Event Count vs Rows**: Never infer completeness from `eventCount` alone if the job has been paused or finalized prematurely.

### 1.4 Negative Controls on Splunk
To license `VALID_NEGATIVE`:
1. **`ScopeHealthControl`**:
   ```spl
   | metadata type=sourcetypes index="botsv3"
   | search sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
   | eval lag = now() - recentTime
   ```
   Fails if `lag > threshold_seconds`.
2. **`AnyRecordInScope`**:
   ```spl
   search index="botsv3" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
          earliest="2026-09-01T08:00:00Z" latest="2026-09-01T12:00:00Z"
   | head 1
   ```
3. **`PredicateObservabilityControl`**:
   Validates that the target field (e.g. `CommandLine`) is present in the field list returned by `| fieldsummary`.

---

## 2. EDR Adapter Specification (CrowdStrike / Defender)

### 2.1 Native Scopes vs Operations
EDR systems maintain separate scope boundaries from operational endpoints:

```python
ProviderScope(
    provider_id="crowdstrike_fdr",
    native_partition={
        "tenant_id": "cust-a419-corp",
        "dataset": "fdr_events",
        "cid": "9b12e..."
    },
    scope_id="cs_tenant_primary"
)
```

- **Scope Axis**: `(tenant_id, dataset, endpoint_id)`.
- **Operation Axis**: Telemetry workflows (`ProcessLineage`, `NetworkConnections`, `FileWrites`, `RegistryChanges`) are provider operations bound to capabilities, **never** axes of a Cell.

### 2.2 Rate Limits and Cursor Pagination
EDR REST APIs impose aggressive rate limits (e.g., 429 Too Many Requests):
- **Rate Limit Handling**: The adapter implements exponential backoff with full jitter ($t_{wait} = \min(t_{max}, 2^{attempt} \times U(0.8, 1.2))$).
- **Cursor-Based Pagination**: EDR streams use opaque cursors (e.g., `offsetToken`, `nextCursor`).
  - A query with limit $L$ returns rows and `nextCursor`.
  - If `nextCursor` is present and non-empty, the result is `complete = False`.
  - Re-issuing must continue from `nextCursor`, never restarting from offset 0.

### 2.3 Negative Controls on EDR
1. **`ScopeHealthControl`**: Checks sensor agent check-in timestamp (`last_seen_timestamp`). If sensor is disconnected/offline during the investigation window, negative evidence is blocked.
2. **`AnyRecordInScope`**: Checks if the sensor recorded any event (e.g., heartbeat or idle telemetry) during the window.
3. **`PredicateObservabilityControl`**: Verifies agent policy settings (e.g. Script Control, Network Monitor enabled in prevention policy).

---

## 3. IDS Adapter Specification (Suricata / Zeek)

### 3.1 Sensor and Stream Scopes
Suricata EVE-JSON and Zeek tab/JSON logs address data via sensor interface and stream types:

```python
ProviderScope(
    provider_id="suricata_core",
    native_partition={
        "sensor_id": "sensor-dmz-01",
        "interface": "eth1",
        "stream": "dns"
    },
    scope_id="ids_dmz_dns"
)
```

- **Stream Scopes**: `alert`, `dns`, `flow`, `http`, `tls`, `fileinfo`.
- **Cell Identity**: A Cell is `(ids_dmz_dns, ANY, 2026-09-01T10:00:00Z/2026-09-01T12:00:00Z)`.

### 3.2 Evolving Schema & Unknown Native Records
Network protocols evolve rapidly; IDS engines continuously introduce new metadata keys (e.g., `ja4`, `tls.sni`, `quic`):
- **Contract Rule**: Records containing undeclared or novel fields are **never dropped**.
- **Normalization**: The record preserves its full native JSON dictionary, assigned `native_type = "eve_dns"` and `semantic_type = None` (`UNMAPPED`).
- **Coverage Bound**: Counted in `CoverageBound.unmapped_observations`.

### 3.3 Negative Controls on IDS
1. **`ScopeHealthControl`**: Examines `stats` events for `capture.kernel_drops` and `decoder.invalid`. If drop rate exceeds 1%, `ScopeHealthControl` fails with `STALE_SCOPE` / `DROPPED_PACKETS`.
2. **`AnyRecordInScope`**: Verifies the sensor interface was operational and received packets during the window.
3. **`PredicateObservabilityControl`**: Verifies parser enabled in `suricata.yaml` (e.g., `app-layer.protocols.dns.enabled = yes`).

---

## 4. Summary Matrix: Real-Provider Gate

| Backend | Native Partition Coordinates | Query Language / Protocol | Pagination Mechanism | Primary Failure Mode for Negative Licensing |
|---|---|---|---|---|
| **Splunk** | `(index, sourcetype, source)` | Parameterized SPL | Offset / EventCount ($L+1$) | Search job preview, props missing field extraction, ingest lag |
| **EDR** | `(tenant_id, dataset, cid)` | REST API / GraphQL | Opaque cursor token | Sensor offline, rate limit exhausted, policy disabled |
| **IDS** | `(sensor_id, interface, stream)` | Elastic/ESQL or EVE-JSON | Time chunking / JSON stream | Kernel packet drops, parser disabled, tap failure |

All three provider classes integrate into the core through `ProviderScope`, `ProviderOperation`, and `CapabilityBinding` without altering the universal `Cell` model or adding `event_family` axes.
