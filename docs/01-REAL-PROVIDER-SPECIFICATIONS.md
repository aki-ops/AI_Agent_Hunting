# Real-Provider Specifications (v5.0)

This document describes the provider boundary used by the v5.0 architecture,
defining field roles, logical provider operations, and adapter contracts.

---

## 1. Common Provider Contract [Tags: REF-OCSF, REF-OTEL, REF-AIQL]

Every provider must expose, directly or through an adapter:
```text
ProviderScope
  → capability/catalog discovery
  → Logical Provider Operations & Field Roles
  → QueryResult(executed_ok, complete, rows, diagnostics)
```

1. `ProviderScope`: Identifies native partitions (index, sourcetype, sensor, tenant) and temporal bounds.
2. `Cell = (ProviderScope, entity | ANY, time_bucket)`: Execution coordinate tracking queried partitions and cursors.
3. Native records and native fields are preserved during ingestion. Unknown native types must never be dropped.

---

## 2. Field Roles and Semantic Disambiguation Contract [Tags: REF-FOR572, REF-OMEGALOG]

To prevent catastrophic attribution errors (e.g. treating web servers or destination IPs as user workstations),
telemetry fields carry strict semantic roles:

| Field Role | Meaning | Example Native Fields (Splunk/Windows/Suricata) | Incompatible Conflation |
|---|---|---|---|
| `CLIENT_IP` | Originating host network address initiating request | `c_ip`, `client_ip`, `src_ip`, `IpAddress` (Event 4624) | NEVER conflate with `SERVER_IP` or `DESTINATION_IP` |
| `SERVER_IP` | Destination service host answering request | `s_ip`, `server_ip`, `dest_ip`, `destination_ip` | NEVER conflate with `CLIENT_IP` or `SOURCE_IP` |
| `ENDPOINT_HOST` | Client computer or workstation executing user session | `host`, `ComputerName`, `workstation_name` | NEVER conflate with `SERVER_HOST` or `SENSOR_HOST` |
| `SERVER_HOST` | Application/web server responding to inbound traffic | `host` (on web/IIS/database servers), `site`, `dest_host` | NEVER bind as client endpoint |
| `SENSOR_HOST` | Network probe or proxy appliance recording traffic | `host` (on forwarder/sensor), `sensor_id` | NEVER bind as client or server endpoint |
| `ACCOUNT_NAME` | Authenticated user identity string | `user`, `username`, `TargetUserName`, `Account_Name` | NEVER match against hostname or string fragments |
| `PERSON_NAME` | Human individual specified in request | `Amber Turing`, `display_name` | Must be resolved to `ACCOUNT_NAME` via directory/logon |
| `DOMAIN_NAME` | FQDN or web domain | `query`, `domain`, `site`, `cs_host` | |
| `PROCESS_NAME` | Executable image name | `image`, `process_name`, `NewProcessName` | |

---

## 3. Logical Provider Operations by Relation [Tags: REF-AIQL, REF-MITRE-ANALYTICS]

Rather than accepting unconstrained query text or broad sweeps, adapters declare
support for relation-first operations:

```text
1. resolve_person_to_account(person_name) → AccountNode
2. resolve_account_to_endpoint(account_name, time_window) → EndpointNode
3. resolve_endpoint_to_client_ip(endpoint_host, time_window) → IPNode
4. find_web_activity_from_client_ip(client_ip, time_window, predicates) → WebRequestObservations
5. find_dns_activity_from_client_ip(client_ip, time_window, predicates) → DNSQueryObservations
6. find_process_from_endpoint(endpoint_host, time_window, predicates) → ProcessObservations
7. find_file_change_from_process(endpoint_host, process_id, time_window) → FileObservations
```

---

## 4. Splunk Adapter (v5.0)

### 4.1 Scope & Capability Mapping
- **Indexes**: `botsv1`, `botsv2`, enterprise telemetry partitions.
- **Sourcetypes**:
  - Identity & Logon: `WinEventLog:Security` (Event ID 4624, 4625, 4672).
  - Web & Proxy: `stream:http`, `iis`, `pan:traffic`, `squid`.
  - DNS: `stream:dns`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (Event ID 22).
  - Process & System: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (Event ID 1, 3, 11).

### 4.2 Parameterized Operation Compilation
The adapter translates logical operations into parameterized SPL:
- `resolve_account_to_endpoint`:
  ```spl
  search index="botsv2" sourcetype="WinEventLog:Security" EventCode=4624 TargetUserName="<account>"
  | table _time, TargetUserName, ComputerName, IpAddress, LogonType
  ```
- `find_web_activity_from_client_ip`:
  ```spl
  search index="botsv2" (sourcetype="stream:http" OR sourcetype="pan:traffic") src_ip="<client_ip>"
  | table _time, src_ip, dest_ip, site, cs_host, uri, cs_uri_stem, status
  ```

### 4.3 Completeness & Negative Controls
- Implements the L+1 row limit on oneshot REST searches.
- Controls: `control_health`, `control_any_record`, `control_observability`.

---

## 5. CDB Adapter (Local SQLite Replay)

Provides deterministic replay of pre-recorded forensic cases for unit testing and offline CI:
- Maps logical operations to parameterized SQL statements.
- Preserves identical `QueryResult` envelope and field role typing as live SIEM adapters.

---

## 6. EDR & IDS Extension Contracts

- **EDR Contract**: Exposes process tree lineage, memory injection, and network socket bindings keyed by endpoint ID and process GUID.
- **IDS Contract**: Exposes protocol stream events (HTTP, TLS, DNS, flow) keyed by sensor interface and source/destination IP pairs.
