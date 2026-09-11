# Real-Provider Specifications (v7)

This document defines the provider boundary. Providers expose capabilities and
typed logical operations; they do not define the semantic investigation path.

## 1. Common provider contract

```text
ProviderScope
  -> capability/catalog discovery
  -> logical operations and field roles
  -> QueryResult(executed_ok, complete, rows, diagnostics)
```

`ProviderScope` identifies native partitions (index, sourcetype, sensor,
tenant) and temporal bounds. `Cell = (ProviderScope, entity | ANY,
time_bucket)` tracks execution and coverage. Native records and unknown native
types are preserved.

A provider operation must expose three separate contracts: execution
completeness, semantic proof capability, and retrieval-route policy. A complete
empty result means only that the bounded request reached the provider's declared
completion point. It is not a valid negative unless the operation declares the
required negative/completeness semantics and the controller has exhausted every
permitted route.

Retrieval policy is declarative and bounded. It may identify predicate classes
that are safe to relax for candidate discovery, but every stage retains the
verified entity binding, provider scope, time interval, projection, row/page
limit and proof obligations. Each attempt has an auditable stage and
no-progress signature. Providers must not implement a hidden broad-sweep
fallback.

Capabilities that are statically reachable but do not declare the roles and
constraints needed to prove a requested relation remain retrieval-only. The
engine may invoke relation-scoped census/profiling and a bounded probe; only a
successful probe can publish a runtime capability. Source names and operation
IDs are identifiers, not semantic evidence.

Provider results should preserve `native_query` on the result that executed it,
observed fields, completeness, cursor/page information, diagnostics and source
schema provenance. A synthetic binding/user-selection event is not a provider
query and must not inherit mutable adapter query state.

When a provider represents an artifact transition, its validated operation must
declare exact native field IDs through `action_roles`, `state_roles`,
`temporal_roles`, `artifact_identity_roles` and/or `correlation_roles`. The
verifier accepts only cited observations present in the ledger, from one
provider/scope and a compatible typed entity, with parseable ordered timestamps
inside the edge's declared correlation bound. At least one action or explicit
before/after-state contract and one stable artifact identity/correlation value
must agree across the cited rows. A filename suffix or source label cannot
establish a state transition, encryption, or ransomware causality.

## 2. Field roles

| Role | Meaning | Example native fields | Must not be conflated with |
|---|---|---|---|
| `CLIENT_IP` | Originating host address | `c_ip`, `client_ip`, `src_ip`, `IpAddress` | `SERVER_IP`, `DESTINATION_IP` |
| `SERVER_IP` | Destination service address | `s_ip`, `server_ip`, `dest_ip` | `CLIENT_IP`, `SOURCE_IP` |
| `ENDPOINT_HOST` | Client/workstation executing a session | `host`, `ComputerName`, `workstation_name` | `SERVER_HOST`, `SENSOR_HOST` |
| `SERVER_HOST` | Server responding to a request | `host`, `site`, `dest_host` | User endpoint |
| `SENSOR_HOST` | Probe/proxy recording traffic | `host`, `sensor_id` | Client/server endpoint |
| `ACCOUNT_NAME` | Authenticated identity | `user`, `username`, `TargetUserName` | Hostname/display name |
| `PERSON_NAME` | Human named in request | display name | Account without evidence |
| `DOMAIN_NAME` | FQDN/web domain | `query`, `domain`, `site`, `cs_host` | IP without resolution |
| `PROCESS_NAME` | Executable image | `image`, `process_name`, `NewProcessName` | File/version value |

These are semantic roles, not a closed event taxonomy. Provider-native fields
remain available alongside normalized roles.

## 3. Logical operations

Adapters declare operations with required input kinds, output fact kinds,
partitions, permissions, pagination and completeness. The examples below are
not a closed list or mandatory sequence:

```text
resolve_identity(input_entity, time_window) -> identity_facts
find_attribute(subject, attribute, time_window) -> typed_attribute_facts
find_relation(subject, predicate, object_type, time_window) -> relation_rows
search_content(terms, scope, time_window) -> native_rows
find_process(input_entity, predicates, time_window) -> process_rows
find_file(input_entity, predicates, time_window) -> file_rows
find_network(input_entity, predicates, time_window) -> network_rows
```

The ClaimGraph determines which observation contract is needed. The semantic
projection does not invent identity, endpoint, IP or protocol prerequisites.
The capability binder may introduce a prerequisite only when a declared
operation requires it and must label that dependency explicitly. The adapter
maps validated logical operations to native syntax; the LLM never emits raw
SPL/KQL/SQL.

## 4. Splunk adapter

The active index and source partitions are discovered/configured at runtime and
are not hard-coded in the semantic layer. The adapter may support identity,
web/proxy, DNS, process, file, network and application partitions when present.

Example compilation:

```spl
search index="<validated_index>" sourcetype="WinEventLog:Security"
      EventCode=4624 TargetUserName="<validated_account>"
| table _time, TargetUserName, ComputerName, IpAddress, LogonType
```

The concrete query is generated only after logical operation and parameters pass
validation. Pagination and completeness are returned in `QueryResult`.

## 5. CDB adapter

CDB provides deterministic local replay through the same logical operation and
`QueryResult` contracts. It must not be used as an unrelated fallback merely
because it is reachable.

## 6. EDR, IDS and future providers

EDR, IDS, mail and other providers are adapter extensions. Each must declare
capabilities and pass the same ClaimGraph, query safety, evidence citation,
completeness and replay tests. Adding a provider must not add a provider-specific
semantic branch to the agent.
