# 02 — METHOD AND IMPLEMENTATION PLAN (v3 — provider-scope reset)

This is the implementation source of truth for the revised core contracts. It
replaces the previous family-centric plan. `01_FINAL-ARCHITECTURE.md` defines
module boundaries; `03_LITERATURE-AND-TRACEABILITY.md` records evidence; this
document defines the executable method and acceptance criteria.

## 0. Non-negotiable model

The system has four different questions, and therefore four different concepts:

| Question | Contract | What it must not do |
|---|---|---|
| Where can data be addressed? | `ProviderScope` | infer a universal event taxonomy |
| How can that provider be queried? | `ProviderOperation` | pretend all providers share fields or event codes |
| What evidence would answer the investigation question? | `EvidenceRequirement` | enumerate every vendor event type |
| What did a returned record mean? | `native_type` + optional `SemanticType` | drop an unknown record into `OTHER` |

`EventFamily` is not a Cell axis and is not the query universe. If retained for
reporting, it is a nullable post-hoc semantic label. An event without a label is
still a valid observation: its scope, native type, fields and raw reference are
preserved.

Coverage is two-dimensional:

1. **scope coverage** — whether a known provider partition was searched
   completely for a cell;
2. **requirement coverage** — whether an evidence requirement was bound to an
   executable provider operation and executed successfully.

Neither dimension may be inferred from the other.

## 1. Provisional parameters

Parameters are engineering defaults, not scientific facts. They are calibrated
by the experiments named below.

| Parameter | MVP default | Calibration |
|---|---:|---|
| `bucket` | 1 h | EXP-02 |
| `W` seed radius | ±2 buckets | EXP-02 |
| `min_bucket` | 5 min | EXP-02b |
| `sweep_limit` | 5,000 rows | EXP-02b |
| `N_taint` | 20 entities/turn | EXP-10 |
| `B` sampling budget | 200 | EXP-02b |
| `min_ingest_lag` | 15 min | EXP-04 |
| `T_max / Q_max` | 15 / 60 | EXP-08 |

## 2. C1 — Telemetry discovery

### Decision

Start with an explicit deployment manifest, represented as native provider
scopes and operations rather than an event-family registry. Optional provider
discovery may enrich the manifest. It cannot silently turn an unbounded,
undiscoverable backend into a bounded coverage claim.

### Configuration contract

```yaml
providers:
  - id: splunk_prod
    backend: spl
    scopes:
      - id: windows_security
        native_partition:
          index: security
          sourcetype: WinEventLog:Security
        coverage_start: 2026-01-01T00:00:00Z
        coverage_end: null
        retention_days: 90
        known_gaps: []
    operations:
      - id: spl_search
        scope_ids: [windows_security]
        pagination: cursor
        limit_semantics: provider-dependent
```

Examples of `native_partition` are `(index, sourcetype)` for Splunk, a
dataset/tenant or endpoint collection for an EDR, and `(stream, sensor)` for an
IDS. An endpoint API operation is not automatically a data partition.

### Runtime state and boundedness

```python
state.provider_health[(provider_scope, window)]
state.operation_health[(operation_id, window)]
state.observed_fields[(provider_scope, native_type)] -> set[str]
state.unmapped_observations[observation_id]
state.scope_gaps[(provider_scope, window)]
```

Discovery validates IDs, partition identity, retention/coverage metadata and
operation schemas. Missing semantic mappings are not load failures. Unknown
native records are not discarded.

`UNKNOWN_SOURCE` means a source outside the configured/discovered provider
catalog. It is not enumerable and must not enter the denominator. A known scope
with no usable operation is `UNQUERYABLE`; it is enumerable and enters the
coverage denominator with an explicit reason.

**DoD:** malformed manifests fail closed; every known scope has a stable ID;
each operation declares target scope(s), pagination and completeness semantics;
discovery produces an explicit list of scopes without any `EventFamily`
declaration.

## 3. C2 — Searchable universe, Cells and frontier

### Contracts

```python
ProviderScope = {
    provider_id: str,
    native_partition: dict[str, str],
    scope_id: str,
}

Cell = {
    provider_scope: ProviderScope,
    entity: EntityRef | ANY,
    time_bucket: TimeBucket,
}
```

`Cell` is a coverage address. It does not contain `event_family`,
`EvidenceRequirement`, `operation_id`, or a normalized event code.

Entity identity is deterministic: host is normalized; account is canonical
(SID preferred); process is `(host, pid, first_seen_ts)` because PIDs are
reused; IP is normalized; file is `(host, normalized_path)`; domain is a
lower-cased FQDN with the trailing dot removed. `ANY` is a wildcard value, not a
discovered entity.

### Known cells and states

For each configured/discovered scope, create wildcard cells over eligible
coverage windows. Add instance cells only when entities are observed from the
alert or a returned observation:

```text
KNOWN_wild = {(scope, ANY, window) : window within coverage and retention}
KNOWN_inst = {(scope, entity, window) : entity was observed and window valid}
KNOWN      = KNOWN_wild ∪ KNOWN_inst
```

No unobserved event type is needed to enumerate a scope. A new, vendor-specific,
malformed, or unmapped event therefore cannot make the Cell universe
incomplete.

| State | Meaning | Coverage consequence |
|---|---|---|
| `EXPLORED` | scope-level scan returned `complete=True` | scope coverage achieved |
| `PARTIAL` | rows returned but completeness is false | not covered; paginate/split |
| `UNEXPLORED` | no valid scan result | not covered; selectable |
| `UNQUERYABLE` | known scope has no compatible operation | denominator + explicit gap |
| `UNREACHABLE` | permanent provider/retention/known-gap failure | denominator + explicit gap |

An operation-specific query that finds process or DNS evidence does not make the
whole scope `EXPLORED`. Only a complete scope scan can make that claim. This is
the distinction between evidence retrieval and coverage accounting.

`UNKNOWN_SOURCE` is outside the denominator. `UNMAPPED` means a record was
retrieved but has no semantic label; it remains evidence and is counted in the
unmapped-observation bound. `UNEXPLAINED` means evidence has not yet been
connected to the current hypothesis.

### Partial results

```python
on_partial(cell):
    if duration(cell.time_bucket) <= min_bucket:
        mark(cell, UNREACHABLE, reason="irreducibly_truncated")
    else:
        enqueue(Cell(scope, entity, left_half(cell.time_bucket)))
        enqueue(Cell(scope, entity, right_half(cell.time_bucket)))
```

Never re-issue the same truncated query forever. Cursor pagination is preferred
when the provider gives a trustworthy completeness contract; time splitting is
the fallback.

### Hypothesis-independent frontier

The frontier follows entities from the alert and observations regardless of
semantic mapping:

```python
seeds = alert.entities ∪ {e for o in observations for e in o.entities}
frontier = {(scope, e, window)
            for scope in known_scopes
            for e in seeds
            for window in anchor_windows(e)
            if cell_state(scope, e, window) in {UNEXPLORED, PARTIAL}}
```

Wildcard cells are selected by `SAMPLE`, not `EXPAND`. Tainted entities are
rate-limited and deferred, never silently discarded.

**DoD:** an entity-free alert has a non-empty wildcard frame when a known scope
exists; unknown native records do not disappear; partial scans do not subsume
instance cells; counters distinguish wildcard, instance and unqueryable cells.

## 4. C3 — Sampling

Sampling is a bounded exploration policy, not a completeness proof. It chooses
known but unvisited cells when the full frame is too large or the alert has no
entities.

```text
alert without entities
  → seed window
  → wildcard cells per known ProviderScope
  → source-stratified sample
  → scope_scan operation
  → observations + completeness metadata
```

Strata are provider scopes (optionally crossed with time windows), never event
families. Use equal allocation with a minimum per scope, then deterministic
systematic/random selection within each stratum. Record the frame, seed,
budget, selected cells, excluded cells and completion status.

The report says `sampled`, `fully explored`, `partial`, or `unqueryable`; it
never reports an unsampled remainder as clean. A `3/n` bound applies only to a
defined random frame under its assumptions, not to unknown sources,
undiscovered partitions or unqueryable scopes.

**DoD:** same seed → same selection; every known scope receives fair allocation
when budget permits; sampling upgrades a cell to `EXPLORED` only when the
provider operation says it is complete.

## 5. C4 — Evidence requirements and expectation ledger

`EvidenceRequirement` is a small, versioned vocabulary of evidence shapes, such
as `process_ancestry`, `authentication_activity`, `network_connection`,
`file_modification`, `dns_activity`, `persistence_change`, and `scope_records`.
It is provider-independent and extensible; it is not a catalogue of vendor
event types.

An unknown requirement is `UNSUPPORTED_REQUIREMENT`: record it in the ledger,
execute no fabricated query, and report the missing capability. Adding a new
requirement is a versioned configuration/code change, not an unconstrained LLM
decision during an investigation.

```python
Expectation = {
    id: str,
    evidence_requirement: EvidenceRequirement,
    entity: EntityRef | ANY,
    window: TimeBucket,
    predicate: Optional[Predicate],
    priority: int,
}
```

Discrimination uses requirement, entity, window and predicate—not a post-hoc
family label. One requirement can be satisfied by different native records on
different providers.

## 6. C5 — Capability binding and query planning

```text
Expectation
  → EvidenceRequirement
  → CapabilityBinding(provider, scope, operation, parameter mapping)
  → native query
```

```python
ProviderOperation = {
    id: str,
    provider_id: str,
    scope_ids: list[str],
    params_schema: dict,
    pagination: PaginationContract,
    limit_semantics: LimitSemantics,
    rate_limit: Optional[RateLimit],
}

CapabilityBinding = {
    evidence_requirement: EvidenceRequirement,
    provider_id: str,
    operation_id: str,
    parameter_mapping: dict,
    confidence: EXACT | PARTIAL,
}
```

Bindings are explicit and testable. A binding may map one requirement to
several native operations. `PARTIAL` bindings surface missing fields or
semantics and cannot be presented as exact coverage.

The LLM may propose a native query only inside an adapter allowlist of
operations, fields and predicates. The adapter validates syntax, scope, time,
limits and permissions. Failed validation returns a typed diagnostic and does
not execute arbitrary text.

## 7. C6 — Query execution and result envelope

```python
QueryResult = {
    query_id: str,
    provider_scope: ProviderScope,
    operation_id: str,
    expectation_id: Optional[str],
    rows: list[dict],
    complete: bool,
    cursor: Optional[str],
    observed_fields: list[str],
    native_types: list[str],
    diagnostic: Optional[Diagnostic],
    provenance: Provenance,
}
```

`complete=False` is not a negative result. Empty rows with `complete=True` may
support negative evidence only after C7 controls pass. Matching uses
expectation/cell identity and requirement predicates; it never requires a raw
record to belong to a predeclared family.

## 8. C7 — Negative evidence controls

Negative evidence requires all three controls:

1. `ScopeHealthControl(scope, window)` — provider reachable and ingestion lag
   acceptable;
2. `AnyRecordInScope(scope, entity, window)` — complete broad scan possible and
   its result envelope trustworthy;
3. `PredicateObservabilityControl(scope, requirement, predicate)` — native
   fields/type/value domain needed by the predicate observable or guaranteed by
   the adapter.

Only then can an empty targeted query support `VALID_NEGATIVE`. A zero-row broad
sweep is not evidence of absence when the scope is partial, stale, unqueryable,
or the needed field is absent. Controls do not emit observations and cannot
satisfy expectations.

## 9. C8–C10 — ledger, observations, normalization and taint

```python
Observation = {
    id: str,
    provider_scope: ProviderScope,
    cell_id: str,
    timestamp: datetime,
    native_type: Optional[str],
    semantic_type: Optional[SemanticType],
    fields: dict[str, Any],
    entities: list[EntityRef],
    taint: dict[str, TaintStatus],
    raw_ref: RawReference,
    provenance: Provenance,
    attributed_by: Optional[str],
}
```

`native_type` is preserved exactly when available and `semantic_type` is
nullable. Unknown/unmapped records are first-class observations; there is no
catch-all `OTHER` branch that could create a false completeness claim.

The mandatory normalized envelope is limited to stable cross-provider fields:
timestamp (or explicit missing status), provider scope, raw reference,
provenance, native type and extracted entity references when available.
Provider-specific fields stay in `fields`. Field presence is measured by
`(provider_scope, native_type, field)`, never by `(source, event_family, field)`.

Taint attaches to field/value provenance. Tainted entities may generate leads
and frontier cells within a budget but cannot alone establish attribution or a
negative result.

## 10. C11 — investigation query surface

The seven workflows are stable question patterns. Their backend implementation
is a capability binding, not a family declaration:

| Workflow | Evidence requirement | Typical native operations |
|---|---|---|
| `ProcessLineage` | `process_ancestry` | EDR process-tree, SIEM search |
| `LogonHistory` | `authentication_activity` | identity/Windows search |
| `NetworkConnections` | `network_connection` | EDR network, IDS flow search |
| `PersistenceArtifacts` | `persistence_change` | EDR/file/registry search |
| `FileWrites` | `file_modification` | EDR/file search |
| `DNSQueries` | `dns_activity` | DNS/IDS/SIEM search |
| `BroadSweep` | `scope_records` | complete scope scan |

Control operations are `ScopeHealthControl`, `AnyRecordInScope`, and
`PredicateObservabilityControl`.

For the CDB adapter, MVP exposes one `scope_scan` over its fixture partition.
Splunk `(index, sourcetype)`, EDR datasets/tenants/endpoints, and IDS
streams/sensors remain native to their adapters; no universal `event_code` is
required.

## 11. M2 LLM API contract

The real M2 abduction engine calls an external LLM API through an internal
`ApiLLMProvider` interface. Local model inference is out of scope for the
current deployment decision. A stub provider is used for deterministic tests
and must not make network calls.

```text
structured investigation context
  → ApiLLMProvider.generate()
  → schema-validated JSON
  → explanations + EvidenceRequirements
  → M3 constraint validation
```

The API receives only structured extracted data, observation IDs, provenance,
taint metadata, current hypotheses, coverage bounds and validated schemas. Raw
alert/log text is never sent to the API. The API response cannot mutate
observations, attribution, statuses, controls, actions, stopping state or
disposition. API endpoint, model, timeout, token limits and credentials are
deployment configuration/secrets.

## 12. State machine and coverage report

```text
ALERT → BOOTSTRAP (entities may be empty)
      → PLAN (requirements → bindings → operations)
      → EXECUTE (partial/complete envelope)
      → NORMALIZE (native preserved; semantic mapping optional)
      → EXPAND + SAMPLE (bounded new cells)
      → ASSESS (explanation + coverage bounds)
```

```python
CoverageBound = {
    known_scope_cells: int,
    explored_scope_cells: int,
    partial_scope_cells: int,
    unqueryable_scope_cells: int,
    unreachable_scope_cells: int,
    sampled_scope_cells: int,
    unmapped_observations: int,
    unknown_sources: list[str],       # reported, not counted
    unsupported_requirements: list[str],
}
```

`scope_coverage` and `requirement_coverage` are reported separately. Neither a
high requirement score nor a complete targeted query implies that all records
in a provider scope were seen.

## 13. Validation experiments and implementation gates

| Experiment | Question | Gate |
|---|---|---|
| EXP-01 | deterministic entity identity | PID reuse separated; replay stable |
| EXP-02/02b | bucket, split and sample budget | no infinite partial loop; sample reproducible |
| EXP-03 | fixed priority order | no post-hoc tuning |
| EXP-04 | ingestion lag | stale scope cannot license negative evidence |
| EXP-08 | query/turn budget | bounded execution with explicit incompleteness |
| EXP-09 | attribution threshold | uncalibrated threshold never stated as fact |
| EXP-10 | tainted entity budget | deferred entities counted, not dropped |
| EXP-11 | unknown native records | unknown type remains queryable evidence |
| EXP-12 | unqueryable scope | denominator includes explicit bound |
| EXP-13 | cross-provider binding | one requirement binds to heterogeneous operations |

The minimum fixture contains an entity-bearing alert, entity-free alert,
unknown native event, partial page, stale scope, scope with no adapter, and the
same evidence represented differently by two providers.

## 14. Implementation phases & current status

### Phase 0 — Contract gate (Done)
Implement `ProviderScope`, `Cell`, `EntityRef|ANY`, `ProviderOperation`,
`EvidenceRequirement`, `Observation`, `QueryResult`, diagnostics and coverage
states. Add serialization and invariant tests. Verified that `Cell` has no
`event_family` field and unknown observations round-trip.

### Phase 1 — Discovery, input and normalization (Done)
Implement manifest loading, canonical alert fixtures (both entity-bearing and
entity-free), stable scope ID assignment, and deterministic entity/window extraction.

### Phase 2 — M1 observation ledger & raw store (Done)
Implement protected raw store, append-only observation ledger, native type retention
(`semantic_type=None` for `UNMAPPED`), deterministic per-field taint labeling, and
separate wildcard vs instance cell tracking.

### Phase 3 — M3 constraints and M4 controller (Done)
Implement capability matcher, frontier manager, provider-scope-stratified deterministic
sampling, contradiction resolution (weakening/rejection), diagnostic partitioning,
lexicographic action loop (`TEST` > `EXPAND` > `SAMPLE`), stopping conditions
(`STOP_RESOLVED` vs `STOP_BOUNDED`), and final account emission.

### Phase 4 — M5 adapter and controls (Done)
Implement the 7 investigation workflows on the CDB SQLite adapter (`ProcessLineage`,
`LogonHistory`, `NetworkConnections`, `PersistenceArtifacts`, `FileWrites`, `DNSQueries`,
`BroadSweep`) and the 3 negative controls (`ScopeHealthControl`, `AnyRecordInScope`,
`PredicateObservabilityControl`) with strict $L+1$ EOF completeness.

### Phase 5 — M2 API abduction, human loop and reporter (Done)
Implement `StubAbductionProvider` and `ApiLLMProvider`, strict response schema validation,
prompt injection barriers (raw logs isolated), human testimony modeling, and pure
report rendering (`render_investigation_report`).

### Full Loop Orchestrator & CLI Tooling (Done)
- `InvestigationOrchestrator`: Full autonomous end-to-end engine loop connecting M1–M5.
- CLI Runner (`main.py`, `src/hunting/cli.py`): Alert ingestion via file, CLI flags,
  stdin pipe, interactive prompt, and mandatory analyst confirmation sign-off.
- CDB Seed Script (`scripts/seed_cdb.py`): Generates sample attack telemetry.
- Full E2E & Security Regression test suite: 100 passing tests.

### Real-Provider Gate (Phase A: Simulation Done | Phase B: Live Pending)
- **Phase A (Specification & Simulation - Done)**: Documented native partition scopes,
  search-time fields, $L+1$ completeness, cursor rate limits, and evolving schema in
  `docs/01-REAL-PROVIDER-SPECIFICATIONS.md`. Verified via simulation contract tests in
  `tests/unit/test_real_providers.py`.
- **Phase B (Live Production Execution - Pending)**: Live network SDK/API integration
  against production Splunk, EDR, and IDS clusters with live credentials and live telemetry.


## 15. Go/no-go rule

The project is ready for a limited CDB vertical slice when Phase 0 invariants,
the minimum fixture, and EXP-11/12 pass. It is not ready to claim production
completeness until at least one real SIEM, one EDR and one IDS adapter
demonstrate their native scope and completeness contracts.

## 16. Step-to-source traceability

The tags below are defined in `03_LITERATURE-AND-TRACEABILITY.md`. A tag is a
rationale for a mechanism, not a proof that our implementation is correct.

| Method step | Design decision | Reference(s) | Evidence status |
|---|---|---|---|
| discover scopes | address native partitions; do not infer a universal event taxonomy | `REF-SPLUNK-01`, `REF-SURICATA-01`, `REF-OCSF-01` | official docs; implementation still needs tests |
| create Cells | count provider/entity/time regions and expose unknown boundary | `REF-INCOMP-01`, `REF-SAMP-01` | adapted/composed |
| build EvidenceRequirements | describe required evidence independently from vendor records | `REF-ATTACK-DC-01`, `REF-SYNRAG-01` | adapted |
| bind requirement to operation | compile platform-neutral request into executable backend query | `REF-SYNRAG-01`, `REF-SIEVE-01` | research direction; adapter validation is ours |
| preserve native observation | enrich heterogeneous records without erasing native shape | `REF-OCSF-01`, `REF-OTEL-01`, `REF-MATRYOSHKA-01` | adapted |
| keep unknown/unmapped records | avoid closed parser/taxonomy assumption | `REF-SIEVE-01`, `REF-SURICATA-01` | adapted + project contract |
| sample Cells | bound exploration inside a declared sampling frame | `REF-SAMP-01` | adapted; not a completeness proof |
| license negative evidence | distinguish empty answer from incomplete information | `REF-INCOMP-01` | controls are original and must be tested |
| isolate LLM from logs/state | treat log content as adversarial input and keep evidence grounded | `REF-INJECT-01`, `REF-EVID-01` | adapted |
| evaluate open-ended hunting | measure recall and reachability on an executable benchmark | `REF-CDB-01` | benchmark evidence; not validation of our agent |

## 17. Provider-neutral extension contract

The core is not Splunk-specific. A new backend is an adapter that implements
the same boundary:

```python
class ProviderAdapter:
    def discover_scopes(self) -> list[ProviderScope]: ...
    def operations(self) -> list[ProviderOperation]: ...
    def validate(self, operation_id: str, params: dict) -> None: ...
    def execute(self, operation_id: str, params: dict) -> QueryResult: ...
    def health(self, scope: ProviderScope, window: TimeBucket) -> ControlResult: ...
    def observability(self, scope: ProviderScope, predicate: Predicate) -> ControlResult: ...
```

The adapter may expose different native capabilities:

| Backend class | Typical scope | Typical operations | Core invariant |
|---|---|---|---|
| SIEM/search index | index/sourcetype/source, dataset or tenant | search, aggregate, metadata | fields are runtime-observed and completeness is explicit |
| EDR | dataset/tenant/endpoint collection | process tree, process search, network, file activity | relationships and cursor pagination are first-class |
| IDS/network sensor | stream/sensor/tenant | flow, alert, DNS, protocol search | native event type is optional predicate and may evolve |
| cloud/audit/API source | account/region/service/table | API list, audit search, object history | provider cursor, retention and permission gaps are explicit |
| CDB/mock | fixture partition | `scope_scan`, deterministic query | used for contract and replay tests only |

Adding a backend requires: native scope manifest, operation schemas, parameter
validation, pagination/completeness tests, field observability tests,
unknown-record fixture, `UNQUERYABLE` fixture, and negative-evidence tests. The
core planner, Cell model, sampling policy and coverage report do not change.

This is the extensibility criterion: adding a provider adds an adapter and
bindings; it must not add a new Cell axis or require enumerating every vendor
event type before querying.

## 18. Capability descriptor and matcher

To prevent each provider from accumulating hand-written planner logic, every
adapter publishes a machine-readable descriptor:

```python
CapabilityDescriptor = {
    provider_id: str,
    scopes: list[ProviderScope],
    operations: list[ProviderOperation],
    bindings: list[CapabilityBinding],
}
```

`CapabilityMatcher` selects an `EXACT` or `PARTIAL` binding for an
`EvidenceRequirement`, validates the requested entity/predicate against the
operation schema, and returns `UNSUPPORTED_REQUIREMENT` when no safe binding
exists. The core planner consumes descriptors and does not contain Splunk,
EDR, IDS or cloud-specific branches.

The stable flow is therefore:

```text
question
  → EvidenceRequirement
  → CapabilityMatcher(CapabilityDescriptor)
  → ProviderOperation
  → adapter.validate/execute
  → common QueryResult
```

This flow is frozen for implementation. Experiments may change defaults,
bindings, sampling allocation, retry policy and adapter internals. They may not
silently reintroduce provider-specific axes into `Cell` or turn semantic labels
into a prerequisite for retrieval.
