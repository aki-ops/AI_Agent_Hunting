# Implementation Checklist (v3)

Executable worklist for `01_FINAL-ARCHITECTURE.md` and
`02_METHOD-AND-IMPLEMENTATION-PLAN.md`. A checked item requires a test or
execution evidence; documentation alone is not completion evidence.

## Scope and gates

### Phase 0 — contract gate

- [x] Python 3.10+ project, CI, lint and test runner.
- [x] Replay manifest contains git SHA, config hash and deterministic seed.
- [x] Implement `ProviderScope` with native partition, coverage, retention and gaps.
- [x] Implement `Cell(provider_scope, entity, time_bucket)` with **no** `event_family` field.
- [x] Implement `EntityRef` concrete variants and the real `ANY` wildcard value.
- [x] Implement `ProviderOperation` with scope IDs, parameter schema, pagination and completeness semantics.
- [x] Implement `EvidenceRequirement` and `CapabilityBinding` with `EXACT/PARTIAL`.
- [x] Implement `CapabilityDescriptor` and a provider-neutral `CapabilityMatcher`.
- [x] Implement `Observation` with preserved `native_type` and nullable `semantic_type`.
- [x] Implement `QueryResult.complete`; never infer completeness from row count alone.
- [x] Implement diagnostics and states `UNEXPLORED`, `PARTIAL`, `EXPLORED`, `UNQUERYABLE`, `UNREACHABLE`.
- [x] Implement `UNMAPPED`, `UNEXPLAINED`, `UNSUPPORTED_REQUIREMENT` and `UNKNOWN_SOURCE` handling.
- [x] Implement `CoverageBound` with separate scope/requirement coverage and unmapped counts.
- [x] Malformed contracts fail validation; unknown semantic type does not.
- [x] `TESTIMONY` cannot become `OBSERVED`; M2 cannot write attribution/status.

### Phase 0 acceptance

- [x] Contract round-trip tests pass.
- [x] Unknown native observation round-trips with `semantic_type=None`.
- [x] `UNQUERYABLE` is in the denominator; `UNKNOWN_SOURCE` is reported outside it.
- [x] A complete targeted query does not mark the whole provider scope explored.

## Phase 1 — discovery, input and normalization

- [x] Define canonical alert fixtures, including an entity-free alert.
- [x] Deterministically extract and normalize alert entities and time window.
- [x] Load/validate a provider manifest; no event-family declarations required.
- [x] Assign stable IDs to every configured/discovered `ProviderScope`.
- [x] Validate operation-to-scope relationships and operation schemas.
- [x] Preserve native partition identity in provenance.
- [x] Build CDB/mock fixture with at least one scope and one `scope_scan` operation.
- [x] Add fixtures for a stale scope, known gap, unknown native record and no-adapter scope.

### Acceptance

- [x] Entity-bearing alert creates instance candidates.
- [x] Entity-free alert creates a finite wildcard frame from known scopes alone.
- [x] Retention-expired/known-gap cells are never selected.
- [x] A known scope with no operation is `UNQUERYABLE`, not silently omitted.


## Phase 2 — M1 observation ledger

- [x] Implement raw event loaders and protected raw references.
- [x] Preserve provider-native records and native type, including unknown types.
- [x] Extract stable envelope fields and provider-specific fields without assuming a universal schema.
- [x] Apply per-field taint and provenance deterministically.
- [x] Store append-only observations and query outcomes.
- [x] Record `observed_fields[(provider_scope, native_type)]`.
- [x] Maintain unattributed observations independent of semantic mapping.
- [x] Keep `UNMAPPED` observations available to abduction and reporting.
- [x] Track wildcard and instance cells separately.
- [x] Store partial parents as audit-only split records; exclude them from active coverage.

### Acceptance

- [x] Parse failures become typed diagnostics; no silent drops.
- [x] Every observation has scope, provenance, raw reference and field taint.
- [x] Unknown event without event code remains a valid observation.
- [x] Complete scope scan can mark scope coverage; targeted evidence query cannot.

## Phase 3 — M3 constraints and M4 controller

### Planning, frontier and sampling

- [ ] Compile `EvidenceRequirement → CapabilityBinding → ProviderOperation`.
- [ ] Select bindings from adapter descriptors; no provider-specific branches in the core planner.
- [ ] Record unsupported requirements without fabricating a query.
- [ ] Build wildcard cells per known `ProviderScope`.
- [ ] Add instance cells from alert/observed entities regardless of semantic mapping.
- [ ] Restrict wildcard selection to `SAMPLE`; restrict entity expansion to `EXPAND`.
- [ ] Implement provider-scope-stratified deterministic sampling with seed and budget ledger.
- [ ] Implement cursor pagination and time-split fallback for `PARTIAL` results.
- [ ] Bound split depth with `min_bucket`; never re-issue the same truncated query forever.

### Constraints and stopping

- [ ] Schema and cited-observation integrity checks.
- [ ] Contradiction handling and preserved rejection reasons.
- [ ] Fixed action order and lexicographic selection.
- [ ] Retryable/permanent diagnostic partition.
- [ ] Turn/query budgets and tainted-entity budget; deferred entities counted.
- [ ] `STOP_RESOLVED` requires a surviving explanation and no blocking uncertainty.
- [ ] `STOP_BOUNDED` requires residuals and coverage bound.
- [ ] Every terminal path emits separate scope and requirement coverage.

## Phase 4 — M5 adapter and controls

### Investigation workflows — mint observations

- [ ] `ProcessLineage → process_ancestry`.
- [ ] `LogonHistory → authentication_activity`.
- [ ] `NetworkConnections → network_connection`.
- [ ] `PersistenceArtifacts → persistence_change`.
- [ ] `FileWrites → file_modification`.
- [ ] `DNSQueries → dns_activity`.
- [ ] `BroadSweep → scope_records` on a wildcard Cell.

### Control operations — never mint observations

- [ ] `ScopeHealthControl(scope, window)`.
- [ ] `AnyRecordInScope(scope, entity, window)`.
- [ ] `PredicateObservabilityControl(scope, requirement, predicate)`.
- [ ] License `VALID_NEGATIVE` only when all three controls pass and target result is empty/complete.
- [ ] Do not treat `len(rows) < limit` as proof of EOF.
- [ ] Handle capability misses as `UNQUERYABLE` or `UNSUPPORTED_REQUIREMENT` with diagnostics.
- [ ] Validate all LLM-proposed native queries against adapter allowlists.

### Acceptance

- [ ] Seven workflows execute on the CDB/mock adapter.
- [ ] Three controls execute without entering the observation ledger.
- [ ] Exactly-limit and cursor-more results remain incomplete.
- [ ] Truncated, stale, field-absent and unqueryable queries cannot license a negative.

## Phase 5 — M2, human loop and reporter

- [ ] Implement stubbed abduction before real LLM abduction.
- [ ] LLM input contains structured extracted data and taint only, never raw logs.
- [ ] Enforce benign/malicious/unknown explanation diversity where applicable.
- [ ] Generate expectations in terms of evidence requirements, not event families.
- [ ] Validate entity references, predicates and requirement version.
- [ ] Cap/merge explanations deterministically.
- [ ] Model human input as `TESTIMONY`; preserve conflicts and resolution records.
- [ ] Implement analyst confirmation requirements.
- [ ] Compute disposition as a pure M4 function; M5 only renders.
- [ ] Final account cites observation IDs, query IDs, diagnostics and coverage bound.

## Security and regression tests

- [ ] Raw log content never appears in an LLM prompt.
- [ ] Hidden benchmark fields are blocked.
- [ ] M2 cannot mutate observations, statuses or attribution.
- [ ] No LLM output can stop, escalate, control, or compute disposition directly.
- [ ] Attacker-planted entities cannot exhaust frontier budget.
- [ ] Injection fixtures cover command lines, URLs, DNS names, usernames and filenames.
- [ ] Regression: unknown native event is retained and unmapped.
- [ ] Regression: no event-family registry is required to query a scope.
- [ ] Regression: entity-free sampling is reproducible and scope-stratified.
- [ ] Regression: partial result cannot become valid negative.
- [ ] Regression: no-adapter scope is explicit in denominator.
- [ ] Regression: empty surviving-explanation set means bounded, not resolved, stop.

## MVP integration scenarios

- [ ] Entity-bearing alert → instance frontier → operation → observation → stub explanation → stop.
- [ ] Entity-free alert → wildcard scope cells → `BroadSweep` → entities → instance frontier.
- [ ] Unknown native event → ledger → `UNMAPPED` → abduction candidate, without false family.
- [ ] Partial scope scan → `PARTIAL` → cursor/split → complete children; no parent re-issue.
- [ ] Empty target → three controls → `VALID_NEGATIVE` or typed uncertainty.
- [ ] No-adapter known scope → `UNQUERYABLE` → `INSUFFICIENT_EVIDENCE` contribution.
- [ ] Every terminal path emits residuals and `CoverageBound`.

## Real-provider gate

- [ ] Splunk adapter documents native `(index, sourcetype[, source])` scopes, search-time fields and completeness.
- [ ] EDR adapter documents dataset/tenant/endpoint scopes separately from process/network/file operations, cursor and rate limits.
- [ ] IDS adapter documents stream/sensor scopes, optional native predicates and evolving schema.
- [ ] At least one real SIEM, EDR and IDS execution test passes before production-completeness claims.

## Definition of done

The CDB MVP is complete only when both entity-bearing and entity-free scenarios
pass end-to-end with zero LLM calls, unknown records are preserved, all state
transitions are auditable/replayable, terminal outputs contain valid separate
coverage bounds, and security assertions pass. This is a limited POC gate, not
production readiness for every backend.

## Traceability required for every implementation item

Before checking an item, record the applicable source tag in `03` and the
execution evidence. The following is the minimum map:

| Checklist area | Reference/document | What it supports | What must still be measured here |
|---|---|---|---|
| Provider scopes and native partitions | `REF-SPLUNK-01`, `REF-SURICATA-01`, `REF-OCSF-01` | native addressability and observed schema | discovery/completeness per adapter |
| Provider operations and bindings | `REF-SYNRAG-01`, `REF-SIEVE-01` | backend-aware executable query generation | syntax, execution and semantic correctness |
| Native + semantic observation envelope | `REF-OCSF-01`, `REF-OTEL-01`, `REF-MATRYOSHKA-01` | optional normalization without erasure | unknown-event retention and mapping accuracy |
| Evidence requirements | `REF-ATTACK-DC-01` | question-side evidence concepts | unsupported-requirement behavior |
| Cells and incomplete results | `REF-INCOMP-01` | empty vs unknown distinction | false-negative/negative-license rate |
| Sampling | `REF-SAMP-01` | bounded sampling within a defined frame | recall, bias and reproducibility |
| LLM/log boundary | `REF-INJECT-01`, `REF-EVID-01` | adversarial-log isolation and grounded evidence | security regression tests |
| Open-ended hunting evaluation | `REF-CDB-01` | executable benchmark methodology | recall, cost and reachability on our implementation |

The references justify the direction; they do not allow an item to be marked
done without a passing test or captured run.
