# CONTRADICTION RESOLUTION — v3 provider-scope reset

## Active authority

```text
01_FINAL-ARCHITECTURE.md              WHAT: modules and boundaries
02_METHOD-AND-IMPLEMENTATION-PLAN.md  HOW: contracts, algorithms and gates
03_LITERATURE-AND-TRACEABILITY.md     evidence and source provenance
04-IMPLEMENTATION-CHECKLIST.md        executable worklist
context.md                            concise operational summary
```

Older family-centric wording in previous patches and drafts is historical. It
must not be used as a runtime contract.

## Resolved architectural issue

The former design overloaded `EventFamily` with three incompatible roles:

1. provider addressability;
2. post-hoc event semantics;
3. question-side evidence requirements.

That design fails for unknown events, evolving IDS schemas, EDR relationships,
search-time SIEM fields and records without event codes. The v3 contract
separates them:

| Role | v3 contract |
|---|---|
| native data partition | `ProviderScope` |
| provider function/query | `ProviderOperation` |
| question-side evidence shape | `EvidenceRequirement` |
| returned record semantics | `native_type` + nullable `semantic_type` |

## Four binding decisions

1. `Cell` is exactly `(ProviderScope, entity/ANY, time_bucket)`; it has no
   `event_family` field.
2. Native records are never forced into a closed semantic enum. Preserve the
   native type and allow `semantic_type=None` (`UNMAPPED`).
3. Expectations use `EvidenceRequirement`; an unsupported requirement is
   explicit and does not trigger a fabricated query.
4. `ProviderScope` and `ProviderOperation` are separate. Operations reference
   target scopes; an EDR endpoint is not automatically a partition.
5. Coverage reports two axes. `UNQUERYABLE` is in the denominator,
   `UNKNOWN_SOURCE` is outside it, and unmapped observations are counted.

## Consequences

- A new event type in a known scope remains queryable by a broad/native
  operation, even without a semantic mapping.
- `EXPLORED` requires a complete scope-level scan. A successful targeted query
  cannot upgrade whole-scope coverage.
- Sampling is stratified by provider scope, not event family.
- Negative evidence uses `ScopeHealthControl`, `AnyRecordInScope` and
  `PredicateObservabilityControl`; controls never mint observations.
- Production claims require real SIEM, EDR and IDS adapter tests. CDB/mock is a
  limited vertical-slice gate only.

## Readiness

The project may begin Phase 0 contract implementation immediately. Adapter
implementation waits for Phase 0 invariant tests, including unknown-record
preservation, partial-result handling, unqueryable denominator accounting and
absence of `event_family` from Cell.
