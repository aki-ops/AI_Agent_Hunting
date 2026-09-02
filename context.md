# AI Agent Hunting — Project Context (v3)

Use `01_FINAL-ARCHITECTURE.md` for WHAT, `02_METHOD-AND-IMPLEMENTATION-PLAN.md`
for HOW/contracts/tasks, `03_LITERATURE-AND-TRACEABILITY.md` for sources, and
`04-IMPLEMENTATION-CHECKLIST.md` for executable work. This file is a concise
operational context, not a fourth contract.

## Objective

Build an evidence-grounded, human-in-the-loop threat investigation agent. It
produces an auditable account with claim-to-observation links, preserves
competing explanations, never treats an empty query as real-world absence, and
reports residual uncertainty and blind spots. Raw log text is untrusted and
never enters an LLM prompt.

## Current status

The previous family-centric contract has been replaced. The core is ready only
for a **limited CDB/mock vertical slice after Phase 0 contract tests pass**. It
is not production-ready for Splunk/EDR/IDS until real-provider completeness and
scope tests pass.

Five modules remain: M1 Observation Ledger, M2 Abduction Engine, M3 Constraint
Checker, M4 Controller, and M5 Adapter/Reporter. M2/M5 may use an LLM; all state,
retrieval, constraints, coverage and disposition remain deterministic.

## Core vocabulary

| Concept | Meaning |
|---|---|
| `ProviderScope` | native addressable data partition with provider, retention, coverage and gaps |
| `ProviderOperation` | executable provider function/query with schema, pagination and completeness contract |
| `Cell` | `(ProviderScope, entity/ANY, time_bucket)` coverage unit |
| `EvidenceRequirement` | versioned question-side evidence shape, not a vendor event catalogue |
| `native_type` | original provider record/relationship type, preserved |
| `semantic_type` | optional post-hoc mapping; may be `None` |
| `EventFamily` | optional reporting label only; never a Cell axis or query restriction |

If a record belongs to no semantic family, keep it as an observation with native
fields and `semantic_type=None` (`UNMAPPED`). Never route it to `OTHER` or drop
it. If a known scope has no operation, mark `UNQUERYABLE` and count it in the
coverage denominator. A source outside the catalog is `UNKNOWN_SOURCE`: report
it as a blind spot, but do not pretend it is enumerable.

## Cells and coverage

```text
Cell = (provider_scope, entity | ANY, time_bucket)
```

Wildcard Cells come from known provider scopes and permit an entity-free alert
to bootstrap through `BroadSweep`. Instance Cells are added from alert or
observed entities, regardless of semantic mapping. A complete targeted query
does not make a scope explored; only a complete scope-level scan does.

States are `EXPLORED`, `PARTIAL`, `UNEXPLORED`, `UNQUERYABLE` and
`UNREACHABLE`. `PARTIAL` is split/paginated and never re-issued indefinitely.
Coverage reports scope coverage separately from requirement coverage and counts
unmapped observations.

## Query flow

```text
alert
  → configured/discovered ProviderScopes
  → EvidenceRequirement
  → CapabilityMatcher(CapabilityDescriptor)
  → CapabilityBinding
  → allow-listed ProviderOperation
  → native query/result (complete or partial)
  → Observation (native preserved, semantic optional)
  → expansion/sampling/assessment
```

Investigation workflows: `ProcessLineage`, `LogonHistory`,
`NetworkConnections`, `PersistenceArtifacts`, `FileWrites`, `DNSQueries`,
`BroadSweep`.

Negative evidence has three controls: `ScopeHealthControl`, `AnyRecordInScope`,
and `PredicateObservabilityControl`. Controls never mint observations. A zero
row targeted result is `VALID_NEGATIVE` only when the target is complete and all
three controls pass.

An unsupported requirement is recorded as `UNSUPPORTED_REQUIREMENT`; the agent
does not invent a query. An LLM may propose native query text only inside the
adapter's validated operation/field/predicate allowlist.

## Implementation order

1. Phase 0 contracts, validators and invariant tests.
2. Phase 1 manifest, CDB scope/operation and normalization.
3. M1 ledger, native observation preservation and coverage accounting.
4. M3 constraints, M4 controller, frontier and deterministic sampling.
5. M5 CDB adapter, seven workflows and three controls.
6. Stubbed abduction with zero LLM calls and replayable audit log.
7. Real abduction, human loop and reporter.
8. Real SIEM/EDR/IDS adapters only after native scope/completeness tests.

## Non-negotiable security assertions

- raw log content never appears in LLM prompts;
- M2 cannot mutate observations, attribution or statuses;
- no LLM output can select controls, stop, or compute disposition;
- tainted entities are rate-limited and deferred entities are counted;
- unknown records are retained; incomplete/stale/unqueryable results cannot license negatives.
