# AI Agent Hunting — Project Context (v4)

Use `01_FINAL-ARCHITECTURE.md` for WHAT, `02_METHOD-AND-IMPLEMENTATION-PLAN.md`
for HOW/contracts/tasks, `03_LITERATURE-AND-TRACEABILITY.md` for sources, and
`04-IMPLEMENTATION-CHECKLIST.md` for executable work. This file is a concise
operational context, not a fourth contract.

## Objective

Build a pure hypothesis-driven, evidence-grounded threat-hunting engine. It
starts from a hypothesis/TTP/IOC/CVE/CTI/question, preserves competing
explanations, never treats an empty query as real-world absence, and reports
residual uncertainty and blind spots. Raw log text is untrusted and never
enters a repeated LLM prompt.

## Current status

The v4 target contract is documented in `01–04`. The existing implementation is
still the earlier alert-oriented MVP and requires migration before it can claim
the v4 hypothesis-only flow. It is not production-ready for Splunk/EDR/IDS
until real-provider completeness and scope tests pass.

Six implementation components are defined: knowledge/behavior compiler,
capability/adapters, query planner/validator, observation/evidence layer, hunt
controller, and account renderer. LLM calls are bounded gates; state,
capability validation, coverage, and stopping remain deterministic.

## Core vocabulary

| Concept | Meaning |
|---|---|
| `ProviderScope` | native addressable data partition with provider, retention, coverage and gaps |
| `ProviderOperation` | executable provider function/query with schema, pagination and completeness contract |
| `Cell` | `(ProviderScope, entity/ANY, time_bucket)` coverage unit |
| `EvidenceRequirement` | versioned question-side evidence shape, not a vendor event catalogue |
| `native_type` | original provider record/relationship type, preserved |
| `semantic_type` | optional post-hoc mapping; may be `None` |
| `EventFamily` | not a Cell axis or query universe; native event types remain in observations |

If a record belongs to no semantic family, keep it as an observation with native
fields and `semantic_type=None` (`UNMAPPED`). Never route it to `OTHER` or drop
it. If a known scope has no operation, mark `UNQUERYABLE` and count it in the
coverage denominator. A source outside the catalog is `UNKNOWN_SOURCE`: report
it as a blind spot, but do not pretend it is enumerable.

## Cells and coverage

```text
Cell = (provider_scope, entity | ANY, time_bucket)
```

Wildcard Cells come from known provider scopes and permit a sparse hypothesis
to bootstrap through bounded discovery. Instance Cells are added from request
or observed entities, regardless of semantic mapping. A complete targeted query
does not make a scope explored; only a complete scope-level scan does.

States are `EXPLORED`, `PARTIAL`, `UNEXPLORED`, `UNQUERYABLE` and
`UNREACHABLE`. `PARTIAL` is split/paginated and never re-issued indefinitely.
Coverage reports scope coverage separately from requirement coverage and counts
unmapped observations.

## Query flow

```text
HuntRequest/HuntObjective
  → configured ProviderScopes and capabilities
  → EvidenceRequirement
  → CapabilityMatcher(CapabilityDescriptor)
  → CapabilityBinding
  → allow-listed ProviderOperation
  → native query/result (complete or partial)
  → Observation (native preserved, semantic optional)
  → EvidenceFact/EvidenceGroup
  → TEST/EXPAND/DISCOVER/PIVOT/REFINE
  → assessment
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
2. Knowledge/behavior compiler and hypothesis-only input.
3. Capability descriptors, query templates and validated fallback.
4. Observation ledger, fact extraction and EvidenceGroup compression.
5. Evidence compatibility, hunt controller and bounded LLM gates.
6. CDB vertical slice and cost/recall/security experiments.
7. Real SIEM/EDR/IDS adapters only after native scope/completeness tests.

## Non-negotiable security assertions

- raw log content never appears in LLM prompts;
- M2 cannot mutate observations, attribution or statuses;
- no LLM output can select controls, stop, or compute disposition;
- tainted entities are rate-limited and deferred entities are counted;
- unknown records are retained; incomplete/stale/unqueryable results cannot license negatives.
