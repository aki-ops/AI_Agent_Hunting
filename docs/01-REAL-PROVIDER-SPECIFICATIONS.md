# Real Provider Specifications (v9)

This document defines the provider boundary for the **Evidence-Grounded
Progressive Hunt Graph**. It is subordinate to `01_FINAL-ARCHITECTURE.md` and
must not introduce a second reasoning architecture.

The provider layer answers one question only: **what telemetry can this
deployment actually search, and how can it search it safely?** It does not
decide whether a hypothesis is true and it does not manufacture semantic proof.

## 1. Provider contract

Every provider implementation MUST expose a versioned capability manifest:

```text
ProviderManifest
  provider_id
  provider_type
  deployment_id
  schema_version
  discovered_at
  scopes[]
  sources[]
  operations[]
  retention_bounds
  permission_bounds
  known_gaps[]
```

`ProviderScope` preserves the provider-native partition, such as a Splunk
index, an EDR tenant or an IDS sensor group. A source records the native source
name, sourcetype/data type, sampled fields, time bounds and discovery
provenance. Discovery results are deployment facts, not universal ontology.

## 2. Query boundary

The reasoning layer sends a provider-neutral `QueryIntent` containing:

- the goal and unresolved variables;
- current typed bindings and time bounds;
- the evidence relation that must be tested;
- required output variables;
- applicable cost and safety budgets.

The provider planner may select a validated template or ask an LLM to propose a
provider-native query. Generated queries MUST pass parsing, allow-list,
scope/time, pagination, dry-run and output-schema validation before execution.
An LLM proposal is never directly executable.

Every adapter returns a `QueryResult` envelope:

```text
QueryResult
  executed_ok
  rows[]
  complete
  cursor
  diagnostics[]
  scanned_units
  elapsed_ms
  provider_cost
```

`complete` is explicit. A row limit, `head`, timeout, missing page or truncated
provider response MUST NOT be interpreted as end-of-data.

## 3. Capability and source selection

Source selection is progressive rather than a fixed route table:

1. filter by actual availability, permission, retention and time overlap;
2. retrieve candidate sources from manifest metadata using deterministic and
   reproducible lexical/schema evidence;
3. if ambiguity remains, use a bounded LLM routing call over compact source
   cards, not the entire schema inventory;
4. validate that selected sources expose or can derive the variables required
   by the current goal;
5. retain alternative sources when evidence is insufficient.

No source, sourcetype, index or field is globally synonymous with a behavior.
For example, SMTP is not intrinsically "email evidence" and Sysmon is not
intrinsically "process proof". They become eligible only when the deployment
manifest and current relation requirements support that interpretation.

The runtime MUST NOT silently select the first registered provider. It MUST NOT
fall back to CDB/SQLite when live-provider discovery fails. Selection requires
an explicit successful capability match; otherwise the result is
`UNREACHABLE`, `UNSUPPORTED` or a clarification request.

## 4. Observation classification

Provider execution is classified before reasoning:

| Class | Meaning | Allowed next action |
|---|---|---|
| `QUERY_INVALID` | Query failed static/dry-run validation | repair or regenerate |
| `QUERY_FAILURE` | Provider rejected, timed out or failed | retry, alternate operation or stop bounded |
| `PARTIAL` | Some rows returned but search is incomplete | paginate, split time or narrow scope |
| `EMPTY` | Complete search returned no rows | test an alternative source/path; negative evidence only if the proof contract allows it |
| `CONTRADICTORY` | Valid evidence conflicts with the current claim | preserve contradiction and revise competing hypotheses |
| `AMBIGUOUS` | Multiple bindings or interpretations remain | add a discriminator or ask the user |
| `PROOF_GAP` | Data exists but does not satisfy the required relation | choose another operation/path |
| `VERIFIED` | An approved proof evaluator accepted the relation | commit bindings and advance the graph |

Rows alone are never `VERIFIED`.

## 5. Proof boundary

`ProviderOperation` metadata expresses routing eligibility and expected outputs;
it is not proof authority. A goal is supported only when its versioned
`ProofContract` evaluator checks the returned observations, bindings, entity and
time constraints, provenance and completeness requirements.

The adapter may normalize provider-native rows into append-only observations,
but it may not change hypothesis state, goal state or stopping state.

## 6. Provider-specific notes

### 6.1 Splunk

- Discover indexes and sourcetypes from the live deployment.
- Store compact source cards and field summaries with timestamps and sample
  provenance.
- Compile provider-native SPL only after a source is selected.
- Require bounded time ranges, explicit index scope and safe commands.
- Treat `head`/result limits as incomplete unless an independent count or
  provider completion signal establishes completeness.
- Record job SID, executed SPL, earliest/latest time, result count and provider
  diagnostics for audit.

The current accepted live test corpus is BOTS v2. References to BOTS v1 are
legacy and must not be used by active tests or default configuration.

### 6.2 CDB/SQLite

CDB is an explicit mock/test provider. It may be selected only when requested
by configuration or test fixture. It is not a fallback for a failed Splunk,
EDR or IDS connection.

### 6.3 Future SIEM, EDR and IDS providers

New providers implement the same manifest, query-intent, result-envelope and
proof-boundary contracts. Adding a provider must not require a new reasoning
architecture or provider-specific goal semantics.

## 7. Acceptance tests

A provider is accepted only when tests demonstrate:

- manifest discovery reflects the live deployment and records provenance;
- source selection does not depend on fixed scenario routes;
- generated native queries are validated before execution;
- pagination and bounded time splitting preserve completeness semantics;
- unknown native event types survive ingestion;
- unrelated non-empty rows cannot satisfy a relation proof;
- ambiguous bindings cause discrimination/clarification, not silent selection;
- provider failure cannot trigger a silent backend fallback;
- audit artifacts reproduce the exact query and provider response metadata;
- the same semantic graph can run through at least one mock and one live
  provider without changing reasoning logic.

## 8. Current status

The contracts above are the v9 target. Existing adapters and tests implement
parts of them, but production wiring is not complete. Completion is tracked in
`04-IMPLEMENTATION-CHECKLIST.md` and sequenced in
`08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md`.
