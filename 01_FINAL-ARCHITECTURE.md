# 01 — FINAL ARCHITECTURE (v3 — ProviderScope/ProviderOperation reset)

**Status: CORE CONTRACT FROZEN.** This document defines module boundaries and
terminology. Runtime parameters and implementation tasks live in `02`. The
revised contracts must pass the Phase 0 invariant tests before adapters begin.

## 1. Objective

Take an arbitrary security alert—including one carrying no entities—and
produce an auditable account of what happened, not an unjustified verdict. The
agent must keep competing explanations alive, distinguish “found nothing” from
“nothing happened”, treat log text as untrusted data, and report what it could
not see.

## 2. Architecture

```text
 ALERT
   |
   v
 [M1] OBSERVATION LEDGER  <----- observations ----- [M3] CONSTRAINT CHECKER
   |                                                   ^
   | unattributed observations                         |
   v                                                   |
 [M2] ABDUCTION ENGINE (LLM) ---- explanations ------ [M4] CONTROLLER
                                                           |
                                                           | bounded query plan
                                                           v
                                               [M5] ADAPTER / REPORTER (LLM)
                                                           |
                                         native provider query + final account
                                                           v
                                                        ANALYST
```

There are five modules. M2 and M5 may call an LLM. No module may add a second
state machine, a universal event ontology, or an implicit completeness oracle.

## 3. Module responsibilities

| Module | Responsibility | LLM |
|---|---|---|
| **M1 Observation Ledger** | Deterministic parsing, entity extraction, taint/provenance, native observation preservation, outcome typing, attribution bookkeeping and coverage accounting. The prompt-injection boundary. | Forbidden |
| **M2 Abduction Engine** | Propose candidate explanations and the `EvidenceRequirement`s each predicts. This is the only open-world component. | Required |
| **M3 Constraint Checker** | Check schema, provenance, contradictions, expectation results and negative-evidence preconditions. The only module allowed to change explanation/attribution status. | Forbidden |
| **M4 Controller** | Select cells/actions, enforce budgets, schedule sampling, decide escalation/stopping, and compute the final disposition exactly once. | Forbidden |
| **M5 Adapter / Reporter** | Bind requirements to allow-listed `ProviderOperation`s, validate/execute native queries, and render the final account. Never derives a disposition. | Required |

## 4. The four separate contracts

| Question | Contract | Boundary |
|---|---|---|
| Where is data addressable? | `ProviderScope` | native partition, coverage, retention, gaps |
| How is it queried? | `ProviderOperation` | provider API/search, parameters, pagination, completeness |
| What evidence would answer a question? | `EvidenceRequirement` | small versioned question vocabulary |
| What did a record mean? | `native_type` + nullable `SemanticType` | optional post-hoc enrichment |

`EventFamily` is not a Cell axis, not a registry denominator, and not a
restriction on what the agent may query. If kept, it is only an optional
semantic label assigned after retrieval. An event with no label is a valid
observation and retains its native type, fields, raw reference and provenance.

## 5. Addressability and query surface

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

A `Cell` answers only whether a provider scope/entity/time region has been
explored. It has no event-family, intent or operation axis.

The seven investigation workflows are:

`ProcessLineage`, `LogonHistory`, `NetworkConnections`, `PersistenceArtifacts`,
`FileWrites`, `DNSQueries`, and `BroadSweep`.

The three control operations are:

`ScopeHealthControl`, `AnyRecordInScope`, and `PredicateObservabilityControl`.

Workflows map to `EvidenceRequirement`s; requirements map to provider
operations. A requirement can be answered by different native records on
different providers. A provider does not need a universal `event_code`.

`BroadSweep` operates on a wildcard Cell and is the entity-free bootstrap path.
It may mint observations. Controls never mint observations and exist only to
license a `VALID_NEGATIVE` result.

## 6. LLM runtime and deterministic boundary

The real M2 runtime calls an external LLM API through an internal
`ApiLLMProvider` interface. Provider, model, endpoint, timeout and token limits
are configuration/secrets, not investigation logic. Local model inference is
outside the current deployment decision. A stub provider remains available for
deterministic tests and never calls a network.

API calls are permitted for proposing explanations/requirements, proposing a
native query inside an adapter allowlist, and rendering a narrative from a
fixed schema. The LLM may not extract fields, label taint, retrieve data,
expand scope, change state, type outcomes, select actions, run controls,
attribute evidence, stop the investigation, or compute disposition.

The M2 API contract is:

```text
structured investigation context
  → ApiLLMProvider.generate()
  → schema-validated JSON
  → explanations + EvidenceRequirements
  → M3 constraint validation
```

Raw log text is never passed to the LLM. Only structured, taint-labelled data
and validated schemas cross the boundary.

## 7. Investigation lifecycle

```text
ALERT
  → DISCOVER  configured/discovered ProviderScopes and operations
  → BOOTSTRAP entities (possibly empty) and time window
  → SCOPE     wildcard cells, then instance cells from observations
  → PLAN      EvidenceRequirement → CapabilityBinding → ProviderOperation
  → EXECUTE   native query with complete/partial metadata
  → NORMALIZE preserve native record; semantic mapping optional
  → ABDUCE    explanations for unaccounted observations
  → VALIDATE  constraints, controls and contradictions
  → EXPAND + SAMPLE bounded frontier exploration
  → ASSESS    explanations, residuals and separate coverage bounds
  → TERMINATE STOP_RESOLVED or STOP_BOUNDED
  → CONFIRM   analyst confirmation where mandatory
```

An entity-free alert is first-class: wildcard Cells come from known provider
scopes alone. A complete targeted query does not make an entire scope explored;
only a complete scope scan can make that coverage claim.

## 8. Dispositions

M4 computes one mutually exclusive disposition and writes it once:

| Disposition | Meaning |
|---|---|
| `MALICIOUS` / `BENIGN` | one surviving explanation of that class leads unambiguously |
| `UNKNOWN` | evidence supports a surviving explanation whose class is unknown |
| `INSUFFICIENT_EVIDENCE` | investigation cannot choose because required evidence is missing, dark, unqueryable or budget-bounded |
| `CONFLICTED` | unresolved evidence conflict or tied explanations of different classes |

`UNKNOWN` is a statement about the behaviour; `INSUFFICIENT_EVIDENCE` is a
statement about our observability. Unavailable required telemetry is always the
latter.

## 9. Coverage claims

Coverage is reported on two axes:

- **scope coverage:** `EXPLORED`, `PARTIAL`, `UNEXPLORED`, `UNQUERYABLE` and
  `UNREACHABLE` cells;
- **requirement coverage:** requirements that are `EXACT`, `PARTIAL`,
  `UNSUPPORTED_REQUIREMENT`, executed-complete, or failed.

`UNKNOWN_SOURCE` is outside the configured/discovered universe. It is reported
as a blind spot but not counted as a denominator. Retrieved records without a
semantic mapping are `UNMAPPED`, remain first-class evidence, and are counted
in the coverage bound.

The architecture claims neither hypothesis completeness nor visibility into
undeclared/deleted/suppressed data. It bounds and reports those limitations.
