# 02 — METHOD AND IMPLEMENTATION PLAN (v4.1)

`01_FINAL-ARCHITECTURE.md` defines WHAT the system is. This file defines the
current executable HOW. `03` contains sources and traceability; `04` records
tests and remaining gates.

## 1. End-to-end lifecycle

```text
HuntRequest
  → KnowledgeBehaviorCompiler
  → HuntObjective + Hypothesis[] + EvidenceRequirementV4[]
  → Provider capability discovery/validation
  → Cell registration and Expectation instantiation
  → QueryTemplate or validated LLM fallback
  → LogicalQueryPlan → NativeQueryPlan
  → provider QueryResult
  → ObservationLedger
  → deterministic fact extraction and EvidenceCard grouping
  → expectation status and hypothesis reasoning
  → ActionController action selection
  → coverage-aware FinalHuntAccount and Markdown report
```

The engine can start with only `HuntRequest.content`. Explicit entities create
targeted Cells; no entity creates a wildcard Cell and may lead to bounded
DISCOVER/PIVOT actions.

## 2. Compilation

### 2.1 Deterministic paths

Known CVE records use the versioned knowledge base and separate exposure,
preconditions, exploitation indicators, post-exploitation and gaps. Known TTP
and IOC requests use registered behavior templates and provider-neutral
requirements. Structured YAML/JSON hypotheses are parsed directly.

These paths do not call an LLM.

### 2.2 Free-text semantic path

For unstructured `HYPOTHESIS` and `NL_QUESTION` requests:

1. The semantic compiler receives the request text.
2. It returns an unverified claim, semantic entities, mechanism status,
   competing hypotheses, assumptions and requirements.
3. `validate_compiler_llm_output` accepts only allowed semantic intents,
   evidence types, citations, descriptions and falsification conditions.
4. Search hints become query constraints only. They do not create evidence or
   confirmed Cells.
5. Invalid, missing or unavailable semantic compilation produces
   `INSUFFICIENTLY_SPECIFIED` and `STOP_INSUFFICIENT`.

There is no natural-language keyword fallback. A hypothesis statement cannot
classify an evidence card merely because it contains a word such as “web” or
“process”. Compatibility requires typed expectations; unresolved cards may be
sent to one bounded batch evaluator.

## 3. Requirements and expectations

`EvidenceRequirementV4` is question-side and provider-neutral. It contains an
evidence type/semantic intent, necessity, predicate, falsification condition,
source references and optional search hints.

`Expectation` binds one requirement to one concrete entity, provider scope and
time window. The engine creates expectations from explicit entities and from
entities discovered by bounded sweep/pivot actions. Hypothesis-to-requirement
binding uses requirement IDs, `supports` and the typed hypothesis class—not
hypothesis or requirement name matching.

## 4. Capability and query planning

```text
EvidenceRequirement
  → provider VersionedCapabilityDescriptor
  → CapabilityBinding
  → QueryTemplate (preferred)
  → QueryPlan validation
  → LogicalQueryPlan
  → provider NativeQueryPlan
```

Validation checks provider/scope, entity kind, time window, permissions,
observable fields, query limits and completeness contract. Missing capability
is returned as `UNSUPPORTED_REQUIREMENT`; unreachable scope is returned as
`UNREACHABLE`.

If no query template exists and an LLM planner is configured, it may propose
structured query parameters or custom native text. The result is parsed,
allowlisted, dry-run validated and compiled before execution. The LLM never
executes a query and cannot select a controller action.

Current implementations:

- `CdbAdapter`: local SQLite replay/test backend.
- `SplunkLiveAdapter`: live Splunk REST/oneshot search backend, using
  `configs/splunk_botsv1.yaml` when available or discovery mode otherwise.

EDR and IDS are extension contracts, not current live adapters.

## 5. Execution and completeness

Adapters return a `QueryResult` envelope containing execution status, rows,
native query, provider/scope information, observed fields, native types,
cursor and explicit `complete`.

For the current Splunk adapter, the search job endpoint is called in oneshot
mode. The adapter normalizes provider rows and applies an L+1 limit: returning
more than the requested limit yields `complete=False` and a bounded cursor;
otherwise the result is complete. A partial result cannot license negative
evidence.

Negative evidence additionally requires:

1. `ScopeHealthControl` passes;
2. `AnyRecordInScope` confirms active telemetry; and
3. `PredicateObservabilityControl` confirms the queried predicate is
   observable.

Controls produce diagnostics; they do not create observations.

## 6. Observation and evidence processing

Each returned row is stored as an append-only `Observation` with native type,
native fields, provider scope, timestamp and normalized entities. Unknown
native types are retained.

Deterministic fact extraction recognizes process execution, web request, DNS,
authentication, file modification, persistence and network facts according to
available fields/native provider mappings. Relationships and timestamps are
preserved for correlation.

`EvidenceGroupBuilder` fingerprints repeated facts and produces compact
`EvidenceCard` records with counts, representative observation IDs, entity/time
summaries, field summaries, relations and completeness. LLM contexts contain
cards/deltas, never the raw ledger.

## 7. Evidence evaluation and reasoning

The deterministic evaluator checks:

- evidence type against the expectation type;
- entity compatibility;
- field predicates (`EQUALS`, `CONTAINS`, `EXISTS`, `ABSENT`); and
- temporal/entity correlation for multi-stage chains.

Without an expectation, the compatibility result is empty/unknown. If an
evaluator caller is configured, unresolved cards can be sent together in one
structured batch, and returned hypothesis IDs are schema-filtered against the
active set. This is advisory; status changes still follow deterministic
expectation results and controller rules.

Competing hypotheses remain active until their own expectations are concluded.
For a typed web-request attack chain, web, process/artifact evidence must be
co-located and temporally correlated before the chain is considered supported.

## 8. Controller and actions

The Action Controller chooses the first available action in this order:

```text
TEST → CONTROL → EXPAND → DISCOVER → PIVOT → REFINE → STOP
```

- `TEST`: execute an untested expectation.
- `CONTROL`: run telemetry health/record/observability controls.
- `EXPAND`: execute a requirement against a discovered concrete entity.
- `DISCOVER`: bounded wildcard/scope sweep.
- `PIVOT`: investigate bounded entities extracted from returned rows.
- `REFINE`: batch unresolved evidence for advisory semantic evaluation.
- `STOP`: emit the account after deterministic stopping evaluation.

The budget ledger defaults to 15 turns, 60 queries, 3 LLM calls, 100 scan
Cells and 300 seconds. LLM usage additionally tracks prompt/completion tokens,
latency, model and estimated USD cost.

## 9. Reporting and outcomes

`FinalHuntAccount` cites hypotheses, requirements, cards, observations,
queries, diagnostics, residuals and coverage. It distinguishes:

```text
SUPPORTED / CONTRADICTED / INCONCLUSIVE / UNKNOWN /
UNREACHABLE / INSUFFICIENTLY_SPECIFIED / UNSUPPORTED
```

`NO_EVIDENCE_FOUND` is a rendering of an unresolved/unknown hunt, not proof of
benign behavior. Scope coverage, requirement coverage, unobservable data,
unqueryable providers and incomplete results remain separate.

## 10. Current verification plan

The verified local/live path is:

```text
semantic fixture or structured request
  → CDB replay or Splunk BOTSv1
  → query/result envelope
  → observation/cards
  → bounded action loop
  → account/report
```

The semantic fixture validates contracts but has zero monetary cost. A real
LLM API run is a separate integration gate because model quality, latency,
token usage and provider policy must be measured independently.
