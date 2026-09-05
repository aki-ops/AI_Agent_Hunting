# AI Agent Hunting — Project Context (v4.1)

Read the documents in this order:

1. `01_FINAL-ARCHITECTURE.md` — canonical boundaries;
2. `02_METHOD-AND-IMPLEMENTATION-PLAN.md` — executable lifecycle;
3. `03_LITERATURE-AND-TRACEABILITY.md` — sources and design provenance;
4. `04-IMPLEMENTATION-CHECKLIST.md` — verified work and open gates.

`README.md` contains setup and run commands. `docs/01-REAL-PROVIDER-SPECIFICATIONS.md`
contains provider extension contracts.

## Objective

Build a pure hypothesis-driven threat-hunting engine. It starts from a
hypothesis/TTP/IOC/CVE/CTI/question, preserves competing explanations, never
treats an empty or partial query as real-world absence, and reports residual
uncertainty and blind spots.

## Implemented runtime

The current implementation contains:

- `KnowledgeBehaviorCompiler` for deterministic known knowledge and bounded
  semantic compilation of free text;
- `CanonicalQueryPlanner` and native CDB/Splunk query compilers;
- CDB SQLite and live Splunk adapters;
- append-only observations, deterministic facts and compressed evidence cards;
- typed expectation evaluation, temporal/entity correlation and bounded
  controller actions;
- final account/report rendering and LLM token/cost tracking.

Free text without `--llm api` is intentionally stopped as
`STOP_INSUFFICIENT`. The offline semantic stub is a test fixture, not a model
of production understanding. Live EDR/IDS adapters remain future work.

## Core vocabulary

| Concept | Meaning |
|---|---|
| `ProviderScope` | native addressable partition with retention, coverage and gaps |
| `ProviderOperation` | provider function with schema, pagination and completeness contract |
| `Cell` | `(ProviderScope, entity/ANY, time_bucket)` coverage address |
| `EvidenceRequirement` | provider-neutral question-side evidence shape |
| `Expectation` | one requirement bound to entity, scope and time |
| `native_type` | original provider record type, preserved |
| `semantic_type` | optional normalized meaning; may be absent |
| `search_hints` | query constraints from semantic compilation; never evidence |
| `EventFamily` | not a Cell axis or complete query universe |

Unknown native records are retained. A known scope without a usable operation
is `UNQUERYABLE`; a source outside the catalog is an explicit blind spot, not
an invented enumeration.

## Runtime flow

```text
request
 → compile hypothesis/requirements
 → discover provider capabilities
 → register wildcard or instance Cells
 → create typed Expectations
 → plan/validate/compile native query
 → execute provider query
 → append Observation
 → extract/group EvidenceCards
 → test expectations and correlate evidence
 → controller selects next action
 → build account/report
```

Action precedence is `TEST → CONTROL → EXPAND → DISCOVER → PIVOT → REFINE → STOP`.
The default budget is 15 turns, 60 queries, 3 LLM calls, 100 scan Cells and
300 seconds. The LLM cannot execute queries, mutate state, select actions or
determine final disposition.

## Verification boundary

The current live evidence is for Splunk BOTSv1. CDB/mock provider tests cover
the provider-neutral contracts. Real LLM API, EDR and IDS runs still need
separate captured integration evidence before production claims.
