# 02 — METHOD AND IMPLEMENTATION PLAN (v7)

`01_FINAL-ARCHITECTURE.md` defines the architecture. This document is the
implementation plan for its dynamic telemetry-discovery and hybrid query
synthesis revision. `03` records the research basis; `04` is the evidence-gated
checklist. No item is complete merely because a query returned plausible rows.

## 1. Decision and boundary

The agent must work with unfamiliar provider schemas without hard-coding that
SMTP means mail, Sysmon means process/file, or a person maps to an account or
host in one fixed order. It therefore uses a **dynamic capability path**:

```text
request
  -> provider census
  -> SemanticGoalGraph
  -> LLM source-capability proposals
  -> deterministic validation + bounded probes
  -> validated RuntimeCapabilityGraph
  -> goal/claim binding and action selection
  -> QueryIntent compiler OR quarantined raw-native-query path
  -> QueryResult -> EvidenceGraph -> verification -> report
```

The LLM is creative only in proposing a graph, source mappings and query
intent. It is not authoritative over source existence, field meaning, query
cost, returned facts, identity bindings or the final verdict.

There are two legal native-query paths:

1. **Normal path — QueryIntent.** LLM or planner emits a provider-neutral,
   typed intent. The adapter binds validated source/field roles and compiles
   SPL/KQL/SQL/API syntax.
2. **Novel path — quarantined native-query candidate.** If the intent language
   cannot express a necessary operation, the LLM may propose native syntax. It
   is parsed into an AST, policy-validated, cost-gated and dry-run before any
   live execution. A rejected query never reaches the provider.

Raw native syntax is therefore permitted as a bounded fallback, not as the
primary control plane and not as an unrestricted tool call.

## 2. Runtime method

### Step 0 — Freeze request and budget

Persist the exact `HuntRequest`, user-provided entities, time policy, provider
hints, model version and budgets. Request text and telemetry text are untrusted
data, not instructions that can alter scope, provider selection, budget or
verdict.

Output: immutable request and run ledger.

### Step 1 — Provider-neutral telemetry census

Every reachable provider returns a `TelemetryCensus`, without semantic guesses:

- permitted index/table/stream identifiers and time range;
- source/sourcetype/native type identifiers and event counts;
- field names, inferred primitive types, null/coverage rates and aliases;
- bounded, privacy-filtered representative values or field sketches;
- permissions, retention, pagination and query-cost limits;
- provider-native query primitives.

The census has a stable `schema_fingerprint`. It is retained in the local
capability catalog and is never serialized wholesale into the semantic
compiler prompt. The complete profiles remain available to deterministic
validation; later retrieval creates a bounded relation-specific view for the
source profiler.

Output: audited `TelemetryCensus` and initial `CapabilityGraph` containing
only bootstrap operations such as census and bounded probe execution.

### Step 2 — Semantic goal graph

The semantic compiler receives the request only. It proposes a schema-strict
`SemanticGoalGraph`: typed variables, requested answer
variables, relations, qualifiers, dependencies, OR alternatives, assumptions
and acceptance conditions.

It cannot emit a provider query, native field name, event ID, evidence claim or
final verdict. A deterministic validator preserves the original objective,
rejects unsupported expansion and checks graph acyclicity/provenance.

Output: accepted graph with unresolved semantic requirements, for example
`person --associated_with--> endpoint --has_file_event--> file`.

### Step 2.5 — Relation-scoped capability retrieval

For each unresolved graph relation, a deterministic batcher orders native
source profiles by metadata and field overlap with that relation's typed
requirements, but does not discard low-scoring sources. Every discovered source
and field is scheduled into one or more context-sized batches. The score only
controls processing order; it is not a semantic assertion, a Top-K cutoff or a
fixed `event_family` mapping.

The batcher records the terms, scores, processing order, source/field coverage,
batch count and any unprofiled native sources. It passes only one compact batch
to each LLM call. The complete census remains the authoritative deterministic
validation set, so prompt truncation cannot authorize a field that the provider
did not expose. If the census itself is incomplete, the relation remains
coverage-limited rather than being marked unsupported.

Output: relation-specific exhaustive batches and an auditable coverage trace.

### Step 3 — Semantic source-capability profiling

For graph requirements that no already validated capability satisfies, call the
new `source_profiler` once per `(provider, scope, schema_fingerprint,
requirement_signature)` cache key. It receives only the compact candidates
for that relation and may propose candidates in this form:

```json
{
  "source_id": "census-defined ID",
  "relation": "associated_with",
  "input_roles": {"person": "field-id"},
  "output_roles": {"endpoint": "field-id"},
  "proof_mode": "retrieval_only | relation_observable",
  "probe": {"kind": "cooccurrence", "projection_roles": ["person", "endpoint"]},
  "rationale_refs": ["field-id", "sample-id"],
  "confidence": 0.0
}
```

`source_id`, field IDs, roles, relation kinds and probe kinds are enums or
references to census records. The profiler may not invent a source, field,
entity value, index selector or native query. Source names are weak hints; the
field profile and probe are the evidence for capability.

Output: `SourceCapabilityProposal[]`, all still untrusted candidates.

### Step 4 — Deterministic proposal validation and probes

Validate each proposal against the census:

- source/field IDs exist and are permitted;
- role/type combinations are compatible;
- requested relation/proof mode is allowed;
- source selector, time scope and fan-out comply with policy;
- no user or telemetry text has been treated as a command.

The adapter compiles each accepted `ProbeSpec` itself. A probe has a small
time window, bounded row count, narrow projection and a hard timeout. It tests
whether the declared source can actually expose the proposed roles/relation.

Successful probe = **observable capability**, not proof of the user claim.
Rejected, empty, incomplete or ambiguous probes retain diagnostics and never
become an operation silently.

Output: `RuntimeCapability` records with status `VALIDATED`, `CANDIDATE`,
`REJECTED`, `UNSUPPORTED` or `UNREACHABLE`, plus query/citation artifacts.

### Step 5 — Dynamic capability materialization and graph binding

Materialize a validated proposal into a provider-neutral `ProviderOperation`
with source selector, input/output roles, relation/fact contract, proof mode,
query limits and provenance. Cache it by schema fingerprint and invalidate it
when the provider schema, permission state or index scope changes.

The planner binds graph edges only to validated runtime capabilities. A static
provider descriptor can provide generic census/probe primitives, but cannot be
an authoritative semantic route merely because it mentions SMTP, Sysmon,
Windows Security, email, host or file.

Bindings remain `CANDIDATE` until observations satisfy the edge's acceptance
rule. Equivalent anchor routes form an OR group; dependent regions form AND
dependencies. Multiple bindings are retained, then disambiguated by a bounded
query or an explicit user choice—never by selecting the first host/account.

### Step 6 — Query intent synthesis and compilation

For each selected operation the planner emits a `QueryIntent`, not query text:

```text
QueryIntent {
  goal_id, operation_id, source_selector,
  relation_to_test, request-grounded/provider-observed bindings,
  predicates expressed as field roles and typed operators,
  time_scope, projection roles, aggregation/correlation operator,
  expected_output_shape, expected_cost_bound
}
```

The adapter resolves role IDs to fields from the validated runtime capability
and compiles parameterized SPL/KQL/SQL/API syntax. Values may only originate
from the frozen request, validated configuration or cited provider observation.
For example, a display name cannot mutate into an account name; a device label
cannot mutate into a hostname.

Discovery intent is allowed when an anchor is unknown, but it must use narrow
projection, aggregation/deduplication and bounded cardinality—not a raw
`index=* | head` dump.

### Step 7 — Quarantined raw native-query fallback

Use this only when the adapter declares that the accepted `QueryIntent` cannot
express a required operation. The LLM receives the intent, validated source
profile, permitted field IDs, query budget and target output schema. It may
return one `NativeQueryCandidate` with reason and expected result shape.

Before dispatch, the native-query gate must:

1. parse query text into a provider AST (not regex-only validation);
2. permit only read-only AST operators and provider-specific safe functions;
3. require a census-known index/table/source and an explicit time bound;
4. require narrow projection plus result, subsearch and scan-cost limits;
5. reject mutation, external side effects, opaque script execution, forbidden
   commands and unbounded fan-out;
6. ensure all identifiers are census-known and all value bindings are trusted;
7. estimate cost and run a bounded dry-run/parse check; and
8. validate that returned fields match the declared output shape.

One structured repair attempt may receive only validator diagnostics. Further
failure becomes `UNSUPPORTED_QUERY_EXPRESSION` or `STOP_BUDGET_EXHAUSTED`, not
an unbounded retry loop.

### Step 8 — Evidence, verification and bounded replanning

Adapters return complete `QueryResult` envelopes. The ledger stores raw rows
append-only; deterministic extractors create facts, evidence cards and
candidate edges. The verifier checks cited observations, role identity,
temporal qualifiers, acceptance rules and query completeness before promoting
an edge or final answer.

Replanning is permitted only after a material delta: a rejected/missing
capability, ambiguity, new evidence changing a dependency, a complete-empty
retrieval attempt, or a coverage gap. It receives structured attempt/gap
diagnostics and evidence cards, never the full raw ledger. The controller owns
all state, retry, query, scan, token and runtime budgets.

For every required relation, the controller maintains separate execution,
proof and route-exhaustion state. A complete provider request with zero rows is
`ATTEMPTED_EMPTY`, not a completed semantic route. The next action is selected
from this bounded order when valid: continue pagination, advance the declared
retrieval policy, execute a declared alternative, discover/probe a missing
capability, or stop. A no-progress signature prevents replaying an identical
operation/source/binding/time/predicate stage.

The declared retrieval policy may relax only retrieval-only predicates. It must
retain provider scope, verified identity binding, time interval, projection,
row/page limits and every proof obligation. Rows obtained by a relaxed stage
remain candidates until deterministic verification satisfies the original
relation and qualifiers.

Capability profiling is triggered by proof-aware readiness, not merely by the
absence of a composable static plan. A static operation is ready only when its
typed route, grounded inputs, source provenance, retrieval contract and
proof/qualifier observability cover the outstanding relation. Static
retrieval-only reachability therefore cannot suppress profiling after a proof
or complete-empty route gap.

### Step 9 — Final account

The report must show:

1. the question and accepted SemanticGoalGraph;
2. each required edge and its dependency/alternative group;
3. profiler source proposals, validation/probe decisions and cache status;
4. each chosen QueryIntent, generated native query, compact result sample and
   its relation to the graph edge;
5. verified evidence, unresolved gaps and why a stop was selected; and
6. LLM calls/tokens/latency/cost and provider query/scan cost.

## 3. Detailed code plan

### Phase A — Contracts and migration boundary

Create `TelemetryCensus`, `TelemetrySourceProfile`, `SourceCapabilityProposal`,
`ProbeSpec`, `RuntimeCapability`, `QueryIntent`, `NativeQueryCandidate` and
`NativeQueryValidationResult`. Extend `ProviderOperation` with runtime
provenance, role bindings, proof mode, schema fingerprint and expiry.

Expected locations:

- `src/hunting/contracts/capabilities.py`
- `src/hunting/contracts/source_profile.py` (new)
- `src/hunting/contracts/query_intent.py` (new)
- `src/hunting/contracts/native_query.py` (new)

Acceptance: invalid IDs, raw fields in semantic graph output, unsupported role
combinations and missing output contracts are rejected by unit tests.

### Phase B — Census and safe provider profiling

Add `build_telemetry_census()` and `execute_probe()` to the adapter contract.
Splunk gathers metadata and bounded field sketches; CDB implements the same
contract through table/schema inspection. Do not attach a semantic label from a
sourcetype name in either adapter.

Expected locations:

- `src/hunting/capabilities/census.py`
- `src/hunting/m5_adapter/splunk_adapter.py`
- `src/hunting/m5_adapter/cdb_adapter.py`

Acceptance: a renamed or unfamiliar source with suitable fields survives
census; a source named SMTP without sender/receiver fields is not labelled mail.

### Phase C — Source profiler and cache

Add `source_profiler` to the LLM caller registry, schema-strict response parser
and cache. Limit it to one call plus at most one repair per cache key. Feed only
relation-scoped profile batches and graph requirements; use the complete
census only for deterministic validation. The retrieval score distribution,
batch count, source/field coverage and any census gaps must be persisted in the audit.

Expected locations:

- `src/hunting/m2_abduction/provider.py` or the current LLM factory
- `src/hunting/capabilities/source_profiler.py` (new)
- `src/hunting/capabilities/profile_cache.py` (new)

Acceptance: source/field hallucinations, prompt injection and oversized raw
sample input are rejected; cache hit makes zero profiler calls; a profile
limit can never be reported as complete discovery.

### Phase D — Proposal validation, probes and materialization

Implement a deterministic validator, generic probe compiler and capability
materializer. Refactor static source-role dictionaries so they are optional
bootstrap hints with provenance, never default semantic truth.

Expected locations:

- `src/hunting/capabilities/source_mapping_validator.py` (new)
- `src/hunting/capabilities/probe_executor.py` (new)
- `src/hunting/capabilities/runtime_materializer.py` (new)
- `src/hunting/capabilities/inventory.py`
- `src/hunting/m5_adapter/splunk_adapter.py`

Acceptance: planner can use a runtime-discovered operation; a failed probe
cannot create one; a successful schema-only probe cannot prove an incident fact.

### Phase E — Goal planner and QueryIntent compiler

Change the semantic executor to select `VALIDATED` runtime capabilities by
graph edge. Implement role-to-field binding and parameterized native compiler.
Ensure OR anchor routes, ambiguity and fan-out obey existing evidence policy.

Expected locations:

- `src/hunting/planner/semantic_executor.py`
- `src/hunting/capabilities/binder.py`
- `src/hunting/engine.py`
- provider adapters' query compilers

Acceptance: a person/endpoint/file graph can choose a schema-discovered route;
it never chooses the first candidate and never constructs a broad query without
a declared discovery reason.

### Phase F — AST-gated native-query fallback

Implement provider-specific parser/adapters behind a common native-query gate.
For Splunk, use a real SPL parser if available; otherwise implement a limited
grammar for the supported SPL subset and reject syntax outside it. Do not claim
arbitrary full-SPL safety without a full parser.

Expected locations:

- `src/hunting/query_safety/native_query_gate.py` (new)
- `src/hunting/query_safety/spl_ast.py` (new or parser integration)
- `src/hunting/query_safety/policy.py` (new)
- `src/hunting/m5_adapter/splunk_adapter.py`

Acceptance: mutation/side-effect commands, unknown fields/indexes, missing time
scope, unbounded subsearches and query-text injection are blocked before live
dispatch; valid unusual read-only SPL passes dry-run and shape validation.

### Phase G — Evidence/report observability

Store source-profile IDs, proposal IDs, probe query IDs, intent IDs, native
candidate gate decisions and cache metadata in the ledger. Render them in the
analyst report without dumping raw observations.

Expected locations:

- `src/hunting/reporter/builder.py`
- `src/hunting/reporter/renderer.py`
- `src/hunting/engine.py`

Acceptance: an analyst can reconstruct why a source and query were selected,
what returned, and why the answer is supported/inconclusive.

### Phase H — Evaluation and rollout

Run in `source_profiling=off|audit|auto|force` modes. Start in `audit`: static
and dynamic candidate plans are compared but only the existing safe path runs.
Promote only after replay results meet predeclared thresholds.

Measure source-role mapping precision/recall, capability-probe precision,
planner/edge/evidence/answer F1, hallucinated-source/field rate, unsupported
expansion rate, queries, scan volume, LLM calls/tokens/cost and latency.

## 4. Required test matrix

| Test | Required result |
|---|---|
| Unfamiliar process source | Fields/samples permit a validated process capability without the word Sysmon. |
| Renamed mail source | Source can be proposed/validated from sender-recipient fields, not source name. |
| Misleading source name | SMTP-named source lacking message roles is rejected. |
| Missing telemetry | Graph returns unsupported/coverage gap, never fabricated query or NOT_FOUND. |
| Multiple person-to-host candidates | All candidates retained; disambiguation or user decision occurs. |
| Novel correlation | Intent compiler is tried first; raw candidate is AST-gated only when necessary. |
| Raw SPL injection/mutation | Rejected before dispatch. |
| Schema change | Cache invalidates and profiles again. |
| Repeated run, unchanged schema | Cache hit; no profiler call. |
| Partial query | Cannot prove absence or a negative verdict. |
| State transition | The edge carries the validated operation proof contract. Verification requires ledger-backed citations in one provider/scope, compatible typed entity values, parseable ordered timestamps within the declared bound, declared `action_roles` plus `state_roles`, and a stable value from `artifact_identity_roles` or `correlation_roles`. A suffix or source label is never a transition or causality fact. |
| Semantic negative | Requires every declared bounded route exhausted, every attempt complete-empty, and an explicit provider negative/completeness license. Without all three the terminal result is `INCONCLUSIVE`. |

## 5. Definition of done

This revision is complete only when a labelled run can: discover an unfamiliar
source from a bounded census; obtain a validated runtime capability through a
probe; build a graph-bound `QueryIntent`; compile or safely quarantine a novel
native query; preserve evidence and completeness; explain the source/query
choice; and report mapping, evidence and answer metrics separately from cost.

It is not complete when the result merely looks plausible on BotSv2, when a
source label is hard-coded, or when raw native query text can bypass the gate.
