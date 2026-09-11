# 01 — FINAL ARCHITECTURE (v7)

## Source of truth

This document defines the architecture. `02_METHOD-AND-IMPLEMENTATION-PLAN.md`
defines execution and migration. `03_LITERATURE-AND-TRACEABILITY.md` records
what external sources support and what remains a thesis engineering choice.
`04-IMPLEMENTATION-CHECKLIST.md` is the evidence-gated implementation plan.
`06-REFERENCE-ARCHITECTURE-DECISION.md` contains the detailed decision record
and research sources behind this revision.

The system is an **evidence-seeking investigation agent**. It accepts a
question, hypothesis, CTI/TTP/IOC/CVE or scheduled hunt and produces an
auditable answer or an explicit inconclusive result. It is neither an
unconstrained LLM nor a collection of scenario templates.

## 1. Core architecture

```text
Request
  -> Provider Census
  -> LLM SemanticGoalGraph Proposal
  -> Deterministic Plan Validation
  -> Relation-scoped Capability Retrieval
  -> LLM Source-Capability Proposal
  -> Deterministic Validation and Bounded Capability Probes
  -> Runtime Capability Binding and Action Selection
  -> QueryIntent Compilation or Quarantined Native-Query Validation
  -> Safe Native Query Execution
  -> Observation / Fact / Evidence Graph Update
  -> Claim Verification and Bounded Replanning
  -> Grounded Answer, Coverage and Cost Report
```

The same contracts are used for every request. The runtime must not branch on
`email`, `Tor`, `CVE`, `web`, `process`, `event_family`, or `request_mode` to
select a prewritten investigation story.

The investigation path is produced from:

1. the user's declared objective;
2. typed goals, relations and restrictions proposed by the semantic compiler;
3. provider capabilities and required inputs/outputs;
4. observations acquired during the current run; and
5. explicit acceptance, refutation, coverage and budget rules.

This gives a general contract without pretending that every hunt has the same
behavioural path.

## 2. Scientific grounding and limits

| Architectural principle | External grounding | Boundary of the claim |
|---|---|---|
| Evidence/provenance graph | SLEUTH, HOLMES, OmegaLog | Supports multi-hop reconstruction and context preservation; does not require every question to use a fixed attack graph. |
| Typed logical query before native syntax | AIQL, ThreatRaptor | Supports an intermediate query/behaviour representation; does not prove this repository's exact schema. |
| Hypothesis/evidence/action loop | Evidential Cyber Threat Hunting, ATHAFI, TaHiTI | Supports explicit uncertainty and adaptive collection; thresholds and stopping enums are local choices. |
| Schema/capability-aware execution | OCSF, MITRE Data Components, Microsoft Threat Hunting Assistant | Supports provider-aware binding and extensible semantics; no taxonomy covers every native event. |
| LLM bounded by deterministic execution and verification | ExCyTIn-Bench and safe tool-use research | Supports measuring and constraining the LLM; does not make a model reliable by itself. |
| Flexible threat-hunting process | Maxam et al. field study | Supports avoiding one prescriptive workflow; does not specify our implementation. |

Full links and source tiers are in `03`. External papers support principles,
not the exact budgets, prompts, class names, or F1 thresholds in this project.

## 3. Universal data contracts

### 3.1 Request

```python
HuntRequest = {
    "id": str,
    "kind": "QUESTION" | "HYPOTHESIS" | "TTP" | "IOC" |
            "CVE" | "CTI_REPORT" | "SCHEDULED",
    "content": str,
    "entities": list[EntityRef],
    "time_policy": TimePolicy | None,
    "provider_hints": list[str],
}
```

The request is an objective, not evidence. An explicit entity is an unverified
seed until a provider observation establishes the required relation.

### 3.2 SemanticGoalGraph and compatibility ClaimGraph

The provider-neutral semantic contract proposed by the LLM and accepted only
after validation is `SemanticGoalGraph`. It contains typed variables,
relations, qualifiers, answer variables, assumptions and uncertainties.
`ClaimGraph` remains a compatibility representation for the older execution
path; it is mechanically projected into the semantic graph and is not allowed
to bypass typed capability binding.

```text
SemanticGoalGraph {
  id,
  variables: typed entities/values and constraints,
  relations: subject -> relation -> object,
  qualifiers: required restrictions on relations,
  answers: variables requested by the user,
  assumptions, uncertainties,
}
```

There is no universal `event_family` axis and no automatic semantic branch.
Technical prerequisites may be added only when an operation explicitly
requires them; they are recorded as prerequisites, not as extra conclusions.

Every relation must be traceable to the request or a declared prerequisite;
unsupported story expansion is rejected. The runtime planner composes typed AND
dependencies and declared OR alternatives. It does not infer account, endpoint,
IP, message, recipient, role or web paths from request keywords. Operation-
required prerequisites belong to capability binding.

The graph is not required to pass through a particular identity type. If the
request has a person and the provider can discover endpoint keys directly,
`person -> host` is a valid route; `person -> account -> host` is only another
typed route when an account relation is actually observable. This keeps the
account/host anchor region flexible without selecting a host by name or order.

### 3.3 Telemetry census and CapabilityGraph

The Provider Census first creates a versioned, provider-neutral
`TelemetryCensus`. It records native partitions, schemas, field coverage,
retention, permissions, query primitives and bounded privacy-filtered field
sketches. It does **not** conclude that a sourcetype is mail, process, file or
any other semantic category merely from its name.

For an unresolved graph requirement, the LLM may propose a source capability
using only census IDs: a source, source fields as typed roles, relation/fact
kind and a bounded `ProbeSpec`. A deterministic validator checks every ID and
policy constraint; the adapter compiles and executes the probe. Only a
successful probe materializes a versioned `RuntimeCapability`.

The resulting `CapabilityGraph` contains bootstrap and validated runtime
operations:

```text
ProviderScope
  -> native partitions / index or table
  -> schema and field aliases
  -> logical operations
  -> input entity kinds
  -> output fact kinds
  -> permissions / retention / time limits
  -> pagination / completeness semantics
```

`ProviderOperation` is provider-neutral at the contract boundary. Its normal
execution form is a typed `QueryIntent`; the adapter owns binding validated
roles and compiling SPL, KQL, SQL or API syntax. It must declare which semantic
constraint keys it can prove and which it can use only as retrieval hints. A
searchable restriction narrows candidate retrieval but never upgrades the
relation verdict; only a proof-supported restriction can do that. A provider is
not selected merely because it is reachable: it must satisfy an outstanding
relation and expose the relevant contract.

The census is not sent wholesale to one LLM call. After the semantic graph is
validated, a deterministic batcher orders native source profiles separately
for each unresolved relation, but schedules every discovered source and every
field. It splits that complete set into context-sized batches; ordering is only
an execution optimization and never an admission decision. The LLM source
profiler sees one relation-specific batch at a time, while the complete census
remains the authoritative validation set. An incomplete batch run is a
coverage gap, never an implicit "no source" result.

When a `QueryIntent` cannot express a needed provider feature, a separately
gated LLM may submit one native-query candidate. It is not executed directly:
the provider parser converts it to an AST, then the policy requires read-only
operators, census-known identifiers, trusted values, explicit time/result/scan
bounds and a dry-run. This preserves novel-query expressiveness without making
raw SPL an unrestricted LLM tool.

Runtime bindings follow the same epistemic rule. A complete query may produce a
usable row while still leaving a requested restriction unproven; that output is
`CANDIDATE`, not `VERIFIED`. It may be consumed by a downstream exploratory
retrieval step so the system can collect discriminating evidence across the
whole candidate set, but it can never license a positive claim until the
restriction is proven. The executor must preserve every candidate and never
select the first value.
When a step returns more distinct output bindings than the configured fan-out
bound, the executor preserves all rows for audit but pauses for explicit
narrowing rather than launching unbounded downstream queries. Declared
alternative methods are tried only for an empty/failed method, not to multiply
an already ambiguous result.

A semantic route has three independent states that must never be collapsed:

1. **execution complete** — one bounded provider attempt finished;
2. **proof complete** — cited observations satisfy the relation and every
   required proof-supported restriction; and
3. **route exhausted** — every valid bounded retrieval stage, continuation,
   declared alternative and eligible capability-discovery action was either
   attempted or rejected with an audited reason.

A complete-empty query establishes only the first state. It normally creates an
`ATTEMPTED_EMPTY` relation assessment and a material delta for bounded recovery;
it does not establish semantic absence. Per-goal assessment states are
`UNPLANNED`, `PLANNED`, `ATTEMPTED_EMPTY`, `ATTEMPTED_PARTIAL`,
`CANDIDATE_OBSERVED`, `PROOF_GAP`, `CAPABILITY_GAP`, `VERIFIED` and
`ROUTE_EXHAUSTED`, with separate terminal causes for user decision, unsupported,
unreachable and budget exhaustion.

Provider operations declare an ordered, bounded retrieval policy. A recovery
stage may remove only predicates classified as retrieval hints. Verified entity
bindings, provider scope, time window, projection, row/page limits and proof
obligations remain invariant across stages. The controller records each attempt
and rejects a repeated no-progress signature. This is progressive retrieval,
not an unbounded fallback sweep.

Static typed reachability is not capability readiness. Readiness is evaluated
per required relation from typed reachability, input grounding, source/runtime
provenance, retrieval support, proof-supported restrictions, qualifier
observability and prior route state. A reachable retrieval-only operation may
collect candidates, but it cannot suppress runtime capability discovery when a
proof or observability gap remains.

### 3.4 Observation and EvidenceGraph

Raw observations are append-only and retain provider-native fields, native type,
query ID, cursor/completeness, timestamps and integrity metadata. Normalized
facts are additive aliases and never replace native data.

The EvidenceGraph contains observations and citations, normalized facts and
field roles, candidate and verified relations, claim status
(`UNPROVEN`, `SUPPORTED`, `REFUTED`, `PARTIAL`, `UNKNOWN`) and coverage/diagnostic
records.

Only deterministic verification may promote a claim. LLM prose cannot create an
observation, value, relation or final verdict.

## 4. Component responsibilities and LLM boundary

| Component | Responsibility | LLM boundary |
|---|---|---|
| Provider Census | Discover reachable sources, partitions, schemas, permissions and completeness. | None. |
| Relation-scoped Batcher | Schedule every source/field for an unresolved graph relation in auditable context-sized batches. | None. |
| Semantic Compiler | Convert request into typed variables, relations, qualifiers and answer variables. | One schema-strict proposal; no native query and no evidence assertion. |
| Source Capability Profiler | Propose source/field-role/relation candidates from bounded census data. | One schema-strict candidate set; no invented source/field/value and no evidence assertion. |
| Plan Validator | Preserve objective, reject unsupported expansion and validate provenance. | None. |
| Capability Validator and Probe Executor | Verify source/field IDs and materialize only observable runtime operations. | None. |
| Capability Binder | Match claim requirements to validated operations with compatible inputs/outputs. | Optional ranking only among already valid candidates. |
| Action Controller | Select bounded actions from unresolved claims and available capabilities. | None for safety, state and budget. |
| Provider Adapter | Compile `QueryIntent`, or AST-validate a quarantined native candidate, then execute read-only queries and expose completeness. | Native candidate only after intent compilation is insufficient; never direct execution. |
| Observation Ledger | Preserve raw rows and audit metadata. | None. |
| Fact/Evidence Builder | Extract facts, roles and evidence cards; update graph. | None for admission and identity of facts. |
| Claim Verifier | Check citations, roles, time, completeness and acceptance rules. State-transition claims consume the validated operation's exact `temporal_roles`, `action_roles`, `state_roles`, `artifact_identity_roles` and `correlation_roles`; supplied observations must be cited members of the ledger and share provider/scope plus a compatible typed entity. | None. |
| Grounded Explainer | Explain verified evidence and limitations. | At most one bounded call; citations are checked and no new values allowed. |
| Final Reporter | Render answer, evidence, queries, coverage, stopping decision and cost. | LLM text is advisory only. |

## 5. Coverage coordinate

```text
Cell = (ProviderScope, entity | ANY, time_bucket)
```

`Cell` is an execution and coverage coordinate. It has no `event_family`,
`event_code`, semantic-intent or reasoning role. It records queried scope,
entity, time, cursor state and completeness.

Coverage is reported independently: claim coverage, scope coverage, query
completeness and evidence coverage. No targeted query implies full scope
coverage. An incomplete or unobservable query cannot support a negative
conclusion.

## 6. Action and stopping policy

An action is valid only if it reduces at least one unresolved claim and its
operation contract is satisfiable. Discovery, resolution, testing,
correlation, expansion and refinement are action labels—not a fixed universal
sequence.

```text
unresolved claims
  -> candidate operations
  -> completeness/cost/relevance score
  -> bounded action
  -> new observations
  -> verification or bounded replanning
```

Terminal decisions include `STOP_RESOLVED`, `STOP_REFUTED`,
`STOP_INCONCLUSIVE`, `STOP_COVERAGE_GAP`, `STOP_UNSUPPORTED_CAPABILITY`,
`STOP_UNREACHABLE` and `STOP_BUDGET_EXHAUSTED`. `NO_EVIDENCE_FOUND` is not
equivalent to `BENIGN`.

## 7. Resource and security policy

Budgets are configuration values to be measured, not scientific constants:
LLM calls, tokens, queries, scan cells, runtime, retries and result volume.
The controller stops when a budget is exhausted and records why.

User text, CTI, and native log content are untrusted data. Prompt injection
must not change objective, claims, provider policy, scope, state, disposition
or budgets.

## 8. Final output

The analyst-facing report contains request and answer contract, claim plan and
reason, cited evidence and explanation, queries and completeness, answer/claim
states, coverage, limitations and LLM/query/runtime cost. The raw ledger
remains available as an auditable artifact rather than an unstructured report
dump.
